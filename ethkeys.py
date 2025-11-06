#!/usr/bin/env python3
"""
Async Ethereum key scanner using aiohttp and coincurve for fast derivation.

- Uses coincurve + eth_utils.keccak for pubkey -> address
- Uses asyncio + aiohttp for non-blocking RPC requests
- Keeps concurrency to 5 simultaneous workers via asyncio.Semaphore
- Appends every tried key to triedeth.txt so the run can resume
- Appends found blocks (non-colored) to found.txt
- Debug mode (-d) prints every progress line and every 10s prints keys/s
"""

import asyncio
import argparse
import sys
import signal
import os
import re
from datetime import datetime
from decimal import Decimal, getcontext
from colorama import init as colorama_init, Fore, Style
from typing import Optional, Tuple, List

# cryptography & utils
try:
    import coincurve
    from eth_utils import keccak, to_checksum_address
except Exception as e:
    print("ERROR: coincurve and eth_utils are required. Install with: pip install coincurve eth-utils")
    raise

import aiohttp
import aiohttp.client_exceptions

# precision for Decimal
getcontext().prec = 40

# ---- Config ----
BASE_HEX = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
RPC_URL = "https://ethereum.publicnode.com"
CONCURRENCY = 5  # keep 5 "threads" worth of concurrency
BATCH_SIZE = 20   # smaller default batch (you can change via --batch)
SLEEP_BETWEEN_BATCHES = 1.0
THRESHOLD_ETH = Decimal("0.0000001")
RETRY_SLEEP = [1, 2, 3]  # backoff sequence (seconds)
TRIED_FILE = "triedeth.txt"
FOUND_FILE = "found.txt"
STATS_INTERVAL = 10.0  # seconds for debug stats print
TIMEOUT = 10  # seconds for RPC call timeout
# -----------------

colorama_init(autoreset=True)

# locks for synchronous file writing (we'll run file IO in threadpool to avoid blocking)
# use a simple asyncio-compatible wrapper via asyncio.to_thread
_file_lock = asyncio.Lock()

# regex to strip ANSI for width computations
_ansi_re = re.compile(r'\x1b\[[0-9;]*m')

# global counters
total_tried = 0
total_tried_lock = asyncio.Lock()

# shutdown flag
shutdown_flag = False


def strip_ansi(s: str) -> str:
    return _ansi_re.sub('', s)


def derive_address_from_priv_int(priv_int: int) -> Tuple[str, str]:
    """
    Fast derivation using coincurve + keccak. Returns (priv_hex, checksum_address).
    """
    priv_bytes = priv_int.to_bytes(32, byteorder="big")
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)  # 65 bytes, 0x04 prefix
    pub_no_prefix = pub_uncompressed[1:]
    addr_bytes = keccak(pub_no_prefix)[-20:]
    address = to_checksum_address("0x" + addr_bytes.hex())
    priv_hex = f"0x{priv_int:064x}"
    return priv_hex, address


def format_found_block(idx: int, priv_hex: str, address: str, balance_eth: Decimal) -> Tuple[str, str]:
    bal_str = f"{balance_eth.normalize():f}"
    color = Fore.GREEN if balance_eth >= THRESHOLD_ETH else Fore.RED
    lines = [
        f"Index  : {idx}",
        f"Priv   : {priv_hex}",
        f"Address: {address}",
        f"Balance: {bal_str} ETH"
    ]
    width = max(len(strip_ansi(l)) for l in lines) + 2
    border = "+" + "-" * width + "+"
    # file block (no color)
    file_block = "\n".join([
        border,
        "| " + f"Index  : {idx}".ljust(width - 2) + " |",
        "| " + f"Priv   : {priv_hex}".ljust(width - 2) + " |",
        "| " + f"Address: {address}".ljust(width - 2) + " |",
        "| " + f"Balance: {bal_str} ETH".ljust(width - 2) + " |",
        border
    ]) + "\n"
    # console block (colored balance)
    printable_lines = [
        border,
        "| " + f"Index  : {idx}".ljust(width - 2) + " |",
        "| " + f"Priv   : {priv_hex}".ljust(width - 2) + " |",
        "| " + f"Address: {address}".ljust(width - 2) + " |",
        "| " + f"Balance: {color}{bal_str} ETH{Style.RESET_ALL}".ljust(width - 2 + len(color) + len(Style.RESET_ALL)) + " |",
        border
    ]
    console_block = "\n".join(printable_lines) + "\n"
    return console_block, file_block


async def append_tried_line(idx: int, priv_hex: str, address: str):
    line = f"{idx},{priv_hex},{address},{datetime.utcnow().isoformat()}Z\n"
    async with _file_lock:
        # do actual write in a thread so we don't block event loop for disk IO
        await asyncio.to_thread(_append_to_file, TRIED_FILE, line)


async def append_found_block(file_block: str):
    async with _file_lock:
        await asyncio.to_thread(_append_to_file, FOUND_FILE, file_block)


def _append_to_file(filename: str, text: str):
    # helper running in threadpool (sync)
    with open(filename, "a", encoding="utf-8") as f:
        f.write(text)


def read_resume_offset_from_triedfile() -> int:
    """
    Reads TRIED_FILE synchronously and returns next start offset (max idx + 1).
    If file doesn't exist or empty, returns 1.
    This runs at startup (sync is fine).
    """
    if not os.path.exists(TRIED_FILE):
        return 1
    max_idx = 0
    try:
        with open(TRIED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(",")
                try:
                    idx = int(parts[0])
                    if idx > max_idx:
                        max_idx = idx
                except Exception:
                    continue
    except Exception:
        return 1
    return max_idx + 1


def wei_hex_to_decimal_eth(wei_hex: str) -> Decimal:
    wei_int = int(wei_hex, 16)
    return Decimal(wei_int) / Decimal(10**18)


async def eth_get_balance_with_retries(session: aiohttp.ClientSession, address: str, debug: bool=False) -> Decimal:
    """
    Async eth_getBalance with retry/backoff. Uses aiohttp session.
    """
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1,
    }
    attempt = 0
    last_exc = None
    max_attempts = 1 + len(RETRY_SLEEP)
    while attempt < max_attempts and not shutdown_flag:
        try:
            async with session.post(RPC_URL, json=payload, timeout=TIMEOUT) as resp:
                text = await resp.text()
                resp.raise_for_status()
                j = await resp.json()
                if "result" not in j:
                    raise RuntimeError(f"Invalid RPC response: {j} (text={text})")
                return wei_hex_to_decimal_eth(j["result"])
        except Exception as e:
            last_exc = e
            attempt += 1
            if debug:
                print(f"[DEBUG] RPC attempt {attempt}/{max_attempts} for {address} failed: {e}")
            if attempt >= max_attempts or shutdown_flag:
                break
            sleep_time = RETRY_SLEEP[attempt - 1] if (attempt - 1) < len(RETRY_SLEEP) else RETRY_SLEEP[-1]
            await asyncio.sleep(sleep_time)
    raise last_exc


async def worker_task(priv_int: int, idx: int, session: aiohttp.ClientSession, semaphore: asyncio.Semaphore, debug: bool):
    """
    Derives address, queries balance (with retries), appends tried line, returns found tuple if balance > 0.
    """
    global total_tried

    # derive (sync, fast)
    try:
        priv_hex, address = derive_address_from_priv_int(priv_int)
    except Exception as e:
        if debug:
            print(f"[DEBUG] idx={idx} derive error: {e}")
        return None

    async with semaphore:
        # perform RPC with retries
        try:
            balance_eth = await eth_get_balance_with_retries(session, address, debug=debug)
        except Exception as e:
            # append tried line and count even if failed
            await append_tried_line(idx, priv_hex, address)
            async with total_tried_lock:
                total_tried += 1
            if debug:
                print(f"[DEBUG] idx={idx} address={address} error after retries: {e}")
            else:
                print(f"[ERROR] idx={idx} address={address} error: {e}")
            return None

    # append tried line and increment
    await append_tried_line(idx, priv_hex, address)
    async with total_tried_lock:
        total_tried += 1

    if balance_eth > 0:
        return (idx, priv_hex, address, balance_eth)
    else:
        if debug:
            print(f"[DEBUG] idx={idx} address={address} balance=0")
        return None


async def stats_printer(debug: bool, stop_event: asyncio.Event):
    """
    Every STATS_INTERVAL seconds, if debug enabled, print keys/sec averaged over interval.
    """
    last_count = 0
    last_time = asyncio.get_event_loop().time()
    while not stop_event.is_set():
        await asyncio.sleep(STATS_INTERVAL)
        if not debug:
            continue
        now = asyncio.get_event_loop().time()
        async with total_tried_lock:
            curr = total_tried
        delta = curr - last_count
        dt = now - last_time
        kps = delta / dt if dt > 0 else 0.0
        print(Fore.GREEN + f"[STATS] {kps:.2f} keys/s over last {dt:.1f}s (total tried: {curr})" + Style.RESET_ALL)
        last_count = curr
        last_time = now


def generate_priv_ints_for_batch(base_int: int, start_offset: int, count: int):
    """
    Yield (priv_int, idx) pairs for offsets start_offset .. start_offset+count-1
    priv_int = base_int - idx
    """
    for i in range(count):
        idx = start_offset + i
        priv_int = base_int - idx
        if priv_int <= 0:
            break
        yield priv_int, idx


async def main_async(base_hex: str, start_offset: int = 1, batch_size: int = BATCH_SIZE, debug: bool = False, resume: bool = True):
    global shutdown_flag, total_tried

    base_int = int(base_hex, 16)
    if resume:
        resumed = read_resume_offset_from_triedfile()
        if resumed > start_offset:
            print(f"Resuming from tried file: setting start_offset {start_offset} -> {resumed}")
            start_offset = resumed

    offset = start_offset

    # aiohttp session reused for all requests
    connector = aiohttp.TCPConnector(limit=0)  # no limit here; concurrency controlled by our semaphore
    async with aiohttp.ClientSession(connector=connector) as session:
        semaphore = asyncio.Semaphore(CONCURRENCY)
        stop_event = asyncio.Event()
        stats_task = asyncio.create_task(stats_printer(debug, stop_event))

        print(f"Starting async scanner against {RPC_URL} with concurrency={CONCURRENCY}, batch_size={batch_size}, debug={debug}")
        print("Press Ctrl+C to stop.")
        try:
            while not shutdown_flag:
                items = list(generate_priv_ints_for_batch(base_int, offset, batch_size))
                if not items:
                    print("Reached zero or no more positive private keys. Stopping.")
                    break

                # spawn tasks for this batch
                tasks = [
                    asyncio.create_task(worker_task(priv_int, idx, session, semaphore, debug))
                    for (priv_int, idx) in items
                ]

                # as tasks complete, handle results
                for coro in asyncio.as_completed(tasks):
                    try:
                        result = await coro
                        if result:
                            idx, priv_hex, address, balance_eth = result
                            console_block, file_block = format_found_block(idx, priv_hex, address, balance_eth)
                            # print console block
                            print(console_block, end="", flush=True)
                            # persist file block (run in thread)
                            await append_found_block(file_block)
                    except Exception as e:
                        if debug:
                            print(f"[DEBUG] Unexpected worker exception: {e}")
                        else:
                            print(f"[ERROR] Unexpected worker exception: {e}")

                offset += batch_size
                if shutdown_flag:
                    break
                await asyncio.sleep(SLEEP_BETWEEN_BATCHES)
        except asyncio.CancelledError:
            pass
        finally:
            stop_event.set()
            await asyncio.sleep(0)  # allow stats_task to notice
            if not stats_task.done():
                stats_task.cancel()
                try:
                    await stats_task
                except asyncio.CancelledError:
                    pass

    print("Scanner stopped.")


def handle_sigint():
    global shutdown_flag
    shutdown_flag = True
    print("\nStopping scanner... (signal caught)")


def main():
    parser = argparse.ArgumentParser(description="Async Ethereum key scanner (coincurve + aiohttp)")
    parser.add_argument("-d", "--debug", action="store_true", help="enable debug mode (very verbose + keys/s)")
    parser.add_argument("--batch", type=int, default=BATCH_SIZE, help="batch size per loop")
    parser.add_argument("--start-offset", type=int, default=1, help="start offset (1 => base-1)")
    parser.add_argument("--no-resume", dest="no_resume", action="store_true", help="do not read triedeth.txt to resume")
    args = parser.parse_args()

    # setup shutdown handlers
    loop = asyncio.get_event_loop()
    for signame in ('SIGINT', 'SIGTERM'):
        try:
            loop.add_signal_handler(getattr(signal, signame), handle_sigint)
        except NotImplementedError:
            # Windows: fallback to signal.signal
            signal.signal(getattr(signal, signame), lambda s, f: handle_sigint())

    try:
        asyncio.run(main_async(BASE_HEX, start_offset=args.start_offset, batch_size=args.batch, debug=args.debug, resume=(not args.no_resume)))
    except KeyboardInterrupt:
        print("\nInterrupted by user, exiting.")
    except Exception as e:
        print(f"[FATAL] {e}")
        raise


if __name__ == "__main__":
    main()
