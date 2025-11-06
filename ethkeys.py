#!/usr/bin/env python3
"""
Fast async Ethereum key scanner (resumable).
- Uses coincurve + eth_utils.keccak for key derivation
- aiohttp async RPC requests
- 5 concurrent workers
- Retries with backoff
- Saves resume.txt (last scanned index)
- Writes only found addresses to found.txt
- Debug mode (-d) prints progress + keys/s
"""

import asyncio
import aiohttp
import time
from decimal import Decimal, getcontext
from colorama import Fore, Style, init as colorama_init
from eth_utils import keccak, to_checksum_address
from coincurve import PrivateKey
import argparse
import os

getcontext().prec = 40
colorama_init(autoreset=True)

RPC_URL = "https://ethereum.publicnode.com"
THREADS = 5
BATCH_SIZE = 10
SLEEP_BETWEEN_BATCHES = 0.2
THRESHOLD_ETH = Decimal("0.0000001")
RETRY_SLEEP = [1, 2, 3]
BASE_HEX = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
RESUME_FILE = "resume.txt"
FOUND_FILE = "found.txt"

total_tried = 0
total_tried_lock = asyncio.Lock()


def wei_hex_to_eth(wei_hex: str) -> Decimal:
    return Decimal(int(wei_hex, 16)) / Decimal(10**18)


def derive_address(priv_int: int):
    priv_bytes = priv_int.to_bytes(32, "big")
    pub = PrivateKey(priv_bytes).public_key.format(compressed=False)[1:]
    address = to_checksum_address("0x" + keccak(pub)[-20:].hex())
    priv_hex = f"0x{priv_int:064x}"
    return priv_hex, address


async def eth_get_balance(session: aiohttp.ClientSession, address: str, debug: bool):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1,
    }
    for attempt, sleep_time in enumerate([0] + RETRY_SLEEP):
        try:
            async with session.post(RPC_URL, json=payload, timeout=10) as resp:
                r = await resp.json()
                if "result" not in r:
                    raise Exception(f"Invalid RPC response: {r}")
                return wei_hex_to_eth(r["result"])
        except Exception as e:
            if debug:
                print(f"[DEBUG] Retry {attempt + 1} for {address}: {e}")
            await asyncio.sleep(sleep_time)
    raise Exception("RPC failed after retries")


def format_found(idx: int, priv_hex: str, address: str, balance: Decimal):
    bal_str = f"{balance:.8f}"
    color = Fore.GREEN if balance > 0 else ""
    border = "+" + "-" * 60 + "+"
    block = (
        f"{border}\n"
        f"| Index  : {idx}\n"
        f"| Priv   : {priv_hex}\n"
        f"| Address: {address}\n"
        f"| Balance: {color}{bal_str} ETH{Style.RESET_ALL}\n"
        f"{border}\n"
    )
    return block


def save_found(block: str):
    with open(FOUND_FILE, "a") as f:
        f.write(block)


def load_resume() -> int:
    if os.path.exists(RESUME_FILE):
        with open(RESUME_FILE) as f:
            try:
                return int(f.read().strip())
            except ValueError:
                return 1
    return 1


def save_resume(idx: int):
    with open(RESUME_FILE, "w") as f:
        f.write(str(idx))


async def worker(priv_int: int, idx: int, session: aiohttp.ClientSession, sem: asyncio.Semaphore, debug: bool):
    global total_tried
    priv_hex, address = derive_address(priv_int)

    async with sem:
        try:
            balance = await eth_get_balance(session, address, debug)
        except Exception as e:
            if debug:
                print(f"[DEBUG] {idx} {address} failed: {e}")
            return None

    async with total_tried_lock:
        total_tried += 1

    if balance > 0:
        block = format_found(idx, priv_hex, address, balance)
        print(block)
        save_found(block)
    elif debug:
        print(f"[DEBUG] idx={idx} balance=0")

    return None


async def stats_monitor(start_time: float, debug: bool, stop_event: asyncio.Event):
    last = 0
    last_t = start_time
    while not stop_event.is_set():
        await asyncio.sleep(10)
        if not debug:
            continue
        now = time.time()
        async with total_tried_lock:
            curr = total_tried
        rate = (curr - last) / (now - last_t)
        print(Fore.GREEN + f"[STATS] {rate:.2f} keys/s (total {curr})" + Style.RESET_ALL)
        last, last_t = curr, now


async def main_loop(base_hex: str, start_idx: int, debug: bool):
    base_int = int(base_hex, 16)
    sem = asyncio.Semaphore(THREADS)
    stop_event = asyncio.Event()
    asyncio.create_task(stats_monitor(time.time(), debug, stop_event))

    offset = start_idx
    print(f"Starting from offset {offset}, threads={THREADS}, batch={BATCH_SIZE}")

    async with aiohttp.ClientSession() as session:
        while True:
            tasks = []
            for i in range(BATCH_SIZE):
                priv_int = base_int - (offset + i)
                if priv_int <= 0:
                    print("Reached end of key range.")
                    stop_event.set()
                    return
                tasks.append(worker(priv_int, offset + i, session, sem, debug))

            await asyncio.gather(*tasks)
            offset += BATCH_SIZE
            save_resume(offset)
            await asyncio.sleep(SLEEP_BETWEEN_BATCHES)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Async Ethereum key scanner")
    parser.add_argument("-d", "--debug", action="store_true", help="debug mode")
    args = parser.parse_args()

    start_idx = load_resume()
    try:
        asyncio.run(main_loop(BASE_HEX, start_idx, debug=args.debug))
    except KeyboardInterrupt:
        print("\nStopped by user.")
