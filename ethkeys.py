#!/usr/bin/env python3
import os
import sys
import time
import threading
import traceback
import asyncio
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import coincurve
from eth_utils import keccak

# Files
TRIED_FILE = "triedeth.txt"
FOUND_FILE = "found.txt"

# Concurrency & locks
scanned_lock = threading.Lock()   # protects in_memory_tried and file append for tried
found_lock = threading.Lock()     # protects found file append
in_memory_tried = set()
stop_event = threading.Event()    # thread-safe stop signal

# Visuals
LIGHT_GREEN = "\033[92m"
RESET_COLOR = "\033[0m"

# RPC
ETH_RPC = "https://ethereum.publicnode.com"

# Load tried keys at startup (if any)
if os.path.exists(TRIED_FILE):
    try:
        with open(TRIED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                l = line.strip()
                if l:
                    in_memory_tried.add(l)
    except Exception as e:
        print(f"[warn] Could not load {TRIED_FILE}: {e}", file=sys.stderr)

def append_tried(key_repr: str):
    """Append tried key if not already present. Thread-safe and idempotent."""
    with scanned_lock:
        if key_repr in in_memory_tried:
            return
        try:
            with open(TRIED_FILE, "a", encoding="utf-8") as f:
                f.write(key_repr + "\n")
            in_memory_tried.add(key_repr)
        except Exception as e:
            # If file write fails, still add to memory to avoid retries in the same run
            in_memory_tried.add(key_repr)
            print(f"[error] Failed to append tried key to file: {e}", file=sys.stderr)

def append_found(line: str):
    with found_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def format_found_block(chain, privhex, address, balance_str):
    border = "=" * 60
    return "\n".join([
        border,
        f"CHAIN: {chain}",
        f"PRIVATE_KEY: {privhex}",
        f"ADDRESS: {address}",
        f"BALANCE: {LIGHT_GREEN}{balance_str}{RESET_COLOR}",
        border
    ])

# ---------- Key generation / address derivation ----------
def gen_eth_privkey_bytes():
    """Return 32 bytes of a new random secp256k1 private key."""
    return coincurve.PrivateKey().secret

def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if len(pub_uncompressed) == 65 and pub_uncompressed[0] == 0x04 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return "0x" + addr_bytes.hex()  # lowercase, 0x-prefixed

# ---------- RPC with retries and exact backoff ----------
async def rpc_post_with_retries(url: str, json_payload: dict, session: aiohttp.ClientSession, debug: bool=False):
    """
    Send POST with 3 attempts. Backoffs are exactly 1s, 2s, 3s between attempts.
    On each attempt, if debug: print request and response (or failure).
    """
    delays = [1, 2, 3]
    last_exc = None
    for attempt in range(1, 4):
        try:
            async with session.post(url, json=json_payload, timeout=15) as r:
                text = await r.text()
                if debug:
                    print(f"[debug][RPC attempt {attempt}] POST {url} payload={json_payload} status={r.status} response={text}")
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            last_exc = e
            if attempt == 3:
                # final attempt failed -> re-raise
                if debug:
                    print(f"[debug][RPC attempt {attempt}] final failure: {e}")
                raise
            else:
                delay = delays[attempt - 1]
                if debug:
                    print(f"[debug][RPC attempt {attempt}] failed: {e}. retrying in {delay}s...")
                await asyncio.sleep(delay)
    raise last_exc

async def eth_get_balance(rpc_url, address, session, debug: bool=False):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    j = await rpc_post_with_retries(rpc_url, payload, session, debug)
    if isinstance(j, dict) and "error" in j:
        raise RuntimeError(f"RPC error: {j['error']}")
    # Some nodes may return hex string or None; handle safely
    result = j.get("result", 0) if isinstance(j, dict) else 0
    if result is None:
        return 0
    return int(result, 16)

# ---------- Worker (single) ----------
async def worker_eth_async(chain_name: str, rpc_url: str, debug: bool=False):
    """
    One async worker that continuously generates keys, checks balances.
    Intended to be run inside a thread-specific event loop.
    """
    # Use a single ClientSession per worker
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        generated_counter = 0
        while not stop_event.is_set():
            try:
                priv = gen_eth_privkey_bytes()
                privhex = "0x" + priv.hex()
                key_repr = f"{chain_name}:{privhex}"

                # Ensure we never retry the same key across threads/runs
                with scanned_lock:
                    already = key_repr in in_memory_tried
                    if not already:
                        # append immediately so other threads know it's tried
                        try:
                            with open(TRIED_FILE, "a", encoding="utf-8") as f:
                                f.write(key_repr + "\n")
                        except Exception as e:
                            # if file append fails, still add to memory to avoid retrying in this run
                            print(f"[error] Could not write to {TRIED_FILE}: {e}", file=sys.stderr)
                        in_memory_tried.add(key_repr)

                if already:
                    if debug:
                        print(f"[debug] Skipping already-tried key: {privhex}")
                    await asyncio.sleep(0.01)
                    continue

                # At this point, the key_repr has been recorded (atomic-ish under scanned_lock)
                address = eth_priv_to_address(priv)

                if debug:
                    generated_counter += 1
                    # print every generated key in debug mode
                    print(f"[debug][gen #{generated_counter}] priv={privhex} address={address}")

                # Check balance with exact retry/backoff behavior handled in eth_get_balance
                try:
                    bal_wei = await eth_get_balance(rpc_url, address, session, debug)
                except Exception as e:
                    # Normal mode: print errors. Debug mode: full trace.
                    print(f"[error] RPC or balance error for {address}: {e}")
                    if debug:
                        traceback.print_exc()
                    # small sleep to avoid tight loop on persistent RPC failure
                    await asyncio.sleep(0.1)
                    continue

                if bal_wei and bal_wei > 0:
                    bal_eth = bal_wei / 10**18
                    bal_str = f"{bal_eth:.18f} ETH (wei={bal_wei})"
                    out = format_found_block(chain_name, privhex, address, bal_str)
                    print(out)
                    append_found(f"{chain_name} | {privhex} | {address} | {bal_str}")

                # tiny sleep to be network-friendly
                await asyncio.sleep(0.005)
            except Exception as e:
                # Always surface worker exceptions in normal mode; more detail in debug
                print(f"[error] Worker exception: {e}")
                if debug:
                    traceback.print_exc()
                await asyncio.sleep(0.05)

# ---------- Thread runner ----------
def run_worker_in_thread(chain_name: str, rpc_url: str, debug: bool=False):
    """
    Each thread runs its own asyncio event loop and runs the async worker.
    This allows us to use multiple threads while keeping async RPC IO.
    """
    try:
        # Create & set a new event loop for this thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        coro = worker_eth_async(chain_name, rpc_url, debug)
        loop.run_until_complete(coro)
    except Exception as e:
        print(f"[worker][fatal] Thread worker crashed: {e}", file=sys.stderr)
        if debug:
            traceback.print_exc()
    finally:
        try:
            loop.stop()
            loop.close()
        except Exception:
            pass

# ---------- Main ----------
def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Print everything (debug mode)")
    parser.add_argument("-t", "--threads", type=int, default=3, help="Number of threads to spawn (default: 3)")
    args = parser.parse_args()
    debug = args.debug
    thread_count = max(1, min(10, args.threads))  # reasonable bounds

    print(f"[info] Starting Ethereum scanner. Debug={debug}. Threads={thread_count}. Press Ctrl+C to stop.")
    # Ensure files exist
    open(TRIED_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=thread_count) as ex:
        futures = []
        for i in range(thread_count):
            futures.append(ex.submit(run_worker_in_thread, "ethereum", ETH_RPC, debug))
        try:
            # Wait until KeyboardInterrupt
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, shutting down...")
            stop_event.set()
            # give workers a moment to exit
            time.sleep(0.5)
        finally:
            # best-effort shutdown: threads will see stop_event and exit their loops
            for f in futures:
                try:
                    f.cancel()
                except Exception:
                    pass
    print("[info] Scanner stopped. Goodbye.")

if __name__ == "__main__":
    main()
