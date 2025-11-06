#!/usr/bin/env python3
import os
import sys
import time
import threading
import traceback
import asyncio
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

# ----- dynamic imports -----
def ensure_import(name, package=None):
    try:
        return __import__(name)
    except Exception:
        pkg = package or name
        print(f"[setup] package '{pkg}' not found, attempting to install...", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        return __import__(name)

aiohttp = ensure_import("aiohttp")

# ed25519 from cryptography (you said it's installed)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

# ----- constants -----
SOL_RPC = "https://solana.publicnode.com"
TRIED_FILE = "tried.txt"
FOUND_FILE = "found.txt"
LIGHT_GREEN = "\033[92m"
LIGHT_RED = "\033[91m"
RESET_COLOR = "\033[0m"

# ----- globals -----
scanned_lock = threading.Lock()
found_lock = threading.Lock()
in_memory_tried = set()
stop_event = threading.Event()
sequential_counter = 0

# ----- load tried keys -----
if os.path.exists(TRIED_FILE):
    try:
        with open(TRIED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                l = line.strip()
                if l:
                    in_memory_tried.add(l)
    except Exception as e:
        print(f"[warn] Could not load {TRIED_FILE}: {e}", file=sys.stderr)

# ----- helpers -----
def append_tried(key_repr: str):
    with scanned_lock:
        if key_repr in in_memory_tried:
            return
        with open(TRIED_FILE, "a", encoding="utf-8") as f:
            f.write(key_repr + "\n")
        in_memory_tried.add(key_repr)

def append_found(line: str):
    with found_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def format_found_block(priv_repr, address, balance_str, positive: bool):
    border = "=" * 60
    color = LIGHT_GREEN if positive else LIGHT_RED
    return "\n".join([
        border,
        f"PRIVATE_KEY: {priv_repr}",
        f"ADDRESS: {address}",
        f"BALANCE: {color}{balance_str}{RESET_COLOR}",
        border
    ])

# ----- improved sequential-but-wallet-friendly key generator -----
def gen_sequential_seed():
    """
    Produce a deterministic 32-byte seed from a monotonically increasing counter.
    We hash the counter (big-endian bytes) with SHA-256 and return the digest.
    This yields evenly-distributed 32 bytes (no long runs of zeros) while remaining sequential/reproducible.
    """
    global sequential_counter
    sequential_counter += 1
    # Use the counter as big-endian bytes (minimal length)
    counter_bytes = sequential_counter.to_bytes((sequential_counter.bit_length() + 7) // 8 or 1, "big")
    # Hash the counter bytes to produce a 32-byte seed
    seed32 = hashlib.sha256(counter_bytes).digest()
    return seed32

# ----- base58 encoder -----
B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def base58_encode(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    res = bytearray()
    while n > 0:
        n, rem = divmod(n, 58)
        res.append(B58_ALPHABET[rem])
    leading_zeros = 0
    for c in b:
        if c == 0:
            leading_zeros += 1
        else:
            break
    return (B58_ALPHABET[0:1] * leading_zeros + bytes(reversed(res))).decode()

# ----- ed25519 derivation -----
def ed25519_pub_from_seed(seed32: bytes) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(seed32)
    pub = priv.public_key()
    return pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

# ----- RPC helpers -----
async def rpc_post_with_retries(url: str, json_payload: dict, session: aiohttp.ClientSession, debug: bool=False, max_attempts: int=3):
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            async with session.post(url, json=json_payload, timeout=15) as r:
                text = await r.text()
                if debug:
                    print(f"[debug][rpc] POST {url} payload={json_payload} status={r.status} resp={text}")
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            last_exc = e
            if attempt < max_attempts:
                await asyncio.sleep(attempt)
    raise last_exc

async def sol_get_balance(rpc_url, address, session, debug=False):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [address, {"commitment": "confirmed"}]}
    j = await rpc_post_with_retries(rpc_url, json_payload=payload, session=session, debug=debug) if False else await rpc_post_with_retries(rpc_url, payload, session, debug)
    if "error" in j:
        raise RuntimeError(f"RPC error: {j['error']}")
    res = j.get("result", {})
    lamports = res.get("value", 0) or 0
    return int(lamports)

# ----- Solana worker -----
async def worker_sol_async(rpc_url, debug=False, concurrency=20):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        sem = asyncio.Semaphore(concurrency)

        async def check_one():
            async with sem:
                try:
                    seed = gen_sequential_seed()
                    seed_hex = seed.hex()
                    key_repr = f"solana:{seed_hex}"
                    if key_repr in in_memory_tried:
                        return
                    append_tried(key_repr)

                    pub = ed25519_pub_from_seed(seed)
                    address = base58_encode(pub)

                    lamports = await sol_get_balance(rpc_url, address, session, debug)
                    sol_balance = lamports / 1_000_000_000
                    threshold = 0.000000  # your threshold: >0.000000 = green, ≤0.000000 = red
                    positive = sol_balance > threshold
                    bal_str = f"{sol_balance:.9f} SOL (lamports={lamports})"

                    if positive:
                        secret_bytes = seed + pub
                        secret_json_array = json.dumps(list(secret_bytes))
                        print(format_found_block(secret_json_array, address, bal_str, positive))
                        append_found(f"solana | {secret_json_array} | {address} | {bal_str}")
                    else:
                        # show red (hidden priv) as before
                        print(format_found_block("<hidden>", address, bal_str, positive))
                except Exception:
                    if debug:
                        traceback.print_exc()
                    await asyncio.sleep(0.01)

        while not stop_event.is_set():
            tasks = [check_one() for _ in range(concurrency)]
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.005)

# ----- async runner -----
def run_async_worker(coro_func, *args, **kwargs):
    try:
        asyncio.run(coro_func(*args, **kwargs))
    except Exception as e:
        print(f"[worker][fatal] {e}")

# ----- main -----
def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-c", "--concurrency", type=int, default=20, help="Concurrent async requests per worker (default: 20)")
    args = parser.parse_args()
    debug = args.debug
    concurrency = max(1, args.concurrency)

    print(f"[info] Starting Solana scanner. Debug={debug}. Mode=sequential-hash. Concurrency={concurrency}. Press Ctrl+C to stop.")
    open(TRIED_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=5) as ex:
        for _ in range(5):
            ex.submit(run_async_worker, worker_sol_async, SOL_RPC, debug, concurrency)
        try:
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, shutting down immediately...")
            stop_event.set()
            time.sleep(0.2)
    print("[info] Scanner stopped. Goodbye.")

if __name__ == "__main__":
    main()
