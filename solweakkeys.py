#!/usr/bin/env python3
import os
import sys
import time
import threading
import traceback
import asyncio
import json
import hashlib
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

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

# ----- sequential key generator -----
def gen_sequential_seed():
    """Generates a deterministic 32-byte seed based on a global counter."""
    global sequential_counter
    sequential_counter += 1
    counter_bytes = sequential_counter.to_bytes((sequential_counter.bit_length() + 7) // 8 or 1, "big")
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

# ----- ed25519 using installed lightweight library -----
import ed25519

def ed25519_pub_from_seed(seed32: bytes) -> bytes:
    """Derive public key from 32-byte private seed."""
    sk = ed25519.SigningKey(seed32)
    vk = sk.get_verifying_key()
    return vk.to_bytes()

# ----- RPC call using urllib (no aiohttp) -----
def sol_get_balance(rpc_url, address, debug=False):
    payload = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address, {"commitment": "confirmed"}]
    }).encode()
    req = urllib.request.Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            text = r.read().decode()
            j = json.loads(text)
            if "error" in j:
                raise RuntimeError(f"RPC error: {j['error']}")
            value = j.get("result", {}).get("value", 0)
            return int(value)
    except urllib.error.URLError as e:
        if debug:
            print("[rpc] error:", e)
        return 0
    except Exception as e:
        if debug:
            traceback.print_exc()
        return 0

# ----- worker -----
def sol_worker(debug=False):
    """Worker thread that generates seeds, checks balances, logs results."""
    while not stop_event.is_set():
        try:
            seed = gen_sequential_seed()
            seed_hex = seed.hex()
            key_repr = f"solana:{seed_hex}"
            if key_repr in in_memory_tried:
                continue
            append_tried(key_repr)

            pub = ed25519_pub_from_seed(seed)
            address = base58_encode(pub)

            lamports = sol_get_balance(SOL_RPC, address, debug)
            sol_balance = lamports / 1_000_000_000
            threshold = 0.000000
            positive = sol_balance > threshold
            bal_str = f"{sol_balance:.9f} SOL (lamports={lamports})"

            if positive:
                secret_bytes = seed + pub
                secret_json_array = json.dumps(list(secret_bytes))
                print(format_found_block(secret_json_array, address, bal_str, positive))
                append_found(f"solana | {secret_json_array} | {address} | {bal_str}")
            else:
                print(format_found_block("<hidden>", address, bal_str, positive))
        except Exception:
            if debug:
                traceback.print_exc()
            time.sleep(0.01)

# ----- main -----
def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-w", "--workers", type=int, default=5, help="Number of worker threads (default: 5)")
    args = parser.parse_args()
    debug = args.debug
    workers = max(1, args.workers)

    print(f"[info] Starting Solana scanner (using ed25519). Debug={debug}. Workers={workers}. Press Ctrl+C to stop.")
    open(TRIED_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for _ in range(workers):
            ex.submit(sol_worker, debug)
        try:
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, stopping...")
            stop_event.set()
            time.sleep(0.2)
    print("[info] Scanner stopped. Goodbye.")

if __name__ == "__main__":
    main()
