#!/usr/bin/env python3
import os
import sys
import time
import threading
import traceback
import asyncio
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser
from typing import Optional

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
coincurve = ensure_import("coincurve")
eth_utils = ensure_import("eth_utils")
from eth_utils import to_checksum_address, keccak

ETH_RPC = "https://ethereum.publicnode.com"
TRIED_FILE = "tried.txt"
FOUND_FILE = "found.txt"
scanned_lock = threading.Lock()
found_lock = threading.Lock()
in_memory_tried = set()
stop_event = threading.Event()

# Load already tried keys
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

def format_found_block(chain, privhex, address, balance_str):
    border = "=" * 60
    return "\n".join([
        border,
        f"CHAIN: {chain}",
        f"PRIVATE_KEY: {privhex}",
        f"ADDRESS: {address}",
        f"BALANCE: {balance_str}",
        border
    ])

# ----- Generators -----
repetitive_patterns = [b'a', b'b', b'c', b'd', b'e', b'f', b'1', b'2', b'3', b'4']
sequential_counter_eth = 0
repetitive_index_eth = 0
MIXED_PATTERNS = b'abcdefghijklmnopqrstuvwxyz0123456789'
mixed_index_eth = 0

def gen_repetitive_eth():
    global repetitive_index_eth
    letter = repetitive_patterns[repetitive_index_eth % len(repetitive_patterns)]
    repetitive_index_eth += 1
    return letter * 32

def gen_sequential_numeric_eth():
    global sequential_counter_eth
    sequential_counter_eth += 1
    return sequential_counter_eth.to_bytes(32, "big", signed=False)

def gen_mixed_sequence_eth():
    global mixed_index_eth
    key = bytearray(32)
    for i in range(32):
        key[i] = MIXED_PATTERNS[(mixed_index_eth + i) % len(MIXED_PATTERNS)]
    mixed_index_eth += 1
    return bytes(key)

GENERATOR_MODES = ['repetitive', 'sequential', 'mixed']
mode_index_eth = 0

def gen_eth_privkey_bytes():
    global mode_index_eth
    mode = GENERATOR_MODES[mode_index_eth % len(GENERATOR_MODES)]
    mode_index_eth += 1
    if mode == 'repetitive':
        return gen_repetitive_eth()
    elif mode == 'sequential':
        return gen_sequential_numeric_eth()
    elif mode == 'mixed':
        return gen_mixed_sequence_eth()
    else:
        return gen_sequential_numeric_eth()

# ----- Address derivation -----
def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if len(pub_uncompressed) == 65 and pub_uncompressed[0] == 0x04 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return to_checksum_address("0x" + addr_bytes.hex())

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

async def eth_like_get_balance(rpc_url: str, address: str, session: aiohttp.ClientSession, debug=False) -> int:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    j = await rpc_post_with_retries(rpc_url, payload, session=session, debug=debug, max_attempts=3)
    result = j.get("result")
    return int(result, 16) if result else 0

# ----- Worker -----
async def worker_eth_async(chain_name, rpc_url, debug=False):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            try:
                priv = gen_eth_privkey_bytes()
                privhex = priv.hex()
                key_repr = f"{chain_name}:{privhex}"
                if key_repr in in_memory_tried:
                    if debug:
                        print(f"[{chain_name}] duplicate key, skipping {privhex}")
                    await asyncio.sleep(0.02)
                    continue
                append_tried(key_repr)
                address = eth_priv_to_address(priv)
                if debug:
                    print(f"[{chain_name}] trying priv={privhex} -> addr={address}")
                try:
                    bal_wei = await eth_like_get_balance(rpc_url, address, session, debug=debug)
                except Exception as rpc_e:
                    if debug:
                        print(f"[{chain_name}][rpc error] {rpc_e}")
                    await asyncio.sleep(0.2)
                    continue
                if bal_wei > 0:
                    bal_eth = bal_wei / 10**18
                    bal_str = f"{bal_eth:.18f} (wei={bal_wei})"
                    out = format_found_block(chain_name, privhex, address, bal_str)
                    print(out)
                    append_found(f"{chain_name} | {privhex} | {address} | {bal_str}")
                await asyncio.sleep(0.02)
            except Exception as e:
                if debug:
                    traceback.print_exc()
                await asyncio.sleep(0.05)

def run_async_worker(coro_func, *args, **kwargs):
    try:
        asyncio.run(coro_func(*args, **kwargs))
    except Exception as e:
        print(f"[worker][fatal] {e}")

def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--modes", nargs="+", choices=['repetitive','sequential','mixed'], help="Override generator modes and order")
    args = parser.parse_args()
    debug = args.debug

    if args.modes:
        global GENERATOR_MODES
        GENERATOR_MODES = args.modes

    print(f"[info] Starting Ethereum scanner. Debug={debug}. Modes={GENERATOR_MODES}. Press Ctrl+C to stop.")

    open(TRIED_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = []
        for _ in range(5):
            futures.append(ex.submit(run_async_worker, worker_eth_async, "ethereum", ETH_RPC, debug))
        try:
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, shutting down...")
            stop_event.set()
            time.sleep(0.2)
    print("[info] Scanner stopped. Goodbye.")

if __name__ == "__main__":
    main()
