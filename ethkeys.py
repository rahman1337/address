#!/usr/bin/env python3
"""
eth_scanner.py

Ethereum key scanner (multi-threaded) with debug/performance stats and persistent tried list.

Features:
 - 3 threads by default (configurable)
 - Private keys as lowercase hex (0x...)
 - Addresses both lowercase and EIP-55 checksum
 - RPC call uses checksum address
 - Debug mode prints all keys checked + performance stats every 10s
 - Normal mode prints only FOUND results and errors
 - Found results appended to found.txt as the same FOUND block text
 - Every tried private key is appended to triedeth.txt and never retried
Dependencies:
 pip install ecdsa pysha3
"""
import argparse
import os
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from ecdsa import SECP256k1, SigningKey
from sha3 import keccak_256
import urllib.request
import urllib.error
from decimal import Decimal

RPC_URL = "https://ethereum.publicnode.com"
NUM_THREADS = 3
RPC_TIMEOUT = 10  # seconds
TRIED_FILE = "triedeth.txt"
FOUND_FILE = "found.txt"

# Thread-safe print
_print_lock = threading.Lock()
def safe_print(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs, flush=True)

# Load tried keys into memory (set) and ensure file exists
_tried_lock = threading.Lock()
_tried_set = set()
def load_tried():
    if not os.path.exists(TRIED_FILE):
        # create empty file
        open(TRIED_FILE, "a").close()
        return
    try:
        with open(TRIED_FILE, "r") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                # normalize: allow lines with or without 0x
                if s.startswith("0x") or s.startswith("0X"):
                    s = s[2:]
                _tried_set.add(s.lower())
    except Exception as e:
        safe_print(f"[WARN] could not load {TRIED_FILE}: {e}")

def append_tried(priv_hex):
    """Append a newly-tried private key (hex without 0x) to triedeth.txt and to memory set."""
    priv_hex = priv_hex.lower()
    with _tried_lock:
        if priv_hex in _tried_set:
            return False
        try:
            with open(TRIED_FILE, "a") as f:
                f.write("0x" + priv_hex + "\n")
            _tried_set.add(priv_hex)
            return True
        except Exception as e:
            safe_print(f"[WARN] could not write to {TRIED_FILE}: {e}")
            # Even if writing failed, add to in-memory set to avoid immediate retry
            _tried_set.add(priv_hex)
            return True

# Key generation
def generate_private_key():
    curve = SECP256k1
    order = curve.order
    while True:
        priv = os.urandom(32)
        priv_int = int.from_bytes(priv, "big")
        if 1 <= priv_int < order:
            return priv

def private_key_to_public_key(priv_bytes):
    sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
    vk = sk.verifying_key
    return b'\x04' + vk.to_string()

def public_key_to_address_lower(pub_bytes):
    assert pub_bytes[0] == 0x04
    keccak = keccak_256()
    keccak.update(pub_bytes[1:])
    digest = keccak.digest()
    return digest[-20:].hex()  # lowercase 40-char hex

def to_checksum_address(address_hex):
    addr = address_hex.lower()
    keccak = keccak_256()
    keccak.update(addr.encode('ascii'))
    hash_hex = keccak.hexdigest()
    checksummed = []
    for i, c in enumerate(addr):
        if c in '0123456789':
            checksummed.append(c)
        else:
            checksummed.append(c.upper() if int(hash_hex[i], 16) >= 8 else c)
    return '0x' + ''.join(checksummed)

def rpc_eth_getBalance(address_hex_with_0x):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address_hex_with_0x, "latest"],
        "id": 1
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(RPC_URL, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=RPC_TIMEOUT) as resp:
            resp_data = resp.read().decode("utf-8")
            js = json.loads(resp_data)
            if "error" in js:
                raise RuntimeError(f"RPC error: {js['error']}")
            result = js.get("result")
            if result is None:
                raise RuntimeError("No result in RPC response")
            return int(result, 16)
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"HTTPError: {e.code} {e.reason}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"URLError: {e.reason}")
    except Exception:
        raise

def wei_to_eth_str(wei_int):
    eth = Decimal(wei_int) / Decimal(10**18)
    return format(eth.normalize(), 'f')

def append_found_block_to_file(priv_hex, addr_lower_0x, addr_checksum, balance_wei, balance_eth_str):
    """Append the same FOUND block text (as printed) to found.txt"""
    block_lines = []
    block_lines.append("FOUND -->")
    block_lines.append(f"  Private key (hex): 0x{priv_hex}")
    block_lines.append(f"  Address (lowercase): {addr_lower_0x}")
    block_lines.append(f"  Address (EIP-55) :    {addr_checksum}")
    block_lines.append(f"  Balance (wei):     {balance_wei}")
    block_lines.append(f"  Balance (ETH):     {balance_eth_str}")
    block_lines.append("-" * 60)
    try:
        with open(FOUND_FILE, "a") as f:
            for ln in block_lines:
                f.write(ln + "\n")
    except Exception as e:
        safe_print(f"[WARN] could not write to {FOUND_FILE}: {e}")

def worker_loop(worker_id, debug=False, total_counter=None):
    tries = 0
    while True:
        try:
            # generate until we get a private key not yet tried
            while True:
                priv = generate_private_key()
                priv_hex = priv.hex()  # lowercase hex
                # quick check in-memory set and append
                with _tried_lock:
                    already = priv_hex in _tried_set
                if already:
                    # extremely unlikely, but skip and generate another
                    continue
                # append_tried will add to set atomically and persist to file
                append_tried(priv_hex)
                break

            pub = private_key_to_public_key(priv)
            addr_hex = public_key_to_address_lower(pub)
            addr_lower_0x = "0x" + addr_hex
            addr_checksum = to_checksum_address(addr_hex)

            tries += 1
            if debug:
                safe_print(f"[worker {worker_id}] try #{tries} priv=0x{priv_hex} addr_lower={addr_lower_0x} addr_checksum={addr_checksum} ... checking")

            try:
                balance_wei = rpc_eth_getBalance(addr_checksum)
            except Exception as e:
                safe_print(f"[ERROR] worker={worker_id} addr={addr_checksum} rpc_error={e}")
                # count this attempt too
                if total_counter is not None:
                    with total_counter["lock"]:
                        total_counter["count"] += 1
                time.sleep(0.5)
                continue

            if debug:
                safe_print(f"[worker {worker_id}] {addr_checksum} balance_wei={balance_wei}")

            if total_counter is not None:
                with total_counter["lock"]:
                    total_counter["count"] += 1

            if balance_wei and balance_wei > 0:
                balance_eth_str = wei_to_eth_str(balance_wei)
                safe_print("FOUND -->")
                safe_print(f"  Private key (hex): 0x{priv_hex}")
                safe_print(f"  Address (lowercase): {addr_lower_0x}")
                safe_print(f"  Address (EIP-55) :    {addr_checksum}")
                safe_print(f"  Balance (wei):     {balance_wei}")
                safe_print(f"  Balance (ETH):     {balance_eth_str}")
                safe_print("-" * 60)
                # append the same block to found.txt
                append_found_block_to_file(priv_hex, addr_lower_0x, addr_checksum, balance_wei, balance_eth_str)

            # throttle (adjust if you need faster/slower scanning)
            time.sleep(0.01)

        except KeyboardInterrupt:
            raise
        except Exception as e:
            safe_print(f"[ERROR] worker={worker_id} unexpected error: {e}")
            time.sleep(0.2)

def main():
    parser = argparse.ArgumentParser(description="Ethereum key scanner (multi-threaded).")
    parser.add_argument("--debug", "-d", action="store_true", help="print all scanning progress (verbose)")
    parser.add_argument("--threads", "-t", type=int, default=NUM_THREADS, help="number of threads (default 3)")
    args = parser.parse_args()

    # load tried file
    load_tried()

    safe_print(f"Starting eth_scanner with {args.threads} threads. RPC: {RPC_URL}")
    if args.debug:
        safe_print("Debug mode: ON (printing all progress).")
    else:
        safe_print("Normal mode: ON (printing only found balances and errors).")

    # Performance counter (debug mode only)
    total_counter = {"count": 0, "lock": threading.Lock()}
    start_time = time.time()
    if args.debug:
        def stats_loop():
            while True:
                time.sleep(10)
                with total_counter["lock"]:
                    elapsed = time.time() - start_time
                    rate = total_counter["count"] / elapsed if elapsed > 0 else 0
                    print(f"[STATS] {elapsed:.1f}s elapsed | {total_counter['count']} total keys | {rate:.1f} keys/sec")
        threading.Thread(target=stats_loop, daemon=True).start()

    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        try:
            for i in range(args.threads):
                exe.submit(worker_loop, i+1, args.debug, total_counter)
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            safe_print("KeyboardInterrupt received, shutting down...")
        except Exception as e:
            safe_print(f"Fatal error in main thread: {e}")

if __name__ == "__main__":
    main()
