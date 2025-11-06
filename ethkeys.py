#!/usr/bin/env python3
import argparse
import os
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from coincurve import PrivateKey
from sha3 import keccak_256
from decimal import Decimal

# ---- config ----
RPC_URL = "https://ethereum.publicnode.com"
NUM_THREADS = 3
RPC_TIMEOUT = 10  # seconds for HTTP requests
TRIED_FILE = "triedeth.txt"
FOUND_FILE = "found.txt"

# secp256k1 curve order (decimal)
SECP256K1_ORDER = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

# ---- shutdown event ----
_stop_event = threading.Event()

# ---- thread-safe printing ----
_print_lock = threading.Lock()
def safe_print(*args, **kwargs):
    with _print_lock:
        print(*args, **kwargs, flush=True)

# ---- tried file handling ----
_tried_lock = threading.Lock()
_tried_set = set()
def load_tried():
    if not os.path.exists(TRIED_FILE):
        open(TRIED_FILE, "a").close()
        return
    try:
        with open(TRIED_FILE, "r") as f:
            for line in f:
                s = line.strip()
                if not s:
                    continue
                if s.startswith("0x") or s.startswith("0X"):
                    s = s[2:]
                _tried_set.add(s.lower())
    except Exception as e:
        safe_print(f"[WARN] could not load {TRIED_FILE}: {e}")

def append_tried(priv_hex):
    """Append private key (hex without 0x) to triedeth.txt and memory set. Returns True if added."""
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
            # still add to in-memory set to avoid immediate retry
            _tried_set.add(priv_hex)
            return True

# ---- crypto (coincurve) ----
def generate_private_key():
    """Generate a secure 32-byte private key that is valid for secp256k1."""
    while not _stop_event.is_set():
        priv = os.urandom(32)
        priv_int = int.from_bytes(priv, "big")
        if 1 <= priv_int < SECP256K1_ORDER:
            return priv
    raise KeyboardInterrupt  # if stopping

def private_key_to_public_key(priv_bytes):
    """
    Return uncompressed public key bytes (65 bytes: 0x04 || X || Y) using coincurve.
    """
    pk = PrivateKey(priv_bytes)
    pub = pk.public_key.format(compressed=False)  # 65 bytes, starts with 0x04
    return pub

# ---- address derivation ----
def public_key_to_address_lower(pub_bytes):
    """Return lowercase 40-char hex address (no 0x)."""
    assert pub_bytes[0] == 0x04
    k = keccak_256()
    k.update(pub_bytes[1:])
    digest = k.digest()
    return digest[-20:].hex()

def to_checksum_address(address_hex):
    """EIP-55 checksum; input: 40-char hex (case-insensitive), returns 0x-prefixed mixed-case."""
    addr = address_hex.lower()
    k = keccak_256()
    k.update(addr.encode('ascii'))
    hash_hex = k.hexdigest()
    out = []
    for i, c in enumerate(addr):
        if c in '0123456789':
            out.append(c)
        else:
            out.append(c.upper() if int(hash_hex[i], 16) >= 8 else c)
    return "0x" + "".join(out)

# ---- HTTP session helper (persistent connections) ----
def make_session():
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=Retry(total=1, backoff_factor=0.1))
    s.mount("https://", adapter)
    s.headers.update({"Content-Type": "application/json"})
    return s

def rpc_eth_getBalance_session(session, address_hex_with_0x):
    """Use requests.Session to POST JSON-RPC and return integer wei."""
    payload = {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [address_hex_with_0x, "latest"], "id": 1}
    try:
        resp = session.post(RPC_URL, json=payload, timeout=RPC_TIMEOUT)
        resp.raise_for_status()
        js = resp.json()
        if "error" in js:
            raise RuntimeError(f"RPC error: {js['error']}")
        result = js.get("result")
        if result is None:
            raise RuntimeError("No result in RPC response")
        return int(result, 16)
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(f"HTTPError: {e}")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"RequestException: {e}")
    except Exception:
        raise

# ---- formatting / files for found ----
def wei_to_eth_str(wei_int):
    eth = Decimal(wei_int) / Decimal(10**18)
    return format(eth.normalize(), 'f')

def append_found_block_to_file(priv_hex, addr_lower_0x, addr_checksum, balance_wei, balance_eth_str):
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

# ---- worker loop ----
def worker_loop(worker_id, debug=False, total_counter=None):
    """
    Each worker uses its own persistent HTTP session and fast coincurve crypto.
    Exits quickly when _stop_event is set.
    """
    session = make_session()
    tries = 0
    while not _stop_event.is_set():
        try:
            # generate unique private key not in tried set
            while not _stop_event.is_set():
                priv = generate_private_key()
                priv_hex = priv.hex()
                with _tried_lock:
                    already = priv_hex in _tried_set
                if already:
                    continue
                append_tried(priv_hex)
                break
            if _stop_event.is_set():
                break

            pub = private_key_to_public_key(priv)
            addr_hex = public_key_to_address_lower(pub)
            addr_lower_0x = "0x" + addr_hex
            addr_checksum = to_checksum_address(addr_hex)

            tries += 1
            if debug:
                safe_print(f"[worker {worker_id}] try #{tries} priv=0x{priv_hex} addr_lower={addr_lower_0x} addr_checksum={addr_checksum} ... checking")

            # RPC call via persistent session
            try:
                balance_wei = rpc_eth_getBalance_session(session, addr_checksum)
            except Exception as e:
                safe_print(f"[ERROR] worker={worker_id} addr={addr_checksum} rpc_error={e}")
                # count attempt even on error
                if total_counter is not None:
                    with total_counter["lock"]:
                        total_counter["count"] += 1
                # quick responsive sleep that breaks early on shutdown
                for _ in range(5):
                    if _stop_event.is_set():
                        break
                    time.sleep(0.1)
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
                append_found_block_to_file(priv_hex, addr_lower_0x, addr_checksum, balance_wei, balance_eth_str)

            # brief throttle split into small sleeps so shutdown is responsive
            for _ in range(10):  # total ~0.01s
                if _stop_event.is_set():
                    break
                time.sleep(0.001)

        except KeyboardInterrupt:
            break
        except Exception as e:
            if _stop_event.is_set():
                break
            safe_print(f"[ERROR] worker={worker_id} unexpected error: {e}")
            for _ in range(4):
                if _stop_event.is_set():
                    break
                time.sleep(0.05)
    if debug:
        safe_print(f"[worker {worker_id}] exiting")

# ---- main ----
def main():
    parser = argparse.ArgumentParser(description="Ethereum key scanner (multi-threaded).")
    parser.add_argument("--debug", "-d", action="store_true", help="print all scanning progress (verbose)")
    parser.add_argument("--threads", "-t", type=int, default=NUM_THREADS, help="number of threads (default 3)")
    args = parser.parse_args()

    # load tried keys
    load_tried()

    safe_print(f"Starting eth_scanner with {args.threads} threads. RPC: {RPC_URL}")
    if args.debug:
        safe_print("Debug mode: ON (printing all progress).")
    else:
        safe_print("Normal mode: ON (printing only found balances and errors).")

    # performance counter (debug only)
    total_counter = {"count": 0, "lock": threading.Lock()}
    start_time = time.time()
    if args.debug:
        def stats_loop():
            while not _stop_event.is_set():
                time.sleep(10)
                with total_counter["lock"]:
                    elapsed = time.time() - start_time
                    rate = total_counter["count"] / elapsed if elapsed > 0 else 0
                    print(f"[STATS] {elapsed:.1f}s elapsed | {total_counter['count']} total keys | {rate:.1f} keys/sec")
        threading.Thread(target=stats_loop, daemon=True).start()

    # start worker threads
    futures = []
    with ThreadPoolExecutor(max_workers=args.threads) as exe:
        try:
            for i in range(args.threads):
                futures.append(exe.submit(worker_loop, i+1, args.debug, total_counter))
            # main waits; Ctrl+C handled here
            while not _stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            safe_print("KeyboardInterrupt received, signalling workers to stop...")
            _stop_event.set()
        finally:
            # attempt graceful shutdown
            try:
                # stop accepting new tasks
                exe.shutdown(wait=False)
            except Exception:
                pass
            # wait briefly for threads to exit
            deadline = time.time() + 5.0
            while any(not f.done() for f in futures) and time.time() < deadline:
                time.sleep(0.1)
            # final wait (best-effort)
            try:
                exe.shutdown(wait=True, timeout=2)
            except TypeError:
                # older Python might not support timeout param
                try:
                    exe.shutdown(wait=True)
                except Exception:
                    pass
            safe_print("Shutdown complete.")

if __name__ == "__main__":
    main()
