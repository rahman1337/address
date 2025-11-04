#!/usr/bin/env python3
"""
Mainnet multi-chain scanner (BNB/BSC, Ethereum, Solana)

Features:
- 3 threads (one per chain) via ThreadPoolExecutor
- Generates valid private keys per chain, derives addresses
- Checks balances via provided RPC endpoints:
    bsc.publicnode.com
    ethereum.publicnode.com
    solana.publicnode.com
- Appends tried private keys to scanned_keys.txt (no repeats)
- Appends positive-balance finds to found.txt
- Stops immediately on Ctrl+C
- Normal mode: prints only found results (formatted)
- Debug mode (-d): prints full progress, web responses, balances, errors
- RPC calls include fallback retries (max 3 attempts with sleeps 1,2,3s)
"""

import os
import sys
import time
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser
from typing import Optional

# ---- dependency imports with auto-install if needed ----
def ensure_import(name, package=None):
    try:
        return __import__(name)
    except Exception:
        pkg = package or name
        print(f"[setup] package '{pkg}' not found, attempting to install...", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        return __import__(name)

# packages used by the script
requests = ensure_import("requests")
base58 = ensure_import("base58")
# cryptography will be used for Solana ed25519 keypair generation
_ = ensure_import("cryptography")
eth_keys = ensure_import("eth_keys")
eth_utils = ensure_import("eth_utils")

from eth_keys import keys as eth_keys_keys
from eth_utils import to_checksum_address

# cryptography imports (after ensuring package present)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import secrets

# ---- Configuration (endpoints) ----
BSC_RPC = "https://bsc.publicnode.com"
ETH_RPC = "https://ethereum.publicnode.com"
SOL_RPC = "https://solana.publicnode.com"

# ---- Files and concurrency primitives ----
SCANNED_FILE = "scanned_keys.txt"
FOUND_FILE = "found.txt"
scanned_lock = threading.Lock()
found_lock = threading.Lock()
in_memory_scanned = set()  # to avoid duplicates in process
stop_event = threading.Event()

# Load scanned keys already present (to avoid repeats across restarts)
def load_scanned_keys():
    global in_memory_scanned
    if os.path.exists(SCANNED_FILE):
        try:
            with open(SCANNED_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    l = line.strip()
                    if l:
                        in_memory_scanned.add(l)
        except Exception as e:
            print(f"[warn] Could not load {SCANNED_FILE}: {e}", file=sys.stderr)
load_scanned_keys()

# Helpers
def append_scanned(key_repr: str):
    """Append a single line to scanned file if not present. Thread-safe."""
    with scanned_lock:
        if key_repr in in_memory_scanned:
            return
        with open(SCANNED_FILE, "a", encoding="utf-8") as f:
            f.write(key_repr + "\n")
        in_memory_scanned.add(key_repr)

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

# ---- Crypto / key derivation ----
from eth_keys import keys as ethkeys

# Official secp256k1 order constant (ensures valid private keys in [1, N-1])
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def gen_eth_privkey_bytes():
    """
    Generate a valid Ethereum/BSC private key (32 bytes)
    within the secp256k1 keyspace [1, N-1].
    """
    while True:
        b = secrets.token_bytes(32)
        priv_int = int.from_bytes(b, "big")
        if 1 <= priv_int < SECP256K1_N:
            return b

def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = eth_keys_keys.PrivateKey(priv_bytes)
    checksum_addr = pk.public_key.to_checksum_address()
    return checksum_addr

def bsc_priv_to_address(priv_bytes: bytes) -> str:
    # BSC uses same key/address format as Ethereum
    return eth_priv_to_address(priv_bytes)

def gen_solana_keypair():
    """
    Generate an ed25519 keypair for Solana using cryptography.
    Returns (seed_bytes, base58_pubkey_address).
    Approach: generate a 32-byte seed and construct the private key object
    via Ed25519PrivateKey.from_private_bytes(seed). This is broadly compatible.
    """
    # 32-byte seed
    seed = secrets.token_bytes(32)
    # construct private key object from seed bytes
    priv_obj = Ed25519PrivateKey.from_private_bytes(seed)
    pub_raw = priv_obj.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    address = base58.b58encode(pub_raw).decode()
    return seed, address

# ---- RPC helper with retries ----
def rpc_post_with_retries(url: str, json_payload: dict, debug: bool=False, max_attempts: int=3):
    """
    POST to `url` with `json_payload`, retrying up to max_attempts.
    Sleeps 1,2,3 seconds between attempts respectively.
    On success returns requests.Response; on final failure raises the last exception.
    """
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            r = requests.post(url, json=json_payload, timeout=15)
            if debug:
                print(f"[debug][rpc] POST {url} payload={json_payload} status={r.status_code}")
                print(f"[debug][rpc] response: {r.text}")
            # raise_for_status to convert HTTP errors to exceptions
            r.raise_for_status()
            return r
        except Exception as e:
            last_exc = e
            # If debug, print attempt info and planned sleep
            if debug:
                print(f"[debug][rpc] attempt {attempt} failed for {url}: {e}")
            else:
                # in normal mode print brief error on last attempt only
                if attempt == max_attempts:
                    print(f"[error][rpc] failed {url}: {e}")
            # sleep before next attempt unless it was the last
            if attempt < max_attempts:
                sleep_seconds = attempt  # 1, then 2, then 3...
                if debug:
                    print(f"[debug][rpc] sleeping {sleep_seconds}s before retry #{attempt+1}")
                time.sleep(sleep_seconds)
    # all attempts exhausted
    raise last_exc

# ---- Balance checking RPCs (use rpc_post_with_retries) ----
def eth_like_get_balance(rpc_url: str, address: str, debug=False) -> Optional[int]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getBalance",
        "params": [address, "latest"]
    }
    try:
        r = rpc_post_with_retries(rpc_url, payload, debug=debug, max_attempts=3)
        j = r.json()
        if "error" in j:
            raise RuntimeError(f"RPC error: {j['error']}")
        result = j.get("result")
        if result is None:
            raise RuntimeError("No result field in RPC response")
        # result is hex string like "0x123"
        balance_wei = int(result, 16)
        return balance_wei
    except Exception as e:
        # bubble up for worker to handle (worker prints short error line already)
        raise

def solana_get_balance(rpc_url: str, address: str, debug=False) -> Optional[int]:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getBalance",
        "params": [address, {"commitment": "final"}]
    }
    try:
        r = rpc_post_with_retries(rpc_url, payload, debug=debug, max_attempts=3)
        j = r.json()
        if "error" in j:
            raise RuntimeError(f"RPC error: {j['error']}")
        result = j.get("result")
        if result is None:
            raise RuntimeError("No result field in RPC response")
        value = result.get("value")
        if value is None:
            raise RuntimeError("No value in result")
        # Solana balance is in lamports (1 SOL = 1e9 lamports)
        return int(value)
    except Exception as e:
        raise

# ---- Worker loops for each chain ----
def worker_eth(chain_name, rpc_url, debug=False):
    # ethereum-like chain (ETH or BSC)
    while not stop_event.is_set():
        try:
            priv = gen_eth_privkey_bytes()
            privhex = priv.hex()
            key_repr = f"{chain_name}:{privhex}"
            if key_repr in in_memory_scanned:
                if debug:
                    print(f"[{chain_name}] duplicate key, skipping {privhex}")
                continue
            address = eth_priv_to_address(priv)
            append_scanned(key_repr)

            if debug:
                print(f"[{chain_name}] trying priv={privhex} -> addr={address}")

            try:
                bal_wei = eth_like_get_balance(rpc_url, address, debug=debug)
            except Exception as rpc_e:
                # Print and continue
                print(f"[{chain_name}][error] RPC/check failed for {address}: {rpc_e}")
                if debug:
                    traceback.print_exc()
                time.sleep(0.5)
                continue

            if debug:
                print(f"[{chain_name}] balance (wei) = {bal_wei}")

            if bal_wei and bal_wei > 0:
                # convert to human-readable (ether)
                bal_eth = bal_wei / 10**18
                bal_str = f"{bal_eth:.18f} (wei={bal_wei})"
                out = format_found_block(chain_name, privhex, address, bal_str)
                print(out)
                append_found(f"{chain_name} | {privhex} | {address} | {bal_str}")
            # small sleep to be polite
            time.sleep(0.01)
        except Exception as e:
            print(f"[{chain_name}][exception] {e}")
            if debug:
                traceback.print_exc()
            time.sleep(0.2)

def worker_bsc(chain_name, rpc_url, debug=False):
    # BSC uses same format as Ethereum
    worker_eth(chain_name, rpc_url, debug=debug)

def worker_solana(chain_name, rpc_url, debug=False):
    while not stop_event.is_set():
        try:
            seed, address = gen_solana_keypair()
            privhex = seed.hex()
            key_repr = f"{chain_name}:{privhex}"
            if key_repr in in_memory_scanned:
                if debug:
                    print(f"[{chain_name}] duplicate key, skipping {privhex}")
                continue
            append_scanned(key_repr)

            if debug:
                print(f"[{chain_name}] trying priv(seed)={privhex} -> addr={address}")

            try:
                lamports = solana_get_balance(rpc_url, address, debug=debug)
            except Exception as rpc_e:
                print(f"[{chain_name}][error] RPC/check failed for {address}: {rpc_e}")
                if debug:
                    traceback.print_exc()
                time.sleep(0.5)
                continue

            if debug:
                print(f"[{chain_name}] balance (lamports) = {lamports}")

            if lamports and lamports > 0:
                sol_str = f"{lamports} lamports ({lamports / 1e9:.9f} SOL)"
                out = format_found_block(chain_name, privhex, address, sol_str)
                print(out)
                append_found(f"{chain_name} | {privhex} | {address} | {sol_str}")

            time.sleep(0.01)
        except Exception as e:
            print(f"[{chain_name}][exception] {e}")
            if debug:
                traceback.print_exc()
            time.sleep(0.2)

# ---- Main ----
def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="debug mode: print everything")
    args = parser.parse_args()
    debug = args.debug

    print(f"[info] Starting scanner. Debug={debug}. Press Ctrl+C to stop.")
    # Ensure files exist
    open(SCANNED_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=3) as ex:
        # submit three chain workers
        futures = []
        futures.append(ex.submit(worker_eth, "ethereum", ETH_RPC, debug))
        futures.append(ex.submit(worker_bsc, "bsc", BSC_RPC, debug))
        futures.append(ex.submit(worker_solana, "solana", SOL_RPC, debug))

        try:
            # Wait until user hits Ctrl+C; threads run until stop_event set
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, shutting down immediately...")
            stop_event.set()
            # Allow small grace period for threads to detect stop_event
            time.sleep(0.2)
        finally:
            # attempt to cancel futures (they will exit when stop_event is set)
            for f in futures:
                try:
                    # no direct cancel; rely on cooperative stop
                    pass
                except Exception:
                    pass
    print("[info] Scanner stopped. Goodbye.")

if __name__ == "__main__":
    main()
