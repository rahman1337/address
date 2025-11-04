#!/usr/bin/env python3
"""
Scanner with improved Solana deterministic seeds that are predictable
but high-entropy (SHA256(salt || counter)) so wallets will accept them.
"""

import os
import sys
import time
import threading
import asyncio
import hashlib
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
        subprocess.check_call([sys.executable, "-m", "pip", "-q", "install", pkg])
        return __import__(name)

aiohttp = ensure_import("aiohttp")
base58 = ensure_import("base58")
ed25519_mod = None
try:
    ed25519_mod = __import__("ed25519")
except Exception:
    try:
        ed25519_mod = ensure_import("ed25519")
    except Exception:
        ed25519_mod = None
coincurve = ensure_import("coincurve")
eth_utils = ensure_import("eth_utils")
from eth_utils import to_checksum_address, keccak

BSC_RPC = "https://bsc.publicnode.com"
ETH_RPC = "https://ethereum.publicnode.com"
SOL_RPC = "https://solana.publicnode.com"

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

def append_found_line_by_line(chain, privhex, address, balance_str):
    """Writes found entry line by line to found.txt"""
    with found_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(f"CHAIN: {chain}\n")
            f.write(f"PRIVATE_KEY: {privhex}\n")
            f.write(f"ADDRESS: {address}\n")
            f.write(f"BALANCE: {balance_str}\n")
            f.write("="*60 + "\n")

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ---------------- Ethereum/BSC Generators ----------------
sequential_counter_eth = 0
repetitive_patterns = [b'a', b'b', b'c', b'd', b'e', b'f', b'1', b'2', b'3', b'4']
repetitive_index_eth = 0
MIXED_PATTERNS = b'abcdefghijklmnopqrstuvwxyz0123456789'
mixed_index_eth = 0
GENERATOR_MODES = ['repetitive', 'sequential', 'mixed']  # user-overridable
mode_index_eth = 0

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

# ---------------- Simplified deterministic Solana generator ----------------
hashed_index_solana = 0
DEFAULT_SOLANA_SALT = b"scanner-salt-v1"  

def gen_hashed_solana_seed(salt: bytes):
    """Return a 32-byte deterministic SHA256(salt || counter) seed."""
    global hashed_index_solana
    counter_bytes = hashed_index_solana.to_bytes(8, "big")
    hashed_index_solana += 1
    h = hashlib.sha256()
    h.update(salt)
    h.update(counter_bytes)
    return h.digest()

def gen_solana_keypair_direct(salt: bytes):
    """Generate seed + address in one deterministic step."""
    seed = gen_hashed_solana_seed(salt)
    sk = ed25519_mod.SigningKey(seed)
    vk = sk.get_verifying_key()
    pub_bytes = vk.to_bytes() if hasattr(vk, "to_bytes") else bytes(vk)
    address = base58.b58encode(pub_bytes).decode()
    full_sk_bytes = seed + pub_bytes  # 64 bytes, wallet-importable
    return full_sk_bytes.hex(), address

# ---------------- Address derivation ----------------
def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if len(pub_uncompressed) == 65 and pub_uncompressed[0] == 0x04 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return to_checksum_address("0x" + addr_bytes.hex())

def bsc_priv_to_address(priv_bytes: bytes) -> str:
    return eth_priv_to_address(priv_bytes)

# ---------------- RPC helpers ----------------
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

async def eth_like_get_balance(rpc_url: str, address: str, session: aiohttp.ClientSession, debug=False) -> Optional[int]:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    j = await rpc_post_with_retries(rpc_url, payload, session=session, debug=debug, max_attempts=3)
    if "error" in j:
        raise RuntimeError(f"RPC error: {j['error']}")
    result = j.get("result")
    if result is None:
        raise RuntimeError("No result field in RPC response")
    return int(result, 16)

async def solana_get_balance(rpc_url: str, address: str, session: aiohttp.ClientSession, debug=False) -> Optional[int]:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [address, {"commitment": "final"}]}
    j = await rpc_post_with_retries(rpc_url, payload, session=session, debug=debug, max_attempts=3)
    if "error" in j:
        raise RuntimeError(f"RPC error: {j['error']}")
    result = j.get("result")
    if result is None or "value" not in result:
        raise RuntimeError("No value in RPC result")
    return int(result["value"])

# ---------------- Workers ----------------
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
                if bal_wei and bal_wei > 0:
                    bal_eth = bal_wei / 10**18
                    bal_str = f"{bal_eth:.18f} (wei={bal_wei})"
                    append_found_line_by_line(chain_name, privhex, address, bal_str)
                await asyncio.sleep(0.02)
            except Exception:
                await asyncio.sleep(0.05)

async def worker_bsc_async(chain_name, rpc_url, debug=False):
    await worker_eth_async(chain_name, rpc_url, debug=debug)

async def worker_solana_async(chain_name, rpc_url, salt_bytes, debug=False):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            try:
                full_privhex, address = gen_solana_keypair_direct(salt_bytes)
                key_repr = f"{chain_name}:{full_privhex}"
                if key_repr in in_memory_tried:
                    if debug:
                        print(f"[{chain_name}] duplicate seed, skipping {full_privhex[:16]}...")
                    await asyncio.sleep(0.02)
                    continue
                append_tried(key_repr)

                if debug:
                    print(f"[{chain_name}] trying priv={full_privhex[:16]}... -> addr={address}")

                try:
                    lamports = await solana_get_balance(rpc_url, address, session, debug=debug)
                except Exception as rpc_e:
                    if debug:
                        print(f"[{chain_name}][rpc error] {rpc_e}")
                    await asyncio.sleep(0.2)
                    continue

                if lamports and lamports > 0:
                    sol_str = f"{lamports} lamports ({lamports / 1e9:.9f} SOL)"
                    append_found_line_by_line(chain_name, full_privhex, address, sol_str)
                await asyncio.sleep(0.02)
            except Exception:
                await asyncio.sleep(0.05)

# ---------------- Runner ----------------
def run_async_worker(coro_func, *args, **kwargs):
    try:
        asyncio.run(coro_func(*args, **kwargs))
    except Exception as e:
        print(f"[worker][fatal] {e}")

def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("--solana-salt", type=str, default=DEFAULT_SOLANA_SALT.decode(),
                        help="Salt used for deterministic hashed Solana seeds (default: 'scanner-salt-v1')")
    args = parser.parse_args()
    debug = args.debug
    salt_bytes = args.solana_salt.encode()

    print(f"[info] Starting scanner. Debug={debug}. Solana-salt={args.solana_salt}. Press Ctrl+C to stop.")

    open(TRIED_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = []
        futures.append(ex.submit(run_async_worker, worker_eth_async, "ethereum", ETH_RPC, debug))
        futures.append(ex.submit(run_async_worker, worker_bsc_async, "bsc", BSC_RPC, debug))
        futures.append(ex.submit(run_async_worker, worker_solana_async, "solana", SOL_RPC, salt_bytes, debug))
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
