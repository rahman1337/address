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

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ----- Counters / indexes for various generators -----
# numeric/sequential counters
sequential_counter_eth = 0
sequential_counter_solana = 0

# repetitive pattern index (single byte repeated 32x)
repetitive_patterns = [b'a', b'b', b'c', b'd', b'e', b'f', b'1', b'2', b'3', b'4']
repetitive_index_eth = 0
repetitive_index_solana = 0

# mixed pattern sliding window
MIXED_PATTERNS = b'abcdefghijklmnopqrstuvwxyz0123456789'
mixed_index_eth = 0
mixed_index_solana = 0

# mode-cycle: order in which generators are used for each worker
GENERATOR_MODES = ['repetitive', 'sequential', 'mixed']  # will cycle through these
mode_index_eth = 0
mode_index_solana = 0

# ----- GENERATORS -----
def gen_repetitive_eth():
    """Produce a 32-byte value consisting of a single repeated byte (e.g. b'aaaa...')"""
    global repetitive_index_eth
    letter = repetitive_patterns[repetitive_index_eth % len(repetitive_patterns)]
    repetitive_index_eth += 1
    return letter * 32

def gen_repetitive_solana():
    global repetitive_index_solana
    letter = repetitive_patterns[repetitive_index_solana % len(repetitive_patterns)]
    repetitive_index_solana += 1
    return letter * 32

def gen_sequential_numeric_eth():
    """Produce 32-byte big-endian from an incrementing counter"""
    global sequential_counter_eth
    sequential_counter_eth += 1
    # wrap if too big for 32 bytes (practically won't happen)
    return sequential_counter_eth.to_bytes(32, "big", signed=False)

def gen_sequential_numeric_solana():
    global sequential_counter_solana
    sequential_counter_solana += 1
    return sequential_counter_solana.to_bytes(32, "big", signed=False)

def gen_mixed_sequence_eth():
    """Produce 32-byte sliding mixed pattern (letters+digits) for deterministic variety."""
    global mixed_index_eth
    key = bytearray(32)
    for i in range(32):
        key[i] = MIXED_PATTERNS[(mixed_index_eth + i) % len(MIXED_PATTERNS)]
    mixed_index_eth += 1
    return bytes(key)

def gen_mixed_sequence_solana():
    global mixed_index_solana
    seed = bytearray(32)
    for i in range(32):
        seed[i] = MIXED_PATTERNS[(mixed_index_solana + i) % len(MIXED_PATTERNS)]
    mixed_index_solana += 1
    return bytes(seed)

# Wrapper functions that cycle through all generators in GENERATOR_MODES
def gen_eth_privkey_bytes():
    """Cycle through all ETH generator modes and return a 32-byte private key."""
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
        # fallback to numeric
        return gen_sequential_numeric_eth()

def gen_solana_keypair():
    """Cycle through all Solana generator modes and return (seed, address)."""
    global mode_index_solana
    mode = GENERATOR_MODES[mode_index_solana % len(GENERATOR_MODES)]
    mode_index_solana += 1

    if mode == 'repetitive':
        seed = gen_repetitive_solana()
    elif mode == 'sequential':
        seed = gen_sequential_numeric_solana()
    elif mode == 'mixed':
        seed = gen_mixed_sequence_solana()
    else:
        seed = gen_sequential_numeric_solana()

    if ed25519_mod is None:
        # still allow non-ed25519 sanity checks to pass, but we can't derive pubkey/address
        raise RuntimeError("ed25519 module not available — please install it with: pip install ed25519")

    sk = ed25519_mod.SigningKey(seed)
    vk = sk.get_verifying_key()
    pub_raw = vk.to_bytes() if hasattr(vk, "to_bytes") else bytes(vk)
    address = base58.b58encode(pub_raw).decode()
    return seed, address

# ----- Address derivation -----
def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if len(pub_uncompressed) == 65 and pub_uncompressed[0] == 0x04 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return to_checksum_address("0x" + addr_bytes.hex())

def bsc_priv_to_address(priv_bytes: bytes) -> str:
    return eth_priv_to_address(priv_bytes)

# ----- Sanity checks (unchanged behavior, but permissive enough for patterned keys) -----
def sanity_check_secp256k1_privkey(priv_bytes: bytes) -> bool:
    try:
        if not isinstance(priv_bytes, (bytes, bytearray)) or len(priv_bytes) != 32:
            return False
        priv_int = int.from_bytes(priv_bytes, "big")
        if not (1 <= priv_int < SECP256K1_N):
            return False
        # Keep some variety requirements but relaxed so patterned keys can pass sometimes
        s = set(priv_bytes)
        if len(s) <= 1:
            return False
        if len(s) < 2:
            return False
        return True
    except Exception:
        return False

def sanity_check_ed25519_seed(seed: bytes) -> bool:
    try:
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            return False
        s = set(seed)
        if len(s) <= 1:
            return False
        if len(s) < 2:
            return False
        if ed25519_mod is None:
            return True
        sk = ed25519_mod.SigningKey(seed)
        vk = sk.get_verifying_key()
        pub_raw = vk.to_bytes() if hasattr(vk, "to_bytes") else bytes(vk)
        if not isinstance(pub_raw, (bytes, bytearray)) or len(pub_raw) != 32:
            return False
        if set(pub_raw) == {0}:
            return False
        return True
    except Exception:
        return False

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

# ----- Workers (use the wrapper generators that cycle through modes) -----
async def worker_eth_async(chain_name, rpc_url, debug=False):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            try:
                priv = gen_eth_privkey_bytes()
                if not sanity_check_secp256k1_privkey(priv):
                    if debug:
                        print(f"[{chain_name}][sanity] rejected priv (failed sanity): {priv.hex()}")
                    await asyncio.sleep(0.05)
                    continue
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
                    out = format_found_block(chain_name, privhex, address, bal_str)
                    print(out)
                    append_found(f"{chain_name} | {privhex} | {address} | {bal_str}")
                await asyncio.sleep(0.02)
            except Exception as e:
                if debug:
                    traceback.print_exc()
                await asyncio.sleep(0.05)

async def worker_bsc_async(chain_name, rpc_url, debug=False):
    await worker_eth_async(chain_name, rpc_url, debug=debug)

async def worker_solana_async(chain_name, rpc_url, debug=False):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            try:
                # gen_solana_keypair cycles between repetitive/sequential/mixed
                try:
                    seed, address = gen_solana_keypair()
                except RuntimeError as e:
                    if debug:
                        print(f"[{chain_name}][error] {e}")
                    # can't proceed without ed25519; sleep and continue
                    await asyncio.sleep(1.0)
                    continue
                if not sanity_check_ed25519_seed(seed):
                    if debug:
                        print(f"[{chain_name}][sanity] rejected seed (failed sanity): {seed.hex()}")
                    await asyncio.sleep(0.05)
                    continue
                privhex = seed.hex()
                key_repr = f"{chain_name}:{privhex}"
                if key_repr in in_memory_tried:
                    if debug:
                        print(f"[{chain_name}] duplicate seed, skipping {privhex}")
                    await asyncio.sleep(0.02)
                    continue
                append_tried(key_repr)
                if debug:
                    print(f"[{chain_name}] trying seed={privhex} -> addr={address}")
                try:
                    lamports = await solana_get_balance(rpc_url, address, session, debug=debug)
                except Exception as rpc_e:
                    if debug:
                        print(f"[{chain_name}][rpc error] {rpc_e}")
                    await asyncio.sleep(0.2)
                    continue
                if lamports and lamports > 0:
                    sol_str = f"{lamports} lamports ({lamports / 1e9:.9f} SOL)"
                    out = format_found_block(chain_name, privhex, address, sol_str)
                    print(out)
                    append_found(f"{chain_name} | {privhex} | {address} | {sol_str}")
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
    parser.add_argument("--modes", nargs="+", choices=['repetitive','sequential','mixed'], help="Override generator modes and order (space-separated)")
    args = parser.parse_args()
    debug = args.debug

    if args.modes:
        # override the generator mode cycle if requested
        global GENERATOR_MODES
        GENERATOR_MODES = args.modes

    print(f"[info] Starting scanner. Debug={debug}. Modes={GENERATOR_MODES}. Press Ctrl+C to stop.")

    open(TRIED_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = []
        futures.append(ex.submit(run_async_worker, worker_eth_async, "ethereum", ETH_RPC, debug))
        futures.append(ex.submit(run_async_worker, worker_bsc_async, "bsc", BSC_RPC, debug))
        futures.append(ex.submit(run_async_worker, worker_solana_async, "solana", SOL_RPC, debug))
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
