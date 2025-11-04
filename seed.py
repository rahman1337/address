#!/usr/bin/env python3
import os
import sys
import time
import threading
import traceback
import asyncio
import random
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
bip32utils = ensure_import("bip32utils")
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

SCANNED_MNEMONICS_FILE = "scanned_mnemonics.txt"
FOUND_FILE = "found.txt"
scanned_lock = threading.Lock()
found_lock = threading.Lock()
in_memory_scanned = set()
stop_event = threading.Event()

# Controls: how many accounts (address indices) to check per mnemonic
ACCOUNTS_PER_MNEMONIC = 3  # 1..3 (you asked for up to 3)

# Load already scanned mnemonics
if os.path.exists(SCANNED_MNEMONICS_FILE):
    try:
        with open(SCANNED_MNEMONICS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                l = line.strip()
                if l:
                    in_memory_scanned.add(l)
    except Exception as e:
        print(f"[warn] Could not load {SCANNED_MNEMONICS_FILE}: {e}", file=sys.stderr)

# Load word list for mnemonics
if not os.path.exists("seed.txt"):
    print("[error] seed.txt not found! Provide 2048 words, one per line.", file=sys.stderr)
    sys.exit(1)

with open("seed.txt", "r", encoding="utf-8") as f:
    WORD_LIST = [line.strip() for line in f if line.strip()]

if len(WORD_LIST) != 2048:
    print(f"[error] seed.txt must contain exactly 2048 words, found {len(WORD_LIST)}", file=sys.stderr)
    sys.exit(1)

# ----- Helpers -----
def append_scanned_mnemonic(mnemonic_key: str):
    """mnemonic_key should be unique per (mnemonic,index) e.g. 'mnemonic :: 0'"""
    with scanned_lock:
        if mnemonic_key in in_memory_scanned:
            return
        with open(SCANNED_MNEMONICS_FILE, "a", encoding="utf-8") as f:
            f.write(mnemonic_key + "\n")
        in_memory_scanned.add(mnemonic_key)

def append_found(line: str):
    with found_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def format_found_block(chain, mnemonic, index, privhex, address, balance_str):
    border = "=" * 60
    return "\n".join([
        border,
        f"CHAIN: {chain}",
        f"MNEMONIC: {mnemonic}",
        f"ACCOUNT_INDEX: {index}",
        f"PRIVATE_KEY: {privhex}",
        f"ADDRESS: {address}",
        f"BALANCE: {balance_str}",
        border
    ])

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# ----- Predictable mnemonic generator with cycle patterns -----
mnemonic_counter = 0
pattern_cycle = ["repetitive", "sequential", "mixed"]  # round-robin patterns

def gen_predictable_mnemonic():
    """Generate a 12-word predictable mnemonic cycling through:
       - repetitive: same word repeated 12x
       - sequential: 12 consecutive words starting from an offset
       - mixed: alternating/stride pattern for more variety
    """
    global mnemonic_counter
    # capture and advance counter atomically-ish
    idx = mnemonic_counter
    mnemonic_counter += 1

    pattern = pattern_cycle[idx % len(pattern_cycle)]
    # choose a base start index derived from the counter (to cycle through wordlist)
    base = (idx * 7) % len(WORD_LIST)  # stride by 7 for more variation

    words = []
    if pattern == "repetitive":
        # pick a single word and repeat
        w = WORD_LIST[base]
        words = [w] * 12
    elif pattern == "sequential":
        # 12 consecutive words, wrapping the list
        for i in range(12):
            words.append(WORD_LIST[(base + i) % len(WORD_LIST)])
    else:  # mixed
        # stride + alternating: picks words at base + i*stride, but replace every 3rd with a nearby word
        stride = 3 + ((idx // len(pattern_cycle)) % 5)  # vary stride slowly
        for i in range(12):
            pick = (base + i * stride) % len(WORD_LIST)
            # every 3rd position, use a neighbor to create a "mixed" feel
            if (i % 3) == 2:
                pick = (pick + 1) % len(WORD_LIST)
            words.append(WORD_LIST[pick])

    return " ".join(words)

# ----- BIP32 derivation helpers (allow account index) -----
def mnemonic_to_eth_priv_index(mnemonic: str, address_index: int) -> bytes:
    """Derive Ethereum private key from mnemonic using BIP44 path m/44'/60'/0'/0/<address_index>."""
    # NOTE: original code used the mnemonic bytes as entropy (predictable mapping).
    # Keep the same approach so behaviour remains deterministic.
    seed_bytes = mnemonic.encode("utf-8")
    master = bip32utils.BIP32Key.fromEntropy(seed_bytes)
    child = master.ChildKey(44 + bip32utils.BIP32_HARDEN).ChildKey(60 + bip32utils.BIP32_HARDEN)\
                 .ChildKey(0 + bip32utils.BIP32_HARDEN).ChildKey(0).ChildKey(address_index)
    return child.PrivateKey()

def mnemonic_to_solana_seed_index(mnemonic: str, account_index: int) -> bytes:
    """Return 32-byte seed for Solana (ed25519) from mnemonic and account index."""
    # simple deterministic mapping: include account index in the input then slice to 32 bytes
    s = f"{mnemonic}:{account_index}"
    return s.encode("utf-8")[:32]  # preserves previous simple mapping but gives per-index variation

# ----- Address derivation (unchanged) -----
def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if len(pub_uncompressed) == 65 and pub_uncompressed[0] == 0x04 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return to_checksum_address("0x" + addr_bytes.hex())

def bsc_priv_to_address(priv_bytes: bytes) -> str:
    return eth_priv_to_address(priv_bytes)

# ----- Sanity checks (unchanged) -----
def sanity_check_secp256k1_privkey(priv_bytes: bytes) -> bool:
    try:
        if not isinstance(priv_bytes, (bytes, bytearray)) or len(priv_bytes) != 32:
            return False
        priv_int = int.from_bytes(priv_bytes, "big")
        return 1 <= priv_int < SECP256K1_N
    except Exception:
        return False

def sanity_check_ed25519_seed(seed: bytes) -> bool:
    try:
        if not isinstance(seed, (bytes, bytearray)) or len(seed) != 32:
            return False
        if ed25519_mod is None:
            return True
        sk = ed25519_mod.SigningKey(seed)
        vk = sk.get_verifying_key()
        pub_raw = vk.to_bytes() if hasattr(vk, "to_bytes") else bytes(vk)
        return isinstance(pub_raw, (bytes, bytearray)) and len(pub_raw) == 32
    except Exception:
        return False

# ----- RPC helpers (unchanged) -----
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

# ----- Workers (updated to iterate accounts per mnemonic) -----
async def worker_eth_async(chain_name, rpc_url, debug=False):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            try:
                mnemonic = gen_predictable_mnemonic()
                # iterate accounts 0..ACCOUNTS_PER_MNEMONIC-1
                for acct_idx in range(ACCOUNTS_PER_MNEMONIC):
                    priv = mnemonic_to_eth_priv_index(mnemonic, acct_idx)
                    if not sanity_check_secp256k1_privkey(priv):
                        if debug:
                            print(f"[{chain_name}][sanity] rejected priv for idx {acct_idx}")
                        await asyncio.sleep(0.01)
                        continue
                    key_repr = f"{mnemonic}::{acct_idx}"
                    if key_repr in in_memory_scanned:
                        await asyncio.sleep(0.005)
                        continue
                    append_scanned_mnemonic(key_repr)
                    address = eth_priv_to_address(priv)
                    if debug:
                        print(f"[{chain_name}] trying mnemonic idx {acct_idx} -> addr={address}")
                    try:
                        bal_wei = await eth_like_get_balance(rpc_url, address, session, debug=debug)
                    except Exception as rpc_e:
                        if debug:
                            print(f"[{chain_name}][rpc error] {rpc_e}")
                        await asyncio.sleep(0.05)
                        continue
                    if bal_wei and bal_wei > 0:
                        bal_eth = bal_wei / 10**18
                        bal_str = f"{bal_eth:.18f} (wei={bal_wei})"
                        out = format_found_block(chain_name, mnemonic, acct_idx, priv.hex(), address, bal_str)
                        print(out)
                        append_found(f"{chain_name} | {mnemonic} | {acct_idx} | {priv.hex()} | {address} | {bal_str}")
                    await asyncio.sleep(0.01)
                await asyncio.sleep(0.01)
            except Exception:
                if debug:
                    traceback.print_exc()
                await asyncio.sleep(0.02)

async def worker_bsc_async(chain_name, rpc_url, debug=False):
    await worker_eth_async(chain_name, rpc_url, debug=debug)

async def worker_solana_async(chain_name, rpc_url, debug=False):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            try:
                mnemonic = gen_predictable_mnemonic()
                for acct_idx in range(ACCOUNTS_PER_MNEMONIC):
                    seed = mnemonic_to_solana_seed_index(mnemonic, acct_idx)
                    if not sanity_check_ed25519_seed(seed):
                        if debug:
                            print(f"[{chain_name}][sanity] rejected seed idx {acct_idx}")
                        await asyncio.sleep(0.01)
                        continue
                    key_repr = f"{mnemonic}::{acct_idx}"
                    if key_repr in in_memory_scanned:
                        await asyncio.sleep(0.005)
                        continue
                    append_scanned_mnemonic(key_repr)
                    if ed25519_mod is None:
                        # can't derive real Solana keys without ed25519; skip gracefully
                        if debug:
                            print(f"[{chain_name}][info] ed25519 module missing, skipping derivation")
                        await asyncio.sleep(0.5)
                        continue
                    sk = ed25519_mod.SigningKey(seed)
                    vk = sk.get_verifying_key()
                    pub_raw = vk.to_bytes() if hasattr(vk, "to_bytes") else bytes(vk)
                    address = base58.b58encode(pub_raw).decode()
                    if debug:
                        print(f"[{chain_name}] trying mnemonic idx {acct_idx} -> addr={address}")
                    try:
                        lamports = await solana_get_balance(rpc_url, address, session, debug=debug)
                    except Exception as rpc_e:
                        if debug:
                            print(f"[{chain_name}][rpc error] {rpc_e}")
                        await asyncio.sleep(0.05)
                        continue
                    if lamports and lamports > 0:
                        sol_str = f"{lamports} lamports ({lamports / 1e9:.9f} SOL)"
                        out = format_found_block(chain_name, mnemonic, acct_idx, seed.hex(), address, sol_str)
                        print(out)
                        append_found(f"{chain_name} | {mnemonic} | {acct_idx} | {seed.hex()} | {address} | {sol_str}")
                    await asyncio.sleep(0.01)
                await asyncio.sleep(0.01)
            except Exception:
                if debug:
                    traceback.print_exc()
                await asyncio.sleep(0.02)

def run_async_worker(coro_func, *args, **kwargs):
    try:
        asyncio.run(coro_func(*args, **kwargs))
    except Exception as e:
        print(f"[worker][fatal] {e}")

def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    parser.add_argument("-n", "--accounts", type=int, choices=[1,2,3], default=3,
                        help="How many accounts per mnemonic to scan (1-3). Default=3")
    args = parser.parse_args()
    debug = args.debug
    global ACCOUNTS_PER_MNEMONIC
    ACCOUNTS_PER_MNEMONIC = args.accounts

    print(f"[info] Starting scanner with mnemonic generation. Debug={debug}. Accounts per mnemonic={ACCOUNTS_PER_MNEMONIC}. Press Ctrl+C to stop.")

    open(SCANNED_MNEMONICS_FILE, "a").close()
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
