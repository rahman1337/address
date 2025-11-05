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
        print(f"[setup] package '{pkg}' not found, installing...", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        return __import__(name)

aiohttp = ensure_import("aiohttp")
bip32utils = ensure_import("bip32utils")
coincurve = ensure_import("coincurve")
eth_utils = ensure_import("eth_utils")
from eth_utils import to_checksum_address, keccak

ETH_RPC = "https://ethereum.publicnode.com"

SCANNED_MNEMONICS_FILE = "scanned_mnemonics.txt"
FOUND_FILE = "found.txt"
scanned_lock = threading.Lock()
found_lock = threading.Lock()
in_memory_scanned = set()
stop_event = threading.Event()

# ----- Load scanned mnemonics -----
if os.path.exists(SCANNED_MNEMONICS_FILE):
    with open(SCANNED_MNEMONICS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            l = line.strip()
            if l:
                in_memory_scanned.add(l)

# ----- Load BIP39 word list -----
if not os.path.exists("seed.txt"):
    print("[error] seed.txt not found! Provide 2048 BIP39 words.", file=sys.stderr)
    sys.exit(1)

with open("seed.txt", "r", encoding="utf-8") as f:
    WORD_LIST = [line.strip() for line in f if line.strip()]

if len(WORD_LIST) != 2048:
    print(f"[error] seed.txt must contain exactly 2048 words, found {len(WORD_LIST)}", file=sys.stderr)
    sys.exit(1)

# ----- File helpers -----
def append_scanned_mnemonic(key: str):
    with scanned_lock:
        if key in in_memory_scanned:
            return
        with open(SCANNED_MNEMONICS_FILE, "a", encoding="utf-8") as f:
            f.write(key + "\n")
        in_memory_scanned.add(key)

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

# ----- Mnemonic generator -----
mnemonic_counter = 0
pattern_cycle = ["repetitive", "sequential", "mixed"]

def gen_predictable_mnemonic():
    global mnemonic_counter
    idx = mnemonic_counter
    mnemonic_counter += 1

    pattern = pattern_cycle[idx % len(pattern_cycle)]
    base = (idx * 7) % len(WORD_LIST)

    words = []
    if pattern == "repetitive":
        words = [WORD_LIST[base]] * 12
    elif pattern == "sequential":
        for i in range(12):
            words.append(WORD_LIST[(base + i) % len(WORD_LIST)])
    else:
        stride = 3 + ((idx // len(pattern_cycle)) % 5)
        for i in range(12):
            pick = (base + i * stride) % len(WORD_LIST)
            if (i % 3) == 2:
                pick = (pick + 1) % len(WORD_LIST)
            words.append(WORD_LIST[pick])

    return " ".join(words)

# ----- Ethereum key derivation -----
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def mnemonic_to_eth_priv_index(mnemonic: str, index: int) -> bytes:
    seed_bytes = mnemonic.encode("utf-8")
    master = bip32utils.BIP32Key.fromEntropy(seed_bytes)
    child = master.ChildKey(44 + bip32utils.BIP32_HARDEN)\
                  .ChildKey(60 + bip32utils.BIP32_HARDEN)\
                  .ChildKey(0 + bip32utils.BIP32_HARDEN)\
                  .ChildKey(0).ChildKey(index)
    return child.PrivateKey()

def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if len(pub_uncompressed) == 65 and pub_uncompressed[0] == 0x04 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return to_checksum_address("0x" + addr_bytes.hex())

def sanity_check_privkey(priv_bytes: bytes) -> bool:
    try:
        if not isinstance(priv_bytes, (bytes, bytearray)) or len(priv_bytes) != 32:
            return False
        priv_int = int.from_bytes(priv_bytes, "big")
        return 1 <= priv_int < SECP256K1_N
    except Exception:
        return False

# ----- RPC -----
async def rpc_post_with_retries(url, payload, session, max_attempts=3):
    for attempt in range(1, max_attempts + 1):
        try:
            async with session.post(url, json=payload, timeout=15) as r:
                r.raise_for_status()
                return await r.json()
        except Exception:
            if attempt < max_attempts:
                await asyncio.sleep(attempt)
    raise RuntimeError("RPC failed")

async def eth_get_balance(rpc_url, address, session) -> Optional[int]:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    j = await rpc_post_with_retries(rpc_url, payload, session)
    result = j.get("result")
    return int(result, 16) if result else 0

# ----- Worker -----
async def worker_eth(chain_name, rpc_url, account_index, debug=False):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            try:
                mnemonic = gen_predictable_mnemonic()
                priv = mnemonic_to_eth_priv_index(mnemonic, account_index)
                if not sanity_check_privkey(priv):
                    continue

                key_repr = f"{mnemonic}::{account_index}"
                if key_repr in in_memory_scanned:
                    continue

                append_scanned_mnemonic(key_repr)
                address = eth_priv_to_address(priv)
                if debug:
                    print(f"[{chain_name}] idx {account_index} -> {address}")

                try:
                    bal_wei = await eth_get_balance(rpc_url, address, session)
                except Exception:
                    await asyncio.sleep(0.05)
                    continue

                if bal_wei and bal_wei > 0:
                    bal_eth = bal_wei / 10**18
                    bal_str = f"{bal_eth:.18f} (wei={bal_wei})"
                    out = format_found_block(chain_name, mnemonic, account_index, priv.hex(), address, bal_str)
                    print(out)
                    append_found(f"{chain_name} | {mnemonic} | {account_index} | {priv.hex()} | {address} | {bal_str}")

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

# ----- Main -----
def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    debug = args.debug

    print(f"[info] Ethereum-only scanner. Debug={debug}. Press Ctrl+C to stop.")

    open(SCANNED_MNEMONICS_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = []
        for i in range(3):  # 3 threads for account indices 0,1,2
            futures.append(ex.submit(run_async_worker, worker_eth, "ethereum", ETH_RPC, i, debug))
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
