#!/usr/bin/env python3
import os
import sys
import time
import threading
import traceback
import asyncio
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

# ------------------- imports -------------------
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
mnemonic_mod = ensure_import("mnemonic")
bip32utils = ensure_import("bip32utils")

from eth_utils import to_checksum_address, keccak
from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN

# ------------------- config -------------------
ETH_RPC = "https://ethereum.publicnode.com"
FOUND_FILE = "found.txt"
SCANNED_MNEMONICS_FILE = "scanned_mnemonics.txt"

found_lock = threading.Lock()
mnemonics_lock = threading.Lock()
in_memory_scanned_mnemonics = set()
stop_event = threading.Event()

# ------------------- load scanned mnemonics -------------------
if os.path.exists(SCANNED_MNEMONICS_FILE):
    with open(SCANNED_MNEMONICS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            l = line.strip()
            if l:
                in_memory_scanned_mnemonics.add(l)

# ------------------- helpers -------------------
def append_found(line: str):
    with found_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def append_scanned_mnemonic(mnemonic_str: str):
    with mnemonics_lock:
        if mnemonic_str in in_memory_scanned_mnemonics:
            return
        in_memory_scanned_mnemonics.add(mnemonic_str)
        with open(SCANNED_MNEMONICS_FILE, "a", encoding="utf-8") as f:
            f.write(mnemonic_str + "\n")

def format_found_block(chain, mnemonic, privhex, address, balance_str):
    border = "=" * 60
    return "\n".join([
        border,
        f"CHAIN: {chain}",
        f"MNEMONIC: {mnemonic}",
        f"PRIVATE_KEY: {privhex}",
        f"ADDRESS: {address}",
        f"BALANCE: {balance_str}",
        border
    ])

# ------------------- mnemonic generation -------------------
def gen_mnemonic(strength_bits: int = 128):
    """
    Generate a 12- or 24-word mnemonic (strength_bits: 128 -> 12 words, 256 -> 24 words)
    Avoid previously scanned ones.
    """
    if strength_bits not in (128, 256):
        raise ValueError("strength_bits must be 128 (12 words) or 256 (24 words)")
    mnemo = Mnemonic("english")
    for _ in range(1000):
        m = mnemo.generate(strength=strength_bits)
        m = " ".join(m.split())
        with mnemonics_lock:
            if m in in_memory_scanned_mnemonics:
                continue
            append_scanned_mnemonic(m)
            return m
    raise RuntimeError("Failed to generate a new mnemonic")

# ------------------- derive private key -------------------
def derive_eth_priv(mnemonic_str: str) -> bytes:
    seed_bytes = Mnemonic("english").to_seed(mnemonic_str, passphrase="")
    master_key = BIP32Key.fromEntropy(seed_bytes)
    k = master_key.ChildKey(44 + BIP32_HARDEN)  # 44'
    k = k.ChildKey(60 + BIP32_HARDEN)          # 60'
    k = k.ChildKey(0 + BIP32_HARDEN)           # 0'
    k = k.ChildKey(0)                           # change
    k = k.ChildKey(0)                           # first account
    priv_bytes = k.PrivateKey()
    if isinstance(priv_bytes, int):
        priv_bytes = priv_bytes.to_bytes(32, "big")
    elif isinstance(priv_bytes, bytes) and len(priv_bytes) < 32:
        priv_bytes = priv_bytes.rjust(32, b'\x00')
    return priv_bytes

# ------------------- derive address -------------------
def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub = pk.public_key.format(compressed=False)
    pub_raw = pub[1:] if len(pub) == 65 and pub[0] == 0x04 else pub
    addr_bytes = keccak(pub_raw)[-20:]
    return to_checksum_address("0x" + addr_bytes.hex())

# ------------------- RPC helpers -------------------
async def rpc_post(url: str, payload: dict, session: aiohttp.ClientSession, debug=False):
    for attempt in range(3):
        try:
            async with session.post(url, json=payload, timeout=15) as r:
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            if debug:
                print(f"[rpc attempt {attempt+1}] {e}")
            await asyncio.sleep(0.5)
    raise RuntimeError("RPC failed after 3 attempts")

async def get_balance(rpc_url: str, address: str, session: aiohttp.ClientSession, debug=False) -> int:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    resp = await rpc_post(rpc_url, payload, session, debug=debug)
    result = resp.get("result")
    return int(result, 16) if result else 0

# ------------------- worker -------------------
async def worker(chain_name, rpc_url, debug=False):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            for strength, label in [(128, "12w"), (256, "24w")]:
                try:
                    mnemonic = gen_mnemonic(strength)
                    priv = derive_eth_priv(mnemonic)
                    privhex = priv.hex()
                    addr = eth_priv_to_address(priv)
                    if debug:
                        print(f"[{chain_name}] {label} mnemonic='{mnemonic}' priv={privhex} -> addr={addr}")
                    try:
                        bal_wei = await get_balance(rpc_url, addr, session, debug=debug)
                        if bal_wei > 0:
                            bal_eth = bal_wei / 10**18
                            bal_str = f"{bal_eth:.18f} (wei={bal_wei})"
                            out = format_found_block(f"{chain_name} ({label})", mnemonic, privhex, addr, bal_str)
                            print(out)
                            append_found(f"{chain_name} ({label}) | {mnemonic} | {privhex} | {addr} | {bal_str}")
                    except Exception as e:
                        if debug:
                            print(f"[balance error] {e}")
                    await asyncio.sleep(0.05)
                except Exception as e:
                    if debug:
                        print(f"[worker error] {e}")
                    traceback.print_exc()
                    await asyncio.sleep(0.1)

def run_worker(coro_func, *args, **kwargs):
    try:
        asyncio.run(coro_func(*args, **kwargs))
    except KeyboardInterrupt:
        stop_event.set()
        print("[info] Ctrl+C detected, worker exiting immediately.")
    except Exception as e:
        print(f"[fatal] {e}")

# ------------------- main -------------------
def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true")
    args = parser.parse_args()
    debug = args.debug

    print(f"[info] Starting Ethereum scanner (12 & 24 words, first account only). Debug={debug}. Press Ctrl+C to stop.")

    # ensure files exist
    open(FOUND_FILE, "a").close()
    open(SCANNED_MNEMONICS_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=5) as ex:
        for _ in range(5):
            ex.submit(run_worker, worker, "ethereum", ETH_RPC, debug)
        try:
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            stop_event.set()
            print("\n[info] Ctrl+C detected, stopping all workers...")
            time.sleep(0.2)

    print("[info] Scanner stopped. Goodbye.")

if __name__ == "__main__":
    main()
