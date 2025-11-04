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
import secrets
BSC_RPC = "https://bsc.publicnode.com"
ETH_RPC = "https://ethereum.publicnode.com"
SOL_RPC = "https://solana.publicnode.com"
SCANNED_FILE = "scanned_keys.txt"
FOUND_FILE = "found.txt"
scanned_lock = threading.Lock()
found_lock = threading.Lock()
in_memory_scanned = set()
stop_event = threading.Event()
if os.path.exists(SCANNED_FILE):
    try:
        with open(SCANNED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                l = line.strip()
                if l:
                    in_memory_scanned.add(l)
    except Exception as e:
        print(f"[warn] Could not load {SCANNED_FILE}: {e}", file=sys.stderr)
def append_scanned(key_repr: str):
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
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
def gen_eth_privkey_bytes():
    while True:
        b = secrets.token_bytes(32)
        priv_int = int.from_bytes(b, "big")
        if 1 <= priv_int < SECP256K1_N:
            return b
def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    if len(pub_uncompressed) == 65 and pub_uncompressed[0] == 0x04:
        pub_raw = pub_uncompressed[1:]
    else:
        pub_raw = pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    hex_addr = "0x" + addr_bytes.hex()
    return to_checksum_address(hex_addr)
def bsc_priv_to_address(priv_bytes: bytes) -> str:
    return eth_priv_to_address(priv_bytes)
def gen_solana_keypair():
    if ed25519_mod is None:
        raise RuntimeError("ed25519 module not available — please install it with: pip install ed25519")
    seed = secrets.token_bytes(32)
    sk = ed25519_mod.SigningKey(seed)
    vk = sk.get_verifying_key()
    if hasattr(vk, "to_bytes"):
        pub_raw = vk.to_bytes()
    else:
        pub_raw = bytes(vk)
    address = base58.b58encode(pub_raw).decode()
    return seed, address
def sanity_check_secp256k1_privkey(priv_bytes: bytes) -> bool:
    try:
        if not isinstance(priv_bytes, (bytes, bytearray)) or len(priv_bytes) != 32:
            return False
        priv_int = int.from_bytes(priv_bytes, "big")
        if not (1 <= priv_int < SECP256K1_N):
            return False
        if priv_int <= 2**16:
            return False
        s = set(priv_bytes)
        if len(s) <= 1:
            return False
        if len(s) < 4:
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
        if len(s) < 4:
            return False
        if ed25519_mod is None:
            return True
        sk = ed25519_mod.SigningKey(seed)
        vk = sk.get_verifying_key()
        if hasattr(vk, "to_bytes"):
            pub_raw = vk.to_bytes()
        else:
            pub_raw = bytes(vk)
        if not isinstance(pub_raw, (bytes, bytearray)) or len(pub_raw) != 32:
            return False
        if set(pub_raw) == {0}:
            return False
        return True
    except Exception:
        return False
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
            if debug:
                print(f"[debug][rpc] attempt {attempt} failed for {url}: {e}")
            else:
                if attempt == max_attempts:
                    print(f"[error][rpc] failed {url}: {e}")
            if attempt < max_attempts:
                sleep_seconds = attempt
                if debug:
                    print(f"[debug][rpc] sleeping {sleep_seconds}s before retry #{attempt+1}")
                await asyncio.sleep(sleep_seconds)
    raise last_exc
async def eth_like_get_balance(rpc_url: str, address: str, session: aiohttp.ClientSession, debug=False) -> Optional[int]:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    j = await rpc_post_with_retries(rpc_url, payload, session=session, debug=debug, max_attempts=3)
    if "error" in j:
        raise RuntimeError(f"RPC error: {j['error']}")
    result = j.get("result")
    if result is None:
        raise RuntimeError("No result field in RPC response")
    balance_wei = int(result, 16)
    return balance_wei
async def solana_get_balance(rpc_url: str, address: str, session: aiohttp.ClientSession, debug=False) -> Optional[int]:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [address, {"commitment": "final"}]}
    j = await rpc_post_with_retries(rpc_url, payload, session=session, debug=debug, max_attempts=3)
    if "error" in j:
        raise RuntimeError(f"RPC error: {j['error']}")
    result = j.get("result")
    if result is None:
        raise RuntimeError("No result field in RPC response")
    value = result.get("value")
    if value is None:
        raise RuntimeError("No value in result")
    return int(value)
async def worker_eth_async(chain_name, rpc_url, debug=False):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            try:
                priv = gen_eth_privkey_bytes()
                if not sanity_check_secp256k1_privkey(priv):
                    if debug:
                        print(f"[{chain_name}][sanity] rejected priv (failed sanity check): {priv.hex()}")
                    await asyncio.sleep(0.1)
                    continue
                privhex = priv.hex()
                key_repr = f"{chain_name}:{privhex}"
                if key_repr in in_memory_scanned:
                    if debug:
                        print(f"[{chain_name}] duplicate key, skipping {privhex}")
                    await asyncio.sleep(0.1)
                    continue
                address = eth_priv_to_address(priv)
                append_scanned(key_repr)
                if debug:
                    print(f"[{chain_name}] trying priv={privhex} -> addr={address}")
                try:
                    bal_wei = await eth_like_get_balance(rpc_url, address, session, debug=debug)
                except Exception as rpc_e:
                    print(f"[{chain_name}][error] RPC/check failed for {address}: {rpc_e}")
                    if debug:
                        traceback.print_exc()
                    await asyncio.sleep(0.5)
                    continue
                if debug:
                    print(f"[{chain_name}] balance (wei) = {bal_wei}")
                if bal_wei and bal_wei > 0:
                    bal_eth = bal_wei / 10**18
                    bal_str = f"{bal_eth:.18f} (wei={bal_wei})"
                    out = format_found_block(chain_name, privhex, address, bal_str)
                    print(out)
                    append_found(f"{chain_name} | {privhex} | {address} | {bal_str}")
                await asyncio.sleep(0.1)
            except Exception as e:
                print(f"[{chain_name}][exception] {e}")
                if debug:
                    traceback.print_exc()
                await asyncio.sleep(0.1)
async def worker_bsc_async(chain_name, rpc_url, debug=False):
    await worker_eth_async(chain_name, rpc_url, debug=debug)
async def worker_solana_async(chain_name, rpc_url, debug=False):
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            try:
                seed, address = gen_solana_keypair()
                if not sanity_check_ed25519_seed(seed):
                    if debug:
                        print(f"[{chain_name}][sanity] rejected seed (failed sanity check): {seed.hex()}")
                    await asyncio.sleep(0.1)
                    continue
                privhex = seed.hex()
                key_repr = f"{chain_name}:{privhex}"
                if key_repr in in_memory_scanned:
                    if debug:
                        print(f"[{chain_name}] duplicate key, skipping {privhex}")
                    await asyncio.sleep(0.1)
                    continue
                append_scanned(key_repr)
                if debug:
                    print(f"[{chain_name}] trying priv(seed)={privhex} -> addr={address}")
                try:
                    lamports = await solana_get_balance(rpc_url, address, session, debug=debug)
                except Exception as rpc_e:
                    print(f"[{chain_name}][error] RPC/check failed for {address}: {rpc_e}")
                    if debug:
                        traceback.print_exc()
                    await asyncio.sleep(0.5)
                    continue
                if debug:
                    print(f"[{chain_name}] balance (lamports) = {lamports}")
                if lamports and lamports > 0:
                    sol_str = f"{lamports} lamports ({lamports / 1e9:.9f} SOL)"
                    out = format_found_block(chain_name, privhex, address, sol_str)
                    print(out)
                    append_found(f"{chain_name} | {privhex} | {address} | {sol_str}")
                await asyncio.sleep(0.1)
            except Exception as e:
                print(f"[{chain_name}][exception] {e}")
                if debug:
                    traceback.print_exc()
                await asyncio.sleep(0.1)
def run_async_worker(coro_func, *args, **kwargs):
    try:
        asyncio.run(coro_func(*args, **kwargs))
    except Exception as e:
        print(f"[worker][fatal] {e}")
def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true")
    args = parser.parse_args()
    debug = args.debug
    print(f"[info] Starting scanner. Debug={debug}. Press Ctrl+C to stop.")
    open(SCANNED_FILE, "a").close()
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
        finally:
            for f in futures:
                try:
                    pass
                except Exception:
                    pass
    print("[info] Scanner stopped. Goodbye.")
if __name__ == "__main__":
    main()
