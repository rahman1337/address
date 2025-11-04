#!/usr/bin/env python3
"""
Async multi-chain scanner (ETH/BSC/Solana) - high-throughput version.

Features implemented per user request:
- asyncio + aiohttp networking (connection pooling)
- Batch JSON-RPC requests for eth_getBalance
- coincurve (libsecp256k1) for fast Ethereum/BSC pubkey/address derivation
- Solana: use pynacl if available, otherwise fall back to pure-python ed25519
- Batch key generation + local sanity checks before RPC
- Buffered, append-only file writes (scanned_keys.txt and found.txt)
- Retry/backoff for RPCs (configurable)
- Graceful Ctrl+C shutdown
"""

import asyncio
import os
import sys
import time
import json
import signal
import base58 as py_base58
from argparse import ArgumentParser
from typing import List, Tuple, Optional

# Networking
import aiohttp

# Crypto (fast path)
try:
    from coincurve import PrivateKey as CoincurvePrivateKey
    have_coincurve = True
except Exception:
    have_coincurve = False

# eth utils
from eth_utils import keccak, to_checksum_address

# Solana ed25519: prefer pynacl, else fallback to pure-python ed25519 module if present
have_pynacl = False
try:
    from nacl.signing import SigningKey as NaClSigningKey
    have_pynacl = True
except Exception:
    have_pynacl = False

ed25519_mod = None
try:
    import ed25519 as py_ed25519
    ed25519_mod = py_ed25519
except Exception:
    ed25519_mod = None

# Use os.urandom for speed
import secrets  # still used for compatibility in some places

# Files
SCANNED_FILE = "scanned_keys.txt"
FOUND_FILE = "found.txt"

# Configuration
ETH_RPC = "https://ethereum.publicnode.com"
BSC_RPC = "https://bsc.publicnode.com"
SOL_RPC = "https://solana.publicnode.com"

# Batch sizes (tune to your provider limits)
GEN_BATCH = 256        # number of keys generated per batch
RPC_BATCH = 32         # number of addresses per JSON-RPC batch request
MAX_CONCURRENT_RPC = 6 # number of concurrent batch RPCs per chain
RPC_MAX_ATTEMPTS = 3   # retries per RPC batch
RPC_BACKOFF_BASE = 0.5 # backoff multiplier (seconds -> 0.5,1.0,1.5...)

# Sanity thresholds
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# In-memory scanned set (loaded from file to avoid repeats)
in_memory_scanned = set()

# Queues for buffered writes
scanned_write_queue: asyncio.Queue = asyncio.Queue()
found_write_queue: asyncio.Queue = asyncio.Queue()

# Graceful shutdown
stop_event = asyncio.Event()

# Debug flag
DEBUG = False

# -------------------------
# Utility functions
# -------------------------
def load_scanned():
    if os.path.exists(SCANNED_FILE):
        try:
            with open(SCANNED_FILE, "r", encoding="utf-8") as f:
                for line in f:
                    l = line.strip()
                    if l:
                        in_memory_scanned.add(l)
        except Exception as e:
            print(f"[warn] could not load {SCANNED_FILE}: {e}", file=sys.stderr)

def append_scanned_buffer(key_repr: str):
    # put into asyncio queue for writer
    scanned_write_queue.put_nowait(key_repr)

def append_found_buffer(line: str):
    found_write_queue.put_nowait(line)

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

# -------------------------
# Sanity checks
# -------------------------
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
        # best-effort pubkey derivation if possible
        if ed25519_mod is None and not have_pynacl:
            return True
        try:
            if have_pynacl:
                sk = NaClSigningKey(seed)
                vk = sk.verify_key.encode()
                if len(vk) != 32:
                    return False
                if set(vk) == {0}:
                    return False
            else:
                sk = ed25519_mod.SigningKey(seed)
                vk = sk.get_verifying_key()
                pub_raw = vk.to_bytes() if hasattr(vk, "to_bytes") else bytes(vk)
                if len(pub_raw) != 32:
                    return False
                if set(pub_raw) == {0}:
                    return False
        except Exception:
            return False
        return True
    except Exception:
        return False

# -------------------------
# Crypto helpers
# -------------------------
def gen_eth_privkey_bytes_fast() -> bytes:
    # os.urandom is fastest; secrets.token_bytes wraps it but small overhead
    return os.urandom(32)

def eth_priv_to_checksum_address_coincurve(priv_bytes: bytes) -> str:
    """
    Use coincurve (libsecp256k1) for pubkey derivation, then keccak and EIP-55 checksum.
    If coincurve unavailable, fall back to slower eth_keys approach (if installed).
    """
    if have_coincurve:
        pk = CoincurvePrivateKey(priv_bytes).public_key.format(compressed=False)
        # drop 0x04 prefix
        raw = pk[1:]
        ke = keccak(raw)
        addr_bytes = ke[-20:]
        addr_hex = "0x" + addr_bytes.hex()
        return to_checksum_address(addr_hex)
    else:
        # fallback: try using eth_keys (if installed), else compute via ecdsa which is too slow
        try:
            from eth_keys import keys as eth_keys_local
            pk = eth_keys_local.PrivateKey(priv_bytes)
            return pk.public_key.to_checksum_address()
        except Exception as e:
            raise RuntimeError("coincurve not installed and eth_keys not available; please install coincurve for speed")

def gen_solana_keypair():
    """
    Returns (seed_bytes, base58_address). Uses pynacl if available, else pure-python ed25519 if available.
    """
    seed = os.urandom(32)
    if have_pynacl:
        sk = NaClSigningKey(seed)
        vk = sk.verify_key.encode()
        address = py_base58.b58encode(vk).decode()
        return seed, address
    elif ed25519_mod is not None:
        sk = ed25519_mod.SigningKey(seed)
        vk = sk.get_verifying_key()
        pub_raw = vk.to_bytes() if hasattr(vk, "to_bytes") else bytes(vk)
        address = py_base58.b58encode(pub_raw).decode()
        return seed, address
    else:
        raise RuntimeError("No ed25519 implementation available for Solana. Install 'pynacl' or 'ed25519' package.")

# -------------------------
# RPC helpers (async)
# -------------------------
async def rpc_post_with_retries_aio(session: aiohttp.ClientSession, url: str, payload, attempts=RPC_MAX_ATTEMPTS, debug=False):
    last_exc = None
    # payload may be list (batch) or dict (single)
    for attempt in range(1, attempts + 1):
        try:
            async with session.post(url, json=payload, timeout=20) as resp:
                text = await resp.text()
                if debug:
                    print(f"[debug][rpc] POST {url} payload(len)={len(json.dumps(payload)) if payload else 0} status={resp.status}")
                    print(f"[debug][rpc] response: {text[:1000]}")
                resp.raise_for_status()
                # parse JSON
                j = json.loads(text)
                return j
        except Exception as e:
            last_exc = e
            if debug:
                print(f"[debug][rpc] attempt {attempt} failed for {url}: {e}")
            # backoff small (configurable). keep backoff for transient server errors.
            if attempt < attempts:
                backoff = RPC_BACKOFF_BASE * attempt
                if debug:
                    print(f"[debug][rpc] backing off {backoff}s before retry")
                await asyncio.sleep(backoff)
    raise last_exc

# -------------------------
# Writer task: flush buffers to files in append mode
# -------------------------
async def writer_task():
    # ensures append-only writes; will not overwrite files
    # ensure files exist
    open(SCANNED_FILE, "a").close()
    open(FOUND_FILE, "a").close()
    # buffers local flush intervals
    while not stop_event.is_set() or not (scanned_write_queue.empty() and found_write_queue.empty()):
        wrote = False
        try:
            # drain scanned queue
            lines = []
            while not scanned_write_queue.empty():
                try:
                    lines.append(scanned_write_queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            if lines:
                wrote = True
                with open(SCANNED_FILE, "a", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
            # drain found queue
            lines = []
            while not found_write_queue.empty():
                try:
                    lines.append(found_write_queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            if lines:
                wrote = True
                with open(FOUND_FILE, "a", encoding="utf-8") as f:
                    f.write("\n".join(lines) + "\n")
        except Exception as e:
            print(f"[writer][error] {e}", file=sys.stderr)
        # avoid busy loop
        if not wrote:
            await asyncio.sleep(0.2)
    # final flush done; exit

# -------------------------
# Batch builders
# -------------------------
def build_eth_balance_batch(addresses: List[str]):
    payload = []
    for i, addr in enumerate(addresses):
        payload.append({
            "jsonrpc": "2.0",
            "id": i+1,
            "method": "eth_getBalance",
            "params": [addr, "latest"]
        })
    return payload

# -------------------------
# Chain worker (async)
# -------------------------
async def eth_like_worker(name: str, rpc_url: str, session: aiohttp.ClientSession):
    sem = asyncio.Semaphore(MAX_CONCURRENT_RPC)
    async def do_rpc_batch(priv_addr_pairs: List[Tuple[bytes, str]]):
        # performs a single RPC batch for addresses; uses semaphore to limit concurrency
        async with sem:
            addrs = [addr for _, addr in priv_addr_pairs]
            payload = build_eth_balance_batch(addrs)
            try:
                j = await rpc_post_with_retries_aio(session, rpc_url, payload, debug=DEBUG)
            except Exception as e:
                if DEBUG:
                    print(f"[{name}][rpc error] batch failed: {e}")
                return
            # if response is list (batch) else maybe dict if provider wraps differently
            # map responses by id->result
            if isinstance(j, dict):
                # provider returned a single object? try to interpret
                # some providers return {"result": [...] } - handle that
                if "result" in j and isinstance(j["result"], list):
                    resp_list = j["result"]
                else:
                    # unexpected, skip
                    if DEBUG:
                        print(f"[{name}][rpc] unexpected response shape: {j}")
                    return
            else:
                resp_list = j
            # process results
            for resp in resp_list:
                idx = resp.get("id", None)
                if idx is None:
                    continue
                try:
                    res = resp.get("result")
                    balance_wei = int(res, 16) if res else 0
                except Exception:
                    balance_wei = 0
                # map to priv/addr
                pair = priv_addr_pairs[idx-1]
                priv_bytes = pair[0]
                addr = pair[1]
                if balance_wei and balance_wei > 0:
                    bal_eth = balance_wei / 10**18
                    bal_str = f"{bal_eth:.18f} (wei={balance_wei})"
                    out = format_found_block(name, priv_bytes.hex(), addr, bal_str)
                    print(out)
                    append_found_buffer(f"{name} | {priv_bytes.hex()} | {addr} | {bal_str}")

    # main loop: generate batches -> filter -> map -> RPC in batches
    while not stop_event.is_set():
        # generate batch of candidate keys
        privs = [gen_eth_privkey_bytes_fast() for _ in range(GEN_BATCH)]
        # sanity filter and derive addresses
        pairs = []
        for p in privs:
            if not sanity_check_secp256k1_privkey(p):
                continue
            key_repr = f"{name}:{p.hex()}"
            if key_repr in in_memory_scanned:
                continue
            try:
                addr = eth_priv_to_checksum_address_coincurve(p)
            except Exception as e:
                if DEBUG:
                    print(f"[{name}][crypto error] {e}")
                continue
            # mark as scanned now (so we never re-query same key)
            in_memory_scanned.add(key_repr)
            append_scanned_buffer(key_repr)
            pairs.append((p, addr))
        # dispatch RPCs in sub-batches
        tasks = []
        for i in range(0, len(pairs), RPC_BATCH):
            sub = pairs[i:i+RPC_BATCH]
            tasks.append(asyncio.create_task(do_rpc_batch(sub)))
        if tasks:
            await asyncio.gather(*tasks)
        # loop continues immediately (no artificial sleep) to maximize throughput

async def solana_worker(name: str, rpc_url: str, session: aiohttp.ClientSession):
    sem = asyncio.Semaphore(MAX_CONCURRENT_RPC)
    async def do_rpc_batch(seeds_addrs: List[Tuple[bytes, str]]):
        async with sem:
            addrs = [addr for _, addr in seeds_addrs]
            # build JSON-RPC batch with method "getBalance" (Solana uses single-object returns)
            payload = []
            for i, addr in enumerate(addrs):
                payload.append({
                    "jsonrpc": "2.0",
                    "id": i+1,
                    "method": "getBalance",
                    "params": [addr, {"commitment": "final"}]
                })
            try:
                j = await rpc_post_with_retries_aio(session, rpc_url, payload, debug=DEBUG)
            except Exception as e:
                if DEBUG:
                    print(f"[{name}][rpc error] {e}")
                return
            # parse list
            resp_list = j if isinstance(j, list) else j.get("result", [])
            # if j is dict with "result": list, handle accordingly
            if isinstance(j, dict) and "result" in j and isinstance(j["result"], list):
                resp_list = j["result"]
            # process
            for resp in resp_list:
                idx = resp.get("id", None)
                if idx is None:
                    continue
                result = resp.get("result")
                value = None
                if isinstance(result, dict):
                    value = result.get("value")
                elif isinstance(resp, dict) and "result" in resp and isinstance(resp["result"], dict):
                    value = resp["result"].get("value")
                try:
                    lamports = int(value) if value is not None else 0
                except Exception:
                    lamports = 0
                seed, addr = seeds_addrs[idx-1]
                if lamports and lamports > 0:
                    sol_str = f"{lamports} lamports ({lamports / 1e9:.9f} SOL)"
                    out = format_found_block(name, seed.hex(), addr, sol_str)
                    print(out)
                    append_found_buffer(f"{name} | {seed.hex()} | {addr} | {sol_str}")

    # loop
    while not stop_event.is_set():
        seeds = []
        for _ in range(GEN_BATCH):
            try:
                seed, addr = gen_solana_keypair()
            except Exception as e:
                if DEBUG:
                    print(f"[{name}][crypto error] {e}")
                continue
            if not sanity_check_ed25519_seed(seed):
                continue
            key_repr = f"{name}:{seed.hex()}"
            if key_repr in in_memory_scanned:
                continue
            in_memory_scanned.add(key_repr)
            append_scanned_buffer(key_repr)
            seeds.append((seed, addr))
        # batch RPCs
        tasks = []
        for i in range(0, len(seeds), RPC_BATCH):
            sub = seeds[i:i+RPC_BATCH]
            tasks.append(asyncio.create_task(do_rpc_batch(sub)))
        if tasks:
            await asyncio.gather(*tasks)
        # continue immediately

# -------------------------
# Startup & main
# -------------------------
def handle_sigint():
    if not stop_event.is_set():
        print("\n[info] Ctrl+C detected, shutting down...")
        stop_event.set()

async def main_async(debug: bool):
    global DEBUG
    DEBUG = debug
    load_scanned()
    # start writer task
    writer = asyncio.create_task(writer_task())

    # create aiohttp sessions per chain (tweak connector limits)
    connector = aiohttp.TCPConnector(limit_per_host=MAX_CONCURRENT_RPC * 2, limit=MAX_CONCURRENT_RPC * 10, force_close=False)
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        # launch workers
        tasks = [
            asyncio.create_task(eth_like_worker("ethereum", ETH_RPC, session)),
            asyncio.create_task(eth_like_worker("bsc", BSC_RPC, session)),
            asyncio.create_task(solana_worker("solana", SOL_RPC, session)),
        ]
        # wait until stop_event set
        await stop_event.wait()
        # cancel tasks politely
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    # ensure writer finishes flushing
    await writer

def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="debug mode")
    args = parser.parse_args()
    print(f"[info] Starting async scanner. Debug={args.debug}. Press Ctrl+C to stop.")
    # ensure files exist
    open(SCANNED_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    loop = asyncio.get_event_loop()
    # signal handler for graceful shutdown
    try:
        loop.add_signal_handler(signal.SIGINT, handle_sigint)
    except NotImplementedError:
        # Windows compatibility fallback
        pass
    try:
        loop.run_until_complete(main_async(args.debug))
    finally:
        # best-effort cleanup
        loop.stop()
        loop.close()
    print("[info] Scanner stopped. Goodbye.")

if __name__ == "__main__":
    main()
