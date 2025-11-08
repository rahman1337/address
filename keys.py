#!/usr/bin/env python3
import asyncio
import signal
import os
import time
import math
from itertools import islice
from typing import List, Tuple, Dict

import aiohttp
from coincurve import PrivateKey
from Crypto.Hash import keccak

# -------- CONFIG -------- #
RPC_URL = "https://ethereum-rpc.publicnode.com"
CONCURRENCY = 5       # number of concurrent workers
BATCH_SIZE = 100      # keys generated per worker loop
BATCH_RPC_SIZE = 5    # number of eth_getBalance calls per single POST
STATS_INTERVAL = 10   # seconds
MAX_RETRIES = 3
RPC_TIMEOUT = 20      # seconds for aiohttp timeout

# -------- GLOBAL STATE -------- #
_total_keys = 0
_total_keys_lock = asyncio.Lock()
_stop_event = asyncio.Event()

# -------- SIGNAL HANDLING -------- #
def _on_signal():
    print("\n[INFO] Ctrl+C received — shutting down...")
    _stop_event.set()

def _install_signal_handlers():
    loop = asyncio.get_event_loop()
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, _on_signal)
        except NotImplementedError:
            # Windows fallback: signal.signal works synchronously
            signal.signal(s, lambda *_: _on_signal())

# -------- UTIL: keccak & checksum -------- #
def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def to_checksum_address(addr_hex: str) -> str:
    # addr_hex: hex without 0x, 40 chars lower/upper mix
    addr = addr_hex.lower()
    hash_hex = keccak.new(digest_bits=256, data=addr.encode("ascii")).hexdigest()
    out = []
    for i, ch in enumerate(addr):
        if ch in "0123456789":
            out.append(ch)
        else:
            # If corresponding hash nibble >= 8 then uppercase
            if int(hash_hex[i], 16) >= 8:
                out.append(ch.upper())
            else:
                out.append(ch)
    return "0x" + "".join(out)

# -------- KEY & ADDRESS DERIVATION -------- #
def generate_privkey_bytes() -> bytes:
    # fast system RNG
    return os.urandom(32)

def privkey_to_address_hex(priv_bytes: bytes) -> Tuple[str, str]:
    """
    Returns (priv_hex, checksum_address)
    """
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)  # 65 bytes, 0x04 prefix
    pub_bytes = pub_uncompressed[1:]  # skip 0x04
    addr_bytes = keccak256(pub_bytes)[-20:]
    addr_hex = addr_bytes.hex()
    checksum = to_checksum_address(addr_hex)
    return priv_bytes.hex(), checksum

# -------- RPC batching & retrying -------- #
async def rpc_post(session: aiohttp.ClientSession, payload, attempt: int):
    try:
        async with session.post(RPC_URL, json=payload, timeout=RPC_TIMEOUT) as resp:
            text = await resp.text()
            # try parse json
            try:
                return await resp.json(content_type=None)
            except Exception:
                # fallback: show error and raw text
                raise RuntimeError(f"Invalid JSON response: {text[:400]}")
    except Exception as e:
        if attempt + 1 < MAX_RETRIES:
            print(f"[ERROR] RPC request failed (attempt {attempt+1}/{MAX_RETRIES}): {e} — retrying")
            await asyncio.sleep(0.5 * (attempt + 1))
            return None
        else:
            raise

def make_batch_payload(addresses: List[str], start_id: int) -> List[Dict]:
    payload = []
    cur_id = start_id
    for addr in addresses:
        payload.append({
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [addr, "latest"],
            "id": cur_id
        })
        cur_id += 1
    return payload

# -------- WORKER -------- #
async def worker(worker_id: int, session: aiohttp.ClientSession):
    global _total_keys
    id_counter = worker_id * 10_000_000  # ensure different id spaces per worker
    while not _stop_event.is_set():
        # generate batch of keys and addresses
        batch: List[Tuple[str, str]] = []
        for _ in range(BATCH_SIZE):
            priv = generate_privkey_bytes()
            priv_hex, addr = privkey_to_address_hex(priv)
            batch.append((priv_hex, addr))

        # chunk into groups of BATCH_RPC_SIZE and send each chunk in one POST
        tasks_results: List[Tuple[str, int, str]] = []  # list of (priv_hex, balance_int, addr)
        idx = 0
        while idx < len(batch):
            chunk = batch[idx: idx + BATCH_RPC_SIZE]
            addresses = [addr for (_, addr) in chunk]
            payload = make_batch_payload(addresses, id_counter)
            id_counter += len(payload)

            # Try up to MAX_RETRIES
            result = None
            for attempt in range(MAX_RETRIES):
                resp = await rpc_post(session, payload, attempt)
                if resp is None:
                    continue
                # resp is expected to be a list of responses
                if not isinstance(resp, list):
                    # Unexpected structure; treat as error and retry
                    print(f"[ERROR] Unexpected RPC batch response (not list). Attempt {attempt+1}")
                    resp = None
                    continue
                # build id->result map
                res_map = {}
                ok = True
                for item in resp:
                    if "id" not in item or "result" not in item:
                        ok = False
                        break
                    res_map[item["id"]] = item["result"]
                if not ok:
                    print(f"[ERROR] RPC batch missing fields. Attempt {attempt+1}")
                    resp = None
                    continue
                result = res_map
                break

            if result is None:
                # final failure for this chunk: mark each as error and skip
                for priv_hex, addr in chunk:
                    print(f"[ERROR] Final failure fetching balances for chunk including {addr}")
                    # Still increment counters to reflect attempted keys
                    async with _total_keys_lock:
                        _total_keys += 1
                idx += BATCH_RPC_SIZE
                continue

            # Map results to balances and record outputs
            for i, (priv_hex, addr) in enumerate(chunk):
                # payload ids were assigned sequentially starting at (id_counter - len(payload))
                # compute id for this entry:
                # id_of_item = starting_id + i
                # But we built payload with start id = id_counter_before
                # We recorded that id_counter advanced; compute start:
                start_id = id_counter - len(payload)
                item_id = start_id + i
                raw = result.get(item_id)
                if raw is None:
                    # treat as error for this address
                    print(f"[ERROR] Missing result for id {item_id} ({addr})")
                    balance_int = 0
                else:
                    try:
                        balance_int = int(raw, 16)
                    except Exception:
                        print(f"[ERROR] Bad balance format for {addr}: {raw}")
                        balance_int = 0

                # record result and print accordingly
                async with _total_keys_lock:
                    _total_keys += 1

                if balance_int > 0:
                    # bordered block with KEY, ADDRESS, BALANCE (in ETH)
                    eth_bal = balance_int / 10 ** 18
                    border = "+" + "-" * 60 + "+"
                    print(f"\n{border}")
                    print(f"KEY: {priv_hex}")
                    print(f"ADDRESS: {addr}")
                    print(f"BALANCE: {eth_bal:.18f} ETH")
                    print(f"{border}\n")
                else:
                    eth_bal = 0.0
                    print(f"{addr} | {eth_bal:.6f} ETH")
            idx += BATCH_RPC_SIZE

# -------- STATS TASK -------- #
async def stats_task():
    prev = 0
    while not _stop_event.is_set():
        await asyncio.sleep(STATS_INTERVAL)
        async with _total_keys_lock:
            now = _total_keys
        speed = (now - prev) / STATS_INTERVAL
        prev = now
        print(f"[STATS] {now} | {speed:.2f} keys/s")

# -------- MAIN -------- #
async def main():
    _install_signal_handlers()
    timeout = aiohttp.ClientTimeout(total=RPC_TIMEOUT)
    conn = aiohttp.TCPConnector(limit=0)  # unlimited concurrency within session; workers control concurrency
    async with aiohttp.ClientSession(timeout=timeout, connector=conn) as session:
        workers = [asyncio.create_task(worker(i, session)) for i in range(CONCURRENCY)]
        stats = asyncio.create_task(stats_task())

        # wait for stop_event
        await _stop_event.wait()

        # cancellation and cleanup
        for w in workers:
            w.cancel()
        stats.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await asyncio.gather(stats, return_exceptions=True)
        print("[INFO] Shutdown complete.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # fallback
        print("\n[INFO] Interrupted by user.")
