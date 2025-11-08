#!/usr/bin/env python3
import asyncio
import signal
import os
from typing import List, Tuple, Dict

import aiohttp
from coincurve import PrivateKey
from Crypto.Hash import keccak

# -------- CONFIG -------- #
RPC_URL = "https://ethereum-rpc.publicnode.com"
CONCURRENCY = 5       # number of concurrent workers
BATCH_SIZE = 100      # keys generated per worker loop
BATCH_RPC_SIZE = 10   # increased RPC batch size from 5 -> 10
STATS_INTERVAL = 10   # seconds
MAX_RETRIES = 3
RPC_TIMEOUT = 20      # seconds for aiohttp ClientTimeout
FOUND_FILE = "found.txt"

# Clear terminal at start
os.system("clear")

# -------- UTIL: keccak & checksum -------- #
def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def to_checksum_address(addr_hex: str) -> str:
    addr = addr_hex.lower()
    hash_hex = keccak.new(digest_bits=256, data=addr.encode("ascii")).hexdigest()
    out = []
    for i, ch in enumerate(addr):
        if ch in "0123456789":
            out.append(ch)
        else:
            if int(hash_hex[i], 16) >= 8:
                out.append(ch.upper())
            else:
                out.append(ch)
    return "0x" + "".join(out)

# -------- KEY & ADDRESS DERIVATION -------- #
def generate_privkey_bytes() -> bytes:
    return os.urandom(32)

def privkey_to_address_hex(priv_bytes: bytes) -> Tuple[str, str]:
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)[1:]  # skip 0x04 prefix
    addr_bytes = keccak256(pub_uncompressed)[-20:]
    addr_hex = addr_bytes.hex()
    checksum = to_checksum_address(addr_hex)
    return priv_bytes.hex(), checksum

# -------- RPC batching & retrying (with debug & response print) -------- #
async def rpc_post(session: aiohttp.ClientSession, payload, attempt: int):
    ids = [p.get("id") for p in payload] if isinstance(payload, list) else None
    print(f"[DEBUG] Sending RPC batch (attempt {attempt+1}) ids={ids}")
    try:
        async with session.post(RPC_URL, json=payload) as resp:
            status = resp.status
            text = await resp.text()
            print(f"[DEBUG] HTTP {status} received, first 200 chars: {text[:200]}")
            try:
                return await resp.json(content_type=None)
            except Exception:
                raise RuntimeError("Invalid JSON response: " + text[:400])
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
async def worker(worker_id: int, session: aiohttp.ClientSession,
                 stop_event: asyncio.Event, total_keys_lock: asyncio.Lock,
                 file_lock: asyncio.Lock, state: dict):
    id_counter = worker_id * 10_000_000
    while not stop_event.is_set():
        batch = []
        for _ in range(BATCH_SIZE):
            priv = generate_privkey_bytes()
            priv_hex, addr = privkey_to_address_hex(priv)
            batch.append((priv_hex, addr))

        idx = 0
        while idx < len(batch) and not stop_event.is_set():
            chunk = batch[idx: idx + BATCH_RPC_SIZE]
            addresses = [addr for (_, addr) in chunk]
            start_id = id_counter
            payload = make_batch_payload(addresses, start_id)
            id_counter += len(payload)

            result_map = None
            for attempt in range(MAX_RETRIES):
                resp = await rpc_post(session, payload, attempt)
                if resp is None:
                    continue
                if not isinstance(resp, list):
                    print(f"[ERROR] Unexpected RPC batch response (not list). Attempt {attempt+1}")
                    resp = None
                    continue
                ok = True
                m = {}
                for item in resp:
                    if "id" not in item or "result" not in item:
                        ok = False
                        break
                    m[item["id"]] = item["result"]
                if not ok:
                    print(f"[ERROR] RPC batch missing fields. Attempt {attempt+1}")
                    resp = None
                    continue
                result_map = m
                break

            if result_map is None:
                for priv_hex, addr in chunk:
                    print(f"[ERROR] Final failure fetching balances for chunk including {addr}")
                    async with total_keys_lock:
                        state["total_keys"] += 1
                idx += BATCH_RPC_SIZE
                continue

            for i, (priv_hex, addr) in enumerate(chunk):
                item_id = start_id + i
                raw = result_map.get(item_id)
                if raw is None:
                    print(f"[ERROR] Missing result for id {item_id} ({addr})")
                    balance_int = 0
                else:
                    try:
                        balance_int = int(raw, 16)
                    except Exception:
                        print(f"[ERROR] Bad balance format for {addr}: {raw}")
                        balance_int = 0

                async with total_keys_lock:
                    state["total_keys"] += 1

                if balance_int > 0:
                    eth_bal = balance_int / 10 ** 18
                    border = "+" + "-" * 60 + "+"
                    block = (
                        f"\n{border}\n"
                        f"KEY: {priv_hex}\n"
                        f"ADDRESS: {addr}\n"
                        f"BALANCE: {eth_bal:.18f} ETH\n"
                        f"{border}\n"
                    )
                    print(block, end="")

                    async with file_lock:
                        try:
                            with open(FOUND_FILE, "a", encoding="utf-8") as fh:
                                fh.write(block)
                        except Exception as e:
                            print(f"[ERROR] Failed to write to {FOUND_FILE}: {e}")
                else:
                    print(f"{addr} | {0.0:.6f} ETH")
            idx += BATCH_RPC_SIZE

# -------- STATS TASK -------- #
async def stats_task(stop_event: asyncio.Event, total_keys_lock: asyncio.Lock, state: dict):
    prev = 0
    while not stop_event.is_set():
        await asyncio.sleep(STATS_INTERVAL)
        async with total_keys_lock:
            now = state["total_keys"]
        speed = (now - prev) / STATS_INTERVAL
        prev = now
        print(f"[STATS] {now} | {speed:.2f} keys/s")

# -------- SIGNAL HANDLER -------- #
def install_signal_handlers(loop: asyncio.AbstractEventLoop, stop_event: asyncio.Event):
    def _set_done():
        if not stop_event.is_set():
            print("\n[INFO] Ctrl+C received — shutting down...")
            stop_event.set()
    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(s, _set_done)
        except NotImplementedError:
            signal.signal(s, lambda *_: _set_done())

# -------- MAIN -------- #
async def main():
    stop_event = asyncio.Event()
    total_keys_lock = asyncio.Lock()
    file_lock = asyncio.Lock()
    state = {"total_keys": 0}

    loop = asyncio.get_event_loop()
    install_signal_handlers(loop, stop_event)

    timeout = aiohttp.ClientTimeout(total=RPC_TIMEOUT)
    conn = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(timeout=timeout, connector=conn) as session:
        workers = [asyncio.create_task(worker(i, session, stop_event, total_keys_lock, file_lock, state))
                   for i in range(CONCURRENCY)]
        stats = asyncio.create_task(stats_task(stop_event, total_keys_lock, state))

        await stop_event.wait()

        for w in workers:
            w.cancel()
        stats.cancel()
        await asyncio.gather(*workers, return_exceptions=True)
        await asyncio.gather(stats, return_exceptions=True)
        print("[INFO] Shutdown complete.")

if __name__ == "__main__":
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        print("\n[INFO] Interrupted by user.")
    finally:
        try:
            loop.close()
        except Exception:
            pass
