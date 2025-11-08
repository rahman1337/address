#!/usr/bin/env python3
"""
fast_hd_longrun_fixed.py

High-throughput true BIP39 -> BIP32 -> Ethereum address scanner,
long-run friendly, with unique addresses counter.
"""

import os
import time
import math
import threading
import asyncio
import traceback
import json
import hashlib
from concurrent.futures import ThreadPoolExecutor
from mnemonic import Mnemonic
from bip32 import BIP32
from eth_keys import keys
import aiohttp
import logging

# ---------------- CONFIG ----------------
WORKERS = 12
BATCH_SIZE = 400
DERIVATION_PATH = "m/44'/60'/0'/0/0"
RPC_URL = "https://ethereum.publicnode.com"
HITS_FILE = "hits.txt"
ERROR_LOG = "errors.log"
REPORT_INTERVAL = 10
RPC_MAX_RETRIES = 3
BLOOM_CAPACITY = 30_000_000
BLOOM_ERROR_RATE = 1e-5
# ------------------------------

# Logging
logging.basicConfig(
    filename=ERROR_LOG,
    filemode="a",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
console.setFormatter(formatter)
logging.getLogger().addHandler(console)

mnemo = Mnemonic("english")

# Shared counters & state
checked = 0
checked_lock = threading.Lock()

rpc_success = 0
rpc_errors = 0
rpc_lock = threading.Lock()

unique_addresses = 0
unique_addr_lock = threading.Lock()

# File handles
hits_fp = open(HITS_FILE, "a", encoding="utf-8")

# ---------------- Bloom Filter ----------------
class BloomFilter:
    def __init__(self, capacity: int, error_rate: float):
        m = -capacity * math.log(error_rate) / (math.log(2) ** 2)
        k = (m / capacity) * math.log(2)
        self.m = int(m)
        self.k = max(1, int(round(k)))
        self._bits = bytearray((self.m + 7) // 8)
        self._lock = threading.Lock()

    def _hashes(self, data: bytes):
        h = hashlib.sha256(data).digest()
        idxs = []
        counter = 0
        while len(idxs) < self.k:
            chunk = hashlib.sha256(h + counter.to_bytes(2, "big")).digest()
            for i in range(0, len(chunk), 8):
                if len(idxs) >= self.k:
                    break
                val = int.from_bytes(chunk[i:i+8], "big")
                idxs.append(val % self.m)
            counter += 1
        return idxs

    def add(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        idxs = self._hashes(data)
        with self._lock:
            for i in idxs:
                self._bits[i >> 3] |= (1 << (i & 7))

    def __contains__(self, data):
        if isinstance(data, str):
            data = data.encode("utf-8")
        idxs = self._hashes(data)
        with self._lock:
            for i in idxs:
                if not (self._bits[i >> 3] & (1 << (i & 7))):
                    return False
        return True

mnemonic_bloom = BloomFilter(capacity=BLOOM_CAPACITY, error_rate=BLOOM_ERROR_RATE)
address_bloom = BloomFilter(capacity=BLOOM_CAPACITY, error_rate=BLOOM_ERROR_RATE)

# ---------------- Helpers ----------------
def sha256_bytes(x: str) -> bytes:
    return hashlib.sha256(x.encode("utf-8")).digest()

def generate_unique_mnemonic():
    while True:
        m = mnemo.generate(128)
        h = sha256_bytes(m)
        if h in mnemonic_bloom:
            continue
        mnemonic_bloom.add(h)
        return m

def mnemonic_to_eth_privkey_and_address(mnemonic_phrase):
    seed = mnemo.to_seed(mnemonic_phrase)
    bip32 = BIP32.from_seed(seed)
    privkey_bytes = bip32.get_privkey_from_path(DERIVATION_PATH)
    pk = keys.PrivateKey(privkey_bytes)
    address = pk.public_key.to_checksum_address()
    return pk.to_hex(), address

def process_batch(batch_size):
    global checked, unique_addresses
    results = []
    for _ in range(batch_size):
        try:
            mnemonic = generate_unique_mnemonic()
            privhex, address = mnemonic_to_eth_privkey_and_address(mnemonic)
        except Exception as e:
            logging.error("Derivation error: %s\n%s", e, traceback.format_exc(limit=5))
            continue

        addr_lower = address.lower()
        if addr_lower in address_bloom:
            continue
        address_bloom.add(addr_lower.encode("utf-8"))
        with unique_addr_lock:
            unique_addresses += 1

        with checked_lock:
            checked += 1

        results.append((mnemonic, address, privhex))
    return results

def print_hit(mnemonic, address, privhex, balance_eth):
    border = "=" * 53
    print("\n" + "+" + border + "+")
    print("| MATCH FOUND".ljust(55) + "|")
    print("+" + border + "+")
    print(f"| Mnemonic: {mnemonic}".ljust(55)[:55] + "|")
    print(f"| Address : {address}".ljust(55)[:55] + "|")
    print(f"| PrivKey : {privhex}".ljust(55)[:55] + "|")
    print(f"| Balance : {balance_eth} ETH".ljust(55)[:55] + "|")
    print("+" + border + "+\n")
    try:
        hits_fp.write(f"{mnemonic},{address},{privhex},{balance_eth}\n")
        hits_fp.flush()
    except Exception:
        logging.error("Failed to write hit to file: %s", traceback.format_exc(limit=5))

# ---------------- Async RPC ----------------
async def fetch_balance(session, address, max_retries=3):
    payload = {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [address, "latest"], "id": 1}
    attempt = 0
    backoff_base = 1.2
    global rpc_success, rpc_errors
    while attempt < max_retries:
        try:
            async with session.post(RPC_URL, json=payload, timeout=10) as resp:
                text = await resp.text()
                if resp.status != 200:
                    raise Exception(f"RPC non-200 status {resp.status}: {text[:300]}")
                data = json.loads(text)
                bal_wei = int(data.get("result", "0x0"), 16)
                with rpc_lock:
                    rpc_success += 1
                return bal_wei / 10**18
        except Exception as e:
            attempt += 1
            with rpc_lock:
                rpc_errors += 1
            logging.warning("RPC error for %s attempt %d/%d: %s", address, attempt, max_retries, e)
            await asyncio.sleep(backoff_base ** attempt)
    logging.error("Failed to fetch balance for %s after %d attempts", address, max_retries)
    return 0.0

async def check_balances(results):
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_balance(session, addr) for _, addr, _ in results]
        balances = await asyncio.gather(*tasks, return_exceptions=False)
        hits = []
        for (mnemonic, address, privhex), bal in zip(results, balances):
            try:
                if bal and bal > 0:
                    hits.append((mnemonic, address, privhex, bal))
            except Exception:
                logging.error("Error processing balance result for %s: %s", address, traceback.format_exc(limit=5))
        return hits

# ---------------- Main loop ----------------
async def main_loop():
    logging.info("START scanner: workers=%d, batch=%d, bloom_capacity=%d, bloom_err=%g",
                 WORKERS, BATCH_SIZE, BLOOM_CAPACITY, BLOOM_ERROR_RATE)

    executor = ThreadPoolExecutor(max_workers=WORKERS)
    pending = set()
    last_report = time.time()
    last_checked = 0
    try:
        TARGET_IN_FLIGHT = max(4, WORKERS * 2)
        while True:
            while len(pending) < TARGET_IN_FLIGHT:
                fut = asyncio.get_event_loop().run_in_executor(executor, process_batch, BATCH_SIZE)
                pending.add(fut)

            done, _ = await asyncio.wait(pending, timeout=REPORT_INTERVAL, return_when=asyncio.FIRST_COMPLETED)
            if done:
                for fut in list(done):
                    pending.discard(fut)
                    try:
                        results = fut.result()
                    except Exception as e:
                        logging.error("batch future error: %s\n%s", e, traceback.format_exc(limit=5))
                        continue

                    if not results:
                        continue

                    try:
                        hits = await check_balances(results)
                    except Exception as e:
                        logging.error("check_balances failed: %s\n%s", e, traceback.format_exc(limit=5))
                        hits = []

                    for mnemonic, address, privhex, bal in hits:
                        print_hit(mnemonic, address, privhex, bal)

            now = time.time()
            if now - last_report >= REPORT_INTERVAL:
                with checked_lock:
                    now_checked = checked
                interval = now - last_report
                speed = (now_checked - last_checked) / interval if interval > 0 else 0.0
                with unique_addr_lock:
                    ua = unique_addresses
                with rpc_lock:
                    rs, re = rpc_success, rpc_errors
                logging.info("[INFO] Checked: %s | Speed: %.2f valid mnemonics/sec | Unique addrs(bloom): ~%s | RPC ok: %d | RPC err: %d",
                             f"{now_checked:,}", speed, f"{ua:,}", rs, re)
                last_report = now
                last_checked = now_checked

    except KeyboardInterrupt:
        logging.info("STOP requested by user")
    finally:
        executor.shutdown(wait=False)
        hits_fp.close()

if __name__ == "__main__":
    try:
        asyncio.run(main_loop())
    except Exception as e:
        logging.error("Fatal error: %s\n%s", e, traceback.format_exc(limit=10))
