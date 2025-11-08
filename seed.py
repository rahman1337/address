#!/usr/bin/env python3
"""
seed.py

Clean terminal prints:
- For each checked address prints exactly 2 lines:
  1) <address> | ETH:<eth_balance> | BSC:<bsc_balance>
  2) RPC : eth <status> | bsc <status>

- On hit (either balance > 0) prints bordered hit block and writes CSV line to hits.txt.

Long-run friendly:
- mnemo.generate(128) valid mnemonics
- Bloom filters for dedupe
- ThreadPoolExecutor for derivation
- aiohttp balance checks (no semaphores), retries with backoff
- Error logging to errors.log
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
RPCS = {
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc.publicnode.com"
}
HITS_FILE = "hits.txt"
ERROR_LOG = "errors.log"
RPC_MAX_RETRIES = 3
BLOOM_CAPACITY = 30_000_000
BLOOM_ERROR_RATE = 1e-5
# ------------------------------

# Logging to file + console (no periodic info logs anymore)
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

rpc_stats = {
    "eth": {"ok": 0, "err": 0},
    "bsc": {"ok": 0, "err": 0}
}
rpc_lock = threading.Lock()

unique_addresses = 0
unique_addr_lock = threading.Lock()

# File handle for hits (append)
hits_fp = open(HITS_FILE, "a", encoding="utf-8")

# ---------------- Bloom Filter (dependency-free) ----------------
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
    """Generate a valid mnemonic not yet seen (checked via bloom)."""
    while True:
        m = mnemo.generate(128)  # valid 12-words
        h = sha256_bytes(m)
        if h in mnemonic_bloom:
            continue
        mnemonic_bloom.add(h)
        return m

def mnemonic_to_eth_privkey_and_address(mnemonic_phrase):
    """True BIP39 -> seed -> BIP32 -> private key -> checksum address"""
    seed = mnemo.to_seed(mnemonic_phrase)
    bip32 = BIP32.from_seed(seed)
    privkey_bytes = bip32.get_privkey_from_path(DERIVATION_PATH)
    pk = keys.PrivateKey(privkey_bytes)
    address = pk.public_key.to_checksum_address()
    return pk.to_hex(), address

def process_batch(batch_size):
    """CPU-bound: generate batch_size unique valid mnemonics and derive addresses."""
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

def print_hit(mnemonic, address, privhex, eth_balance, bsc_balance):
    """Bordered print for hits and write to hits file line-by-line (CSV-style)."""
    border = "=" * 53
    print("\n" + "+" + border + "+")
    print("| MATCH FOUND".ljust(55) + "|")
    print("+" + border + "+")
    print(f"| Mnemonic: {mnemonic}".ljust(55)[:55] + "|")
    print(f"| Address : {address}".ljust(55)[:55] + "|")
    print(f"| PrivKey : {privhex}".ljust(55)[:55] + "|")
    print(f"| ETH Bal : {eth_balance} ETH".ljust(55)[:55] + "|")
    print(f"| BSC Bal : {bsc_balance} BNB".ljust(55)[:55] + "|")
    print("+" + border + "+\n")
    try:
        hits_fp.write(f"{mnemonic},{address},{privhex},{eth_balance},{bsc_balance}\n")
        hits_fp.flush()
    except Exception:
        logging.error("Failed to write hit to file: %s", traceback.format_exc(limit=5))

# ---------------- Async RPC (per-chain, returns balance + status_str) ----------------
async def fetch_balance_for_chain(session, address, chain, max_retries=RPC_MAX_RETRIES):
    """Fetch balance for a single chain and return (balance, status_str)."""
    rpc_url = RPCS[chain]
    payload = {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [address, "latest"], "id": 1}
    attempt = 0
    backoff_base = 1.2
    last_status = "NOT_ATTEMPTED"
    while attempt < max_retries:
        try:
            async with session.post(rpc_url, json=payload, timeout=10) as resp:
                text = await resp.text()
                status_code = resp.status
                if resp.status != 200:
                    last_status = f"ERROR ({status_code})"
                    raise Exception(f"RPC status {resp.status}: {text[:300]}")
                data = json.loads(text)
                if "result" not in data:
                    last_status = "ERROR (no result)"
                    raise Exception(f"Missing result field: {data}")
                bal_wei = int(data.get("result", "0x0"), 16)
                bal = bal_wei / 10**18
                with rpc_lock:
                    rpc_stats[chain]["ok"] += 1
                last_status = f"200 OK"
                return bal, last_status
        except Exception as e:
            attempt += 1
            with rpc_lock:
                rpc_stats[chain]["err"] += 1
            last_status = f"ERROR (attempt {attempt}/{max_retries})"
            # print an RPC error status line so user sees the retry
            print(f"RPC : {chain} {last_status}")
            logging.warning("RPC error for %s %s attempt %d/%d: %s", chain, address, attempt, max_retries, e)
            await asyncio.sleep(backoff_base ** attempt)
    last_status = f"FAIL ({max_retries})"
    print(f"RPC : {chain} {last_status}")
    logging.error("Failed to fetch balance for %s %s after %d attempts", chain, address, max_retries)
    return 0.0, last_status

async def check_balances(results):
    """
    For each derived result (mnemonic, address, privhex), fetch ETH and BSC balances concurrently.
    Returns list of hits where either chain has a non-zero balance.
    Also prints exactly two lines per address:
      1) <address> | ETH:<eth_balance> | BSC:<bsc_balance>
      2) RPC : eth <status> | bsc <status>
    """
    async with aiohttp.ClientSession() as session:
        tasks = []
        mapping = []  # (result_idx, chain)
        for idx, (_, addr, _) in enumerate(results):
            for chain in ("eth", "bsc"):
                tasks.append(fetch_balance_for_chain(session, addr, chain))
                mapping.append((idx, chain))

        # gather all balances (+ status strings)
        pairs = await asyncio.gather(*tasks, return_exceptions=False)
        # build per-index dict of balances and statuses
        per_index = [ {"eth": 0.0, "bsc": 0.0}, {"eth_status": "", "bsc_status": ""} ]  # placeholder (we'll rebuild properly)
        per_index = [ {"eth": 0.0, "bsc": 0.0, "eth_status": "", "bsc_status": ""} for _ in results ]

        for (idx, chain), (bal, status) in zip(mapping, pairs):
            per_index[idx][chain] = bal
            per_index[idx][f"{chain}_status"] = status

        hits = []
        for (mnemonic, address, privhex), info in zip(results, per_index):
            eth_bal = info["eth"]
            bsc_bal = info["bsc"]
            # First line: address + balances (fixed format)
            print(f"{address} | ETH:{eth_bal:.18f} | BSC:{bsc_bal:.18f}")
            # Second line: RPC status summary
            eth_status = info.get("eth_status", "N/A")
            bsc_status = info.get("bsc_status", "N/A")
            print(f"RPC : eth {eth_status} | bsc {bsc_status}")

            if (eth_bal and eth_bal > 0) or (bsc_bal and bsc_bal > 0):
                hits.append((mnemonic, address, privhex, eth_bal, bsc_bal))
        return hits

# ---------------- Main loop (no periodic reports) ----------------
async def main_loop():
    logging.info("START scanner (clean prints) workers=%d, batch=%d", WORKERS, BATCH_SIZE)

    executor = ThreadPoolExecutor(max_workers=WORKERS)
    pending = set()
    try:
        TARGET_IN_FLIGHT = max(4, WORKERS * 2)
        while True:
            while len(pending) < TARGET_IN_FLIGHT:
                fut = asyncio.get_event_loop().run_in_executor(executor, process_batch, BATCH_SIZE)
                pending.add(fut)

            done, _ = await asyncio.wait(pending, timeout=None, return_when=asyncio.FIRST_COMPLETED)
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

                for mnemonic, address, privhex, eth_bal, bsc_bal in hits:
                    print_hit(mnemonic, address, privhex, eth_bal, bsc_bal)

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
