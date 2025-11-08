#!/usr/bin/env python3
"""
fast_hd_valid_only.py

True BIP39 -> BIP32 -> Ethereum address scanner (valid-only mnemonics)
- Uses seed.txt wordlist (2048 words)
- 5 threads, 200 valid mnemonics per batch
- Checks balances for every derived address
- Dedupes addresses, prints bordered hits, saves hits.txt
"""

import os
import time
import random
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from mnemonic import Mnemonic
from bip32 import BIP32
from eth_keys import keys
import aiohttp

# ---------------- CONFIG ----------------
WORDLIST_FILE = "seed.txt"   # 2048 words
HITS_FILE = "hits.txt"
RPC_URL = "https://ethereum.publicnode.com"
WORKERS = 5
VALIDS_PER_BATCH = 200        # number of valid mnemonics per worker batch
REPORT_INTERVAL = 5
DERIVATION_PATH = "m/44'/60'/0'/0/0"
RPC_CONCURRENCY = 200
CANDIDATE_CHUNK = 1024        # how many random sequences generated per loop to find valid mnemonics
# ----------------------------------------

# sanity check
if not os.path.exists(WORDLIST_FILE):
    raise SystemExit(f"[ERROR] {WORDLIST_FILE} not found")

# load wordlist
with open(WORDLIST_FILE, "r", encoding="utf-8") as f:
    WORDLIST = [w.strip() for w in f if w.strip()]
if len(WORDLIST) < 2048:
    print(f"[WARN] Wordlist length = {len(WORDLIST)} (expected 2048)")

mnemo = Mnemonic("english")

# shared state
checked = 0
checked_lock = threading.Lock()
seen_addresses = set()
seen_lock = threading.Lock()
hits_fp = open(HITS_FILE, "a", encoding="utf-8")

# helpers
def build_random_12():
    return " ".join(random.choices(WORDLIST, k=12))

def mnemonic_to_eth_privkey_and_address(mnemonic_phrase, passphrase=""):
    seed = mnemo.to_seed(mnemonic_phrase, passphrase=passphrase)
    bip32 = BIP32.from_seed(seed)
    privkey_bytes = bip32.get_privkey_from_path(DERIVATION_PATH)
    pk = keys.PrivateKey(privkey_bytes)
    address = pk.public_key.to_checksum_address()
    return pk.to_hex(), address

def process_batch_sync_valid_only(valids_target):
    global checked
    valid_mnemonics = []

    # generate random 12-word candidates until we get enough valid mnemonics
    while len(valid_mnemonics) < valids_target:
        candidates = [" ".join(random.choices(WORDLIST, k=12)) for _ in range(CANDIDATE_CHUNK)]
        for cand in candidates:
            if mnemo.check(cand):
                valid_mnemonics.append(cand)
                if len(valid_mnemonics) >= valids_target:
                    break

    results = []
    for m in valid_mnemonics:
        try:
            privhex, address = mnemonic_to_eth_privkey_and_address(m)
        except Exception:
            continue

        addr_lower = address.lower()
        with checked_lock:
            checked += 1

        with seen_lock:
            if addr_lower in seen_addresses:
                continue
            seen_addresses.add(addr_lower)

        results.append((m, address, privhex))
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

def append_hit_file(mnemonic, address, privhex, balance_eth):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    hits_fp.write(f"{ts}\t{address}\t{balance_eth}\t{privhex}\t{mnemonic}\n")
    hits_fp.flush()

# Async RPC balance check
async def check_balances_for_results(session, results):
    sem = asyncio.Semaphore(RPC_CONCURRENCY)

    async def fetch_balance(addr):
        payload = {"jsonrpc": "2.0","method": "eth_getBalance","params":[addr,"latest"],"id":1}
        async with sem:
            try:
                async with session.post(RPC_URL, json=payload, timeout=10) as resp:
                    data = await resp.json()
                    balance_wei = int(data.get("result", "0x0"), 16)
                    return balance_wei / 10**18
            except Exception:
                return 0.0

    tasks = []
    addrs = []
    for mnemonic, address, privhex in results:
        tasks.append(fetch_balance(address))
        addrs.append((mnemonic, address, privhex))

    balances = await asyncio.gather(*tasks)
    hits = []
    for (mnemonic, address, privhex), bal in zip(addrs, balances):
        if bal and bal > 0:
            hits.append((mnemonic, address, privhex, bal))
    return hits

# Main loop
async def main_loop():
    print(f"[START] HD scanner (valid-only mnemonics) + RPC checks")
    print(f"Workers: {WORKERS}, Valid mnemonics per batch: {VALIDS_PER_BATCH}, RPC concurrency: {RPC_CONCURRENCY}")
    print(f"Loaded wordlist: {len(WORDLIST)} words\n")

    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=WORKERS)
    async with aiohttp.ClientSession() as session:
        last_report_time = time.time()
        last_checked = 0
        pending_futures = set()

        try:
            TARGET_IN_FLIGHT = max(4, WORKERS*2)

            while True:
                while len(pending_futures) < TARGET_IN_FLIGHT:
                    fut = loop.run_in_executor(executor, process_batch_sync_valid_only, VALIDS_PER_BATCH)
                    pending_futures.add(fut)

                done, _ = await asyncio.wait(pending_futures, timeout=REPORT_INTERVAL, return_when=asyncio.FIRST_COMPLETED)
                if done:
                    for fut in list(done):
                        pending_futures.discard(fut)
                        try:
                            results = fut.result()
                        except Exception:
                            continue

                        if not results:
                            continue

                        hits = await check_balances_for_results(session, results)
                        for mnemonic, address, privhex, bal in hits:
                            print_hit(mnemonic, address, privhex, bal)
                            append_hit_file(mnemonic, address, privhex, bal)

                now = time.time()
                if now - last_report_time >= REPORT_INTERVAL:
                    with checked_lock:
                        now_checked = checked
                    interval = now - last_report_time
                    speed = (now_checked - last_checked) / interval if interval > 0 else 0.0
                    print(f"[INFO] Checked: {now_checked:,} | Speed: {speed:.2f} valid mnemonics/sec | Unique: {len(seen_addresses):,}")
                    last_report_time = now
                    last_checked = now_checked

        except KeyboardInterrupt:
            print("\n[STOP] interrupted by user")
        finally:
            executor.shutdown(wait=False)
            hits_fp.close()

if __name__ == "__main__":
    asyncio.run(main_loop())
