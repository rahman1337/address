#!/usr/bin/env python3
import os
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from mnemonic import Mnemonic
from eth_account import Account

# Enable HD wallet mnemonic support
Account.enable_unaudited_hdwallet_features()

# ===== CONFIG =====
THREADS = 6
BATCH_SIZE = 100
REPORT_INTERVAL = 10
TARGET_FILE = "eth.txt"
# ==================

mnemo = Mnemonic("english")
checked = 0

# Load target addresses
if not os.path.exists(TARGET_FILE):
    print(f"[ERROR] {TARGET_FILE} not found!")
    exit(1)
with open(TARGET_FILE, "r") as f:
    TARGETS = set(line.strip().lower() for line in f if line.strip().startswith("0x"))
print(f"[LOAD] {len(TARGETS):,} target addresses loaded from {TARGET_FILE}")

seen_addresses = set()

def generate_mnemonic():
    return mnemo.generate(strength=128)

def derive_address(mnemonic_phrase):
    acct = Account.from_mnemonic(mnemonic_phrase)
    return acct.address.lower(), mnemonic_phrase

def process_batch(batch):
    global checked
    results = []
    for phrase in batch:
        address, phrase = derive_address(phrase)
        checked += 1
        if address not in seen_addresses:
            seen_addresses.add(address)
            if address in TARGETS:
                results.append((phrase, address))
    return results

def print_hit(phrase, address):
    border = "=" * 53
    print("\n" + "+" + border + "+")
    print("| MATCH FOUND".ljust(55) + "|")
    print("+" + border + "+")
    print(f"| Mnemonic: {phrase}".ljust(55)[:55] + "|")
    print(f"| Address : {address}".ljust(55)[:55] + "|")
    print("+" + border + "+\n")

async def worker(executor):
    loop = asyncio.get_running_loop()
    while True:
        batch = [generate_mnemonic() for _ in range(BATCH_SIZE)]
        hits = await loop.run_in_executor(executor, process_batch, batch)
        for phrase, address in hits:
            print_hit(phrase, address)

async def reporter():
    global checked
    last = 0
    while True:
        await asyncio.sleep(REPORT_INTERVAL)
        now = checked
        speed = (now - last) / REPORT_INTERVAL
        print(f"[INFO] Checked: {now:,} | Speed: {speed:.2f} mnemonics/sec | Unique: {len(seen_addresses):,}")
        last = now

async def main():
    print(f"[START] Offline Ethereum mnemonic checker")
    print(f"Threads: {THREADS}, Batch size: {BATCH_SIZE}\n")
    executor = ThreadPoolExecutor(max_workers=THREADS)
    await asyncio.gather(
        *[worker(executor) for _ in range(THREADS)],
        reporter()
    )

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[STOP] Stopped by user")
