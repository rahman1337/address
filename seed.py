#!/usr/bin/env python3
import asyncio
import aiohttp
from mnemonic import Mnemonic
from eth_account import Account
from concurrent.futures import ThreadPoolExecutor
import time

# ---------------- SETTINGS ----------------
RPC_URL = "https://ethereum.publicnode.com"
MNEMONICS_PER_BATCH = 100
THREAD_WORKERS = 6  # just threads, no multiprocessing
REPORT_INTERVAL = 5  # seconds

mnemo = Mnemonic("english")

# ---------------- GLOBALS ----------------
mnemonics_checked = 0

# ---------------- FUNCTIONS ----------------
def generate_mnemonic():
    return mnemo.generate(strength=128)

def derive_address(mnemonic_phrase):
    global mnemonics_checked
    try:
        acct = Account.from_mnemonic(mnemonic_phrase)
        return acct.address, mnemonic_phrase
    finally:
        mnemonics_checked += 1

async def fetch_balance(session, address):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1
    }
    try:
        async with session.post(RPC_URL, json=payload, timeout=10) as resp:
            data = await resp.json()
            balance_wei = int(data.get("result", "0x0"), 16)
            balance_eth = balance_wei / 10**18
            return balance_eth
    except:
        return 0

async def process_batch(session, batch, executor):
    loop = asyncio.get_running_loop()
    # Derive addresses using threads
    results = await asyncio.gather(*[
        loop.run_in_executor(executor, derive_address, m) for m in batch
    ])

    # Fetch balances asynchronously
    tasks = []
    for address, mnemonic_phrase in results:
        if address:
            tasks.append(fetch_balance(session, address))
        else:
            tasks.append(asyncio.sleep(0, result=0))

    balances = await asyncio.gather(*tasks)

    # Print hits
    for (address, mnemonic_phrase), balance in zip(results, balances):
        if balance > 0:
            print(f"[HIT] {mnemonic_phrase} | {address} | {balance} ETH")

async def worker(session, executor):
    while True:
        batch = [generate_mnemonic() for _ in range(MNEMONICS_PER_BATCH)]
        await process_batch(session, batch, executor)

async def reporter():
    global mnemonics_checked
    last_count = 0
    while True:
        await asyncio.sleep(REPORT_INTERVAL)
        checked_now = mnemonics_checked
        speed = (checked_now - last_count) / REPORT_INTERVAL
        print(f"[INFO] {checked_now} mnemonics checked | Speed: {speed:.2f} mnemonics/sec")
        last_count = checked_now

async def main():
    print(f"[START] Ethereum mnemonic checker with speed report")
    executor = ThreadPoolExecutor(max_workers=THREAD_WORKERS)
    async with aiohttp.ClientSession() as session:
        workers = [worker(session, executor) for _ in range(THREAD_WORKERS)]
        workers.append(reporter())  # add reporter task
        await asyncio.gather(*workers)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[STOP] Stopped by user")
