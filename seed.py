#!/usr/bin/env python3
import asyncio
import aiohttp
import os
import time
from mnemonic import Mnemonic
from eth_account import Account
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor

# ---------------- SETTINGS ----------------
RPC_URL = "https://ethereum.publicnode.com"
MNEMONICS_PER_BATCH = 100
PROCESS_WORKERS = os.cpu_count() or 4
THREAD_WORKERS = 6  # Number of concurrent batches

mnemo = Mnemonic("english")

# ---------------- FUNCTIONS ----------------
def generate_mnemonic():
    return mnemo.generate(strength=128)

def derive_address(mnemonic_phrase):
    try:
        acct = Account.from_mnemonic(mnemonic_phrase)
        return acct.address, mnemonic_phrase
    except:
        return None, mnemonic_phrase

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

async def process_batch(session, mnemonics, process_pool):
    loop = asyncio.get_running_loop()
    # Derive addresses in parallel
    results = await asyncio.gather(*[
        loop.run_in_executor(process_pool, derive_address, m) for m in mnemonics
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

async def worker(session, process_pool):
    while True:
        batch = [generate_mnemonic() for _ in range(MNEMONICS_PER_BATCH)]
        await process_batch(session, batch, process_pool)

async def main():
    print(f"[START] Ultimate Ethereum mnemonic checker")
    print(f"Processes: {PROCESS_WORKERS}, Threads: {THREAD_WORKERS}, Batch size: {MNEMONICS_PER_BATCH}")
    process_pool = ProcessPoolExecutor(max_workers=PROCESS_WORKERS)
    async with aiohttp.ClientSession() as session:
        workers = [worker(session, process_pool) for _ in range(THREAD_WORKERS)]
        await asyncio.gather(*workers)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[STOP] User interrupted")
