#!/usr/bin/env python3
"""
Ultra-fast ETH mnemonic generator + balance checker (with caching)
- Uses coincurve via eth_account
- Multiprocessing across 6 CPU cores
- Queries balances via ethereum.publicnode.com
- Caches checked addresses locally to skip repeats
- Prints non-zero balances only
- Displays speed every 5 seconds
"""

import os, time, json, multiprocessing, requests
from mnemonic import Mnemonic
from eth_account import Account

mnemo = Mnemonic("english")
BATCH = 1000
CORES = 6
RPC_URL = "https://ethereum.publicnode.com"
CACHE_FILE = "checked_addrs.txt"

# Load existing cache (if any)
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def save_cache(cache):
    with open(CACHE_FILE, "w") as f:
        for addr in cache:
            f.write(addr + "\n")

def get_balance(address):
    """Query ETH balance via JSON-RPC."""
    try:
        payload = {
            "jsonrpc": "2.0",
            "method": "eth_getBalance",
            "params": [address, "latest"],
            "id": 1
        }
        r = requests.post(RPC_URL, json=payload, timeout=5)
        data = r.json()
        bal = int(data.get("result", "0x0"), 16)
        return bal
    except Exception:
        return 0

def worker(counter, cache, lock):
    local_count = 0
    while True:
        for _ in range(BATCH):
            words = mnemo.generate(strength=128)
            acct = Account.from_mnemonic(words)
            addr = acct.address

            with lock:
                if addr in cache:
                    continue
                cache.add(addr)

            bal = get_balance(addr)
            if bal > 0:
                eth = bal / 10**18
                print(f"\n[HIT] {addr} | {eth:.8f} ETH | {words}\n", flush=True)
                # Save immediately on hit
                with lock:
                    save_cache(cache)

            local_count += 1

        with counter.get_lock():
            counter.value += local_count
        local_count = 0

def speed_display(counter):
    prev = 0
    while True:
        time.sleep(5)
        with counter.get_lock():
            curr = counter.value
        speed = (curr - prev) / 5.0
        print(f"[SPEED] {speed:,.0f} mnemonics/sec total")
        prev = curr

def main():
    print(f"[START] Using {CORES} CPU cores | Batch {BATCH}")
    manager = multiprocessing.Manager()
    cache = manager.dict()  # shared cache between workers
    lock = multiprocessing.Lock()

    # Preload existing checked addresses
    initial = load_cache()
    for a in initial:
        cache[a] = True
    print(f"[CACHE] Loaded {len(initial):,} previously checked addresses")

    counter = multiprocessing.Value("Q", 0)

    # Speed monitor
    m = multiprocessing.Process(target=speed_display, args=(counter,), daemon=True)
    m.start()

    # Workers
    workers = [
        multiprocessing.Process(target=worker, args=(counter, cache, lock))
        for _ in range(CORES)
    ]
    for w in workers: w.start()
    for w in workers: w.join()

if __name__ == "__main__":
    main()
