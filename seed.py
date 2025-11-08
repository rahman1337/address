#!/usr/bin/env python3
"""
Ultra-fast ETH mnemonic generator + balance checker (threaded)
- Uses threading instead of multiprocessing
- Queries balances via ethereum.publicnode.com
- Caches checked addresses locally
- Prints non-zero balances only
- Displays speed every 5 seconds
"""

import os, time, json, threading, requests
from mnemonic import Mnemonic
from eth_account import Account

mnemo = Mnemonic("english")
BATCH = 1000
THREADS = 6
RPC_URL = "https://ethereum.publicnode.com"
CACHE_FILE = "checked_addrs.txt"

# Shared resources
counter = 0
counter_lock = threading.Lock()
cache_lock = threading.Lock()
cache = set()

# Load existing cache
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def save_cache():
    with cache_lock:
        with open(CACHE_FILE, "w") as f:
            for addr in cache:
                f.write(addr + "\n")

def get_balance(address):
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

def worker():
    global counter
    local_count = 0
    while True:
        for _ in range(BATCH):
            words = mnemo.generate(strength=128)
            acct = Account.from_mnemonic(words)
            addr = acct.address

            # Skip if already checked
            with cache_lock:
                if addr in cache:
                    continue
                cache.add(addr)

            bal = get_balance(addr)
            if bal > 0:
                eth = bal / 10**18
                print(f"\n[HIT] {addr} | {eth:.8f} ETH | {words}\n", flush=True)
                save_cache()

            local_count += 1

        with counter_lock:
            counter += local_count
        local_count = 0

def speed_display():
    global counter
    prev = 0
    while True:
        time.sleep(5)
        with counter_lock:
            curr = counter
        speed = (curr - prev) / 5.0
        print(f"[SPEED] {speed:,.0f} mnemonics/sec total")
        prev = curr

def main():
    global cache
    print(f"[START] Using {THREADS} threads | Batch {BATCH}")
    cache = load_cache()
    print(f"[CACHE] Loaded {len(cache):,} previously checked addresses")

    # Start speed monitor
    t_speed = threading.Thread(target=speed_display, daemon=True)
    t_speed.start()

    # Start worker threads
    threads = [threading.Thread(target=worker, daemon=True) for _ in range(THREADS)]
    for t in threads: t.start()
    for t in threads: t.join()

if __name__ == "__main__":
    main()
