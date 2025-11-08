#!/usr/bin/env python3
import os, time, threading, queue, requests
from mnemonic import Mnemonic
from eth_account import Account

# Enable mnemonic/HD wallet features
Account.enable_unaudited_hdwallet_features()

# Configuration
BATCH = 1000             # number of mnemonics per generation batch
THREADS = 6              # number of balance worker threads
RPC_URL = "https://ethereum.publicnode.com"
CACHE_FILE = "checked_addrs.txt"
CACHE_SAVE_INTERVAL = 30 # seconds
BALANCE_BATCH_SIZE = 20  # number of addresses per JSON-RPC batch

mnemo = Mnemonic("english")
addr_queue = queue.Queue()
cache_lock = threading.Lock()
counter_lock = threading.Lock()
cache = set()
counter = 0
last_cache_save = time.time()

# Load cache
def load_cache():
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            return set(line.strip() for line in f if line.strip())
    return set()

def save_cache():
    global last_cache_save
    with cache_lock:
        with open(CACHE_FILE, "w") as f:
            for addr in cache:
                f.write(addr + "\n")
    last_cache_save = time.time()

def get_balances_batch(batch_addrs):
    """Send one JSON-RPC request with multiple eth_getBalance calls"""
    payload = [
        {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [addr, "latest"], "id": i}
        for i, addr in enumerate(batch_addrs)
    ]
    try:
        r = requests.post(RPC_URL, json=payload, timeout=10)
        results = r.json()
        balances = {}
        for res in results:
            i = res.get("id")
            bal = int(res.get("result", "0x0"), 16)
            balances[batch_addrs[i]] = bal
        return balances
    except:
        return {addr:0 for addr in batch_addrs}

def balance_worker():
    global counter
    batch = []
    while True:
        try:
            # Collect addresses up to BALANCE_BATCH_SIZE
            while len(batch) < BALANCE_BATCH_SIZE:
                batch.append(addr_queue.get(timeout=1))
        except queue.Empty:
            if not batch:
                continue
        words_addrs = batch
        batch_addrs = [addr for words, addr in words_addrs]
        balances = get_balances_batch(batch_addrs)
        for (words, addr) in words_addrs:
            bal = balances.get(addr, 0)
            if bal > 0:
                eth = bal / 10**18
                print(f"\n[HIT] {addr} | {eth:.8f} ETH | {words}\n", flush=True)
            with counter_lock:
                counter += 1
        for _ in words_addrs:
            addr_queue.task_done()
        batch.clear()

def speed_display():
    global counter
    prev = 0
    while True:
        time.sleep(5)
        with counter_lock:
            curr = counter
        speed = (curr - prev) / 5.0
        print(f"[SPEED] {speed:,.0f} addresses/sec | Queue={addr_queue.qsize()}", flush=True)
        prev = curr

def cache_saver():
    while True:
        time.sleep(5)
        if time.time() - last_cache_save > CACHE_SAVE_INTERVAL:
            save_cache()
            print(f"[CACHE] Saved {len(cache):,} addresses", flush=True)

def main():
    global cache
    cache = load_cache()
    print(f"[START] Loaded {len(cache):,} cached addresses")

    # Start balance worker threads
    for _ in range(THREADS):
        t = threading.Thread(target=balance_worker, daemon=True)
        t.start()

    # Start speed monitor
    threading.Thread(target=speed_display, daemon=True).start()

    # Start cache saver
    threading.Thread(target=cache_saver, daemon=True).start()

    # Main mnemonic generation loop
    while True:
        for _ in range(BATCH):
            words = mnemo.generate(strength=128)
            acct = Account.from_mnemonic(words)
            addr = acct.address
            with cache_lock:
                if addr in cache:
                    continue
                cache.add(addr)
            addr_queue.put((words, addr))

if __name__ == "__main__":
    main()
