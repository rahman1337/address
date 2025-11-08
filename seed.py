#!/usr/bin/env python3
"""
fast_hd.py

High-throughput true BIP39 -> BIP32 -> Ethereum address scanner (threaded).
Designed to match the approach used in the Node repo: many concurrent
C-backed PBKDF2 calls + minimal Python overhead.

- Uses WORDLIST from seed.txt (2048 words) to build random 12-word mnemonics.
- Uses mnemonic.to_seed() (C pbkdf2_hmac) for BIP39.
- Derives m/44'/60'/0'/0/0 via BIP32.
- ThreadPoolExecutor workers to run PBKDF2 in parallel.
- Reports speed (mnemonics/sec) periodically.
- Saves hits to hits.txt
"""

import os
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from mnemonic import Mnemonic
from bip32 import BIP32
from eth_keys import keys
from eth_utils import to_checksum_address

# -------- CONFIG --------
WORDLIST_FILE = "seed.txt"   # your 2048 BIP39 words file (one per line)
TARGET_FILE = "eth.txt"      # target addresses (0x... one per line)
HITS_FILE = "hits.txt"
WORKERS = 12                 # concurrent thread workers (try 6, 12, 16)
BATCH_SIZE = 300             # mnemonics per worker task (tune up/down)
REPORT_INTERVAL = 5          # seconds
DERIVATION_PATH = "m/44'/60'/0'/0/0"
# ------------------------

# sanity checks
if not os.path.exists(WORDLIST_FILE):
    raise SystemExit(f"[ERROR] {WORDLIST_FILE} not found")
if not os.path.exists(TARGET_FILE):
    raise SystemExit(f"[ERROR] {TARGET_FILE} not found")

# load wordlist (2048 words)
with open(WORDLIST_FILE, "r", encoding="utf-8") as f:
    WORDLIST = [w.strip() for w in f if w.strip()]
if len(WORDLIST) < 2048:
    print(f"[WARN] Wordlist length = {len(WORDLIST)} (expected 2048)")

# load targets
with open(TARGET_FILE, "r", encoding="utf-8") as f:
    TARGETS = set(line.strip().lower() for line in f if line.strip().startswith("0x"))

mnemo = Mnemonic("english")

# shared globals
checked = 0
checked_lock = threading.Lock()
seen_addresses = set()
seen_lock = threading.Lock()
hits_fp = open(HITS_FILE, "a", encoding="utf-8")


def build_random_mnemonic_from_wordlist():
    # draw 12 words uniformly at random from the 2048 list
    # (use random.choice/choices)
    return " ".join(random.choices(WORDLIST, k=12))


def mnemonic_to_eth_privkey_and_address(mnemonic_phrase, passphrase=""):
    # PBKDF2 -> seed (C-backed). This is the heavy part.
    seed = mnemo.to_seed(mnemonic_phrase, passphrase=passphrase)  # bytes

    # BIP32 derive
    bip32 = BIP32.from_seed(seed)
    privkey_bytes = bip32.get_privkey_from_path(DERIVATION_PATH)
    pk = keys.PrivateKey(privkey_bytes)
    address = pk.public_key.to_checksum_address()
    return pk.to_hex(), address


def process_task(batch_size):
    """Generate batch_size mnemonics, derive, check, return hits list."""
    global checked
    hits_local = []
    for _ in range(batch_size):
        m = build_random_mnemonic_from_wordlist()
        try:
            privhex, address = mnemonic_to_eth_privkey_and_address(m)
        except Exception:
            # skip on any rare error
            continue

        addr_lower = address.lower()
        # increment checked
        with checked_lock:
            checked += 1

        # dedupe and check targets
        with seen_lock:
            if addr_lower in seen_addresses:
                continue
            seen_addresses.add(addr_lower)

        if addr_lower in TARGETS:
            hits_local.append((m, address, privhex))
    return hits_local


def print_hit(mnemonic, address, privhex):
    border = "=" * 53
    print("\n" + "+" + border + "+")
    print("| MATCH FOUND".ljust(55) + "|")
    print("+" + border + "+")
    print(f"| Mnemonic: {mnemonic}".ljust(55)[:55] + "|")
    print(f"| Address : {address}".ljust(55)[:55] + "|")
    print(f"| PrivKey : {privhex}".ljust(55)[:55] + "|")
    print("+" + border + "+\n")


def append_hit_file(mnemonic, address, privhex):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    hits_fp.write(f"{ts}\t{address}\t{privhex}\t{mnemonic}\n")
    hits_fp.flush()


def main_loop():
    global checked
    print(f"[START] True HD scanner — workers={WORKERS}, batch={BATCH_SIZE}")
    print(f"[LOAD] Wordlist {len(WORDLIST)} words, Targets {len(TARGETS):,}")

    executor = ThreadPoolExecutor(max_workers=WORKERS)
    in_flight = set()
    # target in-flight to keep cpu busy (workers * 2 is a good start)
    TARGET_IN_FLIGHT = max(4, WORKERS * 2)

    last_report_time = time.time()
    last_checked = 0

    try:
        while True:
            # spawn tasks until in-flight threshold
            while len(in_flight) < TARGET_IN_FLIGHT:
                fut = executor.submit(process_task, BATCH_SIZE)
                in_flight.add(fut)

            # collect finished futures (non-blocking) and process
            done = {f for f in in_flight if f.done()}
            for f in done:
                in_flight.remove(f)
                try:
                    hits = f.result()
                except Exception:
                    continue
                for mnemonic, address, privhex in hits:
                    print_hit(mnemonic, address, privhex)
                    append_hit_file(mnemonic, address, privhex)

            # periodic report
            now = time.time()
            if now - last_report_time >= REPORT_INTERVAL:
                with checked_lock:
                    now_checked = checked
                interval = now - last_report_time
                speed = (now_checked - last_checked) / interval if interval > 0 else 0.0
                print(f"[INFO] Checked: {now_checked:,} | Speed: {speed:.2f} mnemonics/sec | Unique: {len(seen_addresses):,}")
                last_report_time = now
                last_checked = now_checked

    except KeyboardInterrupt:
        print("\n[STOP] interrupted by user")
    finally:
        hits_fp.close()
        executor.shutdown(wait=False)


if __name__ == "__main__":
    main_loop()
