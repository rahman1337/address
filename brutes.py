#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import argparse
import requests
import threading
from mnemonic import Mnemonic
import bip32utils
import base58
import bech32

# =============================
# Config
# =============================
WORDLIST_FILE = "seed.txt"
THREAD_COUNT = 3
DERIVE_COUNT = 20
SLEEP_BETWEEN_CHECKS = 0.5
RECEIVED_API = "https://blockchain.info/q/getreceivedbyaddress/"
BALANCE_API = "https://blockchain.info/q/addressbalance/"
FOUND_FILE = "found.txt"
HARDEN = 0x80000000
# =============================

# CLI args
ap = argparse.ArgumentParser(description="BTC Mnemonic Scanner (strict BIP paths, 404=None, found.txt logging)")
ap.add_argument("-d", "--debug", action="store_true", help="debug mode (verbose output)")
ap.add_argument("-t", "--threads", type=int, default=THREAD_COUNT, help="number of worker threads")
args = ap.parse_args()
DEBUG = args.debug

# Load wordlist
if not os.path.exists(WORDLIST_FILE):
    sys.exit(f"Missing wordlist file: {WORDLIST_FILE}")

with open(WORDLIST_FILE, "r", encoding="utf-8") as f:
    wl = [w.strip() for w in f.readlines() if w.strip()]

if len(wl) != 2048:
    print(f"[Warning] {WORDLIST_FILE} has {len(wl)} words, expected 2048", flush=True)

mnemo = Mnemonic("english")
mnemo.wordlist = wl

# Lock for found.txt
write_lock = threading.Lock()

# =============================
# Helpers
# =============================
def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

def derive_addresses(seed_bytes, index):
    """Return legacy (1...), nested (3...), bech32 (bc1q...) addresses."""
    root = bip32utils.BIP32Key.fromEntropy(seed_bytes)

    # m/44'/0'/0'/0/i
    k44 = root.ChildKey(44 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(index)
    addr44 = k44.Address()

    # m/49'/0'/0'/0/i
    k49 = root.ChildKey(49 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(index)
    pub49 = k49.PublicKey()
    h160_49 = hash160(pub49)
    redeem = b'\x00\x14' + h160_49
    redeem_h160 = hash160(redeem)
    addr49 = base58.b58encode_check(b'\x05' + redeem_h160).decode()

    # m/84'/0'/0'/0/i
    k84 = root.ChildKey(84 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(index)
    pub84 = k84.PublicKey()
    h160_84 = hash160(pub84)
    conv = bech32.convertbits(h160_84, 8, 5)
    addr84 = bech32.bech32_encode("bc", [0] + conv)

    return [addr44, addr49, addr84]

def check_received(session, addr: str):
    url = RECEIVED_API + addr
    try:
        r = session.get(url, timeout=12)
    except requests.RequestException as e:
        if DEBUG: print(f"[DEBUG] network error for {addr}: {e}", flush=True)
        return None

    if DEBUG:
        body = (r.text or "").strip()[:150]
        print(f"[DEBUG] GET {url} -> {r.status_code} | {body}", flush=True)

    if r.status_code == 404:
        return None  # treat as not used
    try:
        r.raise_for_status()
        return int(r.text.strip())
    except Exception:
        return None

def check_balance(session, addr: str):
    url = BALANCE_API + addr
    try:
        r = session.get(url, timeout=12)
    except requests.RequestException:
        return None
    if DEBUG:
        body = (r.text or "").strip()[:150]
        print(f"[DEBUG] GET {url} -> {r.status_code} | {body}", flush=True)
    if r.status_code != 200:
        return None
    try:
        return int(r.text.strip())
    except Exception:
        return None

def save_found(mnemonic, addr, received, balance):
    """Thread-safe append to found.txt"""
    with write_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(f"{mnemonic}\n{addr}\n{received}\n{balance}\n\n")
    print(mnemonic, flush=True)
    print(addr, flush=True)
    print(received, flush=True)
    print(balance, flush=True)

# =============================
# Worker
# =============================
def worker(tid: int, stop_event: threading.Event):
    session = requests.Session()
    while not stop_event.is_set():
        try:
            mnemonic = mnemo.generate(strength=128)
            seed_bytes = mnemo.to_seed(mnemonic)

            for i in range(DERIVE_COUNT):
                addrs = derive_addresses(seed_bytes, i)
                for addr in addrs:
                    received = check_received(session, addr)
                    time.sleep(SLEEP_BETWEEN_CHECKS)
                    if received is None or received <= 0:
                        continue
                    balance = check_balance(session, addr)
                    time.sleep(SLEEP_BETWEEN_CHECKS)
                    save_found(mnemonic, addr, received, balance if balance is not None else 0)

        except KeyboardInterrupt:
            stop_event.set()
        except Exception as e:
            print(f"[Error][Thread-{tid}] {e}", flush=True)
            time.sleep(1)

# =============================
# Main
# =============================
def main():
    stop_event = threading.Event()
    threads = []
    for i in range(args.threads):
        t = threading.Thread(target=worker, args=(i + 1, stop_event), daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Stopping...", flush=True)
        stop_event.set()
        for t in threads:
            t.join(timeout=2)
        sys.exit(0)

if __name__ == "__main__":
    main()