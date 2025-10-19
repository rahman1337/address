#!/usr/bin/env python3
"""
seed2match.py - Offline BIP39 mnemonic -> BTC (all types) + ETH scanner.
Usage:
    python3 seed2match.py        # normal mode (prints only matches)
    python3 seed2match.py --debug  # prints every mnemonic + derived addresses
"""
import os
import sys
import time
import argparse
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from mnemonic import Mnemonic
import bip32utils
import ecdsa
import sha3
import base58
import bech32

# --- Config ---
BIP39_WORDLIST_PATH = "seed.txt"
BTC_FILES = ["btc1.txt", "btc2.txt", "btc3.txt"]
ETH_FILE = "Eth.txt"
FOUND_FILE = "found.txt"
THREADS = 4
HARDEN = 0x80000000

# queue control
MAX_QUEUE_MULTIPLIER = 2
queue_sem = threading.Semaphore(THREADS * MAX_QUEUE_MULTIPLIER)
append_lock = threading.Lock()  # ensure thread-safe writes to found.txt

# --- Helpers ---
def load_targets(btc_files, eth_file):
    btc_targets = set()
    eth_targets = set()
    for p in btc_files:
        if not os.path.exists(p):
            continue
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                a = ln.strip()
                if not a or a.startswith("#"):
                    continue
                btc_targets.add(a.lower())
    if os.path.exists(eth_file):
        with open(eth_file, "r", encoding="utf-8", errors="ignore") as f:
            for ln in f:
                a = ln.strip()
                if not a or a.startswith("#"):
                    continue
                eth_targets.add(a.lower())
    return btc_targets, eth_targets

def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def derive_btc_addresses(seed_bytes):
    root = bip32utils.BIP32Key.fromEntropy(seed_bytes)

    # m/44'/0'/0'/0/0  (legacy P2PKH)
    k44 = root.ChildKey(44 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    legacy = k44.Address()

    # m/49'/0'/0'/0/0  (P2SH-P2WPKH)
    k49 = root.ChildKey(49 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    pub49 = k49.PublicKey()
    h160_49 = hashlib.new("ripemd160", hashlib.sha256(pub49).digest()).digest()
    redeem_script = b'\x00\x14' + h160_49
    redeem_hash = hashlib.new("ripemd160", hashlib.sha256(redeem_script).digest()).digest()
    p2sh = base58.b58encode_check(b'\x05' + redeem_hash).decode()

    # m/84'/0'/0'/0/0  (native segwit P2WPKH Bech32)
    k84 = root.ChildKey(84 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    pub84 = k84.PublicKey()
    h160_84 = hashlib.new("ripemd160", hashlib.sha256(pub84).digest()).digest()
    conv = bech32.convertbits(h160_84, 8, 5)
    bech32_addr = bech32.bech32_encode("bc", [0] + conv)

    return [legacy.lower(), p2sh.lower(), bech32_addr.lower()]

def derive_eth_address(seed_bytes):
    root = bip32utils.BIP32Key.fromEntropy(seed_bytes)
    k = root.ChildKey(44 + HARDEN).ChildKey(60 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    priv = k.PrivateKey()
    sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    uncompressed = b'\x04' + vk.to_string()
    keccak = sha3.keccak_256()
    keccak.update(uncompressed[1:])
    addr = "0x" + keccak.hexdigest()[-40:]
    return addr.lower()

def append_found(mnemonic, matches):
    with append_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(f"Words: {mnemonic}\n")
            for t, addr in matches:
                f.write(f"{t}: {addr}\n")
            f.write("\n")

# --- Worker (releases semaphore in finally) ---
def check_mnemonic(mnemonic, btc_targets, eth_targets, eth_targets_no0x, debug=False):
    try:
        seed_bytes = mnemo.to_seed(mnemonic)
        btc_addrs = derive_btc_addresses(seed_bytes)
        eth_addr = derive_eth_address(seed_bytes)

        if debug:
            print(f"[DEBUG] Words: {mnemonic}")
            print(f"[DEBUG] BTC: {btc_addrs}")
            print(f"[DEBUG] ETH: {eth_addr}")

        matches = []
        for a in btc_addrs:
            if a in btc_targets:
                matches.append(("BTC", a))
        # check ETH by both forms (with 0x lowercased and without 0x)
        if eth_addr in eth_targets or eth_addr.replace("0x", "") in eth_targets_no0x:
            matches.append(("ETH", eth_addr))

        if matches:
            print("\n=== MATCH FOUND ===")
            print(f"Words: {mnemonic}")
            for t, a in matches:
                print(f"{t}: {a}")
            print("===================\n")
            append_found(mnemonic, matches)
    finally:
        # ensure semaphore is always released
        queue_sem.release()

# wrapper to submit worker safely (acquire semaphore before submit)
def submit_worker(executor, mnemonic, btc_targets, eth_targets, eth_targets_no0x, debug):
    queue_sem.acquire()
    executor.submit(check_mnemonic, mnemonic, btc_targets, eth_targets, eth_targets_no0x, debug)

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Offline BIP39 BTC/ETH scanner")
    parser.add_argument("--debug", action="store_true", help="Enable debug prints for every mnemonic and addresses")
    args = parser.parse_args()

    if not os.path.exists(BIP39_WORDLIST_PATH):
        sys.exit(f"Missing BIP39 wordlist file: {BIP39_WORDLIST_PATH}")

    with open(BIP39_WORDLIST_PATH, "r", encoding="utf-8") as f:
        wl = [w.strip() for w in f.readlines() if w.strip()]

    global mnemo
    mnemo = Mnemonic("english")
    if len(wl) == 2048:
        mnemo.wordlist = wl
    else:
        print(f"[WARN] wordlist length = {len(wl)} (expected 2048). Using Mnemonic default list if different.")

    btc_targets, eth_targets = load_targets(BTC_FILES, ETH_FILE)
    if not btc_targets and not eth_targets:
        sys.exit("No target addresses loaded (check btc1.txt, btc2.txt, btc3.txt, Eth.txt)")

    # precompute eth targets without 0x for faster checks
    eth_targets_no0x = {x.replace("0x", "") for x in eth_targets}

    print(f"Loaded {len(btc_targets)} BTC targets and {len(eth_targets)} ETH targets. Starting (threads={THREADS})...")

    try:
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            while True:
                mnemonic = mnemo.generate(strength=128)  # 12 words
                submit_worker(ex, mnemonic, btc_targets, eth_targets, eth_targets_no0x, args.debug)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
        sys.exit(0)

if __name__ == "__main__":
    main()