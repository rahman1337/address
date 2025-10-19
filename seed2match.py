#!/usr/bin/env python3
import os
import sys
import random
import hashlib
import struct
from threading import Thread, Lock
from queue import Queue
import time

from mnemonic import Mnemonic
import bip32utils
import base58
import bech32
import ecdsa
import sha3  # pip install pysha3

# Config
BIP39_WORDLIST_PATH = "seed.txt"
BTC_FILES_DEFAULT = ["btc1.txt", "btc2.txt", "btc3.txt"]
ETH_FILE_DEFAULT = "Eth.txt"
FOUND_FILE = "found.txt"
HARDEN = 0x80000000
THREADS = 5
DEBUG = "--debug" in sys.argv
lock = Lock()

# Load BIP39 wordlist
if not os.path.exists(BIP39_WORDLIST_PATH):
    sys.exit(f"Missing BIP39 wordlist file: {BIP39_WORDLIST_PATH}")

with open(BIP39_WORDLIST_PATH, "r", encoding="utf-8") as f:
    wl = [w.strip() for w in f.readlines() if w.strip()]

mnemo = Mnemonic("english")
mnemo.wordlist = wl

# --- Derivation functions --- #

def derive_btc_addresses_from_seed(seed_bytes):
    root = bip32utils.BIP32Key.fromEntropy(seed_bytes)

    # legacy
    k44 = root.ChildKey(44 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    legacy = k44.Address()

    # p2sh-p2wpkh
    k49 = root.ChildKey(49 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    pub49 = k49.PublicKey()
    h160 = hashlib.new("ripemd160", hashlib.sha256(pub49).digest()).digest()
    redeem_script = b'\x00\x14' + h160
    redeem_hash = hashlib.new("ripemd160", hashlib.sha256(redeem_script).digest()).digest()
    p2sh = base58.b58encode_check(b'\x05' + redeem_hash).decode()

    # bech32
    k84 = root.ChildKey(84 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    pub84 = k84.PublicKey()
    h160_84 = hashlib.new("ripemd160", hashlib.sha256(pub84).digest()).digest()
    conv = bech32.convertbits(h160_84, 8, 5)
    bech32_addr = bech32.bech32_encode("bc", [0] + conv)

    return legacy, p2sh, bech32_addr

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
    return checksum_eth_address(addr)

def checksum_eth_address(addr: str) -> str:
    addr_noprefix = addr.lower().replace('0x','')
    keccak = sha3.keccak_256()
    keccak.update(addr_noprefix.encode('ascii'))
    hash_hex = keccak.hexdigest()
    out = "0x"
    for c, h in zip(addr_noprefix, hash_hex):
        out += c.upper() if int(h,16) >= 8 else c
    return out

# --- Utilities --- #
def load_address_file(path):
    s = set()
    if not os.path.exists(path):
        return s
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            a = line.strip()
            if a:
                s.add(a)
    return s

def append_found(mnemonic, address):
    with lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(f"Words: {mnemonic}\nMATCH: {address}\n\n")

def worker(queue, btc_addrs, eth_addrs, thread_id):
    tried = 0
    while True:
        strength = random.choice([128, 256])
        mnemonic = mnemo.generate(strength=strength)
        seed_bytes = mnemo.to_seed(mnemonic)

        try:
            legacy, p2sh, bech32_addr = derive_btc_addresses_from_seed(seed_bytes)
            eth_addr = derive_eth_address(seed_bytes)
        except Exception as e:
            tried += 1
            if DEBUG:
                with lock:
                    print(f"[Thread {thread_id}][DerivationError] {e}")
            continue

        tried += 1

        if DEBUG:
            with lock:
                print(f"[Thread {thread_id}][DEBUG] Mnemonic: {mnemonic}")
                print(f"[Thread {thread_id}][DEBUG] BTC: {legacy}, {p2sh}, {bech32_addr}")
                print(f"[Thread {thread_id}][DEBUG] ETH: {eth_addr}")

        # Check for BTC matches
        for addr in (legacy, p2sh, bech32_addr):
            if addr in btc_addrs:
                with lock:
                    print(mnemonic)
                    print(addr)
                append_found(mnemonic, addr)
                break

        # Check for ETH match
        if eth_addr in eth_addrs:
            with lock:
                print(mnemonic)
                print(eth_addr)
            append_found(mnemonic, eth_addr)

        # Progress log every 100 mnemonics per thread
        if tried % 100 == 0:
            with lock:
                print(f"[Thread {thread_id}] Tried {tried} mnemonics")

def main():
    btc_files = BTC_FILES_DEFAULT
    if len(sys.argv) > 1:
        btc_files = sys.argv[1:1+3]

    # Load BTC addresses
    btc_sets = [load_address_file(p) for p in btc_files]
    btc_addrs = set().union(*btc_sets)
    print(f"Number of BTC addresses loaded: {len(btc_addrs)}")

    # Load ETH addresses
    eth_addrs = load_address_file(ETH_FILE_DEFAULT)
    print(f"Number of ETH addresses loaded: {len(eth_addrs)}")

    if not btc_addrs and not eth_addrs:
        sys.exit("No addresses loaded. Exiting.")

    queue = Queue()
    threads = []
    for i in range(THREADS):
        t = Thread(target=worker, args=(queue, btc_addrs, eth_addrs, i+1), daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()