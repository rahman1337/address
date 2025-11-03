#!/usr/bin/env python3
import os
import time
import secrets
import threading
import json
import argparse
import signal
import hashlib
from concurrent.futures import ThreadPoolExecutor

import requests
from coincurve import PrivateKey
import bip32utils

# ----------------- Config -----------------
ACCOUNTS_PER_MNEMONIC = 5   # number of accounts (addresses) scanned per mnemonic (0..4)
WORDLIST_FILE = "seed.txt"
SEEN_FILE = "scanned_mnemonics.txt"
FOUND_FILE = "found.txt"
RPC_URL = "https://ethereum.publicnode.com"
REQUEST_DELAY = 0.1  # seconds between successful requests
BACKOFFS = [1, 3, 5]
THREADS = 5           # number of threads (one thread per account)
TIMEOUT = 10

stop_event = threading.Event()
print_lock = threading.Lock()

# ----------------- CLI / Mode -----------------
parser = argparse.ArgumentParser(description="Ethereum HD scanner")
parser.add_argument("--debug", action="store_true", help="Enable debug output (prints everything)")
args = parser.parse_args()
DEBUG_MODE = args.debug

def debug(msg):
    if DEBUG_MODE:
        with print_lock:
            print(msg)

def always(msg):
    with print_lock:
        print(msg)

# ----------------- Keccak helper -----------------
def keccak_256(data: bytes) -> bytes:
    # Try hashlib new("keccak256")
    try:
        return hashlib.new("keccak256", data).digest()
    except Exception:
        pass
    # Try pysha3
    try:
        import sha3  # pysha3
        return sha3.keccak_256(data).digest()
    except Exception:
        pass
    # Try pycryptodome
    try:
        from Crypto.Hash import keccak
        k = keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
    except Exception:
        pass
    raise RuntimeError("keccak256 not available: install 'pysha3' or 'pycryptodome'")

# ----------------- Ethereum helpers -----------------
def eth_address_from_priv(priv_bytes: bytes) -> str:
    # uncompressed public key: 0x04 || X(32) || Y(32)
    pub_uncompressed = PrivateKey(priv_bytes).public_key.format(compressed=False)
    h = keccak_256(pub_uncompressed[1:])  # skip 0x04
    addr = "0x" + h[-20:].hex()
    return addr

# ----------------- Address checker (Ethereum RPC) -----------------
class AddrChecker:
    def __init__(self, rpc_url=RPC_URL, timeout=TIMEOUT):
        self.session = requests.Session()
        self.rpc_url = rpc_url
        self.timeout = timeout

    def eth_balance(self, addr):
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBalance",
            "params": [addr, "latest"]
        }
        for backoff in BACKOFFS:
            if stop_event.is_set():
                return 0
            try:
                resp = self.session.post(self.rpc_url, json=payload, timeout=self.timeout)
                if resp.status_code == 200:
                    data = resp.json()
                    res = data.get("result")
                    if res is None:
                        time.sleep(self.timeout)
                        continue
                    wei = int(res, 16)
                    time.sleep(REQUEST_DELAY)
                    return wei
            except Exception as e:
                # propagate exceptions to caller as needed; here we just retry
                debug(f"[DEBUG] RPC exception for {addr}: {e}")
            time.sleep(backoff)
        return 0

# ----------------- BIP39 / HD (12-word) -----------------
def read_word_file_2048(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]
    if len(words) != 2048:
        raise RuntimeError("Wordlist must be 2048 words")
    return words

def entropy_to_mnemonic_indices(entropy_bytes):
    digest = hashlib.sha256(entropy_bytes).digest()
    ent_bits = int.from_bytes(entropy_bytes, "big")
    checksum_bits = int.from_bytes(digest, "big") >> (256 - 4)
    combined = (ent_bits << 4) | checksum_bits
    indices = []
    for i in range(12):
        shift = 11 * (12 - 1 - i)
        indices.append((combined >> shift) & 0x7FF)
    return indices

def random_valid_mnemonic_from_wordlist(words):
    entropy = secrets.token_bytes(16)  # 128 bits => 12 words
    indices = entropy_to_mnemonic_indices(entropy)
    return " ".join(words[i] for i in indices)

def bip39_seed_from_mnemonic(mnemonic):
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048, dklen=64)

def derive_priv_for_account_from_seed(seed, account=0):
    # Derivation path: m/44'/60'/account'/0/0
    root = bip32utils.BIP32Key.fromEntropy(seed)
    node = root.ChildKey(44 + bip32utils.BIP32_HARDEN) \
               .ChildKey(60 + bip32utils.BIP32_HARDEN) \
               .ChildKey(account + bip32utils.BIP32_HARDEN) \
               .ChildKey(0) \
               .ChildKey(0)
    return node.PrivateKey()

# ----------------- Seen mnemonics -----------------
def load_seen(path):
    s = set()
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for l in f:
                if l.strip():
                    s.add(l.strip())
    return s

def persist_seen(path, mnemonic):
    with open(path, "a", encoding="utf-8") as f:
        f.write(mnemonic + "\n")
        f.flush()
        os.fsync(f.fileno())

# ----------------- Found logging -----------------
def append_found_block(found_block):
    try:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(found_block + "\n")
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        # If appending fails, still print an error (always printed)
        with print_lock:
            print(f"[ERROR] Failed to append to {FOUND_FILE}: {e}")

# ----------------- Scan function -----------------
def scan_account(priv_bytes, checker, mnemonic, account):
    try:
        addr = eth_address_from_priv(priv_bytes)
        debug(f"[DEBUG] Scanning account={account} address {addr}")

        wei = checker.eth_balance(addr)
        if wei and wei > 0:
            eth = wei / 1e18
            found_block = (
                "\n" + "="*60 + "\n"
                "!!!!! FOUND ETHEREUM ADDRESS !!!!!\n"
                f"MNEMONIC: {mnemonic}\n"
                f"Private key (hex): {priv_bytes.hex()}\n"
                f"Derivation path: m/44'/60'/{account}'/0/0\n"
                f"ADDRESS: {addr}\n"
                f"BALANCE (ETH): {eth}\n"
                f"BALANCE (WEI): {wei}\n"
                + "="*60 + "\n"
            )
            # print found block (always)
            always(found_block)
            # also append to found.txt
            append_found_block(found_block)
    except Exception as e:
        # always print errors
        with print_lock:
            print(f"[ERROR] account={account} exception: {e}")

# ----------------- Main -----------------
def main():
    words = read_word_file_2048(WORDLIST_FILE)
    seen = load_seen(SEEN_FILE)
    checker = AddrChecker(RPC_URL, timeout=TIMEOUT)

    # Note: per your request, we do not print startup/info lines in normal mode.
    debug(f"[DEBUG] Starting Ethereum HD scan: {ACCOUNTS_PER_MNEMONIC} accounts per mnemonic, {THREADS} threads")

    def signal_handler(sig, frame):
        stop_event.set()
        # print interruption message (useful)
        always("\n[INFO] Interrupted. Stopping...")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while not stop_event.is_set():
        try:
            mnemonic = random_valid_mnemonic_from_wordlist(words)
            if mnemonic in seen:
                debug("[DEBUG] mnemonic already seen, skipping")
                continue
            seed = bip39_seed_from_mnemonic(mnemonic)
            seen.add(mnemonic)
            persist_seen(SEEN_FILE, mnemonic)

            # use a thread pool with one thread per account
            with ThreadPoolExecutor(max_workers=THREADS) as ex:
                futures = []
                for account in range(ACCOUNTS_PER_MNEMONIC):
                    if stop_event.is_set():
                        break
                    try:
                        priv = derive_priv_for_account_from_seed(seed, account)
                        futures.append(ex.submit(scan_account, priv, checker, mnemonic, account))
                    except Exception as e:
                        # derivation problems are errors that should be printed
                        with print_lock:
                            print(f"[ERROR] Failed derivation account={account}: {e}")
                # wait for completion
                for f in futures:
                    try:
                        f.result()
                    except Exception as e:
                        # any exceptions here should be printed
                        with print_lock:
                            print(f"[ERROR] Thread raised exception: {e}")
        except Exception as e:
            # Catch top-level exceptions (file IO, keccak missing, etc.)
            with print_lock:
                print(f"[ERROR] main loop exception: {e}")

if __name__ == "__main__":
    main()
