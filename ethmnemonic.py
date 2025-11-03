#!/usr/bin/env python3
import os, time, secrets, threading, json
import requests
from coincurve import PrivateKey
import bip32utils
import hashlib
from concurrent.futures import ThreadPoolExecutor

# ----------------- Config -----------------
ACCOUNTS_PER_MNEMONIC = 5   # number of accounts (addresses) scanned per mnemonic (0..4)
WORDLIST_FILE = "seed.txt"
SEEN_FILE = "scanned_mnemonics.txt"
RPC_URL = "https://ethereum.publicnode.com"
REQUEST_DELAY = 0.1  # seconds between successful requests
BACKOFFS = [1, 3, 5]
THREADS = 5           # number of threads (one thread per account)

stop_event = threading.Event()
print_lock = threading.Lock()

# ----------------- Crypto helpers -----------------
def sha256(b): return hashlib.sha256(b).digest()

def keccak_256(data: bytes) -> bytes:
    try:
        return hashlib.new("keccak256", data).digest()
    except Exception:
        try:
            import sha3  # pysha3
            return sha3.keccak_256(data).digest()
        except Exception:
            raise RuntimeError("keccak256 not available: install the 'pysha3' package")

def eth_address_from_priv(priv_bytes: bytes) -> str:
    pub_uncompressed = PrivateKey(priv_bytes).public_key.format(compressed=False)
    h = keccak_256(pub_uncompressed[1:])
    addr = "0x" + h[-20:].hex()
    return addr

# ----------------- Address checker (Ethereum RPC) -----------------
class AddrChecker:
    def __init__(self, rpc_url=RPC_URL, timeout=10):
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
            if stop_event.is_set(): return 0
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
            except Exception:
                pass
            time.sleep(backoff)
        return 0

# ----------------- BIP39 / HD -----------------
def read_word_file_2048(file_path):
    with open(file_path,"r",encoding="utf-8") as f:
        words=[line.strip() for line in f if line.strip()]
    if len(words)!=2048: raise RuntimeError("Wordlist must be 2048 words")
    return words

def entropy_to_mnemonic_indices(entropy_bytes):
    digest=hashlib.sha256(entropy_bytes).digest()
    ent_bits=int.from_bytes(entropy_bytes,"big")
    checksum_bits=int.from_bytes(digest,"big")>>(256-4)
    combined=(ent_bits<<4)|checksum_bits
    indices=[]
    for i in range(12):
        shift=11*(12-1-i)
        indices.append((combined>>shift)&0x7FF)
    return indices

def random_valid_mnemonic_from_wordlist(words):
    entropy=secrets.token_bytes(16)
    indices=entropy_to_mnemonic_indices(entropy)
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
    s=set()
    if os.path.exists(path):
        with open(path,"r",encoding="utf-8") as f:
            for l in f:
                if l.strip(): s.add(l.strip())
    return s

def persist_seen(path,mnemonic):
    with open(path,"a",encoding="utf-8") as f:
        f.write(mnemonic+"\n"); f.flush(); os.fsync(f.fileno())

# ----------------- Scan function -----------------
def scan_account(priv_bytes, checker, mnemonic, account):
    try:
        addr = eth_address_from_priv(priv_bytes)
        with print_lock:
            print(f"[DEBUG] Scanning account={account} address {addr}")

        wei = checker.eth_balance(addr)
        if wei and wei > 0:
            eth = wei / 1e18
            with print_lock:
                print("\n" + "="*60)
                print("!!!!! FOUND ETHEREUM ADDRESS !!!!!")
                print(f"MNEMONIC: {mnemonic}")
                print(f"Private key (hex): {priv_bytes.hex()}")
                print(f"Derivation path: m/44'/60'/{account}'/0/0")
                print(f"ADDRESS: {addr}")
                print(f"BALANCE (ETH): {eth}")
                print(f"BALANCE (WEI): {wei}")
                print("="*60 + "\n")
    except Exception as e:
        with print_lock:
            print(f"[ERROR] account={account} exception: {e}")

# ----------------- Main -----------------
def main():
    words = read_word_file_2048(WORDLIST_FILE)
    seen = load_seen(SEEN_FILE)
    checker = AddrChecker(RPC_URL)
    print(f"[INFO] Starting Ethereum HD scan: {ACCOUNTS_PER_MNEMONIC} accounts per mnemonic, {THREADS} threads")

    def signal_handler(sig, frame):
        stop_event.set()
        print("\n[INFO] Interrupted. Stopping...")

    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while not stop_event.is_set():
        mnemonic = random_valid_mnemonic_from_wordlist(words)
        if mnemonic in seen:
            continue
        seed = bip39_seed_from_mnemonic(mnemonic)
        seen.add(mnemonic)
        persist_seen(SEEN_FILE, mnemonic)

        # use a thread pool with one thread per account
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            futures = []
            for account in range(ACCOUNTS_PER_MNEMONIC):
                if stop_event.is_set(): break
                try:
                    priv = derive_priv_for_account_from_seed(seed, account)
                    futures.append(ex.submit(scan_account, priv, checker, mnemonic, account))
                except Exception as e:
                    with print_lock:
                        print(f"[WARN] Failed derivation account={account}: {e}")
            for f in futures:
                try:
                    f.result()
                except Exception:
                    pass

if __name__=="__main__":
    main()
