#!/usr/bin/env python3
import os, time, signal, secrets, hashlib, threading
import requests
from coincurve import PrivateKey
import bip32utils

# ----------------- Config -----------------
MAX_ACCOUNT = 3
MAX_CHANGE = 3
MAX_INDEX = 3
WORDLIST_FILE = "seed.txt"
SEEN_FILE = "scanned_mnemonics.txt"

stop_event = threading.Event()
print_lock = threading.Lock()

# ----------------- Crypto helpers -----------------
SECP256K1_ORDER = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16)
BASE58_ALPHABET="123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def sha256(b): return hashlib.sha256(b).digest()
def ripemd160(b): return hashlib.new('ripemd160',b).digest()
def hash160(b): return ripemd160(sha256(b))

def base58_encode(b):
    zeros=0
    for c in b:
        if c==0: zeros+=1
        else: break
    num=int.from_bytes(b,"big")
    chars=[]
    while num>0:
        num, rem=divmod(num,58)
        chars.append(BASE58_ALPHABET[rem])
    return "1"*zeros + "".join(reversed(chars)) if chars else "1"*zeros

def base58check_encode(payload):
    chk=sha256(sha256(payload))[:4]
    return base58_encode(payload + chk)

def privkey_to_wif(priv_bytes, compressed=True):
    payload=b"\x80"+priv_bytes
    if compressed: payload+=b"\x01"
    return base58check_encode(payload)

def p2pkh(pub): return base58check_encode(b"\x00"+hash160(pub))
def p2sh_p2wpkh(pub):
    redeem_script=b"\x00\x14"+hash160(pub)
    return base58check_encode(b"\x05"+hash160(redeem_script))

# Bech32 / P2WPKH
BECH32_CHARSET="qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def convertbits(data, frombits, tobits, pad=True):
    acc=0; bits=0; ret=[]; maxv=(1<<tobits)-1
    for b in data:
        if b>>frombits: raise ValueError()
        acc=(acc<<frombits)|b; bits+=frombits
        while bits>=tobits: bits-=tobits; ret.append((acc>>bits)&maxv)
    if pad and bits: ret.append((acc<<(tobits-bits))&maxv)
    elif bits>=frombits or ((acc<<(tobits-bits))&maxv): raise ValueError()
    return bytes(ret)

def bech32_polymod(values):
    GEN=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk=1
    for v in values:
        b=(chk>>25)&0xFF
        chk=((chk&0x1FFFFFF)<<5)^v
        for i in range(5):
            if (b>>i)&1: chk^=GEN[i]
    return chk

def bech32_hrp_expand(hrp): return [ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]
def bech32_create_checksum(hrp,data):
    values=bech32_hrp_expand(hrp)+list(data)+[0]*6
    polymod=bech32_polymod(values)^1
    return bytes((polymod>>(5*(5-i))&31) for i in range(6))
def bech32_encode(hrp,data):
    combined=bytes(list(data)+list(bech32_create_checksum(hrp,data)))
    return hrp+"1"+"".join(BECH32_CHARSET[b] for b in combined)
def p2wpkh_bech32(pub):
    h=hash160(pub)
    data=bytes([0])+convertbits(h,8,5)
    return bech32_encode("bc",data)

# ----------------- Address checker -----------------
class AddrChecker:
    def __init__(self, delay=0.6, timeout=10):
        self.session = requests.Session()
        self.delay = delay
        self.timeout = timeout
        self.backoffs = [1,3,5]

    def btc_received(self, addr):
        url=f"https://blockchain.info/q/getreceivedbyaddress/{addr}"
        for backoff in self.backoffs:
            if stop_event.is_set(): return 0
            try:
                resp=self.session.get(url, timeout=self.timeout)
                if resp.status_code==200:
                    time.sleep(self.delay)
                    return int(resp.text.strip())
            except: pass
            time.sleep(backoff)
        return 0

    def btc_balance(self, addr):
        url=f"https://blockchain.info/balance?active={addr}"
        for backoff in self.backoffs:
            if stop_event.is_set(): return None
            try:
                resp=self.session.get(url, timeout=self.timeout)
                if resp.status_code==200:
                    time.sleep(self.delay)
                    data=resp.json()
                    return int(data.get(addr,{}).get("final_balance",0))
            except: pass
            time.sleep(backoff)
        return None

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

def derive_priv_for_path_from_seed(seed, purpose, coin, account=0, change=0, index=0):
    root = bip32utils.BIP32Key.fromEntropy(seed)
    node = root.ChildKey(purpose + bip32utils.BIP32_HARDEN)\
               .ChildKey(coin + bip32utils.BIP32_HARDEN)\
               .ChildKey(account + bip32utils.BIP32_HARDEN)\
               .ChildKey(change)\
               .ChildKey(index)
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
def scan_address(priv_bytes, addr_type, checker, mnemonic, account, change, index):
    try:
        pub = PrivateKey(priv_bytes).public_key.format(compressed=True)
        if addr_type=="p2pkh": addr = p2pkh(pub)
        elif addr_type=="p2sh": addr = p2sh_p2wpkh(pub)
        elif addr_type=="p2wpkh": addr = p2wpkh_bech32(pub)
        else: return

        # ----- DEBUG PRINT -----
        with print_lock:
            print(f"[DEBUG] Scanning {addr_type} address {addr} (account={account} change={change} index={index})")

        recvd = checker.btc_received(addr)
        bal = checker.btc_balance(addr)

        if recvd > 0:
            with print_lock:
                print("\n" + "="*60)
                print("!!!!! FOUND BITCOIN ADDRESS !!!!!")
                print(f"MNEMONIC: {mnemonic}")
                print(f"WIF: {privkey_to_wif(priv_bytes)}")
                print(f"Address type: {addr_type}")
                print(f"Derivation path: account={account} change={change} index={index}")
                print(f"ADDRESS: {addr}")
                print(f"RECEIVED (BTC): {recvd/1e8}")
                print(f"BALANCE (BTC): {bal/1e8 if bal is not None else 'NONE'}")
                print("="*60 + "\n")
    except Exception as e:
        with print_lock:
            print(f"[ERROR] {addr_type} account={account} change={change} index={index} exception: {e}")

# ----------------- Thread task -----------------
def scan_type_for_mnemonic(seed, mnemonic, addr_type, purpose, checker):
    for account in range(MAX_ACCOUNT+1):
        for change in range(MAX_CHANGE+1):
            for index in range(MAX_INDEX+1):
                if stop_event.is_set(): return
                try:
                    priv = derive_priv_for_path_from_seed(seed, purpose, 0, account, change, index)
                    scan_address(priv, addr_type, checker, mnemonic, account, change, index)
                except Exception as e:
                    with print_lock:
                        print(f"[WARN] Failed derivation {addr_type} a={account} c={change} i={index}: {e}")

# ----------------- Main -----------------
def main():
    words = read_word_file_2048(WORDLIST_FILE)
    seen = load_seen(SEEN_FILE)
    checker = AddrChecker()
    print("[INFO] Starting HD scan with 3 threads (one per address type)")
    
    def signal_handler(sig, frame):
        stop_event.set()
        print("\n[INFO] Interrupted. Stopping...")

    import signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    while not stop_event.is_set():
        mnemonic = random_valid_mnemonic_from_wordlist(words)
        if mnemonic in seen: continue
        seed = bip39_seed_from_mnemonic(mnemonic)
        seen.add(mnemonic)
        persist_seen(SEEN_FILE, mnemonic)

        threads = []
        for addr_type, purpose in [("p2pkh",44), ("p2sh",49), ("p2wpkh",84)]:
            t = threading.Thread(target=scan_type_for_mnemonic, args=(seed, mnemonic, addr_type, purpose, checker))
            t.start()
            threads.append(t)
        for t in threads:
            t.join()  # wait for all 3 threads to finish before next mnemonic

if __name__=="__main__":
    main()
