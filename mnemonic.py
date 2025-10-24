#!/usr/bin/env python3
"""
BTC-only HD scanner with multi-account, multi-change, multi-index support.

Defaults: accounts 0..3, change 0..3, index 0..3
Checks blockchain.info/q/getreceivedbyaddress/<addr> first; if received>0 attempts rawaddr for balance.
Persists scanned mnemonics to seen-file (append-only).
"""
import argparse
import threading
import time
import random
import os
import signal
import secrets
import hashlib
import sys
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import requests
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160
import bip32utils

# ---------------- Constants ----------------
SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

stop_event = threading.Event()

# ---------------- Crypto helpers ----------------
def sha256_bytes(b: bytes) -> bytes:
    h = SHA256.new()
    h.update(b)
    return h.digest()

def ripemd160_bytes(b: bytes) -> bytes:
    h = RIPEMD160.new()
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160_bytes(sha256_bytes(b))

def base58_encode(b: bytes) -> str:
    zeros = 0
    for c in b:
        if c == 0:
            zeros += 1
        else:
            break
    num = int.from_bytes(b, "big")
    chars = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(BASE58_ALPHABET[rem])
    return "1"*zeros + "".join(reversed(chars)) if chars else "1"*zeros

def base58check_encode(payload: bytes) -> str:
    chk = sha256_bytes(sha256_bytes(payload))[:4]
    return base58_encode(payload + chk)

def privkey_to_wif(priv_bytes: bytes, compressed: bool = False) -> str:
    payload = b"\x80" + priv_bytes
    if compressed:
        payload += b"\x01"
    return base58check_encode(payload)

def p2pkh_from_pub(pub_bytes: bytes) -> str:
    return base58check_encode(b"\x00" + hash160(pub_bytes))

def p2sh_p2wpkh_from_pub(pub_bytes: bytes) -> str:
    redeem = b"\x00\x14" + hash160(pub_bytes)
    return base58check_encode(b"\x05" + hash160(redeem))

# bech32 / taproot helpers
def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xFF
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp: str):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp: str, data: bytes, bech32m: bool = False):
    values = bech32_hrp_expand(hrp) + list(data) + [0]*6
    polymod = bech32_polymod(values)
    const = 0x2bc830a3 if bech32m else 1
    polymod ^= const
    return bytes((polymod >> (5*(5-i)) & 31) for i in range(6))

def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> bytes:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        if b >> frombits:
            raise ValueError("Invalid data for convertbits")
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid padding in convertbits")
    return bytes(ret)

def bech32_encode(hrp: str, data: bytes, bech32m: bool = False) -> str:
    combined = bytes(list(data) + list(bech32_create_checksum(hrp, data, bech32m=bech32m)))
    return hrp + "1" + "".join(BECH32_CHARSET[b] for b in combined)

def p2wpkh_bech32(pub_bytes: bytes) -> str:
    h160 = hash160(pub_bytes)
    data = bytes([0]) + convertbits(h160, 8, 5)
    return bech32_encode("bc", data, bech32m=False)

def tagged_hash(tag: str, msg: bytes) -> bytes:
    th = sha256_bytes(tag.encode())
    return sha256_bytes(th + th + msg)

def p2tr_from_privkey(priv_bytes: bytes) -> str:
    priv_int = int.from_bytes(priv_bytes, "big")
    if priv_int == 0 or priv_int >= SECP256K1_ORDER:
        raise ValueError("Invalid private key")
    internal_pk = PrivateKey(priv_bytes)
    internal_uncomp = internal_pk.public_key.format(compressed=False)
    internal_xonly = internal_uncomp[1:33]
    tweak_bytes = tagged_hash("TapTweak", internal_xonly)
    tweak_int = int.from_bytes(tweak_bytes, "big") % SECP256K1_ORDER
    tweaked_priv_int = (priv_int + tweak_int) % SECP256K1_ORDER
    if tweaked_priv_int == 0:
        raise ValueError("Taproot tweak invalid")
    tweaked_pk = PrivateKey(tweaked_priv_int.to_bytes(32, "big"))
    tweaked_uncomp = tweaked_pk.public_key.format(compressed=False)
    tweaked_xonly = tweaked_uncomp[1:33]
    data = bytes([1]) + convertbits(tweaked_xonly, 8, 5)
    return bech32_encode("bc", data, bech32m=True)

# ---------------- HTTP checker with jittered backoff ----------------
class AddrChecker:
    def __init__(self, session: requests.Session, sem: threading.Semaphore, delay: float = 0.6, timeout: int = 10, debug: bool = False):
        self.session = session
        self.sem = sem
        self.delay = delay
        self.timeout = timeout
        self.backoffs = [1, 3, 5]
        self.debug = debug

    def _request_with_retries(self, method: str, url: str, **kwargs):
        last_exc = None
        for attempt, backoff in enumerate(self.backoffs, start=1):
            if stop_event.is_set():
                raise RuntimeError("Stopped")
            try:
                self.sem.acquire()
                try:
                    if method.lower() == "get":
                        resp = self.session.get(url, timeout=self.timeout)
                    elif method.lower() == "post":
                        resp = self.session.post(url, timeout=self.timeout, **kwargs)
                    else:
                        raise RuntimeError(f"Unsupported HTTP method: {method}")
                finally:
                    self.sem.release()
                if resp.status_code == 200:
                    time.sleep(self.delay)
                    return resp
                elif resp.status_code == 429:
                    last_exc = RuntimeError("HTTP 429 Too Many Requests")
                else:
                    last_exc = RuntimeError(f"HTTP {resp.status_code}")
            except Exception as e:
                last_exc = e
            if attempt < len(self.backoffs):
                jitter = random.uniform(0.8, 1.2)
                sleep_time = backoff * jitter
                if self.debug:
                    print(f"[WARN] Attempt {attempt} failed for {url}: {last_exc}. Sleeping {sleep_time:.2f}s", flush=True)
                time.sleep(sleep_time)
        raise last_exc

    def btc_received(self, addr: str) -> int:
        url = f"https://blockchain.info/q/getreceivedbyaddress/{addr}"
        resp = self._request_with_retries("get", url)
        return int(resp.text.strip())

    def btc_balance(self, addr: str):
        url = f"https://blockchain.info/rawaddr/{addr}"
        try:
            resp = self._request_with_retries("get", url)
            data = resp.json()
            return int(data.get("final_balance", 0))
        except Exception:
            return None

# ---------------- BIP39/BIP32 helpers ----------------
def read_word_file_2048(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]
    if len(words) != 2048:
        raise RuntimeError(f"Wordlist file must contain exactly 2048 words, one per line (found {len(words)})")
    return words

def entropy_to_mnemonic_indices(entropy_bytes: bytes):
    digest = hashlib.sha256(entropy_bytes).digest()
    ent_bits = int.from_bytes(entropy_bytes, "big")
    checksum_bits = int.from_bytes(digest, "big") >> (256 - 4)
    combined = (ent_bits << 4) | checksum_bits
    indices = []
    for i in range(12):
        shift = 11 * (12 - 1 - i)
        idx = (combined >> shift) & 0x7FF
        indices.append(idx)
    return indices

def random_valid_mnemonic_from_wordlist(words):
    entropy_int = secrets.randbits(128)
    entropy_bytes = entropy_int.to_bytes(16, "big")
    indices = entropy_to_mnemonic_indices(entropy_bytes)
    mnemonic_words = [words[i] for i in indices]
    return " ".join(mnemonic_words), indices

def bip39_seed_from_mnemonic(mnemonic_str: str, passphrase: str = ""):
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic_str.encode("utf-8"), salt, 2048, dklen=64)

def derive_priv_for_path_from_seed(seed_bytes: bytes, purpose: int, coin: int, account: int = 0, change: int = 0, addr_index: int = 0) -> bytes:
    root = bip32utils.BIP32Key.fromEntropy(seed_bytes)
    purpose_node = root.ChildKey(purpose + bip32utils.BIP32_HARDEN)
    coin_node = purpose_node.ChildKey(coin + bip32utils.BIP32_HARDEN)
    account_node = coin_node.ChildKey(account + bip32utils.BIP32_HARDEN)
    change_node = account_node.ChildKey(change)
    addr_node = change_node.ChildKey(addr_index)
    return addr_node.PrivateKey()

# ---------------- Seen persistence ----------------
def load_seen_mnemonics(path):
    s = set()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    w = line.strip()
                    if w:
                        s.add(w)
        except Exception:
            pass
    return s

def persist_seen_mnemonic(path, mnemonic):
    with open(path, "a", encoding="utf-8") as f:
        f.write(mnemonic.replace("\n", " ") + "\n")
        f.flush()
        os.fsync(f.fileno())

# ---------------- Generator (accounts x change x indices) ----------------
_zero_lock = threading.Lock()
_zero_seen = False

def hd_unique_mnemonic_generator(wordlist_path: str, seen_path: str, account_indices=[0,1,2,3], change_indices=[0,1,2,3], addr_indices=[0,1,2,3], passphrase: str = "", debug: bool = False):
    if not os.path.exists(seen_path):
        open(seen_path, "a", encoding="utf-8").close()

    words = read_word_file_2048(wordlist_path)
    seen = load_seen_mnemonics(seen_path)
    while not stop_event.is_set():
        mnemonic, indices = random_valid_mnemonic_from_wordlist(words)
        if mnemonic in seen:
            continue
        seed = bip39_seed_from_mnemonic(mnemonic, passphrase=passphrase)
        privs_results = []  # list of (account, change, addr_index, privs_dict)
        for account in account_indices:
            for change in change_indices:
                for ai in addr_indices:
                    skip = False
                    privs = {}
                    for purpose, keyname in [(44, "p2pkh"), (49, "p2sh"), (84, "p2wpkh"), (86, "p2tr")]:
                        try:
                            priv_bytes = derive_priv_for_path_from_seed(seed, purpose=purpose, coin=0, account=account, change=change, addr_index=ai)
                        except Exception:
                            skip = True
                            break
                        priv_int = int.from_bytes(priv_bytes, "big")
                        if priv_int == 0 or priv_int >= SECP256K1_ORDER:
                            skip = True
                            break
                        privs[keyname] = priv_bytes
                    if skip:
                        continue
                    privs_results.append((account, change, ai, privs))
        if not privs_results:
            continue
        seen.add(mnemonic)
        persist_seen_mnemonic(seen_path, mnemonic)
        if debug:
            print("[DEBUG] mnemonic indices:", indices, flush=True)
            print("[DEBUG] mnemonic:", mnemonic, flush=True)
            print("[DEBUG] derived (acct,chg,idx):", [(a,c,i) for a,c,i,_ in privs_results], flush=True)
        for account, change, ai, privs in privs_results:
            yield mnemonic, account, change, ai, privs

# ---------------- Scanning single address type ----------------
def scan_btc_address_from_priv(priv_bytes: bytes, addr_type: str, checker: AddrChecker, print_lock: threading.Lock, mnemonic: str, account: int, change: int, addr_index: int, debug: bool=False):
    if stop_event.is_set():
        return
    try:
        if addr_type == 'p2pkh':
            pub = PrivateKey(priv_bytes).public_key.format(compressed=True)
            addr = p2pkh_from_pub(pub)
            wif = privkey_to_wif(priv_bytes, compressed=True)
            tweaked_wif = None
        elif addr_type == 'p2sh':
            pub = PrivateKey(priv_bytes).public_key.format(compressed=True)
            addr = p2sh_p2wpkh_from_pub(pub)
            wif = privkey_to_wif(priv_bytes, compressed=True)
            tweaked_wif = None
        elif addr_type == 'p2wpkh':
            pub = PrivateKey(priv_bytes).public_key.format(compressed=True)
            addr = p2wpkh_bech32(pub)
            wif = privkey_to_wif(priv_bytes, compressed=True)
            tweaked_wif = None
        elif addr_type == 'p2tr':
            addr = p2tr_from_privkey(priv_bytes)
            wif = privkey_to_wif(priv_bytes, compressed=True)
            # compute tweaked private
            try:
                internal_pk = PrivateKey(priv_bytes)
                internal_uncomp = internal_pk.public_key.format(compressed=False)
                internal_xonly = internal_uncomp[1:33]
                tweak_bytes = tagged_hash("TapTweak", internal_xonly)
                tweak_int = int.from_bytes(tweak_bytes, "big") % SECP256K1_ORDER
                priv_int = int.from_bytes(priv_bytes, "big")
                tweaked_priv_int = (priv_int + tweak_int) % SECP256K1_ORDER
                tweaked_priv_bytes = tweaked_priv_int.to_bytes(32, "big")
                tweaked_wif = privkey_to_wif(tweaked_priv_bytes, compressed=True)
            except Exception:
                tweaked_wif = None
        else:
            return
    except Exception as e:
        if debug:
            with print_lock:
                print(f"[WARN] address derivation failed for type {addr_type}: {e}", flush=True)
        return

    # received check
    try:
        recvd = checker.btc_received(addr)
    except Exception as e:
        if debug:
            with print_lock:
                print(f"[WARN] btc_received failed for {addr}: {e}", flush=True)
        return

    if recvd == 0:
        return

    # balance fallback
    try:
        bal_sat = checker.btc_balance(addr)
    except Exception:
        bal_sat = None

    bal_str = None if bal_sat is None else f"{bal_sat/1e8:.14f}"

    # print FOUND block
    with print_lock:
        print("\n" + "="*90, flush=True)
        print("!!!!! FOUND BTC ADDRESS WITH FUNDS !!!!!", flush=True)
        print("", flush=True)
        print("MNEMONIC:", mnemonic, flush=True)
        print("ACCOUNT:", account, flush=True)
        print("CHANGE:", change, flush=True)
        print("ADDRESS INDEX:", addr_index, flush=True)
        print("ADDRESS TYPE:", addr_type, flush=True)
        print("ADDRESS:", addr, flush=True)
        print("WIF (internal priv):", wif, flush=True)
        if addr_type == 'p2tr':
            if tweaked_wif:
                print("WIF (tweaked/keyspend priv):", tweaked_wif, flush=True)
            else:
                print("WIF (tweaked/keyspend priv): <unavailable>", flush=True)
        print("RECEIVED (BTC):", f"{recvd/1e8:.14f}", flush=True)
        if bal_str is None:
            print("BALANCE (BTC):", f"{LIGHT_GREEN}NONE{RESET}", flush=True)
        else:
            print("BALANCE (BTC):", f"{LIGHT_GREEN}{bal_str}{RESET}", flush=True)
        print("="*90 + "\n", flush=True)

# ---------------- CLI ----------------
def parse_args():
    p = argparse.ArgumentParser(description="BTC-only HD scanner (accounts x change x indices)")
    p.add_argument("-t", "--threads", type=int, default=4, help="worker threads (default 4)")
    p.add_argument("--accounts", type=str, default="0,1,2,3", help="comma list of account indices (default 0,1,2,3)")
    p.add_argument("--changes", type=str, default="0,1,2,3", help="comma list of change indices (default 0,1,2,3)")
    p.add_argument("--addr-indices", type=str, default="0,1,2,3", help="comma list of address indices (default 0,1,2,3)")
    p.add_argument("--file", type=str, default="seed.txt", help="2048-word wordlist file (one word per line)")
    p.add_argument("--seen-file", type=str, default="scanned_mnemonics.txt", help="file to persist seen mnemonics (append-only)")
    p.add_argument("--passphrase", type=str, default="", help="optional BIP39 passphrase")
    p.add_argument("--delay", type=float, default=0.6, help="delay between successful HTTP requests")
    p.add_argument("--debug", action="store_true", help="enable debug output")
    return p.parse_args()

# ---------------- Main ----------------
def main():
    args = parse_args()
    account_indices = [int(x) for x in args.accounts.split(",") if x.strip().isdigit()]
    change_indices = [int(x) for x in args.changes.split(",") if x.strip().isdigit()]
    addr_indices = [int(x) for x in args.addr_indices.split(",") if x.strip().isdigit()]

    session = requests.Session()
    sem = threading.Semaphore(max(1, args.threads))
    checker = AddrChecker(session, sem, delay=args.delay, debug=args.debug)
    print_lock = threading.Lock()

    signal.signal(signal.SIGINT, lambda s, f: stop_event.set())
    signal.signal(signal.SIGTERM, lambda s, f: stop_event.set())

    gen = hd_unique_mnemonic_generator(args.file, args.seen_file, account_indices, change_indices, addr_indices, passphrase=args.passphrase, debug=args.debug)

    addr_types = ['p2pkh', 'p2sh', 'p2wpkh', 'p2tr']

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = set()
        try:
            for mnemonic, account, change, addr_index, privs in gen:
                if stop_event.is_set():
                    break

                # submit one task per address type for this derived set
                for addr_type in addr_types:
                    priv_bytes = privs.get(addr_type)
                    if priv_bytes is None:
                        continue
                    f = executor.submit(scan_btc_address_from_priv, priv_bytes, addr_type, checker, print_lock, mnemonic, account, change, addr_index, args.debug)
                    futures.add(f)

                # backpressure: wait for some tasks to complete if too many outstanding
                while len(futures) >= args.threads * 4 and not stop_event.is_set():
                    done, _ = wait(futures, return_when=FIRST_COMPLETED, timeout=1)
                    for d in done:
                        futures.discard(d)
                        try:
                            d.result()
                        except Exception as e:
                            with print_lock:
                                print(f"[ERROR] task failed: {e}", flush=True)

            # cancel outstanding
            if futures:
                for fut in list(futures):
                    try:
                        if not fut.done():
                            fut.cancel()
                    except Exception:
                        pass

        except Exception as e:
            with print_lock:
                print(f"[ERROR] main loop exception: {e}", flush=True)
        finally:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)
            print("[INFO] Shutdown requested, exiting.", flush=True)

if __name__ == "__main__":
    main()
