#!/usr/bin/env python3
"""
HD-only scanner (random valid 12-word mnemonics drawn from a 2048-word file).
For each mnemonic the script derives wallet-accurate keys:
  - BTC: m/44'/0'/0'/0/i  -> P2PKH (1...)
         m/49'/0'/0'/0/i  -> P2SH-P2WPKH (3...)
         m/84'/0'/0'/0/i  -> P2WPKH (bc1q...)
         m/86'/0'/0'/0/i  -> P2TR (bc1p...)
  - EVM: m/44'/60'/0'/0/i -> ETH/BSC/POLYGON (0x...)
It generates valid random 12-word mnemonics from the provided 2048-word list (one word per line),
ensures no mnemonic is scanned twice by persisting seen mnemonics to disk.
"""
import argparse
import time
import signal
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
import threading
import requests
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160, keccak
import secrets
import hashlib
import hmac
import struct
import sys
import os
import bip32utils

# Constants
SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"

# ----------------- Helper crypto functions -----------------
def sha256(b: bytes) -> bytes:
    h = SHA256.new()
    h.update(b)
    return h.digest()

def ripemd160(b: bytes) -> bytes:
    h = RIPEMD160.new()
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

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
    chk = sha256(sha256(payload))[:4]
    return base58_encode(payload + chk)

def privkey_to_wif(priv_bytes: bytes, compressed: bool = False) -> str:
    prefix = b"\x80"
    payload = prefix + priv_bytes
    if compressed:
        payload += b"\x01"
    return base58check_encode(payload)

def p2pkh(pub: bytes) -> str:
    return base58check_encode(b"\x00" + hash160(pub))

def p2sh_p2wpkh(pub: bytes) -> str:
    redeem_script = b"\x00\x14" + hash160(pub)
    return base58check_encode(b"\x05" + hash160(redeem_script))

# Bech32 / Taproot helpers (kept from your original)
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
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

def p2wpkh_bech32(pub: bytes) -> str:
    h160 = hash160(pub)
    data = bytes([0]) + convertbits(h160, 8, 5)
    return bech32_encode("bc", data, bech32m=False)

def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + msg)

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

# EVM address
def eth_address_from_priv(priv_bytes: bytes) -> str:
    pk = PrivateKey(priv_bytes)
    uncompressed = pk.public_key.format(compressed=False)
    k = keccak.new(digest_bits=256)
    k.update(uncompressed[1:])
    return "0x" + k.digest()[-20:].hex()

# ----------------- Globals & threading -----------------
stop_event = threading.Event()

# ----------------- HTTP checker with retries (keeps your original behavior) -----------------
class AddrChecker:
    def __init__(self, session: requests.Session, sem: threading.Semaphore, delay=0.6, timeout=10, debug=False):
        self.session = session
        self.sem = sem
        self.delay = delay
        self.timeout = timeout
        self.debug = debug
        self.backoffs = [1,3,5]

    def _request_with_retries(self, method, url, **kwargs):
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
            if self.debug:
                print(f"[WARN] Attempt {attempt} failed for {url}: {last_exc}")
            if attempt < len(self.backoffs):
                time.sleep(backoff)
        raise last_exc

    def btc_received(self, addr):
        url = f"https://blockchain.info/q/getreceivedbyaddress/{addr}"
        resp = self._request_with_retries("get", url)
        return int(resp.text.strip())

    def btc_balance(self, addr):
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance"
        resp = self._request_with_retries("get", url)
        return int(resp.json().get("final_balance", 0))

    def evm_balance(self, chain, addr):
        endpoints = {
            "eth": "https://ethereum.publicnode.com",
            "bsc": "https://bsc-dataseed.binance.org/",
            "polygon": "https://polygon-rpc.com"
        }
        if chain not in endpoints:
            raise RuntimeError("Unknown chain: "+chain)
        url = endpoints[chain]
        payload = {"jsonrpc":"2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1}
        resp = self._request_with_retries("post", url, json=payload)
        data = resp.json()
        result_hex = data.get("result")
        if not result_hex:
            raise RuntimeError(f"No 'result' in RPC response: {data}")
        return int(result_hex, 16)

# ----------------- Logging -----------------
def log(msg, print_lock=None, debug=False, always=False):
    if always or debug:
        if print_lock:
            with print_lock:
                print(msg, flush=True)
        else:
            print(msg, flush=True)

# ----------------- Debug print of all 7 addresses for given privs -----------------
def debug_print_7_addresses(privs_for_btc: dict, evm_priv: bytes):
    """
    privs_for_btc: dict with keys p2pkh,p2sh,p2wpkh,p2tr -> priv_bytes
    evm_priv: private bytes for EVM
    """
    try:
        p2pkh_addr = p2pkh(PrivateKey(privs_for_btc['p2pkh']).public_key.format(compressed=True))
    except Exception:
        p2pkh_addr = "<err>"
    try:
        p2sh_addr = p2sh_p2wpkh(PrivateKey(privs_for_btc['p2sh']).public_key.format(compressed=True))
    except Exception:
        p2sh_addr = "<err>"
    try:
        p2w_addr = p2wpkh_bech32(PrivateKey(privs_for_btc['p2wpkh']).public_key.format(compressed=True))
    except Exception:
        p2w_addr = "<err>"
    try:
        p2tr_addr = p2tr_from_privkey(privs_for_btc['p2tr'])
    except Exception:
        p2tr_addr = "<err>"
    try:
        eth_addr = eth_address_from_priv(evm_priv)
    except Exception:
        eth_addr = "<err>"
    print("[DEBUG] Addresses to scan:")
    print("  BTC P2PKH:", p2pkh_addr)
    print("  BTC P2SH-P2WPKH:", p2sh_addr)
    print("  BTC P2WPKH:", p2w_addr)
    print("  BTC P2TR:", p2tr_addr)
    print("  ETH / BSC / POLYGON:", eth_addr)

# ----------------- Per-kind processing (scans specific address types) -----------------
def scan_btc_address_from_priv(priv_bytes: bytes, checker: AddrChecker, print_lock, debug=False):
    """Scan all BTC address types derived from this single private key (legacy fallback)."""
    if stop_event.is_set():
        return
    pub = PrivateKey(priv_bytes).public_key.format(compressed=True)
    addrs = []
    try:
        addrs.append(p2pkh(pub))
        addrs.append(p2sh_p2wpkh(pub))
        addrs.append(p2wpkh_bech32(pub))
        addrs.append(p2tr_from_privkey(priv_bytes))
    except Exception:
        pass
    for addr in addrs:
        if stop_event.is_set():
            return
        try:
            recvd = checker.btc_received(addr)
            if recvd == 0:
                continue
            bal = checker.btc_balance(addr)
        except Exception as e:
            log(f"[ERROR] BTC {addr} {e}", print_lock, always=True)
            continue
        btc_balance_btc = bal / 1e8
        if btc_balance_btc > 0:
            with print_lock:
                print("\n" + "="*53, flush=True)
                print("!!!!! FOUND BITCOIN ADDRESS WITH FUNDS !!!!!", flush=True)
                print("", flush=True)
                print("ADDRESS:", addr, flush=True)
                print("RECEIVED (BTC):", f"{recvd/1e8:.14f}", flush=True)
                print("BALANCE (BTC):", f"{LIGHT_GREEN}{btc_balance_btc:.14f}{RESET}", flush=True)
                print("="*53 + "\n", flush=True)

def scan_evm_from_priv(priv_bytes: bytes, checker: AddrChecker, print_lock, debug=False):
    """Scan ETH/BSC/POLYGON from a single private key."""
    if stop_event.is_set():
        return
    addr = eth_address_from_priv(priv_bytes)
    for chain in ["eth","bsc","polygon"]:
        if stop_event.is_set():
            return
        try:
            bal = checker.evm_balance(chain, addr)
            native_bal = bal / 1e18
        except Exception as e:
            log(f"[ERROR] {chain.upper()} {addr} {e}", print_lock, always=True)
            continue
        if native_bal > 0:
            with print_lock:
                print("\n" + "="*53, flush=True)
                print("!!!!! FOUND ADDRESS WITH FUNDS !!!!!", flush=True)
                print("", flush=True)
                print("ADDRESS:", addr, flush=True)
                print("COINS:", chain.upper(), flush=True)
                print("BALANCE (wei):", bal, flush=True)
                print("BALANCE (native):", f"{LIGHT_GREEN}{native_bal:.18f} {chain.upper()}{RESET}", flush=True)
                print("="*53 + "\n", flush=True)

# ----------------- BIP39 mnemonic generator helpers -----------------
def read_word_file_2048(file_path: str):
    with open(file_path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]
    if len(words) != 2048:
        raise RuntimeError(f"Wordlist file must contain exactly 2048 words, one per line (found {len(words)})")
    return words

def entropy_to_mnemonic_indices(entropy_bytes: bytes):
    """
    For 12-word mnemonics: entropy 128 bits (16 bytes) + checksum 4 bits -> 132 bits -> 12 * 11 bits indices
    Returns list of 12 indices (0..2047)
    """
    if len(entropy_bytes) != 16:
        raise ValueError("entropy must be 16 bytes")
    digest = hashlib.sha256(entropy_bytes).digest()
    ent_bits = int.from_bytes(entropy_bytes, "big")
    checksum_bits = int.from_bytes(digest, "big") >> (256 - 4)
    combined = (ent_bits << 4) | checksum_bits  # 132 bits
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

# ----------------- BIP32 derivation via bip32utils -----------------
def bip39_seed_from_mnemonic(mnemonic_str: str, passphrase: str = ""):
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic_str.encode("utf-8"), salt, 2048, dklen=64)

def derive_priv_for_path_from_seed(seed_bytes: bytes, purpose: int, coin: int, account: int = 0, change: int = 0, addr_index: int = 0) -> bytes:
    """
    Derive purpose' / coin' / account' / change / addr_index
    Returns 32-byte private key bytes.
    """
    root = bip32utils.BIP32Key.fromEntropy(seed_bytes)
    purpose_node = root.ChildKey(purpose + bip32utils.BIP32_HARDEN)
    coin_node = purpose_node.ChildKey(coin + bip32utils.BIP32_HARDEN)
    account_node = coin_node.ChildKey(account + bip32utils.BIP32_HARDEN)
    change_node = account_node.ChildKey(change)
    addr_node = change_node.ChildKey(addr_index)
    return addr_node.PrivateKey()

# ----------------- Seen mnemonics persistence -----------------
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
    # append line
    with open(path, "a", encoding="utf-8") as f:
        f.write(mnemonic.replace("\n"," ") + "\n")
        f.flush()
        os.fsync(f.fileno())

# ----------------- Generator: produce unique random valid mnemonics and derive keys -----------------
_zero_lock = threading.Lock()
_zero_seen = False

def hd_unique_mnemonic_generator(wordlist_path: str, seen_path: str, addr_index: int = 0, passphrase: str = "", debug: bool = False):
    """
    Infinite generator: yields (mnemonic, privs_dict, evm_priv_bytes)
    privs_dict: {'p2pkh':bytes,'p2sh':bytes,'p2wpkh':bytes,'p2tr':bytes}
    evm_priv_bytes: bytes for ETH/BSC/POLYGON (derived from coin=60 path)
    Ensures mnemonic is never yielded twice; persists seen mnemonics to seen_path.
    """
    words = read_word_file_2048(wordlist_path)
    seen = load_seen_mnemonics(seen_path)
    while not stop_event.is_set():
        mnemonic, indices = random_valid_mnemonic_from_wordlist(words)
        if mnemonic in seen:
            continue
        # derive seed
        seed = bip39_seed_from_mnemonic(mnemonic, passphrase=passphrase)
        privs = {}
        skip = False
        # derive BTC purposes (coin=0)
        for purpose, keyname in [(44, "p2pkh"), (49, "p2sh"), (84, "p2wpkh"), (86, "p2tr")]:
            try:
                priv_bytes = derive_priv_for_path_from_seed(seed, purpose=purpose, coin=0, account=0, change=0, addr_index=addr_index)
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
        # derive EVM priv under coin 60
        try:
            evm_priv = derive_priv_for_path_from_seed(seed, purpose=44, coin=60, account=0, change=0, addr_index=addr_index)
        except Exception:
            # if derivation fails, skip
            continue
        evm_int = int.from_bytes(evm_priv, "big")
        if evm_int == 0 or evm_int >= SECP256K1_ORDER:
            continue
        # zero-key guard (extremely unlikely)
        if evm_int == 0:
            with _zero_lock:
                global _zero_seen
                if _zero_seen:
                    continue
                _zero_seen = True
        # success -> mark seen (persist) and yield
        seen.add(mnemonic)
        persist_seen_mnemonic(seen_path, mnemonic)
        if debug:
            print("[DEBUG] Generated mnemonic indices:", indices)
            print("[DEBUG] Mnemonic:", mnemonic)
        yield (mnemonic, privs, evm_priv)

# ----------------- CLI -----------------
def parse_args():
    p = argparse.ArgumentParser(description="HD-only multi-path scanner (BTC types + ETH/BSC/Polygon). Default --file seed.txt")
    p.add_argument("-t","--threads", type=int, default=3)
    p.add_argument("--chains", type=str, default="eth,bsc,polygon,btc")
    p.add_argument("--addr-index", type=int, default=0, help="address index i in paths (default 0)")
    p.add_argument("--delay", type=float, default=0.6)
    p.add_argument("--backlog-mult", type=int, default=4, help="tasks per thread to keep queued")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--file", type=str, default="seed.txt", help="2048-word file path (one word per line). Default seed.txt")
    p.add_argument("--seen-file", type=str, default="scanned_mnemonics.txt", help="File to persist seen mnemonics (default scanned_mnemonics.txt)")
    p.add_argument("--passphrase", type=str, default="", help="Optional BIP39 passphrase")
    return p.parse_args()

# ----------------- Main -----------------
def main():
    args = parse_args()
    chains = [x.lower() for x in args.chains.split(",")]
    session = requests.Session()
    sem = threading.Semaphore(max(1, args.threads))
    checker = AddrChecker(session, sem, delay=args.delay, debug=args.debug)
    print_lock = threading.Lock()

    backlog_limit = max(2, args.threads * args.backlog_mult)

    def _signal_handler(sig, frame):
        stop_event.set()
        print("\n[INFO] Interrupted by user. Stopping new submissions...", flush=True)
    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # initialize generator (HD-only)
    try:
        gen = hd_unique_mnemonic_generator(
            wordlist_path=args.file,
            seen_path=args.seen_file,
            addr_index=args.addr_index,
            passphrase=args.passphrase,
            debug=args.debug
        )
        log(f"[INFO] Using HD mode (wordlist {args.file}), persisting seen mnemonics -> {args.seen_file}", print_lock, debug=args.debug, always=True)
    except Exception as e:
        print(f"[ERROR] Failed to initialize HD generator: {e}", file=sys.stderr)
        return

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = set()
        try:
            for mnemonic, privs_dict, evm_priv in gen:
                if stop_event.is_set():
                    break

                # debug print all 7 addresses before scanning if debug
                if args.debug:
                    debug_print_7_addresses(privs_dict, evm_priv)

                # Submit BTC scans per derived priv (each priv corresponds to its address type)
                # p2pkh priv -> P2PKH address scanning
                f = executor.submit(scan_btc_address_from_priv, privs_dict['p2pkh'], checker, print_lock, args.debug)
                futures.add(f)
                # p2sh priv -> P2SH-P2WPKH
                f = executor.submit(scan_btc_address_from_priv, privs_dict['p2sh'], checker, print_lock, args.debug)
                futures.add(f)
                # p2wpkh priv -> P2WPKH
                f = executor.submit(scan_btc_address_from_priv, privs_dict['p2wpkh'], checker, print_lock, args.debug)
                futures.add(f)
                # p2tr priv -> P2TR
                f = executor.submit(scan_btc_address_from_priv, privs_dict['p2tr'], checker, print_lock, args.debug)
                futures.add(f)
                # Submit EVM scan (ETH/BSC/POLYGON) from evm_priv
                f = executor.submit(scan_evm_from_priv, evm_priv, checker, print_lock, args.debug)
                futures.add(f)

                # backpressure / backlog limit processing (same as original)
                while len(futures) >= backlog_limit and not stop_event.is_set():
                    done, _ = wait(futures, return_when=FIRST_COMPLETED, timeout=1)
                    for d in done:
                        futures.discard(d)
                        try:
                            d.result()
                        except Exception as e:
                            log(f"[ERROR] task failed: {e}", print_lock, always=True)

            # cancel outstanding futures if any
            if futures:
                try:
                    for fut in list(futures):
                        if not fut.done():
                            fut.cancel()
                except Exception:
                    pass

        except Exception as e:
            log(f"[ERROR] main loop exception: {e}", print_lock, always=True)
        finally:
            try:
                executor.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                executor.shutdown(wait=False)
            print("[INFO] Shutdown requested, exiting.", flush=True)

if __name__ == "__main__":
    main()
