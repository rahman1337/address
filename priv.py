#!/usr/bin/env python3
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
import itertools
import bip32utils

SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"

# ----------------- Helper Functions -----------------
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

# ----------------- Bech32 / Taproot helpers -----------------
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

# ----------------- EVM -----------------
def eth_address_from_priv(priv_bytes: bytes) -> str:
    pk = PrivateKey(priv_bytes)
    uncompressed = pk.public_key.format(compressed=False)
    k = keccak.new(digest_bits=256)
    k.update(uncompressed[1:])
    return "0x" + k.digest()[-20:].hex()

# ----------------- Stop Event (global) -----------------
stop_event = threading.Event()

# ----------------- AddrChecker with Retry -----------------
class AddrChecker:
    def __init__(self, session: requests.Session, sem: threading.Semaphore, delay=0.6, timeout=10, debug=False):
        self.session = session
        self.sem = sem
        self.delay = delay
        self.timeout = timeout
        self.debug = debug
        self.backoffs = [1,3,5]  # retry backoff seconds

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

# ----------------- Per-priv processing -----------------
def process_index_priv(priv_bytes: bytes, checker: AddrChecker, chains, print_lock, debug=False):
    """
    Given priv_bytes (32), perform the BTC and EVM checks and printing.
    This is used by both HD and random modes.
    """
    if stop_event.is_set():
        return
    priv_hex_0x = "0x" + priv_bytes.hex()
    log(f"[DEBUG] priv {priv_hex_0x}", print_lock, debug)

    pk = PrivateKey(priv_bytes)
    pub = pk.public_key.format(compressed=True)
    wif = privkey_to_wif(priv_bytes, compressed=True)

    # BTC checks
    if "btc" in chains:
        btc_addrs = [p2pkh(pub), p2sh_p2wpkh(pub), p2wpkh_bech32(pub)]
        try:
            btc_addrs.append(p2tr_from_privkey(priv_bytes))
        except Exception as e:
            log(f"[DEBUG] Taproot skipped: {e}", print_lock, debug)
        for addr in btc_addrs:
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
                    print("WIF:", wif, flush=True)
                    print("ADDRESS:", addr, flush=True)
                    print("RECEIVED (BTC):", f"{recvd/1e8:.14f}", flush=True)
                    print("BALANCE (BTC):", f"{LIGHT_GREEN}{btc_balance_btc:.14f}{RESET}", flush=True)
                    print("="*53 + "\n", flush=True)

    # EVM checks (eth, bsc, polygon)
    for chain in ["eth","bsc","polygon"]:
        if chain not in chains:
            continue
        if stop_event.is_set():
            return
        addr = eth_address_from_priv(priv_bytes)
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
                print("PRIVATE KEY (hex):", priv_hex_0x, flush=True)
                print("ADDRESS:", addr, flush=True)
                print("COINS:", chain.upper(), flush=True)
                print("BALANCE (wei):", bal, flush=True)
                print("BALANCE (native):", f"{LIGHT_GREEN}{native_bal:.18f} {chain.upper()}{RESET}", flush=True)
                print("="*53 + "\n", flush=True)

# ----------------- HD generators using bip32utils -----------------
_zero_seen = False
_zero_lock = threading.Lock()

def read_word_file_2048(file_path):
    """
    Reads file that contains exactly 2048 words, one per line.
    Returns list of words.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        words = [line.strip() for line in f if line.strip()]
    if len(words) != 2048:
        raise RuntimeError(f"Seed file must contain exactly 2048 words (one per line). Found {len(words)}.")
    return words

def hd_12word_blocks(words, start_block=0):
    """
    Generator over 12-word blocks (non-overlapping) from words list.
    cycles when reaching end.
    yields (block_index, mnemonic_str)
    """
    blocks = len(words) // 12
    if blocks == 0:
        raise RuntimeError("Not enough words for any 12-word mnemonic.")
    i = start_block % blocks
    while not stop_event.is_set():
        base = (i % blocks) * 12
        mnemonic_words = words[base:base+12]
        mnemonic = " ".join(mnemonic_words)
        yield i, mnemonic
        i += 1

def bip39_seed_from_mnemonic(mnemonic_str, passphrase=""):
    """
    BIP-39 seed (PBKDF2 HMAC-SHA512).
    """
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac("sha512", mnemonic_str.encode("utf-8"), salt, 2048, dklen=64)

def derive_priv_for_path(seed_bytes, purpose, account=0, change=0, addr_index=0):
    """
    Using bip32utils derive: purpose' / coin' / account' / change / addr_index
    For Bitcoin mainnet coin is 0 (we use the standard flow).
    Returns private key bytes (32).
    """
    # master from seed
    root = bip32utils.BIP32Key.fromEntropy(seed_bytes)
    # purpose' (hardened)
    purpose_node = root.ChildKey(purpose + bip32utils.BIP32_HARDEN)
    coin_node = purpose_node.ChildKey(0 + bip32utils.BIP32_HARDEN)  # coin type 0 for BTC mainnet
    account_node = coin_node.ChildKey(account + bip32utils.BIP32_HARDEN)
    change_node = account_node.ChildKey(change)
    addr_node = change_node.ChildKey(addr_index)
    return addr_node.PrivateKey()

def hd_generator_from_file_12word_blocks(file_path, start_block=0, addr_index=0, passphrase=""):
    """
    For each 12-word block (non-overlapping) yields a tuple:
       (block_index, { 'p2pkh':priv_bytes, 'p2sh':priv_bytes, 'p2wpkh':priv_bytes, 'p2tr':priv_bytes }, evm_priv_bytes)
    We derive for addr_index (default 0).
    """
    words = read_word_file_2048(file_path)
    for block_idx, mnemonic in hd_12word_blocks(words, start_block=start_block):
        # generate seed
        seed = bip39_seed_from_mnemonic(mnemonic, passphrase=passphrase)
        privs = {}
        skip_block = False
        # derive each purpose
        for purpose, keyname in [(44, "p2pkh"), (49, "p2sh"), (84, "p2wpkh"), (86, "p2tr")]:
            try:
                priv_bytes = derive_priv_for_path(seed, purpose, account=0, change=0, addr_index=addr_index)
            except Exception as e:
                # derivation failed for this purpose; skip block
                skip_block = True
                break
            priv_int = int.from_bytes(priv_bytes, "big")
            if priv_int == 0 or priv_int >= SECP256K1_ORDER:
                skip_block = True
                break
            privs[keyname] = priv_bytes
        if skip_block:
            continue
        # representative evm priv: use p2wpkh (if available)
        evm_priv = privs.get("p2wpkh") or list(privs.values())[0]
        # ensure we don't emit zero twice (edge-case)
        if int.from_bytes(evm_priv, "big") == 0:
            with _zero_lock:
                global _zero_seen
                if _zero_seen:
                    continue
                _zero_seen = True
        yield (block_idx, privs, evm_priv)

# ----------------- Random keypool generator -----------------
def random_keypool_generator():
    while not stop_event.is_set():
        priv_int = secrets.randbelow(SECP256K1_ORDER - 1) + 1
        if priv_int == 0:
            with _zero_lock:
                global _zero_seen
                if _zero_seen:
                    continue
                _zero_seen = True
        priv_bytes = priv_int.to_bytes(32, "big")
        # For random mode we use same priv for all BTC formats
        yield (None, {"p2pkh": priv_bytes, "p2sh": priv_bytes, "p2wpkh": priv_bytes, "p2tr": priv_bytes}, priv_bytes)

# ----------------- CLI -----------------
def parse_args():
    p = argparse.ArgumentParser(description="Multi-chain EVM + BTC infinite scanner with retries (HD via 12-word blocks or random keypool)")
    p.add_argument("-t","--threads", type=int, default=3)
    p.add_argument("--chains", type=str, default="eth,bsc,polygon,btc")
    p.add_argument("--start", type=int, default=0,
                   help="Start block index for HD (0-based). For random mode ignored.")
    p.add_argument("--addr-index", type=int, default=0,
                   help="Address index inside each derived account (default 0).")
    p.add_argument("--delay", type=float, default=0.6)
    p.add_argument("--backlog-mult", type=int, default=4,
                   help="How many tasks per thread to keep queued (multiplier)")
    p.add_argument("--debug", action="store_true")
    p.add_argument("--file", type=str, default=None,
                   help="Path to file containing 2048 words, one per line. If provided => HD mode using non-overlapping 12-word blocks.")
    p.add_argument("--passphrase", type=str, default="", help="Optional BIP39 passphrase for mnemonics")
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

    # Choose generator
    if args.file:
        try:
            gen = hd_generator_from_file_12word_blocks(args.file, start_block=args.start, addr_index=args.addr_index, passphrase=args.passphrase)
            log(f"[INFO] Using HD generator from file {args.file} starting at block {args.start}, addr-index {args.addr_index}", print_lock, debug=args.debug, always=True)
            mode = "hd"
        except Exception as e:
            print(f"[ERROR] Failed to initialize HD generator from {args.file}: {e}", file=sys.stderr)
            return
    else:
        gen = random_keypool_generator()
        log("[INFO] Using random keypool (CSPRNG)", print_lock, debug=args.debug, always=True)
        mode = "random"

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = set()
        try:
            for block_index, privs_dict, evm_priv in gen:
                if stop_event.is_set():
                    break

                # Submit jobs: for each BTC priv, run the checks; also submit evm_priv to check EVM chains
                # Note: In HD mode privs_dict contains four keys (p2pkh/p2sh/p2wpkh/p2tr). In random mode they are identical.
                for kind, priv_bytes in privs_dict.items():
                    f = executor.submit(process_index_priv, priv_bytes, checker, chains, print_lock, args.debug)
                    futures.add(f)
                # also submit evm_priv (may duplicate a previous task if equal to one of privs_dict - that's fine)
                f = executor.submit(process_index_priv, evm_priv, checker, chains, print_lock, args.debug)
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

            # after loop: cancel outstanding futures if any
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
