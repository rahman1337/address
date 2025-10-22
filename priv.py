#!/usr/bin/env python3
"""
scan_4threads_debugcolor.py
- Chains: btc, eth, bsc, polygon
- 4 threads (1 per chain)
- BTC: blockchain.info getreceivedbyaddress -> if >0 sleep 1.1s -> addressbalance
- Sleep per address: 0.6s + jitter up to 0.4s
- Debug (-d): per-address progress and colored HTTP/Web3 status (green=OK, red=error)
- Normal: only FOUND + errors
"""
import argparse
import signal
import sys
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, getcontext
from functools import lru_cache
import requests

# crypto libs
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160
import sha3
from web3 import Web3

# high precision for formatting tiny amounts
getcontext().prec = 80

# ------------------------------
# Config & defaults
# ------------------------------
THREADS = 4
CHAINS = ["btc", "eth", "bsc", "polygon"]
RPCS = {
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc-dataseed.binance.org/",
    "polygon": "https://polygon-rpc.com/",
}
CHAIN_SYMBOL = {"eth": "ETH", "bsc": "BNB", "polygon": "MATIC", "btc": "BTC"}

SLEEP_BASE = 0.6
JITTER_MAX = 0.4
BTC_PRE_BALANCE_SLEEP = 1.1  # user requested
RETRY_MAX = 3
RETRY_BACKOFF = 1.0

SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)

# ANSI colors
CLR_GREEN = "\033[92m"
CLR_RED = "\033[91m"
CLR_RESET = "\033[0m"

# ------------------------------
# Small helpers
# ------------------------------
def sha256_bytes(b: bytes) -> bytes:
    h = SHA256.new(); h.update(b); return h.digest()

def ripemd160_bytes(b: bytes) -> bytes:
    h = RIPEMD160.new(); h.update(b); return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160_bytes(sha256_bytes(b))

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def base58_encode(b: bytes) -> str:
    zeros = len(b) - len(b.lstrip(b"\x00"))
    num = int.from_bytes(b, "big")
    chars = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(BASE58_ALPHABET[rem])
    return "1" * zeros + "".join(reversed(chars)) if chars else "1" * zeros

def base58check_encode(payload: bytes) -> str:
    chk = sha256_bytes(sha256_bytes(payload))[:4]
    return base58_encode(payload + chk)

def wif_from_priv(priv_bytes: bytes) -> str:
    return base58check_encode(b"\x80" + priv_bytes + b"\x01")

def evm_address_from_priv(priv_bytes: bytes) -> str:
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)[1:]
    k = sha3.keccak_256(); k.update(pub_uncompressed)
    return "0x" + k.digest()[-20:].hex()

# human formatting without scientific notation
def human_amount_from_raw(raw_int: int, decimals: int) -> str:
    d = Decimal(raw_int) / (Decimal(10) ** decimals)
    s = format(d, "f")  # fixed format, no exponent
    # strip trailing zeros, keep at least one digit
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    if s == "":
        s = "0"
    return s

# single sleep per address (base + jitter)
def sleep_with_jitter():
    time.sleep(SLEEP_BASE + random.uniform(0, JITTER_MAX))

# ------------------------------
# Bech32/Segwit helpers (lightweight)
# ------------------------------
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
BECH32M_CONST = 0x2bc830a3

def bech32_polymod(values):
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= GEN[i]
    return chk

def bech32_hrp_expand(hrp: str):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp: str, data, spec="bech32"):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0])
    const = 1 if spec == "bech32" else BECH32M_CONST
    ret = polymod ^ const
    return [(ret >> (5 * (5 - i))) & 31 for i in range(6)]

def bech32_encode(hrp: str, data, spec="bech32"):
    combined = data + bech32_create_checksum(hrp, data, spec=spec)
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []; maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def segwit_address(hrp: str, witver: int, witprog: bytes):
    spec = "bech32" if witver == 0 else "bech32m"
    data = [witver] + convertbits(witprog, 8, 5)
    return bech32_encode(hrp, data, spec=spec)

# ------------------------------
# BTC address generation (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR)
# ------------------------------
def make_btc_addresses(priv_bytes: bytes):
    pk = PrivateKey(priv_bytes)
    pub_comp = pk.public_key.format(compressed=True)
    p2pkh = base58check_encode(b"\x00" + hash160(pub_comp))
    redeem = b"\x00\x14" + hash160(pub_comp)
    p2sh = base58check_encode(b"\x05" + hash160(redeem))
    p2wpkh = segwit_address("bc", 0, hash160(pub_comp))
    # For P2TR (bc1p) we use x-only from uncompressed pubkey (key-path-only)
    pub_uncomp = pk.public_key.format(compressed=False)
    x_only = pub_uncomp[1:33]
    p2tr = segwit_address("bc", 1, x_only)
    return p2pkh, p2sh, p2wpkh, p2tr

# ------------------------------
# HTTP helpers with colored debug output
# ------------------------------
def colored_print_status(prefix: str, url: str, status_code: int, debug: bool):
    if not debug:
        return
    if status_code == 200:
        color = CLR_GREEN
    else:
        color = CLR_RED
    print(f"[DEBUG] {prefix} {url} -> {color}{status_code}{CLR_RESET}", flush=True)

def http_get_text(url: str, debug=False, retries=RETRY_MAX):
    last_exc = None
    for attempt in range(1, retries+1):
        try:
            r = requests.get(url, timeout=10)
            if debug:
                colored_print_status("HTTP GET", url, r.status_code, debug)
            r.raise_for_status()
            return r.text
        except Exception as e:
            last_exc = e
            if debug:
                print(f"[DEBUG] HTTP GET attempt {attempt} failed for {url}: {e}", flush=True)
            if attempt < retries:
                time.sleep(RETRY_BACKOFF)
                continue
            raise last_exc

# ------------------------------
# BTC check flow using blockchain.info (plain text)
# ------------------------------
def check_btc_address(addr: str, debug=False):
    """
    Returns (balance_sats:int, human_str:str)
    - getreceivedbyaddress (plain text) first
    - if received_sats > 0: sleep 1.1s then get addressbalance (plain text)
    """
    try:
        txt = http_get_text(f"https://blockchain.info/q/getreceivedbyaddress/{addr}", debug=debug)
        txt = txt.strip()
        if txt == "":
            return 0, "0"
        if "." in txt:
            rec_sats = int(Decimal(txt) * Decimal(1e8))
        else:
            rec_sats = int(txt)
    except Exception as e:
        if debug:
            print(f"[DEBUG] blockchain.info GET received failed for {addr}: {e}", flush=True)
        return 0, "0"

    if rec_sats == 0:
        return 0, "0"

    # user requested delay BEFORE checking balance
    time.sleep(BTC_PRE_BALANCE_SLEEP)

    try:
        txt2 = http_get_text(f"https://blockchain.info/q/addressbalance/{addr}", debug=debug)
        txt2 = txt2.strip()
        if txt2 == "":
            return 0, "0"
        bal_sats = int(txt2)
        human = human_amount_from_raw(bal_sats, 8)
        return bal_sats, human
    except Exception as e:
        if debug:
            print(f"[DEBUG] blockchain.info GET addressbalance failed for {addr}: {e}", flush=True)
        return 0, "0"

# ------------------------------
# EVM helpers
# ------------------------------
@lru_cache(maxsize=512)
def get_token_decimals_cached(w3: Web3, token_addr: str):
    try:
        abi = [{"constant":True,"inputs":[],"name":"decimals","outputs":[{"type":"uint8"}],"type":"function"}]
        return int(w3.eth.contract(address=w3.toChecksumAddress(token_addr), abi=abi).functions.decimals().call())
    except Exception:
        return 18

def evm_get_balance_with_retries(w3: Web3, addr: str, debug=False, retries=RETRY_MAX):
    last_exc = None
    rpc_url = getattr(w3.provider, "endpoint_uri", None)
    for attempt in range(1, retries+1):
        try:
            bal = w3.eth.get_balance(addr)
            if debug and rpc_url:
                print(f"[DEBUG] {w3}{' '}{rpc_url} -> {CLR_GREEN}OK{CLR_RESET}", flush=True)
            return int(bal)
        except Exception as e:
            last_exc = e
            if debug:
                rpc_msg = rpc_url or str(w3)
                print(f"[DEBUG] {rpc_msg} get_balance attempt {attempt} failed: {e}", flush=True)
            if attempt < retries:
                time.sleep(RETRY_BACKOFF)
    raise last_exc

def evm_get_erc20_with_retries(w3: Web3, addr: str, token_addr: str, debug=False, retries=RETRY_MAX):
    abi = [{"constant": True, "inputs":[{"name":"_owner","type":"address"}],
            "name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"}]
    token = w3.eth.contract(address=w3.toChecksumAddress(token_addr), abi=abi)
    last_exc = None
    rpc_url = getattr(w3.provider, "endpoint_uri", None)
    for attempt in range(1, retries+1):
        try:
            res = int(token.functions.balanceOf(w3.toChecksumAddress(addr)).call())
            if debug and rpc_url:
                print(f"[DEBUG] {rpc_url} erc20 {token_addr} -> {CLR_GREEN}OK{CLR_RESET}", flush=True)
            return res
        except Exception as e:
            last_exc = e
            if debug:
                rpc_msg = rpc_url or str(w3)
                print(f"[DEBUG] {rpc_msg} erc20 attempt {attempt} failed for {token_addr}: {e}", flush=True)
            if attempt < retries:
                time.sleep(RETRY_BACKOFF)
    raise last_exc

# ------------------------------
# Index provider (shared)
# ------------------------------
class IndexProvider:
    def __init__(self, start=1):
        self._lock = threading.Lock()
        if not (1 <= start < SECP256K1_ORDER):
            raise ValueError("start out of range")
        self._i = start
    def next_index(self):
        with self._lock:
            v = self._i
            self._i += 1
            if self._i >= SECP256K1_ORDER:
                self._i = 1
            return v

# ------------------------------
# Worker per chain
# ------------------------------
stop_event = threading.Event()
_shutdown_printed = threading.Event()
progress = {"last_idx": 0}

def worker_chain(chain: str, idx_provider: IndexProvider, web3s: dict, print_lock: threading.Lock, debug: bool):
    """
    Each thread pulls next index and checks only its assigned chain.
    """
    while not stop_event.is_set():
        idx = idx_provider.next_index()
        progress["last_idx"] = idx
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        wif = wif_from_priv(priv_bytes)

        if debug:
            with print_lock:
                print(f"[DEBUG] chain={chain} idx={idx} priv=0x{priv_hex[:24]}...", flush=True)

        if chain == "btc":
            try:
                p2pkh, p2sh, p2wpkh, p2tr = make_btc_addresses(priv_bytes)
            except Exception as e:
                with print_lock:
                    print(f"[ERROR] BTC address generation failed idx={idx}: {e}", flush=True)
                sleep_with_jitter()
                continue

            for addr in (p2pkh, p2sh, p2wpkh, p2tr):
                if addr is None:
                    continue
                try:
                    raw_sats, human = check_btc_address(addr, debug=debug)
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] BTC check failed for {addr} idx={idx}: {e}", flush=True)
                    raw_sats, human = 0, "0"
                if raw_sats and int(raw_sats) > 0:
                    with print_lock:
                        print("\n" + "="*80)
                        print("!!!!! FOUND BTC ADDRESS WITH FUNDS !!!!!")
                        print("PRIVATE KEY (hex):", "0x" + priv_hex)
                        print("WIF:", wif)
                        print("ADDRESS:", addr)
                        print("BALANCE (sats):", int(raw_sats))
                        print("BALANCE (BTC):", f"{CLR_GREEN}{human}{CLR_RESET}")
                        print("="*80 + "\n", flush=True)
                sleep_with_jitter()

        else:
            w3 = web3s.get(chain)
            if w3 is None:
                with print_lock:
                    print(f"[ERROR] No RPC configured for chain {chain}", flush=True)
                sleep_with_jitter()
                continue

            try:
                addr = w3.toChecksumAddress(evm_address_from_priv(priv_bytes))
            except Exception as e:
                with print_lock:
                    print(f"[ERROR] invalid derived address for {chain} idx={idx}: {e}", flush=True)
                sleep_with_jitter()
                continue

            native_raw = 0
            try:
                native_raw = evm_get_balance_with_retries(w3, addr, debug=debug)
            except Exception as e:
                with print_lock:
                    print(f"[ERROR] {chain} native balance failed for {addr} idx={idx}: {e}", flush=True)
                native_raw = 0

            token_results = {}
            for sym, taddr in ERC20_TO_CHECK.get(chain, {}).items():
                try:
                    raw = evm_get_erc20_with_retries(w3, addr, taddr, debug=debug)
                    if raw and int(raw) > 0:
                        decs = get_token_decimals_cached(w3, taddr)
                        human_tok = human_amount_from_raw(int(raw), decs)
                        token_results[sym] = (int(raw), decs, human_tok)
                except Exception as e:
                    with print_lock:
                        if debug:
                            print(f"[ERROR] {chain} token {sym} check failed for {addr} idx={idx}: {e}", flush=True)

            token_positive = any(raw > 0 for (raw, _, _) in token_results.values()) if token_results else False
            if (native_raw and int(native_raw) > 0) or token_positive:
                with print_lock:
                    print("\n" + "="*90)
                    print(f"!!!!! FOUND {chain.upper()} PRIVATE KEY WITH FUNDS !!!!!")
                    print("PRIVATE KEY (hex):", "0x" + priv_hex)
                    print("Derived address:", addr)
                    if native_raw and int(native_raw) > 0:
                        native_human = human_amount_from_raw(int(native_raw), 18)
                        print(f"{chain.upper()} native (wei): {int(native_raw)}")
                        print(f"{chain.upper()} native ({CHAIN_SYMBOL.get(chain, chain.upper())}): {CLR_GREEN}{native_human}{CLR_RESET}")
                    else:
                        print(f"{chain.upper()} native (wei): 0")
                    if token_results:
                        print("Token balances:")
                        for s, (raw, decs, human_tok) in token_results.items():
                            print(f"  {s}: raw={raw} decimals={decs} human={CLR_GREEN}{human_tok}{CLR_RESET}")
                    print("="*90 + "\n", flush=True)
            sleep_with_jitter()

# ------------------------------
# Progress thread (debug only)
# ------------------------------
def progress_worker(print_lock: threading.Lock, debug: bool):
    while not stop_event.is_set():
        if debug:
            with print_lock:
                print(f"[DEBUG] last_idx: {progress.get('last_idx', 0)}", end="\r", flush=True)
        time.sleep(2.5)

# ------------------------------
# Main
# ------------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("-d", "--debug", action="store_true", help="debug mode (progress + colored HTTP/Web3 output)")
    p.add_argument("--start", type=int, default=1, help="start index (default 1)")
    args = p.parse_args()
    debug = args.debug

    # prepare web3 instances
    web3s = {}
    for ch, rpc in RPCS.items():
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
            web3s[ch] = w3
        except Exception as e:
            print(f"[ERROR] Failed to create Web3 for {ch}: {e}", flush=True)

    idx_provider = IndexProvider(start=args.start)
    print_lock = threading.Lock()

    def _signal(sig, frame):
        if not _shutdown_printed.is_set():
            with print_lock:
                print("\n[INFO] Interrupted. Stopping workers...", flush=True)
            _shutdown_printed.set()
        stop_event.set()
        time.sleep(0.1)

    signal.signal(signal.SIGINT, _signal)
    signal.signal(signal.SIGTERM, _signal)

    # start debug progress thread
    prog = threading.Thread(target=progress_worker, args=(print_lock, debug), daemon=True)
    prog.start()

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for chain in CHAINS:
            ex.submit(worker_chain, chain, idx_provider, web3s, print_lock, debug)
        try:
            while not stop_event.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            stop_event.set()
        finally:
            ex.shutdown(wait=True)

    with print_lock:
        print("\n[INFO] All workers stopped. Exiting.", flush=True)

if __name__ == "__main__":
    main()