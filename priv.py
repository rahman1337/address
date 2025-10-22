#!/usr/bin/env python3
"""
scan_final_bech32_fixed.py
- Chains: btc (1,3,bc1q,bc1p), eth, bsc, polygon
- 4 threads (one per chain)
- BTC: blockchain.info getreceivedbyaddress -> if >0 sleep 1.1s -> blockchain.info addressbalance
- Sleep per address: 0.6s + jitter up to 0.4s
- FOUND prints always (bold green) for any raw > 0
- Debug (-d): per-address progress + colored HTTP/Web3 status (green OK, red error)
Requirements: pip install coincurve pysha3 web3 requests pycryptodome bech32
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

from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160
import sha3
from web3 import Web3
import bech32  # pip package providing bech32_encode & convertbits

# show tiny decimal values exactly
getcontext().prec = 80

# -------------------------
# Config
# -------------------------
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
BTC_PRE_BALANCE_SLEEP = 1.1
RETRY_MAX = 3
RETRY_BACKOFF = 1.0

SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)

# ANSI colors
BOLD_GREEN = "\033[1;32m"
CLR_GREEN = "\033[92m"
CLR_RED = "\033[91m"
CLR_RESET = "\033[0m"

# -------------------------
# Utilities
# -------------------------
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

def human_amount_from_raw(raw_int: int, decimals: int) -> str:
    d = Decimal(raw_int) / (Decimal(10) ** decimals)
    s = format(d, "f")
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    if s == "":
        s = "0"
    return s

def sleep_with_jitter():
    time.sleep(SLEEP_BASE + random.uniform(0, JITTER_MAX))

# -------------------------
# Bech32 helpers (using bech32 package correctly)
# -------------------------
def bech32_encode_segwit(hrp: str, witver: int, witprog: bytes) -> str:
    # convertbytes/convertbits: bech32.convertbits(data, frombits, tobits, pad=True)
    converted = bech32.convertbits(witprog, 8, 5)
    if converted is None:
        raise ValueError("convertbits failed")
    data = [witver] + converted
    return bech32.bech32_encode(hrp, data)

# -------------------------
# BTC address derivation (all types)
# -------------------------
def make_btc_addresses(priv_bytes: bytes):
    pk = PrivateKey(priv_bytes)
    pub_comp = pk.public_key.format(compressed=True)
    p2pkh = base58check_encode(b"\x00" + hash160(pub_comp))
    redeem = b"\x00\x14" + hash160(pub_comp)
    p2sh = base58check_encode(b"\x05" + hash160(redeem))
    # p2wpkh bech32 (bc1q...)
    p2wpkh = bech32_encode_segwit("bc", 0, hash160(pub_comp))
    # p2tr bech32m (bc1p...)
    # use x-only pubkey (uncompressed pubkey's X coordinate)
    pub_uncomp = pk.public_key.format(compressed=False)
    x_only = pub_uncomp[1:33]
    p2tr = bech32_encode_segwit("bc", 1, x_only)
    return p2pkh, p2sh, p2wpkh, p2tr

# -------------------------
# HTTP helpers with debug coloring
# -------------------------
def colored_debug_http(url: str, status: int, debug: bool, prefix: str = "HTTP GET"):
    if not debug:
        return
    color = CLR_GREEN if status == 200 else CLR_RED
    print(f"[DEBUG] {prefix} {url} -> {color}{status}{CLR_RESET}", flush=True)

def http_get_text(url: str, debug=False, retries=RETRY_MAX):
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, timeout=10)
            colored_debug_http(url, r.status_code, debug)
            r.raise_for_status()
            return r.text
        except Exception as e:
            last_exc = e
            if debug:
                print(f"[DEBUG] HTTP GET attempt {attempt} failed for {url}: {e}", flush=True)
            if attempt < retries:
                time.sleep(RETRY_BACKOFF)
    raise last_exc

# -------------------------
# BTC checker using blockchain.info only
# -------------------------
class BTCChecker:
    def __init__(self, session: requests.Session, debug: bool = False):
        self.session = session
        self.debug = debug

    def get_received_sats(self, addr: str) -> int:
        url = f"https://blockchain.info/q/getreceivedbyaddress/{addr}"
        try:
            txt = http_get_text(url, debug=self.debug)
            txt = txt.strip()
            if txt == "":
                return 0
            # text may be integer (sats) or decimal BTC
            if "." in txt:
                return int(Decimal(txt) * Decimal(1e8))
            return int(txt)
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] getreceived error for {addr}: {e}", flush=True)
            return 0

    def get_balance_sats(self, addr: str) -> int:
        # user-requested delay before balance check
        time.sleep(BTC_PRE_BALANCE_SLEEP)
        url = f"https://blockchain.info/q/addressbalance/{addr}"
        try:
            txt = http_get_text(url, debug=self.debug)
            txt = txt.strip()
            if txt == "":
                return 0
            return int(txt)
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] addressbalance error for {addr}: {e}", flush=True)
            return 0

# -------------------------
# EVM helpers
# -------------------------
@lru_cache(maxsize=512)
def get_token_decimals_cached(w3: Web3, token_addr: str) -> int:
    try:
        abi = [{"constant": True, "inputs": [], "name": "decimals", "outputs": [{"type":"uint8"}], "type":"function"}]
        return int(w3.eth.contract(address=w3.toChecksumAddress(token_addr), abi=abi).functions.decimals().call())
    except Exception:
        return 18

def evm_get_balance_with_retries(w3: Web3, addr: str, debug=False, retries=RETRY_MAX):
    last_exc = None
    rpc_url = getattr(w3.provider, "endpoint_uri", None)
    for attempt in range(1, retries + 1):
        try:
            bal = w3.eth.get_balance(addr)
            if debug:
                print(f"[DEBUG] RPC {rpc_url or w3} get_balance -> {CLR_GREEN}OK{CLR_RESET}", flush=True)
            return int(bal)
        except Exception as e:
            last_exc = e
            if debug:
                print(f"[DEBUG] RPC {rpc_url or w3} get_balance attempt {attempt} failed: {e}", flush=True)
            if attempt < retries:
                time.sleep(RETRY_BACKOFF)
    raise last_exc

def evm_get_erc20_with_retries(w3: Web3, addr: str, token_addr: str, debug=False, retries=RETRY_MAX):
    abi = [{"constant": True, "inputs":[{"name":"_owner","type":"address"}],
            "name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],"type":"function"}]
    token = w3.eth.contract(address=w3.toChecksumAddress(token_addr), abi=abi)
    last_exc = None
    rpc_url = getattr(w3.provider, "endpoint_uri", None)
    for attempt in range(1, retries + 1):
        try:
            res = int(token.functions.balanceOf(w3.toChecksumAddress(addr)).call())
            if debug:
                print(f"[DEBUG] RPC {rpc_url or w3} erc20 {token_addr} -> {CLR_GREEN}OK{CLR_RESET}", flush=True)
            return res
        except Exception as e:
            last_exc = e
            if debug:
                print(f"[DEBUG] RPC {rpc_url or w3} erc20 attempt {attempt} failed for {token_addr}: {e}", flush=True)
            if attempt < retries:
                time.sleep(RETRY_BACKOFF)
    raise last_exc

# -------------------------
# Index provider
# -------------------------
class IndexProvider:
    def __init__(self, start: int = 1):
        self._lock = threading.Lock()
        if not (1 <= start < SECP256K1_ORDER):
            raise ValueError("start out of range")
        self._i = start
    def next_index(self) -> int:
        with self._lock:
            v = self._i
            self._i += 1
            if self._i >= SECP256K1_ORDER:
                self._i = 1
            return v

# -------------------------
# Worker (one thread per chain)
# -------------------------
stop_event = threading.Event()
_shutdown_printed = threading.Event()
progress = {"last_idx": 0}
last_priv_hex = None
last_priv_lock = threading.Lock()

def print_found(chain_label: str, lines: list):
    print("\n" + BOLD_GREEN + "=" * 80 + CLR_RESET)
    print("\n".join(lines))
    print(BOLD_GREEN + "=" * 80 + CLR_RESET + "\n")

def worker_chain(chain: str, idx_provider: IndexProvider, btc_checker: BTCChecker, web3s: dict, evm_checkers: dict, print_lock: threading.Lock, debug: bool):
    global last_priv_hex
    while not stop_event.is_set():
        idx = idx_provider.next_index()
        progress["last_idx"] = idx
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        with last_priv_lock:
            last_priv_hex = priv_hex

        if debug:
            with print_lock:
                print(f"[DEBUG] started chain={chain} idx={idx} priv=0x{priv_hex[:24]}...", flush=True)

        try:
            # BTC path
            if chain == "btc":
                try:
                    p2pkh, p2sh, p2wpkh, p2tr = make_btc_addresses(priv_bytes)
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] BTC address derivation failed idx={idx}: {e}", flush=True)
                    sleep_with_jitter()
                    continue

                for addr in (p2pkh, p2sh, p2wpkh, p2tr):
                    if addr is None:
                        continue
                    try:
                        rec = btc_checker.get_received_sats(addr)
                    except Exception as e:
                        with print_lock:
                            print(f"[ERROR] BTC get_received failed for {addr} idx={idx}: {e}", flush=True)
                        rec = 0
                    if rec and int(rec) > 0:
                        # sleep before balance, then check balance (both via blockchain.info)
                        try:
                            bal = btc_checker.get_balance_sats(addr)
                        except Exception as e:
                            with print_lock:
                                print(f"[ERROR] BTC get_balance failed for {addr} idx={idx}: {e}", flush=True)
                            bal = 0
                        if int(bal) > 0:
                            human = human_amount_from_raw(int(bal), 8)
                            lines = [
                                f"!!!!! FOUND BTC ADDRESS WITH FUNDS !!!!!",
                                f"PRIVATE KEY (hex): 0x{priv_hex}",
                                f"WIF: {wif_from_priv(priv_bytes)}",
                                f"ADDRESS: {addr}",
                                f"BALANCE (sats): {int(bal)}",
                                f"BALANCE (BTC): {human}",
                            ]
                            with print_lock:
                                print_found("btc", lines)
                    # single sleep per address
                    sleep_with_jitter()

            # EVM path
            else:
                w3 = web3s.get(chain)
                checker = evm_checkers.get(chain)
                if w3 is None or checker is None:
                    with print_lock:
                        print(f"[ERROR] No RPC configured for chain {chain}", flush=True)
                    sleep_with_jitter()
                    continue

                try:
                    addr_checksum = w3.toChecksumAddress(evm_address_from_priv(priv_bytes))
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] invalid derived address for {chain} idx={idx}: {e}", flush=True)
                    sleep_with_jitter()
                    continue

                # native balance (wei)
                native_raw = 0
                try:
                    native_raw = evm_get_balance_with_retries(w3, addr_checksum, debug=debug)
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] {chain} native balance failed for {addr_checksum} idx={idx}: {e}", flush=True)
                    native_raw = 0

                # ERC20s (if configured)
                token_results = {}
                for sym, taddr in {}.items():  # empty by default
                    try:
                        raw = evm_get_erc20_with_retries(w3, addr_checksum, taddr, debug=debug)
                        if raw and int(raw) > 0:
                            decs = get_token_decimals_cached(w3, taddr)
                            token_results[sym] = (int(raw), decs, human_amount_from_raw(int(raw), decs))
                    except Exception as e:
                        if debug:
                            with print_lock:
                                print(f"[DEBUG] {chain} token {sym} check failed for {addr_checksum} idx={idx}: {e}", flush=True)

                token_positive = any(raw > 0 for (raw, _, _) in token_results.values()) if token_results else False
                if (native_raw and int(native_raw) > 0) or token_positive:
                    lines = [f"!!!!! FOUND {chain.upper()} PRIVATE KEY WITH FUNDS !!!!!",
                             f"PRIVATE KEY (hex): 0x{priv_hex}",
                             f"DERIVED ADDRESS: {addr_checksum}"]
                    if native_raw and int(native_raw) > 0:
                        native_human = human_amount_from_raw(int(native_raw), 18)
                        lines.append(f"NATIVE (wei): {int(native_raw)}")
                        lines.append(f"NATIVE ({CHAIN_SYMBOL.get(chain, chain.upper())}): {native_human}")
                    if token_results:
                        lines.append("Token balances:")
                        for s, (raw, decs, human_tok) in token_results.items():
                            lines.append(f"  {s}: raw={raw} decimals={decs} human={human_tok}")
                    with print_lock:
                        print_found(chain, lines)

                sleep_with_jitter()

        except Exception as e:
            # keep worker alive; report debug
            with print_lock:
                if debug:
                    print(f"[DEBUG] Worker error idx={idx}: {CLR_RED}{e}{CLR_RESET}", flush=True)
                else:
                    print(f"[ERROR] Worker error idx={idx}: {e}", flush=True)
            sleep_with_jitter()

# -------------------------
# Progress thread (debug)
# -------------------------
def progress_worker(print_lock: threading.Lock, debug: bool):
    while not stop_event.is_set():
        if debug:
            with print_lock:
                print(f"[DEBUG] last_idx: {progress.get('last_idx', 0)}", end="\r", flush=True)
        time.sleep(2.5)

# -------------------------
# Main
# -------------------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("-d", "--debug", action="store_true", help="debug/progress mode")
    p.add_argument("--start", type=int, default=1, help="start index")
    args = p.parse_args()
    debug = args.debug

    # prepare web3 instances
    web3s = {}
    evm_checkers = {}
    for ch, rpc in RPCS.items():
        try:
            w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
            web3s[ch] = w3
            evm_checkers[ch] = EVMChecker(w3, debug=debug)
        except Exception as e:
            print(f"[ERROR] Failed to create Web3 for {ch}: {e}", flush=True)

    idx_provider = IndexProvider(start=args.start)
    session = requests.Session()
    btc_checker = BTCChecker(session, debug=debug)
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

    # start progress thread
    prog = threading.Thread(target=progress_worker, args=(print_lock, debug), daemon=True)
    prog.start()

    # start 4 workers (one per chain)
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for chain in CHAINS:
            ex.submit(worker_chain, chain, idx_provider, btc_checker, web3s, evm_checkers, print_lock, debug)
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