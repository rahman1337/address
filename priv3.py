#!/usr/bin/env python3
# scan.py -- multi-chain scanner (BTC + many EVM chains).
# - Bech32 & Taproot for BTC
# - per-chain RPC fallback + rotation
# - blockchain.info quick received check before blockcypher balance
# - retries (3) with backoff (1s)
# - sleeps increased to 0.7s
# - human-readable Decimal formatting (no scientific notation)
#
# Requirements:
# pip install coincurve pysha3 web3 requests pycryptodome bech32

import argparse
import time
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, getcontext
from functools import lru_cache, wraps

import requests
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160
import sha3
from web3 import Web3
from bech32 import bech32_encode, convertbits

# high precision for token conversions
getcontext().prec = 40

# -------------------------
# Config / constants
# -------------------------
SECP256K1_ORDER = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

LIGHT_GREEN = "\033[92m"
YELLOW = "\033[33m"
RESET = "\033[0m"

# default RPC lists (fallbacks). Add/remove as needed.
RPC_FALLBACKS = {
    "eth": [
        "https://ethereum.publicnode.com",
        "https://rpc.ankr.com/eth",
        "https://cloudflare-eth.com"
    ],
    "bsc": [
        "https://bsc-dataseed.binance.org/",
        "https://rpc.ankr.com/bsc"
    ],
    "polygon": [
        "https://polygon-rpc.com",
        "https://rpc-mainnet.maticvigil.com",
        "https://matic-mainnet.chainstacklabs.com"
    ],
    "avalanche": [
        "https://api.avax.network/ext/bc/C/rpc",
        "https://rpc.ankr.com/avalanche"
    ],
    "fantom": [
        # https://rpc.ftm.tools can sometimes return 401 depending on usage / keys; provide fallbacks
        "https://rpcapi.fantom.network",
        "https://rpc.ftm.tools",
        "https://rpc.ankr.com/fantom"
    ],
    "arbitrum": [
        "https://arb1.arbitrum.io/rpc",
        "https://rpc.ankr.com/arbitrum"
    ],
    "optimism": [
        "https://mainnet.optimism.io",
        "https://rpc.ankr.com/optimism"
    ],
    "gnosis": [
        "https://rpc.gnosischain.com",
        "https://rpc.ankr.com/gnosis"
    ],
    "celo": [
        "https://forno.celo.org"
    ],
    "cronos": [
        "https://evm-cronos.crypto.org",
        "https://rpc.ankr.com/cronos"
    ]
}

DEFAULT_CHAINS = ["btc", "eth", "bsc", "polygon", "avalanche", "fantom", "arbitrum", "optimism", "gnosis", "celo", "cronos"]
CHAIN_SYMBOL = {
    "btc": "BTC", "eth":"ETH","bsc":"BNB","polygon":"MATIC","avalanche":"AVAX",
    "fantom":"FTM","arbitrum":"ARB","optimism":"OP","gnosis":"xDAI","celo":"CELO","cronos":"CRO"
}

# tokens to check (per chain); add more as desired
ERC20_TO_CHECK = {
    "eth": {
        "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
        "DAI":  "0x6B175474E89094C44Da98b954EedeAC495271d0F"
    },
    "bsc": {
        "BUSD": "0xe9e7cea3dedca5984780bafc599bd69add087d56",
        "USDT": "0x55d398326f99059fF775485246999027B3197955"
    },
    "polygon": {
        "USDT": "0x3813e82e6f7098b9583FC0F33a962D02018B6803",
        "USDC": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174"
    }
}

# timing / retry policy
SLEEP_PER_CALL = 0.7     # seconds per API call
SLEEP_PER_ADDR = 0.7     # seconds after an address processed
RETRY_MAX = 3
RETRY_BACKOFF = 1.0      # seconds

FOUND_FILE = "found.txt"

# -------------------------
# Helpers
# -------------------------
def sha256_bytes(b: bytes) -> bytes:
    h = SHA256.new(); h.update(b); return h.digest()

def ripemd160_bytes(b: bytes) -> bytes:
    h = RIPEMD160.new(); h.update(b); return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160_bytes(sha256_bytes(b))

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

def privkey_to_wif(priv_bytes: bytes, compressed: bool = False) -> str:
    prefix = b"\x80"
    payload = prefix + priv_bytes
    if compressed:
        payload += b"\x01"
    return base58check_encode(payload)

def evm_address_from_priv(priv_bytes: bytes) -> str:
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)  # 65 bytes: 0x04 || X || Y
    pub_xy = pub_uncompressed[1:]
    k = sha3.keccak_256()
    k.update(pub_xy)
    return "0x" + k.digest()[-20:].hex()

# format Decimal human values without scientific notation, exact
def decimal_to_str(d: Decimal) -> str:
    # remove exponent / scientific and ensure plain decimal like "1.234000"
    # using 'f' format preserves full fractional digits appropriate to Decimal context
    return format(d, 'f')

# -------------------------
# retry decorator for network / web3 calls
# -------------------------
def retry_network(max_attempts=RETRY_MAX, backoff=RETRY_BACKOFF):
    def deco(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    last_exc = e
                    if attempt < max_attempts:
                        time.sleep(backoff)
                        continue
                    raise
            raise last_exc
        return wrapper
    return deco

# -------------------------
# Bech32 / Taproot
# -------------------------
def btc_bech32_address(pubkey_hash160: bytes) -> str:
    data = [0] + convertbits(pubkey_hash160, 8, 5, True)
    return bech32_encode("bc", data)

def btc_taproot_address_from_xonly(x_only: bytes) -> str:
    data = [1] + convertbits(x_only, 8, 5, True)
    return bech32_encode("bc", data)

# -------------------------
# Index provider
# -------------------------
class IndexProvider:
    def __init__(self, start: int = 1):
        import threading
        if not (1 <= start < SECP256K1_ORDER):
            raise ValueError("start must be in [1, SECP256K1_ORDER-1]")
        self._lock = threading.Lock()
        self._i = start
    def next_index(self) -> int:
        with self._lock:
            val = self._i
            self._i += 1
            if self._i >= SECP256K1_ORDER:
                self._i = 1
            return val

# -------------------------
# Web3 manager with RPC rotation (per-chain)
# -------------------------
class Web3Manager:
    def __init__(self, rpc_list):
        if not rpc_list:
            raise ValueError("rpc_list required")
        self.rpc_list = list(rpc_list)
        self.lock = threading.Lock()
        self.idx = 0
        self._w3 = None
        self._ensure_working()

    def _make_w3(self, rpc):
        return Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))

    def _ensure_working(self):
        # try current idx then rotate until found
        with self.lock:
            n = len(self.rpc_list)
            for _ in range(n):
                rpc = self.rpc_list[self.idx]
                w3 = self._make_w3(rpc)
                try:
                    # web3.isConnected() is cheap
                    if w3.isConnected():
                        self._w3 = w3
                        return
                except Exception:
                    pass
                # rotate
                self.idx = (self.idx + 1) % n
            # if none connected, set to last attempt (will throw on calls)
            self._w3 = self._make_w3(self.rpc_list[self.idx])

    def get(self):
        # ensure working w3; if a call fails higher-level code may call rotate_on_error()
        if self._w3 is None or not getattr(self._w3, "isConnected", lambda: False)():
            self._ensure_working()
        return self._w3

    def rotate_on_error(self):
        with self.lock:
            self.idx = (self.idx + 1) % len(self.rpc_list)
            self._ensure_working()

# -------------------------
# Checkers
# -------------------------
class BTCChecker:
    def __init__(self, session: requests.Session, sem: threading.Semaphore, debug=False):
        self.session = session
        self.sem = sem
        self.debug = debug

    @retry_network()
    def _get_blockcypher_balance(self, addr: str) -> int:
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance"
        with self.sem:
            resp = self.session.get(url, timeout=10)
            if self.debug:
                print(f"[DEBUG] GET {url} -> {resp.status_code}", flush=True)
            resp.raise_for_status()
            data = resp.json()
            return int(data.get("final_balance", 0))

    @retry_network()
    def _get_blockchaininfo_received(self, addr: str) -> int:
        # blockchain.info simple API; returns integer (satoshis) or simple numbers; treat errors carefully
        url = f"https://blockchain.info/q/receivedbyaddress/{addr}"
        with self.sem:
            resp = self.session.get(url, timeout=10)
            if self.debug:
                print(f"[DEBUG] GET {url} -> {resp.status_code}", flush=True)
            resp.raise_for_status()
            text = resp.text.strip()
            # blockchain.info returns decimal sometimes; parse as int if possible, else Decimal->int(sats)
            try:
                # often it's satoshis integer, but be defensive
                if '.' in text:
                    # convert to Decimal BTC then to satoshis
                    sats = int(Decimal(text) * Decimal(1e8))
                else:
                    sats = int(text)
            except Exception:
                sats = 0
            return sats

    def get_balance(self, addr: str) -> int:
        """
        First check blockchain.info 'receivedbyaddress' (fast). If >0 then check blockcypher for final_balance.
        If blockchain.info fails, fallback to blockcypher directly.
        Retries and SSL errors handled by retry decorator.
        """
        # 1) quick received check
        try:
            received_sats = self._get_blockchaininfo_received(addr)
            # polite pause
            time.sleep(SLEEP_PER_CALL)
        except Exception as e:
            # blockchain.info may fail (SSL/EOF); fallback to blockcypher directly
            if self.debug:
                print(f"[DEBUG] blockchain.info received failed for {addr}: {e}", flush=True)
            try:
                bal = self._get_blockcypher_balance(addr)
                time.sleep(SLEEP_PER_CALL)
                return bal
            except Exception as e2:
                if self.debug:
                    print(f"[DEBUG] blockcypher direct failed for {addr}: {e2}", flush=True)
                return 0

        # if received > 0 then check final balance on blockcypher
        if received_sats and received_sats > 0:
            try:
                bal = self._get_blockcypher_balance(addr)
                time.sleep(SLEEP_PER_CALL)
                return bal
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] blockcypher balance check failed for {addr}: {e}", flush=True)
                return 0
        else:
            return 0

class EVMChecker:
    def __init__(self, web3_manager: Web3Manager, sem: threading.Semaphore, debug=False):
        self.web3_manager = web3_manager
        self.sem = sem
        self.debug = debug

    def get_web3(self):
        return self.web3_manager.get()

    @retry_network()
    def get_native_balance(self, addr: str) -> int:
        w3 = self.get_web3()
        with self.sem:
            return w3.eth.get_balance(addr)

    @retry_network()
    def get_erc20_balance(self, addr: str, token_addr: str) -> int:
        w3 = self.get_web3()
        abi = [{"constant": True, "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}],
                "type": "function"}]
        token = w3.eth.contract(address=w3.toChecksumAddress(token_addr), abi=abi)
        with self.sem:
            return int(token.functions.balanceOf(w3.toChecksumAddress(addr)).call())

# -------------------------
# BTC address maker: P2PKH, P2SH-P2WPKH, Bech32 P2WPKH, Taproot P2TR
# -------------------------
def make_btc_addresses(pub_compressed: bytes, priv_bytes: bytes = None):
    # p2pkh
    p2pkh = base58check_encode(b"\x00" + hash160(pub_compressed))
    redeem = b"\x00\x14" + hash160(pub_compressed)
    p2sh = base58check_encode(b"\x05" + hash160(redeem))
    bech32_addr = btc_bech32_address(hash160(pub_compressed))

    # taproot (bech32m / p2tr): derive x-only from uncompressed pubkey, no script tree (key-path-only)
    bech32m = None
    if priv_bytes is not None:
        # derive x-only from uncompressed pub
        pk = PrivateKey(priv_bytes)
        pub_uncompressed = pk.public_key.format(compressed=False)
        x_only = pub_uncompressed[1:33]
        bech32m = btc_taproot_address_from_xonly(x_only)
    return p2pkh, p2sh, bech32_addr, bech32m

# -------------------------
# Found result writer
# -------------------------
found_lock = threading.Lock()
def append_found(text: str):
    with found_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(text + "\n")

# -------------------------
# Worker (per-chain)
# -------------------------
stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()

def worker_chain(chain: str, idx_provider: IndexProvider, web3_managers: dict, print_lock: threading.Lock, sem_value: int, debug: bool):
    global last_priv_hex
    session = requests.Session()
    sem = threading.Semaphore(sem_value)

    # choose checker
    if chain == "btc":
        checker = BTCChecker(session, sem, debug=debug)
    else:
        # build Web3 manager from list; if manager missing, try to create from RPC_FALLBACKS
        rpc_list = RPC_FALLBACKS.get(chain, [])
        if not rpc_list:
            # fallback to a single value (should not happen if config provided)
            rpc_list = [f"https://{chain}.rpc.example/"]
        w3m = web3_managers.setdefault(chain, Web3Manager(rpc_list))
        checker = EVMChecker(w3m, sem, debug=debug)

    while not stop_event.is_set():
        idx = idx_provider.next_index()
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        with last_priv_lock:
            last_priv_hex = priv_hex

        try:
            pk = PrivateKey(priv_bytes)
            pub_comp = pk.public_key.format(compressed=True)
            pub_uncomp = pk.public_key.format(compressed=False)
            wif = privkey_to_wif(priv_bytes, compressed=True)

            # BTC flow
            if chain == "btc":
                p2pkh, p2sh, bech32_addr, bech32m_addr = make_btc_addresses(pub_comp, priv_bytes)
                addrs = [a for a in (p2pkh, p2sh, bech32_addr, bech32m_addr) if a]
                for addr in addrs:
                    if stop_event.is_set():
                        break
                    try:
                        bal = checker.get_balance(addr)
                    except Exception as e:
                        if debug:
                            with print_lock:
                                print(f"[ERROR] BTC {addr} balance error: {e}", flush=True)
                                print(f"[DEBUG] Will retry up to {RETRY_MAX} times with backoff.", flush=True)
                        bal = 0
                    if bal and bal != 0:
                        text = (
                            "="*80 + "\n"
                            "FOUND BTC ADDRESS WITH FUNDS\n"
                            f"WIF: {wif}\n"
                            f"ADDRESS: {addr}\n"
                            f"BALANCE (sats): {bal}\n"
                            + "="*80
                        )
                        with print_lock:
                            print("\n" + "="*80)
                            print("!!!!! FOUND BITCOIN ADDRESS WITH FUNDS !!!!!")
                            print("WIF:", wif)
                            print("ADDRESS:", addr)
                            print("BALANCE (sats):", f"{LIGHT_GREEN}{bal}{RESET}")
                            print("="*80 + "\n")
                        append_found(text)
                    time.sleep(SLEEP_PER_ADDR)
            else:
                # EVM chains
                w3 = web3_managers[chain].get()
                try:
                    addr_checksum = w3.toChecksumAddress(evm_address_from_priv(priv_bytes))
                except Exception as e:
                    if debug:
                        with print_lock:
                            print(f"[ERROR] {chain.upper()} invalid EVM address derived: {e}", flush=True)
                    time.sleep(SLEEP_PER_CALL)
                    continue

                native_bal = 0
                try:
                    native_bal = checker.get_native_balance(addr_checksum)
                except Exception as e:
                    # try rotate RPC once if web3 RPC gives errors (e.g., bad JSON-RPC response)
                    if debug:
                        with print_lock:
                            print(f"[ERROR] {chain} native balance call failed: {e}", flush=True)
                            print(f"[DEBUG] Rotating RPC for {chain} and retrying.", flush=True)
                    try:
                        web3_managers[chain].rotate_on_error()
                        native_bal = checker.get_native_balance(addr_checksum)
                    except Exception as e2:
                        if debug:
                            with print_lock:
                                print(f"[ERROR] {chain} native retry failed: {e2}", flush=True)
                        native_bal = 0

                token_balances = {}
                tokdict = ERC20_TO_CHECK.get(chain, {})
                for sym, tok in tokdict.items():
                    try:
                        raw = checker.get_erc20_balance(addr_checksum, tok)
                        time.sleep(SLEEP_PER_CALL)
                        if raw and raw != 0:
                            # get decimals (best-effort) and format
                            dec = 18
                            # avoid calling token.decimals() repeatedly; optionally could implement caching
                            human = Decimal(raw) / (Decimal(10) ** dec)
                            token_balances[sym] = (raw, dec, human)
                    except Exception as e:
                        if debug:
                            with print_lock:
                                print(f"[ERROR] {chain.upper()} ERC20 {sym} balance error: {e}", flush=True)
                        # rotate RPC and try once
                        try:
                            web3_managers[chain].rotate_on_error()
                            raw = checker.get_erc20_balance(addr_checksum, tok)
                            if raw and raw != 0:
                                dec = 18
                                human = Decimal(raw) / (Decimal(10) ** dec)
                                token_balances[sym] = (raw, dec, human)
                        except Exception:
                            pass

                if (native_bal and native_bal != 0) or token_balances:
                    with print_lock:
                        print("\n" + "="*90, flush=True)
                        print("!!!!! FOUND PRIVATE KEY WITH BALANCES !!!!!", flush=True)
                        print("", flush=True)
                        print("PRIVATE KEY (hex):", "0x" + priv_hex, flush=True)
                        print("Derived address:", addr_checksum, flush=True)
                        if native_bal and native_bal != 0:
                            sym = CHAIN_SYMBOL.get(chain, chain.upper())
                            native_human = Decimal(native_bal) / Decimal(10**18)
                            print(f"{chain.upper()} native (wei): {YELLOW}{native_bal}{RESET}", flush=True)
                            print(f"{chain.upper()} native ({sym}): {LIGHT_GREEN}{decimal_to_str(native_human)}{RESET}", flush=True)
                        if token_balances:
                            print("Token balances:", flush=True)
                            for s,(raw,dec,human) in token_balances.items():
                                print(f"  {s}: raw={YELLOW}{raw}{RESET} decimals={dec} human={LIGHT_GREEN}{decimal_to_str(human)}{RESET}", flush=True)
                        print("="*90 + "\n", flush=True)
                    # save found
                    lines = ["="*90,
                             "FOUND EVM BALANCE",
                             f"CHAIN: {chain}",
                             f"PRIVATE_KEY_HEX: 0x{priv_hex}",
                             f"DERIVED_ADDR: {addr_checksum}"]
                    if native_bal and native_bal != 0:
                        lines.append(f"NATIVE_WEI: {native_bal}")
                        lines.append(f"NATIVE_HUMAN: {decimal_to_str(Decimal(native_bal) / Decimal(10**18))}")
                    for s,(raw,dec,human) in token_balances.items():
                        lines.append(f"TOKEN {s}: raw={raw} decimals={dec} human={decimal_to_str(human)}")
                    lines.append("="*90)
                    append_found("\n".join(lines))

                time.sleep(SLEEP_PER_ADDR)
        except Exception as e:
            if debug:
                with print_lock:
                    print(f"[ERROR] {chain} worker idx={idx} error: {e}", flush=True)
            # on unexpected exception, backoff a bit
            time.sleep(0.7)

# -------------------------
# Main & CLI
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Multi-chain scanner (BTC + many EVM chains).")
    p.add_argument("-t","--threads",type=int,default=len(DEFAULT_CHAINS),help="worker threads (default = number of chains)")
    p.add_argument("-c","--concurrency",type=int,default=2,help="max concurrent HTTP/Web3 requests per thread")
    p.add_argument("--chains",type=str,default=",".join(DEFAULT_CHAINS),help="comma-separated chains")
    p.add_argument("--start",type=int,default=1,help="start index")
    p.add_argument("-d","--debug",action="store_true",help="debug mode")
    return p.parse_args()

def main():
    args = parse_args()
    chains = [c.strip().lower() for c in args.chains.split(",") if c.strip()]
    if not chains:
        print("[FATAL] no chains selected", flush=True)
        sys.exit(1)

    # build web3 managers for EVM chains
    web3_managers = {}
    for c in chains:
        if c == "btc":
            continue
        rpc_list = RPC_FALLBACKS.get(c, [])
        if not rpc_list:
            print(f"[WARN] no RPC defined for {c}, skipping", flush=True)
        else:
            try:
                web3_managers[c] = Web3Manager(rpc_list)
            except Exception as e:
                print(f"[WARN] failed to create Web3Manager for {c}: {e}", flush=True)

    idx_provider = IndexProvider(start=args.start)
    print_lock = threading.Lock()

    def _signal(sig, frame):
        stop_event.set()
        with last_priv_lock:
            cp = last_priv_hex
        if cp:
            print("\n[INFO] Interrupted. Last private key hex:", cp, flush=True)
        else:
            print("\n[INFO] Interrupted. No key processed yet.", flush=True)
    signal.signal(signal.SIGINT, _signal)
    signal.signal(signal.SIGTERM, _signal)

    # auto-distribute: create one thread per chain up to requested threads
    workers = []
    threads_to_launch = min(args.threads, len(chains))
    print(f"[INFO] Launching {threads_to_launch} threads for chains: {', '.join(chains)}", flush=True)
    with ThreadPoolExecutor(max_workers=threads_to_launch) as ex:
        for i, chain in enumerate(chains[:threads_to_launch]):
            # each worker gets its own small semaphore for concurrent HTTP calls
            sem_value = max(1, args.concurrency)
            ex.submit(worker_chain, chain, idx_provider, web3_managers, print_lock, sem_value, args.debug)

        # keep main thread alive until signal
        try:
            while not stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            stop_event.set()

    print("[INFO] All workers stopped. Exiting.", flush=True)

if __name__ == "__main__":
    main()