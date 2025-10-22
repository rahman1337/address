#!/usr/bin/env python3
# scan_auto_per_chain.py — Auto-distributed multi-chain scanner
# Each thread scans one chain: BTC + 10 EVMs
# Supports BTC P2PKH, P2SH, Bech32, Taproot + EVM native & ERC20 balances.

import argparse
import signal
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, getcontext

import requests
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160
import sha3
from web3 import Web3
from bech32 import bech32_encode, convertbits

getcontext().prec = 40

# -------------------------
# Constants
# -------------------------
SECP256K1_ORDER = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"

DEFAULT_CHAINS = ["btc", "eth", "bsc", "polygon", "avalanche",
                  "fantom", "arbitrum", "optimism", "gnosis", "celo", "cronos"]

DEFAULT_RPCS = {
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc-dataseed.binance.org/",
    "polygon": "https://polygon-rpc.com/",
    "avalanche": "https://api.avax.network/ext/bc/C/rpc",
    "fantom": "https://rpc.ftm.tools/",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "optimism": "https://mainnet.optimism.io",
    "gnosis": "https://rpc.gnosischain.com",
    "celo": "https://forno.celo.org",
    "cronos": "https://evm.cronos.org",
}

CHAIN_SYMBOL = {
    "btc": "BTC", "eth": "ETH", "bsc": "BNB", "polygon": "MATIC", "avalanche": "AVAX",
    "fantom": "FTM", "arbitrum": "ARB", "optimism": "OP", "gnosis": "xDAI", "celo": "CELO", "cronos": "CRO"
}

ERC20_TO_CHECK = {
    "eth": {"USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7"},
    "bsc": {"USDT": "0x55d398326f99059fF775485246999027B3197955"},
    "polygon": {"USDT": "0x3813e82e6f7098b9583FC0F33a962D02018B6803"}
}

# -------------------------
# Utilities
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

def privkey_to_wif(priv_bytes: bytes, compressed=True) -> str:
    payload = b"\x80" + priv_bytes + (b"\x01" if compressed else b"")
    return base58check_encode(payload)

def evm_address_from_priv(priv_bytes: bytes) -> str:
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_xy = pub_uncompressed[1:]
    k = sha3.keccak_256()
    k.update(pub_xy)
    return "0x" + k.digest()[-20:].hex()

# -------------------------
# BTC Address Encoders
# -------------------------
def btc_bech32_address(pub_hash160: bytes) -> str:
    data = [0] + convertbits(pub_hash160, 8, 5, True)
    return bech32_encode("bc", data)

def btc_taproot_address(pub_uncompressed: bytes) -> str:
    x_only = pub_uncompressed[1:33]
    data = [1] + convertbits(x_only, 8, 5, True)
    return bech32_encode("bc", data)

def make_btc_addresses(pub_compressed: bytes, pub_uncompressed: bytes):
    h160 = hash160(pub_compressed)
    p2pkh = base58check_encode(b"\x00" + h160)
    redeem = b"\x00\x14" + h160
    p2sh = base58check_encode(b"\x05" + hash160(redeem))
    bech32 = btc_bech32_address(h160)
    taproot = btc_taproot_address(pub_uncompressed)
    return p2pkh, p2sh, bech32, taproot

# -------------------------
# Index Provider
# -------------------------
class IndexProvider:
    def __init__(self, start=1):
        self.index = start
        self.lock = threading.Lock()
    def next_index(self):
        with self.lock:
            val = self.index
            self.index += 1
            if self.index >= SECP256K1_ORDER:
                self.index = 1
            return val

# -------------------------
# Worker
# -------------------------
stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()

def worker(chain, idx_provider, print_lock, sem, debug=False):
    global last_priv_hex

    session = requests.Session()
    if chain != "btc":
        rpc = DEFAULT_RPCS.get(chain)
        w3 = Web3(Web3.HTTPProvider(rpc))
        checker = EVMChecker(w3, sem)
    else:
        checker = BTCChecker(session, sem)

    while not stop_event.is_set():
        idx = idx_provider.next_index()
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        with last_priv_lock:
            last_priv_hex = priv_hex

        pk = PrivateKey(priv_bytes)
        pub_c = pk.public_key.format(compressed=True)
        pub_u = pk.public_key.format(compressed=False)
        wif = privkey_to_wif(priv_bytes, True)

        try:
            if chain == "btc":
                p2pkh, p2sh, bech32, taproot = make_btc_addresses(pub_c, pub_u)
                for addr in (p2pkh, p2sh, bech32, taproot):
                    bal = checker.get_balance(addr)
                    if bal > 0:
                        with print_lock:
                            print("\n" + "="*70)
                            print("!!!!! FOUND BTC ADDRESS !!!!!")
                            print("WIF:", wif)
                            print("ADDR:", addr)
                            print("BALANCE (sats):", f"{LIGHT_GREEN}{bal}{RESET}")
                            print("="*70 + "\n")
                    time.sleep(0.6)
            else:
                addr = w3.toChecksumAddress(evm_address_from_priv(priv_bytes))
                native_bal = checker.get_native_balance(addr)
                tokens = ERC20_TO_CHECK.get(chain, {})
                token_balances = {}
                for sym, taddr in tokens.items():
                    raw = checker.get_erc20_balance(addr, taddr)
                    if raw:
                        token_balances[sym] = Decimal(raw) / Decimal(10**18)
                if native_bal or token_balances:
                    with print_lock:
                        print("\n" + "="*80)
                        print(f"!!!!! FOUND {chain.upper()} ADDRESS !!!!!")
                        print("PRIVATE KEY:", "0x" + priv_hex)
                        print("ADDRESS:", addr)
                        if native_bal:
                            print(f"Native: {LIGHT_GREEN}{Decimal(native_bal)/Decimal(10**18)} {CHAIN_SYMBOL.get(chain, '')}{RESET}")
                        for s, val in token_balances.items():
                            print(f"{s}: {LIGHT_GREEN}{val}{RESET}")
                        print("="*80 + "\n")
                time.sleep(0.2)
        except Exception as e:
            if debug:
                with print_lock:
                    print(f"[ERROR] {chain}: {e}")
            time.sleep(0.3)

# -------------------------
# BTC Checker
# -------------------------
class BTCChecker:
    def __init__(self, session, sem):
        self.s = session
        self.sem = sem
    def get_balance(self, addr):
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance"
        with self.sem:
            r = self.s.get(url, timeout=10)
            if r.status_code != 200:
                return 0
            return int(r.json().get("final_balance", 0))

# -------------------------
# EVM Checker
# -------------------------
class EVMChecker:
    def __init__(self, w3, sem):
        self.w3 = w3
        self.sem = sem
    def get_native_balance(self, addr):
        with self.sem:
            return self.w3.eth.get_balance(addr)
    def get_erc20_balance(self, addr, token_addr):
        abi = [{"constant": True, "inputs": [{"name": "_owner", "type": "address"}],
                "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}],
                "type": "function"}]
        token = self.w3.eth.contract(address=self.w3.toChecksumAddress(token_addr), abi=abi)
        with self.sem:
            return int(token.functions.balanceOf(addr).call())

# -------------------------
# Main
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Auto chain-distributed multi-chain scanner")
    p.add_argument("--start", type=int, default=1, help="Start index")
    p.add_argument("-d", "--debug", action="store_true", help="Enable debug")
    return p.parse_args()

def main():
    args = parse_args()
    chains = DEFAULT_CHAINS
    threads = len(chains)
    idx_provider = IndexProvider(args.start)
    print_lock = threading.Lock()

    def handle_signal(sig, frame):
        stop_event.set()
        print("\n[INFO] Interrupted. Last private key:", last_priv_hex)
        sys.exit(0)
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print(f"[INFO] Launching {threads} threads (1 per chain): {', '.join(chains)}")
    with ThreadPoolExecutor(max_workers=threads) as ex:
        for c in chains:
            sem = threading.Semaphore(2)
            ex.submit(worker, c, idx_provider, print_lock, sem, args.debug)
        try:
            while not stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            handle_signal(None, None)
    print("[INFO] All workers stopped. Exiting.")

if __name__ == "__main__":
    main()