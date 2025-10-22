#!/usr/bin/env python3
# scan_fixed.py – multi-chain scanner (BTC + ETH + BNB + Polygon)
# Requirements: pip install coincurve pysha3 web3 requests pycryptodome

import time, signal, sys, threading, requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal, getcontext
from functools import lru_cache
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160
import sha3
from web3 import Web3

getcontext().prec = 40

# -------------------------
# Constants
# -------------------------
SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
YELLOW = "\033[33m"
LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"

# Default RPC endpoints
DEFAULT_RPCS = {
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc-dataseed.binance.org/",
    "polygon": "https://polygon-rpc.com/",
}

CHAIN_SYMBOL = {"eth": "ETH", "bsc": "BNB", "polygon": "MATIC"}

# ERC20 tokens (major)
ERC20_TO_CHECK = {
    "eth": {
        "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
        "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
    },
    "bsc": {
        "USDT": "0x55d398326f99059fF775485246999027B3197955",
        "BUSD": "0xe9e7cea3dedca5984780bafc599bd69add087d56",
    },
    "polygon": {
        "USDT": "0x3813e82e6f7098b9583FC0F33a962D02018B6803",
        "USDC": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
    },
}

# -------------------------
# Utils
# -------------------------
def sha256_bytes(b: bytes) -> bytes:
    h = SHA256.new(); h.update(b); return h.digest()

def ripemd160_bytes(b: bytes) -> bytes:
    h = RIPEMD160.new(); h.update(b); return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160_bytes(sha256_bytes(b))

def base58_encode(b: bytes) -> str:
    n, zeros = int.from_bytes(b, "big"), len(b) - len(b.lstrip(b"\0"))
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = BASE58_ALPHABET[r] + s
    return "1" * zeros + s

def base58check_encode(payload: bytes) -> str:
    chk = sha256_bytes(sha256_bytes(payload))[:4]
    return base58_encode(payload + chk)

def privkey_to_wif(priv_bytes: bytes, compressed=True) -> str:
    prefix = b"\x80" + priv_bytes + (b"\x01" if compressed else b"")
    return base58check_encode(prefix)

def evm_address_from_priv(priv_bytes: bytes) -> str:
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)[1:]
    k = sha3.keccak_256(); k.update(pub_uncompressed)
    return "0x" + k.digest()[-20:].hex()

def bech32_encode(hrp, witver, witprog):
    import bech32
    data = [witver] + bech32.convertbits(witprog, 8, 5, True)
    return bech32.bech32_encode(hrp, data)

# -------------------------
# Retry wrapper
# -------------------------
def safe_get(url, retries=3, timeout=10):
    for i in range(retries):
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code == 200:
                return r
        except Exception:
            pass
        time.sleep(1.0)
    return None

# -------------------------
# BTC helper
# -------------------------
def make_btc_addresses(pub_compressed: bytes):
    h160 = hash160(pub_compressed)
    p2pkh = base58check_encode(b"\x00" + h160)
    redeem = b"\x00\x14" + h160
    p2sh = base58check_encode(b"\x05" + hash160(redeem))
    try:
        import bech32
        p2wpkh = bech32_encode("bc", 0, h160)
        pk = PrivateKey.from_public_key(pub_compressed)
        taproot = bech32_encode("bc", 1, hash160(pk.public_key.format(compressed=True)))
    except Exception:
        p2wpkh, taproot = None, None
    return p2pkh, p2sh, p2wpkh, taproot

def check_btc(addr):
    # Step 1: check total received first (plain integer)
    rcv = safe_get(f"https://blockchain.info/q/getreceivedbyaddress/{addr}")
    if not rcv:
        return 0
    try:
        received_sats = int(rcv.text.strip())
    except ValueError:
        return 0
    if received_sats == 0:
        return 0

    # Step 2: check live balance only if received > 0
    bc = safe_get(f"https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance")
    if not bc:
        return 0
    try:
        data = bc.json()
        balance_sats = data.get("final_balance", 0)
        return float(Decimal(balance_sats) / Decimal(1e8))
    except Exception:
        return 0

# -------------------------
# EVM helpers
# -------------------------
@lru_cache(maxsize=256)
def get_token_decimals(web3, token):
    try:
        abi = [{"constant":True,"inputs":[],"name":"decimals","outputs":[{"type":"uint8"}],"type":"function"}]
        return int(web3.eth.contract(address=web3.toChecksumAddress(token), abi=abi).functions.decimals().call())
    except Exception:
        return 18

def get_native_balance(w3, addr):
    try:
        return w3.eth.get_balance(addr)
    except Exception:
        return 0

def get_erc20_balance(w3, addr, token):
    try:
        abi = [{"constant":True,"inputs":[{"name":"_owner","type":"address"}],
                "name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],
                "type":"function"}]
        c = w3.eth.contract(address=w3.toChecksumAddress(token), abi=abi)
        return int(c.functions.balanceOf(w3.toChecksumAddress(addr)).call())
    except Exception:
        return 0

# -------------------------
# Index provider
# -------------------------
class IndexProvider:
    def __init__(self, start=1):
        self.lock = threading.Lock()
        self.i = start
    def next(self):
        with self.lock:
            val = self.i
            self.i += 1
            if self.i >= SECP256K1_ORDER:
                self.i = 1
            return val

# -------------------------
# Worker
# -------------------------
stop_event = threading.Event()

def worker(idxp, web3s, print_lock, debug=False):
    while not stop_event.is_set():
        idx = idxp.next()
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        pk = PrivateKey(priv_bytes)
        pub = pk.public_key.format(compressed=True)
        wif = privkey_to_wif(priv_bytes, True)

        # --- BTC ---
        p2pkh, p2sh, p2wpkh, taproot = make_btc_addresses(pub)
        for addr in filter(None, [p2pkh, p2sh, p2wpkh, taproot]):
            bal_btc = check_btc(addr)
            if bal_btc > 0:
                with print_lock:
                    print("\n" + "="*80)
                    print(f"!!!!! FOUND BTC ADDRESS WITH FUNDS !!!!!")
                    print("PrivKey (hex):", priv_hex)
                    print("WIF:", wif)
                    print("Address:", addr)
                    print("Balance (BTC):", f"{LIGHT_GREEN}{bal_btc:.8f}{RESET}")
                    print("="*80 + "\n", flush=True)
            time.sleep(0.6)

        # --- EVM Chains ---
        evm_addr = evm_address_from_priv(priv_bytes)
        for ch, w3 in web3s.items():
            addr = w3.toChecksumAddress(evm_addr)
            native = get_native_balance(w3, addr)
            token_balances = {}
            for sym, tok in ERC20_TO_CHECK.get(ch, {}).items():
                raw = get_erc20_balance(w3, addr, tok)
                if raw:
                    dec = get_token_decimals(w3, tok)
                    human = Decimal(raw) / (Decimal(10) ** dec)
                    token_balances[sym] = (raw, dec, human)

            if native or token_balances:
                with print_lock:
                    print("\n" + "="*90)
                    print(f"!!!!! FOUND {ch.upper()} PRIVATE KEY WITH FUNDS !!!!!")
                    print("PrivKey (hex):", priv_hex)
                    print("Address:", addr)
                    if native:
                        human = Decimal(native) / Decimal(1e18)
                        print(f"Native: {LIGHT_GREEN}{human:.8f} {CHAIN_SYMBOL.get(ch,ch.upper())}{RESET}")
                    if token_balances:
                        print("Tokens:")
                        for s,(raw,dec,human) in token_balances.items():
                            print(f"  {s}: {human:.8f}")
                    print("="*90 + "\n", flush=True)
            time.sleep(0.6)

# -------------------------
# Main
# -------------------------
def main():
    idxp = IndexProvider(1)
    print_lock = threading.Lock()
    web3s = {ch: Web3(Web3.HTTPProvider(rpc)) for ch, rpc in DEFAULT_RPCS.items()}

    def handler(sig, frame):
        stop_event.set()
        print("\n[INFO] Interrupted.", flush=True)
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    with ThreadPoolExecutor(max_workers=3) as ex:
        futs = [ex.submit(worker, idxp, web3s, print_lock) for _ in range(3)]
        try:
            for f in as_completed(futs):
                pass
        except KeyboardInterrupt:
            stop_event.set()

    print("[INFO] All workers stopped. Exiting.", flush=True)

if __name__ == "__main__":
    main()