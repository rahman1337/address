#!/usr/bin/env python3
# scan_full.py
# BTC (1,3,bc1q,bc1p) + ETH + BSC + POLYGON scanner
# Single 0.6s sleep per address, 3 threads, retries/backoff, debug mode, clean shutdown.

import argparse
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, getcontext
from functools import lru_cache, wraps

import requests
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160
import sha3
from web3 import Web3

# Increase decimal precision so tiny fractions print exactly
getcontext().prec = 60

# -------------------------
# Config
# -------------------------
SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)

DEFAULT_RPCS = {
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc-dataseed.binance.org/",
    "polygon": "https://polygon-rpc.com/",
}

CHAIN_SYMBOL = {"eth": "ETH", "bsc": "BNB", "polygon": "MATIC"}

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

THREADS = 3
SLEEP_PER_ADDRESS = 0.6
RETRY_MAX = 3
RETRY_BACKOFF = 1.0

# -------------------------
# Small utilities
# -------------------------
YELLOW = "\033[33m"
LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"

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

def privkey_to_wif(priv_bytes: bytes, compressed: bool = True) -> str:
    payload = b"\x80" + priv_bytes + (b"\x01" if compressed else b"")
    return base58check_encode(payload)

def evm_address_from_priv(priv_bytes: bytes) -> str:
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)  # 65 bytes: 0x04 || X || Y
    pub_xy = pub_uncompressed[1:]
    k = sha3.keccak_256()
    k.update(pub_xy)
    return "0x" + k.digest()[-20:].hex()

# format human amount from raw integer and decimals, avoiding scientific notation,
# and never rounding down to 0 if raw>0.
def human_amount_from_raw(raw_int: int, decimals: int) -> str:
    d = Decimal(raw_int) / (Decimal(10) ** decimals)
    s = format(d, "f")  # plain fixed-point, no exponent
    # strip trailing zeros but keep at least one digit after decimal if there was a decimal point originally
    if "." in s:
        s = s.rstrip("0").rstrip(".")
    if s == "":
        s = "0"
    return s

# -------------------------
# Bech32 / Bech32m (standalone) implementation (used for segwit & taproot)
# -------------------------
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
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0])
    const = 1 if spec == "bech32" else BECH32M_CONST
    ret = polymod ^ const
    return [(ret >> (5 * (5 - i))) & 31 for i in range(6)]

def bech32_encode(hrp: str, data, spec="bech32"):
    combined = data + bech32_create_checksum(hrp, data, spec=spec)
    return hrp + "1" + "".join([BECH32_CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
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

def segwit_encode(hrp: str, witver: int, witprog: bytes):
    spec = "bech32" if witver == 0 else "bech32m"
    data = [witver] + convertbits(witprog, 8, 5)
    return bech32_encode(hrp, data, spec=spec)

# -------------------------
# Taproot tweak (BIP341) and P2TR generation
# -------------------------
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = sha256_bytes(tag.encode())
    h = SHA256.new()
    h.update(tag_hash)
    h.update(tag_hash)
    h.update(msg)
    return h.digest()

def make_p2tr_from_priv(priv_bytes: bytes) -> str:
    # derive internal key and ensure even y parity
    priv_int = int.from_bytes(priv_bytes, "big")
    if not (1 <= priv_int < SECP256K1_ORDER):
        raise ValueError("invalid private key")
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)  # 0x04 || X || Y
    x = pub_uncompressed[1:33]
    y = pub_uncompressed[33:65]
    y_parity = y[-1] & 1
    if y_parity == 1:
        priv_int = (SECP256K1_ORDER - priv_int) % SECP256K1_ORDER
        pk = PrivateKey(priv_int.to_bytes(32, "big"))
        pub_uncompressed = pk.public_key.format(compressed=False)
        x = pub_uncompressed[1:33]
    x_only = x
    tweak = int.from_bytes(tagged_hash("TapTweak", x_only), "big") % SECP256K1_ORDER
    out_priv = (priv_int + tweak) % SECP256K1_ORDER
    if out_priv == 0:
        raise ValueError("invalid output key after tweak")
    out_pk = PrivateKey(out_priv.to_bytes(32, "big"))
    out_pub_uncompressed = out_pk.public_key.format(compressed=False)
    out_x = out_pub_uncompressed[1:33]
    return segwit_encode("bc", 1, out_x)

# -------------------------
# BTC address creation (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR)
# -------------------------
def make_btc_addresses(priv_bytes: bytes):
    # produce compressed pubkey
    pk = PrivateKey(priv_bytes)
    pub_comp = pk.public_key.format(compressed=True)
    # p2pkh
    p2pkh = base58check_encode(b"\x00" + hash160(pub_comp))
    # p2sh-p2wpkh
    redeem = b"\x00\x14" + hash160(pub_comp)
    p2sh = base58check_encode(b"\x05" + hash160(redeem))
    # bech32 p2wpkh
    p2wpkh = segwit_encode("bc", 0, hash160(pub_comp))
    # p2tr bech32m
    try:
        p2tr = make_p2tr_from_priv(priv_bytes)
    except Exception:
        p2tr = None
    return p2pkh, p2sh, p2wpkh, p2tr

# -------------------------
# Retry decorator for HTTP/Web3 calls
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
                    if kwargs.get("_debug", False):
                        print(f"[DEBUG] attempt {attempt} failed for {func.__name__}: {e}")
                    if attempt < max_attempts:
                        time.sleep(backoff)
                        continue
                    raise
            raise last_exc
        return wrapper
    return deco

# -------------------------
# HTTP helper (with retries)
# -------------------------
@retry_network()
def http_get_text(url: str, timeout=10, _debug=False) -> str:
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.text

@retry_network()
def http_get_json(url: str, timeout=10, _debug=False):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()

# -------------------------
# EVM helpers
# -------------------------
@lru_cache(maxsize=512)
def get_token_decimals(web3, token_addr: str) -> int:
    try:
        abi = [{"constant": True, "inputs": [], "name": "decimals", "outputs": [{"type": "uint8"}], "type": "function"}]
        return int(web3.eth.contract(address=web3.toChecksumAddress(token_addr), abi=abi).functions.decimals().call())
    except Exception:
        return 18

@retry_network()
def evm_get_balance(web3: Web3, addr: str, _debug=False) -> int:
    return web3.eth.get_balance(addr)

@retry_network()
def evm_get_erc20_balance(web3: Web3, addr: str, token_addr: str, _debug=False) -> int:
    abi = [{"constant": True, "inputs": [{"name": "_owner", "type": "address"}],
            "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "type": "function"}]
    token = web3.eth.contract(address=web3.toChecksumAddress(token_addr), abi=abi)
    return int(token.functions.balanceOf(web3.toChecksumAddress(addr)).call())

# -------------------------
# BTC check flow
# -------------------------
@retry_network()
def blockchain_info_received(addr: str, _debug=False) -> int:
    # returns sats as integer (plain text)
    url = f"https://blockchain.info/q/getreceivedbyaddress/{addr}"
    text = http_get_text(url, _debug=_debug)
    text = text.strip()
    # Some endpoints may return decimals; interpret robustly
    if text == "":
        return 0
    try:
        if "." in text:
            # treat as BTC decimal -> convert to satoshis
            return int(Decimal(text) * Decimal(1e8))
        return int(text)
    except Exception:
        return 0

@retry_network()
def blockcypher_balance(addr: str, _debug=False) -> int:
    url = f"https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance"
    j = http_get_json(url, _debug=_debug)
    return int(j.get("final_balance", 0))

def check_btc_address(addr: str, debug=False) -> (int, str):
    """
    Returns tuple (balance_sats:int, human_str:str). Always checks 'received' first (blockchain.info),
    and if received>0 queries blockcypher for final_balance. If any network error occurs, exceptions
    bubble in debug mode; in normal mode exceptions are caught and treated as 0 balance.
    """
    try:
        rec = blockchain_info_received(addr, _debug=debug)
    except Exception as e:
        if debug:
            print(f"[DEBUG] blockchain.info received error for {addr}: {e}")
        # fallback: try blockcypher directly
        try:
            bal = blockcypher_balance(addr, _debug=debug)
            human = human_amount_from_raw(bal, 8)
            return bal, human
        except Exception as e2:
            if debug:
                print(f"[DEBUG] blockcypher fallback error for {addr}: {e2}")
            return 0, "0"
    # if received == 0, skip blockcypher
    if rec == 0:
        return 0, "0"
    # received > 0 -> check final balance
    try:
        bal = blockcypher_balance(addr, _debug=debug)
        human = human_amount_from_raw(bal, 8)
        return bal, human
    except Exception as e:
        if debug:
            print(f"[DEBUG] blockcypher balance error for {addr}: {e}")
        return 0, "0"

# -------------------------
# Index provider
# -------------------------
class IndexProvider:
    def __init__(self, start: int = 1):
        self.lock = threading.Lock()
        if not (1 <= start < SECP256K1_ORDER):
            raise ValueError("start out of range")
        self._i = start
    def next_index(self) -> int:
        with self.lock:
            v = self._i
            self._i += 1
            if self._i >= SECP256K1_ORDER:
                self._i = 1
            return v

# -------------------------
# Threading / shutdown
# -------------------------
stop_event = threading.Event()
_shutdown_printed = threading.Event()
progress = {"last_idx": 0}

# -------------------------
# Worker (per thread: scans all chains for each private key index)
# -------------------------
def worker(idx_provider: IndexProvider, web3s: dict, print_lock: threading.Lock, debug: bool):
    while not stop_event.is_set():
        idx = idx_provider.next_index()
        progress["last_idx"] = idx
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        wif = privkey_to_wif(priv_bytes, True)

        if debug:
            with print_lock:
                print(f"[DEBUG] idx={idx} priv=0x{priv_hex}")

        # BTC addresses (P2PKH, P2SH-P2WPKH, P2WPKH, P2TR)
        try:
            p2pkh, p2sh, p2wpkh, p2tr = make_btc_addresses(priv_bytes)
            for addr in (p2pkh, p2sh, p2wpkh, p2tr):
                if addr is None:
                    continue
                # check raw satoshis
                try:
                    bal_sats, human = check_btc_address(addr, debug=debug)
                except Exception as e:
                    # in normal mode, print only ERROR lines, in debug print details
                    with print_lock:
                        if debug:
                            print(f"[ERROR] BTC check failed for {addr}: {e}")
                        else:
                            print(f"[ERROR] BTC check failed for {addr}: {e}")
                    bal_sats, human = 0, "0"
                if bal_sats > 0:
                    with print_lock:
                        print("\n" + "=" * 80)
                        print("!!!!! FOUND BTC ADDRESS WITH FUNDS !!!!!")
                        print("PRIVATE KEY (hex):", "0x" + priv_hex)
                        print("WIF:", wif)
                        print("ADDRESS:", addr)
                        print("BALANCE (sats):", bal_sats)
                        print("BALANCE (BTC):", f"{LIGHT_GREEN}{human}{RESET}")
                        print("=" * 80 + "\n")
                # single sleep PER ADDRESS
                time.sleep(SLEEP_PER_ADDRESS)
        except Exception as e:
            with print_lock:
                if debug:
                    print(f"[ERROR] BTC address generation failed for idx={idx}: {e}")
                else:
                    print(f"[ERROR] BTC address generation failed for idx={idx}: {e}")

        # EVM chains
        evm_addr = evm_address_from_priv(priv_bytes)
        for ch, w3 in web3s.items():
            try:
                addr_checksum = w3.toChecksumAddress(evm_addr)
            except Exception as e:
                with print_lock:
                    if debug:
                        print(f"[ERROR] invalid derived address for {ch} idx={idx}: {e}")
                    else:
                        print(f"[ERROR] invalid derived address for {ch} idx={idx}: {e}")
                continue

            # native balance (wei)
            native_raw = 0
            try:
                native_raw = evm_get_balance(w3, addr_checksum, _debug=debug)
            except Exception as e:
                # attempt once: rotate not implemented here; just report error and continue
                with print_lock:
                    if debug:
                        print(f"[ERROR] {ch} native balance call failed for {addr_checksum} idx={idx}: {e}")
                    else:
                        print(f"[ERROR] {ch} native balance call failed for {addr_checksum} idx={idx}: {e}")
                native_raw = 0

            # tokens
            token_results = {}
            for sym, token_addr in ERC20_TO_CHECK.get(ch, {}).items():
                try:
                    raw = evm_get_erc20_balance(w3, addr_checksum, token_addr, _debug=debug)
                    if raw and int(raw) > 0:
                        decs = get_token_decimals(w3, token_addr)
                        human_tok = human_amount_from_raw(int(raw), decs)
                        token_results[sym] = (int(raw), decs, human_tok)
                except Exception as e:
                    with print_lock:
                        if debug:
                            print(f"[ERROR] {ch} token {sym} balance call failed for {addr_checksum} idx={idx}: {e}")
                        else:
                            print(f"[ERROR] {ch} token {sym} balance call failed for {addr_checksum} idx={idx}: {e}")
                    # continue to next token

            # If any raw balance > 0, print FOUND with raw & human
            token_positive = any(raw > 0 for (raw, _, _) in token_results.values()) if token_results else False
            if native_raw and int(native_raw) > 0 or token_positive:
                with print_lock:
                    print("\n" + "=" * 90)
                    print(f"!!!!! FOUND {ch.upper()} PRIVATE KEY WITH FUNDS !!!!!")
                    print("PRIVATE KEY (hex):", "0x" + priv_hex)
                    print("Derived address:", addr_checksum)
                    if native_raw and int(native_raw) > 0:
                        native_human = human_amount_from_raw(int(native_raw), 18)
                        print(f"{ch.upper()} native (wei): {int(native_raw)}")
                        print(f"{ch.upper()} native ({CHAIN_SYMBOL.get(ch,ch.upper())}): {LIGHT_GREEN}{native_human}{RESET}")
                    else:
                        print(f"{ch.upper()} native (wei): 0")
                    if token_results:
                        print("Token balances:")
                        for s, (raw, decs, human_tok) in token_results.items():
                            print(f"  {s}: raw={raw} decimals={decs} human={LIGHT_GREEN}{human_tok}{RESET}")
                    print("=" * 90 + "\n")
            # single sleep per address
            time.sleep(SLEEP_PER_ADDRESS)

# -------------------------
# Progress thread (debug only)
# -------------------------
def progress_worker(print_lock: threading.Lock, debug: bool):
    while not stop_event.is_set():
        if debug:
            with print_lock:
                print(f"[DEBUG] scanning index: {progress.get('last_idx', 0)}", end="\r", flush=True)
        time.sleep(2.5)

# -------------------------
# Main
# -------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="debug mode (prints progress, requests, errors)")
    parser.add_argument("--start", type=int, default=1, help="start index (default=1)")
    args = parser.parse_args()
    debug = args.debug

    # prepare web3 instances for EVM chains
    web3s = {}
    for ch, rpc in DEFAULT_RPCS.items():
        w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 10}))
        web3s[ch] = w3

    idx_provider = IndexProvider(start=args.start)
    print_lock = threading.Lock()

    def _signal(sig, frame):
        # only print once
        if not _shutdown_printed.is_set():
            with print_lock:
                print("\n[INFO] Interrupted. Stopping workers...", flush=True)
            _shutdown_printed.set()
        stop_event.set()
        # allow threads to wind down, then exit
        time.sleep(0.1)
        try:
            sys.exit(0)
        except SystemExit:
            pass

    signal.signal(signal.SIGINT, _signal)
    signal.signal(signal.SIGTERM, _signal)

    # start progress thread (debug prints)
    prog_thread = threading.Thread(target=progress_worker, args=(print_lock, debug), daemon=True)
    prog_thread.start()

    # start worker threads
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        for _ in range(THREADS):
            ex.submit(worker, idx_provider, web3s, print_lock, debug)
        try:
            # keep main alive until stop_event set
            while not stop_event.is_set():
                time.sleep(0.2)
        except KeyboardInterrupt:
            stop_event.set()
        finally:
            # wait for workers to finish gracefully
            ex.shutdown(wait=True)

    # final flush
    with print_lock:
        print("\n[INFO] All workers stopped. Exiting.", flush=True)

if __name__ == "__main__":
    main()