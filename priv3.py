#!/usr/bin/env python3
# scan.py -- multi-chain scanner (BTC + many EVM chains). Sequential integer -> private key (1,2,3...)
# Requirements: pip install coincurve pysha3 web3 requests pycryptodome

import argparse
import time
import signal
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal, getcontext
from functools import lru_cache

import requests
from coincurve import PrivateKey, PublicKey
from Crypto.Hash import SHA256, RIPEMD160
import sha3
from web3 import Web3

getcontext().prec = 40

# -------------------------
# Constants & defaults
# -------------------------
SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

YELLOW = "\033[33m"
LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"

# RPC endpoints as you provided
DEFAULT_RPCS = {
    "eth":      "https://ethereum.publicnode.com",
    "bsc":      "https://bsc-dataseed.binance.org/",
    "polygon":  "https://polygon-rpc.com/",
    "avalanche":"https://api.avax.network/ext/bc/C/rpc",
    "fantom":   "https://rpc.ftm.tools/",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "optimism": "https://mainnet.optimism.io",
    "gnosis":   "https://rpc.gnosischain.com",
    "celo":     "https://forno.celo.org",
    "cronos":   "https://evm-cronos.crypto.org",
}

CHAIN_SYMBOL = {
    "eth":"ETH","bsc":"BNB","polygon":"MATIC","avalanche":"AVAX","fantom":"FTM",
    "arbitrum":"ARB","optimism":"OP","gnosis":"xDAI","celo":"CELO","cronos":"CRO"
}

# ERC20 tokens to check (only enabling for main chains to limit RPC)
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

# -------------------------
# Utility functions
# -------------------------
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

@lru_cache(maxsize=1024)
def get_token_decimals(web3: Web3, token_addr: str) -> int:
    try:
        token = web3.eth.contract(address=web3.toChecksumAddress(token_addr),
                                  abi=[{"constant":True,"inputs":[],"name":"decimals","outputs":[{"name":"","type":"uint8"}],"type":"function"}])
        return int(token.functions.decimals().call())
    except Exception:
        return 18

# -------------------------
# Bech32 / Bech32m implementation (segwit + taproot)
# -------------------------
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32M_CONST = 0x2bc830a3  # for Bech32m checksum

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if ((top >> i) & 1):
                chk ^= GEN[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data, spec="bech32"):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0])
    if spec == "bech32":
        const = 1
    elif spec == "bech32m":
        const = BECH32M_CONST
    else:
        raise ValueError("spec must be 'bech32' or 'bech32m'")
    ret = polymod ^ const
    return [(ret >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, spec="bech32"):
    combined = data + bech32_create_checksum(hrp, data, spec=spec)
    return hrp + '1' + ''.join([BECH32_CHARSET[d] for d in combined])

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

def segwit_encode(hrp, witver, witprog):
    # choose spec: bech32 for version 0, bech32m for v1+ (BIP350)
    spec = "bech32" if witver == 0 else "bech32m"
    data = [witver] + convertbits(witprog, 8, 5)
    return bech32_encode(hrp, data, spec=spec)

# Tagged hash helper for Taproot (BIP340/341)
def tagged_hash(tag: str, msg: bytes) -> bytes:
    # tagged_hash(tag, msg) = SHA256(SHA256(tag) || SHA256(tag) || msg)
    tag_hash = sha256_bytes(tag.encode())
    h = SHA256.new()
    h.update(tag_hash)
    h.update(tag_hash)
    h.update(msg)
    return h.digest()

# -------------------------
# BTC address maker with P2TR (taproot)
# -------------------------
def make_btc_addresses(pub_compressed: bytes, priv_bytes: bytes = None):
    """
    Returns (p2pkh, p2sh_p2wpkh, p2wpkh_bech32, p2tr_bech32m)
    pub_compressed: compressed public key bytes (33 bytes)
    priv_bytes: optional 32-byte private key (used for taproot tweak calculation)
    """
    # P2PKH
    p2pkh_addr = base58check_encode(b"\x00" + hash160(pub_compressed))
    # P2SH-P2WPKH (redeemscript = 0x00 0x14 <hash160(pub)>)
    redeem = b"\x00\x14" + hash160(pub_compressed)
    p2sh_addr = base58check_encode(b"\x05" + hash160(redeem))
    # Bech32 P2WPKH (witness v0, program = hash160(pub_compressed))
    h160 = hash160(pub_compressed)
    bech32_addr = segwit_encode("bc", 0, h160)

    # P2TR (taproot) - only if priv_bytes provided; otherwise attempt to compute from pub only is not possible reliably
    bech32m_addr = None
    if priv_bytes is not None:
        try:
            bech32m_addr = make_p2tr_address_from_priv(priv_bytes)
        except Exception:
            bech32m_addr = None

    return p2pkh_addr, p2sh_addr, bech32_addr, bech32m_addr

def make_p2tr_address_from_priv(priv_bytes: bytes) -> str:
    """
    BIP341 key-path-only Taproot address (no script tree).
    Steps:
    - Get internal public key P = priv*G (full point). If y(P) is odd, set priv = n - priv (so P has even y).
    - x-only internal key = x(P) 32 bytes.
    - tweak = int(tagged_hash("TapTweak", x_only)) mod n
    - output_priv = (priv + tweak) mod n
    - output_x = x-coordinate of output_priv*G (32 bytes)
    - address = bech32m encode with witness version 1 and program = output_x (32 bytes)
    """
    priv_int = int.from_bytes(priv_bytes, "big")
    if not (1 <= priv_int < SECP256K1_ORDER):
        raise ValueError("invalid private key scalar for taproot")

    # derive public point and parity
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)  # 65 bytes: 0x04||X||Y
    x = pub_uncompressed[1:33]
    y = pub_uncompressed[33:65]
    y_parity = y[-1] & 1  # odd/even detection using last byte LSB

    # If y is odd, negate the private key (priv = n - priv) so that internal pubkey has even y
    if y_parity == 1:
        priv_int = (SECP256K1_ORDER - priv_int) % SECP256K1_ORDER
        # recompute x-only from negated private
        pk = PrivateKey(priv_int.to_bytes(32, "big"))
        pub_uncompressed = pk.public_key.format(compressed=False)
        x = pub_uncompressed[1:33]

    x_only = x  # 32 bytes

    # tweak = int(tagged_hash("TapTweak", x_only)) mod n
    tweak = int.from_bytes(tagged_hash("TapTweak", x_only), "big") % SECP256K1_ORDER

    output_priv_int = (priv_int + tweak) % SECP256K1_ORDER
    if output_priv_int == 0:
        raise ValueError("invalid output private key (zero) after tweak")

    # compute output public key x-only
    out_priv = PrivateKey(output_priv_int.to_bytes(32, "big"))
    out_pub_uncompressed = out_priv.public_key.format(compressed=False)
    out_x = out_pub_uncompressed[1:33]  # 32 bytes x-only

    # segwit v1 (bech32m) with witness program = 32-byte x-only pubkey
    p2tr = segwit_encode("bc", 1, out_x)
    return p2tr

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
# Network checkers
# -------------------------
class BTCChecker:
    def __init__(self, session: requests.Session, sem: threading.Semaphore, debug=False):
        self.session = session
        self.sem = sem
        self.debug = debug
    def get_balance(self, addr: str) -> int:
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance"
        self.sem.acquire()
        try:
            resp = self.session.get(url, timeout=10)
            if self.debug:
                print(f"[DEBUG] GET {url} -> {resp.status_code}", flush=True)
            resp.raise_for_status()
            data = resp.json()
            return int(data.get("final_balance", 0))
        finally:
            self.sem.release()

class EVMChecker:
    def __init__(self, web3: Web3, sem: threading.Semaphore, debug=False):
        self.web3 = web3
        self.sem = sem
        self.debug = debug
    def get_native_balance(self, addr: str) -> int:
        self.sem.acquire()
        try:
            if self.debug:
                print(f"[DEBUG] web3.eth.get_balance({addr})", flush=True)
            return self.web3.eth.get_balance(addr)
        finally:
            self.sem.release()
    def get_erc20_balance(self, addr: str, token_addr: str) -> int:
        self.sem.acquire()
        try:
            token = self.web3.eth.contract(address=self.web3.toChecksumAddress(token_addr),
                                           abi=[{"constant":True,"inputs":[{"name":"_owner","type":"address"}],
                                                 "name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],
                                                 "type":"function"}])
            if self.debug:
                print(f"[DEBUG] token.balanceOf({addr}) on {token_addr}", flush=True)
            return int(token.functions.balanceOf(self.web3.toChecksumAddress(addr)).call())
        finally:
            self.sem.release()

# -------------------------
# Worker
# -------------------------
stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()

def worker_thread(name: str, idx_provider: IndexProvider, btc_checker: BTCChecker, evm_checkers: dict, web3s: dict, print_lock: threading.Lock, chains: list, debug: bool):
    global last_priv_hex
    while not stop_event.is_set():
        idx = idx_provider.next_index()
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        with last_priv_lock:
            last_priv_hex = priv_hex

        try:
            pk = PrivateKey(priv_bytes)
            pub_comp = pk.public_key.format(compressed=True)
            wif = privkey_to_wif(priv_bytes, compressed=True)

            # --- BTC ---
            if "btc" in chains:
                p2pkh_addr, p2sh_addr, bech32_addr, bech32m_addr = make_btc_addresses(pub_comp, priv_bytes)
                for addr in (p2pkh_addr, p2sh_addr, bech32_addr, bech32m_addr):
                    if stop_event.is_set(): break
                    if addr is None:
                        continue
                    try:
                        bal = btc_checker.get_balance(addr)
                    except Exception as e:
                        with print_lock:
                            print(f"[ERROR] BTC {addr} balance error: {e}", flush=True)
                        time.sleep(0.6)
                        continue
                    if bal and bal != 0:
                        with print_lock:
                            print("\n" + "="*72, flush=True)
                            print("!!!!! FOUND BITCOIN ADDRESS WITH FUNDS !!!!!", flush=True)
                            print("WIF:", wif, flush=True)
                            print("ADDRESS:", addr, flush=True)
                            print("BALANCE (sats):", f"{LIGHT_GREEN}{bal}{RESET}", flush=True)
                            print("="*72 + "\n", flush=True)
                    time.sleep(0.6)

            # --- EVM chains (native + ERC20) ---
            # derive EVM address once
            evm_addr = evm_address_from_priv(priv_bytes)  # lower-case 0x...
            for ch in chains:
                if ch == "btc":
                    continue
                if stop_event.is_set(): break
                w3 = web3s.get(ch)
                checker = evm_checkers.get(ch)
                if w3 is None or checker is None:
                    # skip if not configured
                    continue
                try:
                    addr_checksum = w3.toChecksumAddress(evm_addr)
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] {ch.upper()} invalid address derived: {e}", flush=True)
                    continue

                # native
                try:
                    native_bal = checker.get_native_balance(addr_checksum)
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] {ch.upper()} native balance error for {addr_checksum}: {e}", flush=True)
                    native_bal = 0

                # ERC20 (only if list present)
                token_balances = {}
                tokdict = ERC20_TO_CHECK.get(ch, {})
                for sym, tok in tokdict.items():
                    try:
                        raw = checker.get_erc20_balance(addr_checksum, tok)
                        if raw and raw != 0:
                            dec = get_token_decimals(w3, tok)
                            human = Decimal(raw) / (Decimal(10) ** dec)
                            token_balances[sym] = (raw, dec, human)
                    except Exception as e:
                        with print_lock:
                            print(f"[ERROR] {ch.upper()} ERC20 {sym} balance error for {addr_checksum}: {e}", flush=True)
                        # continue checking other tokens

                if (native_bal and native_bal != 0) or token_balances:
                    with print_lock:
                        print("\n" + "="*90, flush=True)
                        print("!!!!! FOUND PRIVATE KEY WITH BALANCES !!!!!", flush=True)
                        print("", flush=True)
                        print("PRIVATE KEY (hex):", "0x" + priv_hex, flush=True)
                        print("Derived address:", addr_checksum, flush=True)
                        if native_bal and native_bal != 0:
                            sym = CHAIN_SYMBOL.get(ch, ch.upper())
                            native_human = Decimal(native_bal) / Decimal(10**18)
                            print(f"{ch.upper()} native (wei): {YELLOW}{native_bal}{RESET}", flush=True)
                            print(f"{ch.upper()} native ({sym}): {LIGHT_GREEN}{native_human}{RESET}", flush=True)
                        if token_balances:
                            print("Token balances:", flush=True)
                            for s,(raw,dec,human) in token_balances.items():
                                print(f"  {s}: raw={YELLOW}{raw}{RESET} decimals={dec} human={LIGHT_GREEN}{human}{RESET}", flush=True)
                        print("="*90 + "\n", flush=True)

                # small polite pause per chain
                time.sleep(0.12)

        except Exception as e:
            with print_lock:
                print(f"[ERROR] {name} idx={idx} worker error: {e}", flush=True)
            time.sleep(0.6)

# -------------------------
# Main & CLI
# -------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Multi-chain scanner (BTC + EVM chains).")
    p.add_argument("-t","--threads",type=int,default=3,help="worker threads")
    p.add_argument("-c","--concurrency",type=int,default=2,help="max concurrent HTTP/Web3 requests")
    p.add_argument("--chains",type=str,default="eth,bsc,polygon,btc",help="comma-separated chains")
    p.add_argument("--start",type=int,default=1,help="start index")
    p.add_argument("-d","--debug",action="store_true",help="debug mode")
    return p.parse_args()

def main():
    args = parse_args()
    chains = [c.strip().lower() for c in args.chains.split(",") if c.strip()]

    # validate chains (allow btc or provided RPCs)
    for c in chains:
        if c != "btc" and c not in DEFAULT_RPCS:
            print(f"[FATAL] unsupported chain: {c}", flush=True)
            sys.exit(1)

    idx_provider = IndexProvider(start=args.start)
    session = requests.Session()
    sem = threading.Semaphore(max(1, args.concurrency))

    # create web3 instances and evm checkers
    web3s = {}
    evm_checkers = {}
    for c in chains:
        if c == "btc":
            continue
        rpc = DEFAULT_RPCS.get(c)
        w3 = Web3(Web3.HTTPProvider(rpc))
        web3s[c] = w3
        evm_checkers[c] = EVMChecker(w3, sem, debug=args.debug)

    btc_checker = BTCChecker(session, sem, debug=args.debug)

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

    with ThreadPoolExecutor(max_workers=max(1,args.threads)) as ex:
        futures = [ex.submit(worker_thread, f"worker-{i+1}", idx_provider, btc_checker, evm_checkers, web3s, print_lock, args.chains.split(","), args.debug, chains) for i in range(max(1,args.threads))]
        try:
            for fut in as_completed(futures):
                if stop_event.is_set():
                    break
                try:
                    fut.result(timeout=0)
                except Exception:
                    pass
        except KeyboardInterrupt:
            stop_event.set()
        ex.shutdown(wait=True)

    print("[INFO] All workers stopped. Exiting.", flush=True)

if __name__ == "__main__":
    main()