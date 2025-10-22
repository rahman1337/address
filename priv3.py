#!/usr/bin/env python3
import argparse
import time
import signal
import sys
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160
from web3 import Web3

# -----------------------
# CONFIG
# -----------------------
SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ANSI colors
YELLOW = "\033[33m"
LIGHT_GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

# EVM chains config: rpc endpoints and ERC-20 tokens
EVM_CHAINS = {
    "eth": {
        "rpc": "https://rpc.ankr.com/eth",
        "native": "ETH",
        "erc20": {
            "USDT": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
            "USDC": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606EB48",
            "DAI": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
            "WBTC": "0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599",
        },
    },
    "bsc": {
        "rpc": "https://bsc-dataseed.binance.org/",
        "native": "BNB",
        "erc20": {
            "BUSD": "0xe9e7cea3dedca5984780bafc599bd69add087d56",
            "USDT": "0x55d398326f99059fF775485246999027B3197955",
        },
    },
    "polygon": {
        "rpc": "https://polygon-rpc.com",
        "native": "MATIC",
        "erc20": {
            "USDT": "0x3813e82e6f7098b9583FC0F33a962D02018B6803",
            "USDC": "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
        },
    },
}

# -----------------------
# HASH & ENCODE HELPERS
# -----------------------
def sha256(b: bytes) -> bytes:
    from Crypto.Hash import SHA256
    h = SHA256.new()
    h.update(b)
    return h.digest()

def ripemd160(b: bytes) -> bytes:
    from Crypto.Hash import RIPEMD160
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
    return "1" * zeros + "".join(reversed(chars)) if chars else "1" * zeros

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

# -----------------------
# INDEX PROVIDER
# -----------------------
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

# -----------------------
# BTC CHECKER
# -----------------------
class BTCChecker:
    def __init__(self, session, sem: threading.Semaphore):
        self.session = session
        self.sem = sem

    def get_balance(self, addr: str) -> int:
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance"
        self.sem.acquire()
        try:
            resp = self.session.get(url, timeout=10)
        finally:
            self.sem.release()
        if resp.status_code != 200:
            raise RuntimeError(f"BTC balance API error: {resp.status_code}")
        data = resp.json()
        return int(data.get("final_balance", 0))

# -----------------------
# EVM CHECKER
# -----------------------
class EVMChecker:
    def __init__(self, web3: Web3, sem: threading.Semaphore):
        self.web3 = web3
        self.sem = sem

    def get_native_balance(self, addr: str) -> int:
        self.sem.acquire()
        try:
            return self.web3.eth.get_balance(addr)
        finally:
            self.sem.release()

    def get_erc20_balance(self, addr: str, token_addr: str) -> int:
        contract = self.web3.eth.contract(address=self.web3.to_checksum_address(token_addr),
                                          abi=[{"constant":True,"inputs":[{"name":"_owner","type":"address"}],
                                                "name":"balanceOf","outputs":[{"name":"balance","type":"uint256"}],
                                                "type":"function"}])
        self.sem.acquire()
        try:
            return contract.functions.balanceOf(self.web3.to_checksum_address(addr)).call()
        finally:
            self.sem.release()

# -----------------------
# WORKER THREAD
# -----------------------
stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()

def worker_thread(name, idx_provider: IndexProvider, print_lock: threading.Lock, debug: bool, chains: list, sem: threading.Semaphore):
    global last_priv_hex
    session = requests.Session()
    btc_checker = BTCChecker(session, sem)

    evm_checkers = {}
    for chain in chains:
        if chain != "btc":
            w3 = Web3(Web3.HTTPProvider(EVM_CHAINS[chain]["rpc"]))
            evm_checkers[chain] = EVMChecker(w3, sem)

    while not stop_event.is_set():
        idx = idx_provider.next_index()
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        with last_priv_lock:
            last_priv_hex = priv_hex

        try:
            pk = PrivateKey(priv_bytes)
            pub = pk.public_key.format(compressed=True)
            wif = privkey_to_wif(priv_bytes, compressed=True)
            addr_btc = [p2pkh(pub), p2sh_p2wpkh(pub)]  # simplified for demo

            for chain in chains:
                if stop_event.is_set():
                    break
                try:
                    if chain == "btc":
                        for a in addr_btc:
                            try:
                                bal = btc_checker.get_balance(a)
                            except Exception as e:
                                with print_lock:
                                    print(f"[ERROR] BTC address {a} balance failed: {e}", flush=True)
                                continue
                            if bal > 0:
                                with print_lock:
                                    print("\n" + "="*50)
                                    print("BTC FOUND!")
                                    print("WIF:", wif)
                                    print("ADDRESS:", a)
                                    print(f"BALANCE: {LIGHT_GREEN}{bal}{RESET} satoshis")
                                    print("="*50 + "\n")
                    else:
                        evm_checker = evm_checkers[chain]
                        addr_hex = pk.to_hex()
                        try:
                            native_bal = evm_checker.get_native_balance(addr_hex)
                        except Exception as e:
                            with print_lock:
                                print(f"[ERROR] {chain.upper()} native balance error for {addr_hex}: {e}", flush=True)
                            native_bal = 0

                        erc_balances = {}
                        for token, t_addr in EVM_CHAINS[chain]["erc20"].items():
                            try:
                                b = evm_checker.get_erc20_balance(addr_hex, t_addr)
                                if b > 0:
                                    erc_balances[token] = b
                            except Exception as e:
                                with print_lock:
                                    print(f"[ERROR] {chain.upper()} ERC20 {token} balance error for {addr_hex}: {e}", flush=True)
                        if native_bal > 0 or erc_balances:
                            with print_lock:
                                print("\n" + "="*50)
                                print(f"{chain.upper()} FOUND!")
                                print("Private key:", addr_hex)
                                print(f"{EVM_CHAINS[chain]['native']}")
                                print(f"balance: {LIGHT_GREEN}{native_bal}{RESET}")
                                for t, b in erc_balances.items():
                                    print(f"{t} balance: {LIGHT_GREEN}{b}{RESET}")
                                print("="*50 + "\n")
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] {chain.upper()} processing failed: {e}", flush=True)
        except Exception as e:
            with print_lock:
                print(f"[ERROR] {name} idx {idx} derivation failed: {e}", flush=True)

# -----------------------
# MAIN
# -----------------------
def parse_args():
    p = argparse.ArgumentParser(description="Multi-chain scanner (BTC/EVM + ERC20)")
    p.add_argument("--chains", type=str, default="btc,eth,bsc,polygon")
    p.add_argument("-t", "--threads", type=int, default=3)
    p.add_argument("-c", "--concurrency", type=int, default=2)
    p.add_argument("--start", type=int, default=1)
    p.add_argument("--debug", action="store_true")
    return p.parse_args()

def main():
    global last_priv_hex
    args = parse_args()
    chains = args.chains.split(",")
    idx_provider = IndexProvider(start=args.start)
    print_lock = threading.Lock()
    sem = threading.Semaphore(max(1, args.concurrency))

    def signal_handler(sig, frame):
        stop_event.set()
        with last_priv_lock:
            hex_checkpoint = last_priv_hex
        print("\n[INFO] Interrupted. Last key:", hex_checkpoint)
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(worker_thread, f"worker-{i+1}", idx_provider, print_lock, args.debug, chains, sem)
                   for i in range(args.threads)]
        try:
            for f in as_completed(futures):
                if stop_event.is_set():
                    break
                try:
                    f.result(timeout=0)
                except Exception:
                    pass
        except KeyboardInterrupt:
            stop_event.set()
        executor.shutdown(wait=True)
    print("[INFO] All workers stopped.")

if __name__ == "__main__":
    main()