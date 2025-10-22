#!/usr/bin/env python3
import argparse
import time
import signal
import sys
import requests
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from coincurve import PrivateKey
from Crypto.Hash import keccak
from decimal import Decimal, getcontext

# for precise wei -> native conversion
getcontext().prec = 40

SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)

YELLOW = "\033[33m"
LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"

# default RPC endpoints (change/override with --rpc_<chain> or --rpc)
DEFAULT_RPCS = {
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc-dataseed.binance.org/",
    "polygon": "https://polygon-rpc.com/",
}

# mapping chain -> native symbol
CHAIN_SYMBOL = {
    "eth": "ETH",
    "bsc": "BNB",
    "polygon": "MATIC",
}

# ---------- Utilities ----------
def eth_address_from_priv(priv_bytes: bytes) -> str:
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_xy = pub_uncompressed[1:]
    k = keccak.new(digest_bits=256)
    k.update(pub_xy)
    addr = "0x" + k.digest()[-20:].hex()
    return addr

def wei_to_native_str(wei: int) -> str:
    native = Decimal(wei) / Decimal(10 ** 18)
    # pretty print with up to 18 decimals
    s = format(native.normalize(), 'f')
    return s

# ---------- Index provider ----------
class IndexProvider:
    def __init__(self, start: int = 1):
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

# ---------- RPC checker ----------
class RpcChecker:
    def __init__(self, session: requests.Session, sem: threading.Semaphore, rpc_url: str, debug: bool = False, timeout: float = 10.0):
        self.session = session
        self.sem = sem
        self.rpc_url = rpc_url.rstrip("/")
        self.debug = debug
        self.timeout = timeout

    def _post_with_retries(self, payload: dict, retries: int = 3, sleep_between: float = 0.6):
        last_exc = None
        for attempt in range(1, retries + 1):
            try:
                self.sem.acquire()
                try:
                    resp = self.session.post(self.rpc_url, json=payload, timeout=self.timeout)
                finally:
                    self.sem.release()
            except Exception as e:
                last_exc = e
                if self.debug:
                    print(f"[DEBUG] POST {self.rpc_url} attempt {attempt} error: {e}", flush=True)
            else:
                if self.debug:
                    print(f"[DEBUG] POST {self.rpc_url} -> {resp.status_code} {resp.reason}", flush=True)
                try:
                    data = resp.json()
                except Exception as e:
                    last_exc = e
                else:
                    if "error" in data:
                        last_exc = RuntimeError(f"RPC error: {data['error']}")
                    else:
                        return data
            if attempt < retries:
                time.sleep(sleep_between)
        raise last_exc

    def get_balance_wei(self, address: str) -> int:
        payload = {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [address, "latest"], "id": 1}
        data = self._post_with_retries(payload)
        if not data or "result" not in data:
            raise RuntimeError("No result in RPC response")
        res = data["result"]
        try:
            return int(res, 16)
        except Exception as e:
            raise RuntimeError(f"Invalid balance value: {res}") from e

# ---------- Worker ----------
stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()

def worker_thread(name: str, idx_provider: IndexProvider, rpc_checkers: dict, chains: list, print_lock: threading.Lock, debug: bool):
    """
    For each index:
      - build priv_bytes
      - derive address per chain
      - query balance for each chain
      - if any balance > 0: print private key and all chains with balances
    """
    global last_priv_hex
    while not stop_event.is_set():
        idx = idx_provider.next_index()
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        priv_hex_prefixed = "0x" + priv_hex
        with last_priv_lock:
            last_priv_hex = priv_hex

        try:
            # collect non-zero balances per chain
            found = []
            for ch in chains:
                checker = rpc_checkers[ch]
                try:
                    addr = eth_address_from_priv(priv_bytes)
                except Exception as e:
                    # impossible normally, but skip if error deriving
                    if debug:
                        with print_lock:
                            print(f"[{name}] error deriving address for chain {ch}: {e}", flush=True)
                    continue

                # Query balance
                try:
                    bal = checker.get_balance_wei(addr)
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] [{name}] chain={ch} addr={addr} balance check FAILED: {e}", flush=True)
                    # be polite and don't hammer if RPC failing
                    time.sleep(0.6)
                    continue

                if bal != 0:
                    found.append((ch, addr, bal))

                # small per-chain delay to reduce hitting rate limits
                time.sleep(0.1)

            if found:
                # Pretty multi-chain report
                with print_lock:
                    print("\n" + "=" * 80, flush=True)
                    print("!!!!! FOUND PRIVATE KEY WITH BALANCES !!!!!", flush=True)
                    print("", flush=True)
                    print("PRIVATE KEY:", priv_hex_prefixed, flush=True)
                    print("", flush=True)
                    print("Chains with native balances:")
                    for ch, addr, bal in found:
                        sym = CHAIN_SYMBOL.get(ch, ch.upper())
                        print("", flush=True)
                        print(f"  Chain: {ch} ({sym})", flush=True)
                        print(f"  Address: {addr}", flush=True)
                        print(f"  Balance (wei): {YELLOW}{bal}{RESET}", flush=True)
                        print(f"  Balance ({sym}): {LIGHT_GREEN}{wei_to_native_str(bal)}{RESET}", flush=True)
                    print("=" * 80 + "\n", flush=True)

            # mandatory sleep per private key loop to be polite overall
            time.sleep(0.6)

        except Exception as e:
            with print_lock:
                print(f"[ERROR] [{name}] idx={idx} worker error: {e}", flush=True)
            time.sleep(0.6)

    if debug:
        with print_lock:
            print(f"[{name}] exiting", flush=True)

# ---------- CLI & Main ----------
def parse_args():
    p = argparse.ArgumentParser(description="Deterministic multi-chain EVM scanner (index -> priv -> multi-chain addresses)")
    p.add_argument("-t", "--threads", type=int, default=3, help="worker threads")
    p.add_argument("-c", "--concurrency", type=int, default=2, help="max concurrent RPC requests across threads")
    p.add_argument("-d", "--debug", action="store_true", help="debug mode")
    p.add_argument("--start", type=int, default=1, help="start index")
    p.add_argument("--chains", type=str, default="eth,bsc,polygon", help="comma-separated chains to check (eth,bsc,polygon)")
    p.add_argument("--rpc_eth", type=str, default=None, help="override ETH RPC URL")
    p.add_argument("--rpc_bsc", type=str, default=None, help="override BSC RPC URL")
    p.add_argument("--rpc_polygon", type=str, default=None, help="override Polygon RPC URL")
    return p.parse_args()

def main():
    global last_priv_hex
    args = parse_args()

    chains = [c.strip().lower() for c in args.chains.split(",") if c.strip()]
    # validate chains
    for ch in chains:
        if ch not in DEFAULT_RPCS:
            print(f"[FATAL] unknown chain '{ch}'", flush=True)
            sys.exit(1)

    # build rpc urls (override if provided)
    rpc_urls = {}
    rpc_urls["eth"] = args.rpc_eth if args.rpc_eth else DEFAULT_RPCS["eth"]
    rpc_urls["bsc"] = args.rpc_bsc if args.rpc_bsc else DEFAULT_RPCS["bsc"]
    rpc_urls["polygon"] = args.rpc_polygon if args.rpc_polygon else DEFAULT_RPCS["polygon"]

    idx_provider = IndexProvider(start=args.start)
    session = requests.Session()
    sem = threading.Semaphore(max(1, args.concurrency))

    # prepare an RpcChecker for each selected chain (they can share the same semaphore/session)
    rpc_checkers = {}
    for ch in set(chains):
        rpc_checkers[ch] = RpcChecker(session=session, sem=sem, rpc_url=rpc_urls[ch], debug=args.debug)

    print_lock = threading.Lock()

    def _signal_handler(sig, frame):
        stop_event.set()
        with last_priv_lock:
            hex_checkpoint = last_priv_hex
        if hex_checkpoint:
            print("\n[INFO] Interrupted by user. Last private key hex tried (checkpoint):", flush=True)
            print(hex_checkpoint, flush=True)
        else:
            print("\n[INFO] Interrupted by user. No key processed yet.", flush=True)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    num_threads = max(1, args.threads)
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(worker_thread, f"worker-{i+1}", idx_provider, rpc_checkers, chains, print_lock, args.debug)
            for i in range(num_threads)
        ]
        try:
            for future in as_completed(futures):
                if stop_event.is_set():
                    break
                try:
                    future.result(timeout=0)
                except Exception:
                    pass
        except KeyboardInterrupt:
            stop_event.set()
            with last_priv_lock:
                hex_checkpoint = last_priv_hex
            if hex_checkpoint:
                print("\n[INFO] Interrupted by user. Last private key hex tried (checkpoint):", flush=True)
                print(hex_checkpoint, flush=True)
            else:
                print("\n[INFO] Interrupted by user. No key processed yet.", flush=True)

        executor.shutdown(wait=True)

    print("[INFO] All workers stopped. Exiting.", flush=True)

if __name__ == "__main__":
    main()