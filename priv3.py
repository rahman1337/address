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

# increase Decimal precision for wei -> ether conversion
getcontext().prec = 36

SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)

# ANSI colors for found output
YELLOW = "\033[33m"
LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"

# Default public RPC endpoints (no API key required)
DEFAULT_RPCS = {
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc-dataseed.binance.org/",
    "polygon": "https://polygon-rpc.com/",
}

# ---------------------------------------------------------------------------
# Utilities: keccak address derivation, wei->native
# ---------------------------------------------------------------------------
def eth_address_from_priv(priv_bytes: bytes) -> str:
    """
    Derive the EVM-style address (0x...) from a 32-byte secp256k1 private key.
    """
    pk = PrivateKey(priv_bytes)
    # uncompressed pubkey: 0x04 || X(32) || Y(32)
    pub_uncompressed = pk.public_key.format(compressed=False)
    # drop the 0x04 prefix
    pub_xy = pub_uncompressed[1:]
    k = keccak.new(digest_bits=256)
    k.update(pub_xy)
    addr = "0x" + k.digest()[-20:].hex()
    return addr

def wei_to_eth_str(wei: int) -> str:
    # convert wei (int) to decimal ETH string
    eth = Decimal(wei) / Decimal(10 ** 18)
    # show up to 18 decimals, strip trailing zeros
    s = format(eth.normalize(), 'f')
    return s

# ---------------------------------------------------------------------------
# Index provider (same deterministic integers 1,2,3,...)
# ---------------------------------------------------------------------------
import threading as _th
class IndexProvider:
    def __init__(self, start: int = 1):
        if not (1 <= start < SECP256K1_ORDER):
            raise ValueError("start must be in [1, SECP256K1_ORDER-1]")
        self._lock = _th.Lock()
        self._i = start

    def next_index(self) -> int:
        with self._lock:
            val = self._i
            self._i += 1
            if self._i >= SECP256K1_ORDER:
                self._i = 1
            return val

# ---------------------------------------------------------------------------
# RPC checker with retries + semaphore (throttles concurrent HTTP calls)
# ---------------------------------------------------------------------------
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
                    # If RPC returns an 'error' field, treat as retryable
                    if "error" in data:
                        last_exc = RuntimeError(f"RPC error: {data['error']}")
                    else:
                        return data
            if attempt < retries:
                time.sleep(sleep_between)
        raise last_exc

    def get_balance_wei(self, address: str) -> int:
        """
        Uses eth_getBalance. Returns integer wei.
        """
        payload = {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [address, "latest"], "id": 1}
        data = self._post_with_retries(payload)
        if not data or "result" not in data:
            raise RuntimeError("No result in RPC response")
        # result is hex string like "0x1234..."
        res = data["result"]
        try:
            return int(res, 16)
        except Exception as e:
            raise RuntimeError(f"Invalid balance value: {res}") from e

# ---------------------------------------------------------------------------
# Worker logic (derives priv from index, computes address, queries balance)
# ---------------------------------------------------------------------------
stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()

def worker_thread(name: str, idx_provider: IndexProvider, checker: RpcChecker, print_lock: threading.Lock, debug: bool):
    global last_priv_hex
    while not stop_event.is_set():
        idx = idx_provider.next_index()
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        with last_priv_lock:
            last_priv_hex = priv_hex

        try:
            address = eth_address_from_priv(priv_bytes)

            if debug:
                with print_lock:
                    print(f"[{name}] scanning idx={idx} addr={address} priv={priv_hex}", flush=True)

            # query balance
            try:
                balance_wei = checker.get_balance_wei(address)
            except Exception as e:
                with print_lock:
                    print(f"[ERROR] [{name}] addr={address} balance check FAILED: {e}", flush=True)
                # short wait to avoid tight error loops
                time.sleep(0.6)
                continue

            if balance_wei != 0:
                # pretty print found block
                with print_lock:
                    print("\n" + "=" * 60, flush=True)
                    print("!!!!! FOUND WALLET WITH BALANCE !!!!!", flush=True)
                    print("", flush=True)
                    print("PRIVATE (hex):", priv_hex, flush=True)
                    print("ADDRESS      :", address, flush=True)
                    print("BALANCE (wei):", f"{YELLOW}{balance_wei}{RESET}", flush=True)
                    print("BALANCE (native):", f"{LIGHT_GREEN}{wei_to_eth_str(balance_wei)}{RESET}", flush=True)
                    print("=" * 60 + "\n", flush=True)

            # small mandatory sleep per address check to be polite to RPCs
            time.sleep(0.6)

        except Exception as e:
            with print_lock:
                print(f"[ERROR] [{name}] idx={idx} private derivation or worker error: {e}", flush=True)
            time.sleep(0.6)

    if debug:
        with print_lock:
            print(f"[{name}] exiting", flush=True)

# ---------------------------------------------------------------------------
# CLI and main
# ---------------------------------------------------------------------------
def parse_args():
    p = argparse.ArgumentParser(description="Deterministic EVM scanner (index -> private key -> address) using public RPC")
    p.add_argument("-t", "--threads", type=int, default=3, help="number of worker threads (default 3)")
    p.add_argument("-c", "--concurrency", type=int, default=2, help="max concurrent HTTP requests across threads (default 2)")
    p.add_argument("-d", "--debug", action="store_true", help="debug mode: prints each RPC status")
    p.add_argument("--start", type=int, default=1, help="start index (default 1)")
    p.add_argument("--chain", type=str, choices=["eth", "bsc", "polygon"], default="eth", help="chain to scan (eth, bsc, polygon)")
    p.add_argument("--rpc", type=str, default=None, help="override RPC URL (optional)")
    return p.parse_args()

def main():
    global last_priv_hex
    args = parse_args()

    rpc_url = args.rpc if args.rpc else DEFAULT_RPCS.get(args.chain)
    if not rpc_url:
        print("[FATAL] no RPC available for chosen chain", flush=True)
        sys.exit(1)

    idx_provider = IndexProvider(start=args.start)
    session = requests.Session()
    sem = threading.Semaphore(max(1, args.concurrency))
    checker = RpcChecker(session=session, sem=sem, rpc_url=rpc_url, debug=args.debug)

    print_lock = threading.Lock()

    def _signal_handler(sig, frame):
        stop_event.set()
        with last_priv_lock:
            hex_checkpoint = last_priv_hex
        if hex_checkpoint:
            print("\n[INFO] Interrupted by user.", flush=True)
            print("[INFO] Last private key hex tried (checkpoint):", flush=True)
            print(hex_checkpoint, flush=True)
        else:
            print("\n[INFO] Interrupted by user. No key processed yet.", flush=True)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    num_threads = max(1, args.threads)
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(worker_thread, f"worker-{i+1}", idx_provider, checker, print_lock, args.debug)
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
                print("\n[INFO] Interrupted by user.", flush=True)
                print("[INFO] Last private key hex tried (checkpoint):", flush=True)
                print(hex_checkpoint, flush=True)
            else:
                print("\n[INFO] Interrupted by user. No key processed yet.", flush=True)

        executor.shutdown(wait=True)

    print("[INFO] All workers stopped. Exiting.", flush=True)

if __name__ == "__main__":
    main()