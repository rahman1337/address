#!/usr/bin/env python3
"""
btc_scanner_found_sleep.py (refactored with jitter)

- Default 4 threads: 3 scanner threads and 1 dedicated balance-checker thread.
- Scanner threads: derive addresses, call getreceivedbyaddress, sleep 0.6s per address.
  If received != 0 they enqueue (address, wif, received) to balance_queue.
- Balance thread: dequeues items, calls addressbalance with retries, sleeps balance_sleep +/- jitter between balance checks to avoid 429.
- AddrChecker already has retries (3) and debug printing.
- Ctrl+C prints checkpoint (last private key hex tried).
- Use -d for debug.
"""
import argparse
import threading
import time
import signal
import requests
import queue
import random
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160

SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ----------------- hashing / base58 / WIF -----------------
def sha256(b: bytes) -> bytes:
    h = SHA256.new()
    h.update(b)
    return h.digest()


def ripemd160(b: bytes) -> bytes:
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


# ----------------- bech32 (BIP-173) -----------------
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xFF
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GENERATORS[i]
    return chk


def bech32_hrp_expand(hrp: str):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32_create_checksum(hrp: str, data: bytes):
    values = bech32_hrp_expand(hrp) + list(data) + [0, 0, 0, 0, 0, 0]
    polymod = bech32_polymod(values) ^ 1
    return bytes((polymod >> (5 * (5 - i)) & 31) for i in range(6))


def bech32_encode(hrp: str, data: bytes) -> str:
    combined = bytes(list(data) + list(bech32_create_checksum(hrp, data)))
    return hrp + "1" + "".join(BECH32_CHARSET[b] for b in combined)


def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> bytes:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        if b >> frombits:
            raise ValueError("Invalid data for convertbits")
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    else:
        if bits >= frombits or ((acc << (tobits - bits)) & maxv):
            raise ValueError("Invalid padding in convertbits")
    return bytes(ret)


def bech32_p2wpkh_from_h160(h160: bytes) -> str:
    version = 0
    data = bytes([version]) + convertbits(h160, 8, 5)
    return bech32_encode("bc", data)


# ----------------- address builders -----------------
def p2pkh(pub: bytes) -> str:
    return base58check_encode(b"\x00" + hash160(pub))


def p2sh_p2wpkh(pub: bytes) -> str:
    redeem_script = b"\x00\x14" + hash160(pub)
    return base58check_encode(b"\x05" + hash160(redeem_script))


def p2wpkh_bech32(pub: bytes) -> str:
    return bech32_p2wpkh_from_h160(hash160(pub))


# ----------------- deterministic index provider -----------------
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


# ----------------- network checker with retries & sleeps -----------------
class AddrChecker:
    def __init__(self, session: requests.Session, debug: bool = False, timeout: float = 10.0):
        self.session = session
        self.debug = debug
        self.timeout = timeout

    def _get_with_retries(self, url: str, retries: int = 3, sleep_between: float = 0.6):
        last_exc = None
        for attempt in range(1, retries + 1):
            try:
                resp = self.session.get(url, timeout=self.timeout)
            except Exception as e:
                last_exc = e
                if self.debug:
                    print(f"[DEBUG] GET {url} attempt {attempt} error: {e}", flush=True)
            else:
                if self.debug:
                    print(f"[DEBUG] GET {url} -> {resp.status_code} {resp.reason}", flush=True)
                if resp.status_code == 200:
                    return resp
                else:
                    last_exc = RuntimeError(f"HTTP {resp.status_code}")
            if attempt < retries:
                time.sleep(sleep_between)
        raise last_exc

    def get_received(self, address: str) -> int:
        url = f"https://blockchain.info/q/getreceivedbyaddress/{address}"
        resp = self._get_with_retries(url)
        return int(resp.text.strip())

    def get_balance(self, address: str) -> int:
        url = f"https://blockchain.info/q/addressbalance/{address}"
        resp = self._get_with_retries(url)
        return int(resp.text.strip())


# ----------------- globals / checkpoint -----------------
stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()

# Queue for balance checks: items are tuples (address, wif, received)
balance_queue = queue.Queue()

# ----------------- worker thread (scanners) -----------------
def worker_thread(name: str, idx_provider: IndexProvider, checker: AddrChecker, print_lock: threading.Lock, debug: bool):
    global last_priv_hex
    while not stop_event.is_set():
        idx = idx_provider.next_index()
        priv_bytes = idx.to_bytes(32, "big")
        priv_hex = priv_bytes.hex()
        with last_priv_lock:
            last_priv_hex = priv_hex

        try:
            pk = PrivateKey(priv_bytes)
            pub_compressed = pk.public_key.format(compressed=True)
            wif_c = privkey_to_wif(priv_bytes, compressed=True)

            addresses = [
                p2pkh(pub_compressed),  # 1...
                p2sh_p2wpkh(pub_compressed),  # 3...
                p2wpkh_bech32(pub_compressed),  # bc1q...
            ]

            if debug:
                with print_lock:
                    print(f"[{name}] scanning idx={idx} priv={priv_hex}", flush=True)

            for addr in addresses:
                if stop_event.is_set():
                    break

                # 1) Check "received" with retries; if fails print error and move on
                try:
                    recvd = checker.get_received(addr)
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] [{name}] addr={addr} getreceived FAILED: {e}", flush=True)
                    # mandatory sleep 0.6s per address check (applies per thread)
                    time.sleep(0.6)
                    continue

                # 2) If received != 0, enqueue for dedicated balance checker (do NOT check here)
                if recvd != 0:
                    try:
                        balance_queue.put_nowait((addr, wif_c, recvd))
                    except queue.Full:
                        # If queue is full (unlikely unless you explicitly set maxsize), print a warning and skip
                        with print_lock:
                            print(f"[WARN] [{name}] balance_queue full; skipping enqueue for {addr}", flush=True)

                # 3) mandatory sleep 0.6s after each address check (per thread)
                time.sleep(0.6)

        except Exception as e:
            with print_lock:
                print(f"[ERROR] [{name}] idx={idx} private derivation failed: {e}", flush=True)
            time.sleep(0.6)

    if debug:
        with print_lock:
            print(f"[{name}] exiting", flush=True)


# ----------------- dedicated balance-checker thread -----------------
def balance_worker(checker: AddrChecker, print_lock: threading.Lock, debug: bool, balance_sleep: float, jitter: float):
    """
    Consumes balance_queue. For each queued item, calls get_balance and prints results.
    Sleeps balance_sleep +/- jitter between balance checks to avoid 429.
    Exits when stop_event is set and queue is empty.
    """
    while True:
        if stop_event.is_set() and balance_queue.empty():
            break
        try:
            addr, wif_c, recvd = balance_queue.get(timeout=0.5)
        except queue.Empty:
            continue  # loop to check stop_event
        try:
            bal = checker.get_balance(addr)
        except Exception as e:
            with print_lock:
                print("\n" + "=" * 60, flush=True)
                print("!!! FOUND (BALANCE CHECK FAILED) !!!", flush=True)
                print("", flush=True)
                print("WIF:", wif_c, flush=True)
                print("ADDRESS:", addr, flush=True)
                print("RECEIVED (sats):", str(recvd), flush=True)
                print("BALANCE CHECK ERROR:", str(e), flush=True)
                print("=" * 60 + "\n", flush=True)
        else:
            with print_lock:
                print("\n" + "=" * 60, flush=True)
                print("!!!!! FOUND ADDRESS WITH RECEIVED FUNDS !!!!!", flush=True)
                print("", flush=True)
                print("WIF:", wif_c, flush=True)
                print("ADDRESS:", addr, flush=True)
                print("RECEIVED (sats):", str(recvd), flush=True)
                print("BALANCE (sats):", str(bal), flush=True)
                print("=" * 60 + "\n", flush=True)
        finally:
            balance_queue.task_done()
            # Sleep balance_sleep +/- jitter (clamped to >= 0.0)
            sleep_time = balance_sleep + random.uniform(-jitter, jitter)
            if sleep_time < 0.0:
                sleep_time = 0.0
            time.sleep(sleep_time)

    if debug:
        with print_lock:
            print("[balance-worker] exiting", flush=True)


# ----------------- CLI / main -----------------
def parse_args():
    p = argparse.ArgumentParser(description="Deterministic BTC scanner (multi-threaded) with dedicated balance thread and jitter")
    p.add_argument("-t", "--threads", type=int, default=4,
                   help="total threads to run (default 4: 3 scanners + 1 balance checker). Minimum 2.")
    p.add_argument("-d", "--debug", action="store_true", help="debug mode: prints each GET status")
    p.add_argument("--start", type=int, default=1, help="start index (default 1)")
    p.add_argument("--balance-sleep", type=float, default=1.0,
                   help="mean sleep (seconds) between balance checks in the dedicated balance thread (default 1.0)")
    p.add_argument("--jitter", type=float, default=0.2,
                   help="max +/- jitter (seconds) applied to balance-sleep (default 0.2, so default range is 0.8-1.2)")
    return p.parse_args()


def main():
    global last_priv_hex
    args = parse_args()
    if args.threads < 2:
        raise SystemExit("threads must be >= 2 (at least one scanner and one balance thread)")

    # We'll use (threads - 1) scanner threads and 1 dedicated balance thread.
    scanner_count = max(1, args.threads - 1)

    idx_provider = IndexProvider(start=args.start)

    session = requests.Session()
    checker = AddrChecker(session=session, debug=args.debug)

    print_lock = threading.Lock()

    # signal handler: set stop and print checkpoint
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

    # start scanner threads
    threads = []
    for i in range(scanner_count):
        t = threading.Thread(
            target=worker_thread,
            args=(f"scanner-{i+1}", idx_provider, checker, print_lock, args.debug),
            daemon=True,
        )
        threads.append(t)
        t.start()

    # start single balance thread with jitter parameters
    bal_thread = threading.Thread(
        target=balance_worker,
        args=(checker, print_lock, args.debug, args.balance_sleep, args.jitter),
        daemon=True,
    )
    threads.append(bal_thread)
    bal_thread.start()

    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
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

    # Wait briefly for threads to finish
    for t in threads:
        t.join(timeout=1.0)

    # Ensure any remaining queued balance checks are attempted before full exit
    # (balance_worker will exit when stop_event is set and queue empty)
    if not balance_queue.empty():
        try:
            # give some time for balance worker to finish remaining items
            balance_queue.join(timeout=5.0)
        except TypeError:
            # older Python's queue.join has no timeout param; ignore
            pass

    print("[INFO] All workers stopped. Exiting.", flush=True)


if __name__ == "__main__":
    main()