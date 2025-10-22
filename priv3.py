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

SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ANSI colors
YELLOW = "\033[33m"
LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"

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

def p2pkh(pub: bytes) -> str:
    return base58check_encode(b"\x00" + hash160(pub))

def p2sh_p2wpkh(pub: bytes) -> str:
    redeem_script = b"\x00\x14" + hash160(pub)
    return base58check_encode(b"\x05" + hash160(redeem_script))

def p2wpkh_bech32(pub: bytes) -> str:
    return bech32_p2wpkh_from_h160(hash160(pub))

class IntIndexProvider:
    """
    Provides sequential integer indices (1,2,3,...) and converts each index to a 32-byte big-endian private key.
    - start is 1-based index (default 1).
    - wraps to 1 when exceeding SECP256K1_ORDER-1 (same behavior as original script).
    """
    def __init__(self, start: int = 1):
        if not (1 <= start < SECP256K1_ORDER):
            raise ValueError("start must be in [1, SECP256K1_ORDER-1]")
        self._lock = threading.Lock()
        self._i = start

    def next_priv_bytes(self) -> (bytes, int):
        """
        Returns tuple (priv_bytes_32, index_int)
        """
        with self._lock:
            val = self._i
            # increment and wrap if necessary
            self._i += 1
            if self._i >= SECP256K1_ORDER:
                self._i = 1
        priv_bytes = val.to_bytes(32, "big")
        return priv_bytes, val

class AddrChecker:
    def __init__(self, session: requests.Session, sem: threading.Semaphore, debug: bool = False, timeout: float = 10.0):
        self.session = session
        self.sem = sem
        self.debug = debug
        self.timeout = timeout

    def _get_with_retries(self, url: str, retries: int = 3, sleep_between: float = 0.6):
        last_exc = None
        for attempt in range(1, retries + 1):
            try:
                # acquire semaphore slot for outbound request
                self.sem.acquire()
                try:
                    resp = self.session.get(url, timeout=self.timeout)
                finally:
                    # always release semaphore even on request exceptions
                    self.sem.release()
            except Exception as e:
                last_exc = e
                if self.debug:
                    print(f"[DEBUG] GET {url} attempt {attempt} error: {e}", flush=True)
            else:
                if self.debug:
                    print(f"[DEBUG] GET {url} -> {resp.status_code} {resp.reason}", flush=True)
                if resp.status_code == 200:
                    return resp
                elif resp.status_code == 429:
                    # Server rate limit — treat as retryable but wait longer before retry
                    last_exc = RuntimeError("HTTP 429 Too Many Requests")
                else:
                    last_exc = RuntimeError(f"HTTP {resp.status_code}")
            if attempt < retries:
                time.sleep(sleep_between)
        raise last_exc

    # Uses blockchain.info quick API to get total received (satoshis).
    # Returns int (total received in satoshis) or raises on failure.
    def get_received(self, address: str) -> int:
        url = f"https://blockchain.info/q/getreceivedbyaddress/{address}"
        resp = self._get_with_retries(url)
        return int(resp.text.strip())

    # Uses BlockCypher address balance endpoint.
    # Returns int(final_balance in satoshis) or raises on failure.
    def get_balance(self, address: str) -> int:
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
        resp = self._get_with_retries(url)
        data = resp.json()
        if "final_balance" in data:
            return int(data["final_balance"])
        elif "balance" in data:
            return int(data["balance"])
        else:
            return int(data.get("total_received", 0))

stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()

def worker_thread(name: str, idx_provider: IntIndexProvider, checker: AddrChecker, print_lock: threading.Lock, debug: bool):
    global last_priv_hex
    while not stop_event.is_set():
        try:
            priv_bytes, idx_val = idx_provider.next_priv_bytes()
            priv_hex = priv_bytes.hex()
            with last_priv_lock:
                last_priv_hex = priv_hex

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
                    print(f"[{name}] scanning idx={idx_val} priv={priv_hex}", flush=True)

            for addr in addresses:
                if stop_event.is_set():
                    break

                # 1) Check "received" with retries; if fails print error and move on
                try:
                    recvd = checker.get_received(addr)
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] [{name}] addr={addr} getreceived FAILED: {e}", flush=True)
                    # sleep 0.6s per address check (applies per thread)
                    time.sleep(0.6)
                    continue

                # 2) If received != 0, wait 1.0s before checking balance to reduce 429
                if recvd != 0:
                    time.sleep(1.0)
                    try:
                        bal = checker.get_balance(addr)
                    except Exception as e:
                        with print_lock:
                            # Print a clearly delimited "found but balance check failed" block
                            print("\n" + "=" * 53, flush=True)
                            print("!!! FOUND (BALANCE CHECK FAILED) !!!", flush=True)
                            print("", flush=True)
                            print("WIF:", wif_c, flush=True)
                            print("ADDRESS:", addr, flush=True)
                            print("INDEX:", idx_val, flush=True)
                            # colored received
                            print("RECEIVED (sats):", f"{YELLOW}{recvd}{RESET}", flush=True)
                            print("BALANCE CHECK ERROR:", str(e), flush=True)
                            print("=" * 53 + "\n", flush=True)
                    else:
                        # Print a clear bordered block for found addresses
                        with print_lock:
                            print("\n" + "=" * 53, flush=True)
                            print("!!!!! FOUND ADDRESS WITH RECEIVED FUNDS !!!!!", flush=True)
                            print("", flush=True)
                            print("WIF:", wif_c, flush=True)
                            print("ADDRESS:", addr, flush=True)
                            print("INDEX:", idx_val, flush=True)
                            # colored received and balance
                            print("RECEIVED (sats):", f"{YELLOW}{recvd}{RESET}", flush=True)
                            print("BALANCE (sats):", f"{LIGHT_GREEN}{bal}{RESET}", flush=True)
                            print("=" * 53 + "\n", flush=True)

                # 3) mandatory sleep 0.6s after each address check (per thread)
                time.sleep(0.6)

        except Exception as e:
            with print_lock:
                print(f"[ERROR] [{name}] private derivation or worker error: {e}", flush=True)
            time.sleep(0.6)

    if debug:
        with print_lock:
            print(f"[{name}] exiting", flush=True)

def parse_args():
    p = argparse.ArgumentParser(description="Deterministic BTC scanner (integer index -> 32-byte big-endian private key)")
    p.add_argument("-t", "--threads", type=int, default=3, help="number of worker threads (default 3)")
    p.add_argument("-c", "--concurrency", type=int, default=2, help="max concurrent HTTP requests across threads (default 2)")
    p.add_argument("-d", "--debug", action="store_true", help="debug mode: prints each GET status")
    p.add_argument("--start", type=int, default=1, help="start index (default 1)")
    return p.parse_args()

def main():
    global last_priv_hex
    args = parse_args()
    try:
        idx_provider = IntIndexProvider(start=args.start)
    except Exception as e:
        print(f"[FATAL] failed to initialize index provider: {e}", flush=True)
        sys.exit(1)

    session = requests.Session()
    # semaphore controlling concurrent HTTP requests across all threads
    sem = threading.Semaphore(max(1, args.concurrency))
    checker = AddrChecker(session=session, sem=sem, debug=args.debug)

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

    # start worker threads via ThreadPoolExecutor
    num_threads = max(1, args.threads)
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(worker_thread, f"worker-{i+1}", idx_provider, checker, print_lock, args.debug)
            for i in range(num_threads)
        ]

        try:
            # Wait until all futures complete or stop_event is set
            for future in as_completed(futures):
                # if stop_event set, break out -- workers will exit on their own
                if stop_event.is_set():
                    break
                # propagate exceptions from worker threads if any
                try:
                    future.result(timeout=0)
                except Exception:
                    # ignore here — worker threads print their own errors
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

        # allow threads a moment to see stop_event and exit
        executor.shutdown(wait=True)

    print("[INFO] All workers stopped. Exiting.", flush=True)

if __name__ == "__main__":
    main()