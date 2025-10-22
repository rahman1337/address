#!/usr/bin/env python3
import argparse
import time
import signal
import sys
import requests
import threading
import os
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

# --------------------- New provider: Prefix + Deterministic Non-repeating Suffix ---------------------
class PrefixCounterProvider:
    """
    Build private key hex as:
      PRIV = <prefix_hex (42 chars)> + <suffix_hex (22 chars)>

    Suffix generation modes:
      - hex:    suffix = counter in hex (0..), zero-padded to 22 hex chars (0-9A-F)
      - digits: suffix = counter in decimal, zero-padded to 22 chars (digits only 0-9)
      - letters: suffix = counter in base-6 mapped to A..F, zero-padded to 22 chars (letters A-F only)

    Ensures full key < SECP256K1_ORDER. Optionally persist the last counter to a file to avoid repeats across runs.
    """
    def __init__(self, prefix_hex: str, mode: str = "hex", start_counter: int = 0, persist_file: str = None):
        prefix_hex = prefix_hex.upper()
        if len(prefix_hex) != 42:
            raise ValueError("prefix_hex must be exactly 42 hex characters (21 bytes)")
        # validate hex
        int(prefix_hex, 16)
        self.prefix_hex = prefix_hex

        # order suffix (remaining 22 hex chars) and numeric bound
        order_hex = format(SECP256K1_ORDER, "064x").upper()
        self.order_suffix_hex = order_hex[42:]  # 22 hex chars
        self.order_suffix_int = int(self.order_suffix_hex, 16)

        self.suffix_len = 22
        self.mode = mode.lower()
        if self.mode not in ("hex", "digits", "letters"):
            raise ValueError("mode must be one of: hex, digits, letters")

        self._lock = threading.Lock()
        self.persist_file = persist_file

        # load persisted counter if available; otherwise use provided start_counter
        self.counter = int(start_counter)
        if persist_file and os.path.exists(persist_file):
            try:
                with open(persist_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                if content:
                    self.counter = max(self.counter, int(content))
            except Exception:
                # ignore and use start_counter
                pass

        # final validation: ensure starting counter does not already exceed order bound
        if not self._counter_valid(self.counter):
            raise RuntimeError("start_counter is out of range for suffix generation (would exceed order)")

    def _persist_counter(self, value: int):
        if not self.persist_file:
            return
        # write the last used counter (as decimal) atomically
        tmp = self.persist_file + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(str(value))
        os.replace(tmp, self.persist_file)

    def _counter_valid(self, counter: int) -> bool:
        """
        Returns True if the suffix produced by this counter would produce a suffix numeric value
        (when interpreted as hex) < order_suffix_int.
        """
        s = self._counter_to_suffix_hex(counter)
        return int(s, 16) < self.order_suffix_int

    def _counter_to_suffix_hex(self, counter: int) -> str:
        if self.mode == "hex":
            s = format(counter, "0{}x".format(self.suffix_len)).upper()
            if len(s) > self.suffix_len:
                # overflow: counter cannot fit into suffix_len hex digits
                raise RuntimeError("counter overflow for suffix length")
            return s.zfill(self.suffix_len)
        elif self.mode == "digits":
            s = str(counter).zfill(self.suffix_len)
            if len(s) > self.suffix_len:
                raise RuntimeError("counter overflow for digits-mode suffix length")
            # digits-only string is valid hex because 0-9 are hex digits
            return s.upper()
        else:  # letters mode: map base-6 digits -> A..F
            # convert counter to base-6, then map 0->A,1->B,...5->F, pad to suffix_len
            if counter < 0:
                raise RuntimeError("counter must be non-negative")
            digits = []
            n = counter
            if n == 0:
                digits = ["A"]
            else:
                while n > 0:
                    digits.append("ABCDEF"[n % 6])  # map 0..5 -> A..F
                    n //= 6
            s = "".join(reversed(digits)).rjust(self.suffix_len, "A")  # pad with 'A' (represents 0)
            if len(s) > self.suffix_len:
                raise RuntimeError("counter overflow for letters-mode suffix length")
            return s.upper()

    def next_priv_bytes(self):
        """
        Increment counter and return (priv_bytes(32), suffix_hex(22), full_priv_hex(64))
        """
        with self._lock:
            # find next counter that yields suffix < order_suffix_int
            while True:
                # advance counter
                c = self.counter
                # We'll use the current counter as the produced suffix, then increment
                if not self._counter_valid(c):
                    # if invalid, we cannot proceed further; stop
                    raise RuntimeError("counter reached the maximum valid suffix bound (would exceed curve order)")
                suffix = self._counter_to_suffix_hex(c)
                # commit counter for next call
                self.counter = c + 1
                # persist last used (we persist the last used counter value, i.e. c)
                self._persist_counter(c)
                break

        full_hex = (self.prefix_hex + suffix).upper()
        priv_int = int(full_hex, 16)
        if not (1 <= priv_int < SECP256K1_ORDER):
            raise RuntimeError("Generated private key out of range (defensive check)")
        return priv_int.to_bytes(32, "big"), suffix, full_hex

# --------------------- AddrChecker (unchanged) ---------------------
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
                self.sem.acquire()
                try:
                    resp = self.session.get(url, timeout=self.timeout)
                finally:
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
                    last_exc = RuntimeError("HTTP 429 Too Many Requests")
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
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
        resp = self._get_with_retries(url)
        data = resp.json()
        if "final_balance" in data:
            return int(data["final_balance"])
        elif "balance" in data:
            return int(data["balance"])
        else:
            return int(data.get("total_received", 0))

# --------------------- Worker and main (mostly unchanged) ---------------------
stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()

def worker_thread(name: str, provider: PrefixCounterProvider, checker: AddrChecker, print_lock: threading.Lock, debug: bool):
    global last_priv_hex
    while not stop_event.is_set():
        try:
            priv_bytes, suffix_hex, full_hex = provider.next_priv_bytes()
            priv_hex = full_hex
            with last_priv_lock:
                last_priv_hex = priv_hex

            pk = PrivateKey(priv_bytes)
            pub_compressed = pk.public_key.format(compressed=True)
            wif_c = privkey_to_wif(priv_bytes, compressed=True)

            addresses = [
                p2pkh(pub_compressed),
                p2sh_p2wpkh(pub_compressed),
                p2wpkh_bech32(pub_compressed),
            ]

            if debug:
                with print_lock:
                    print(f"[{name}] suffix={suffix_hex} priv={priv_hex}", flush=True)

            for addr in addresses:
                if stop_event.is_set():
                    break

                try:
                    recvd = checker.get_received(addr)
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] [{name}] addr={addr} getreceived FAILED: {e}", flush=True)
                    time.sleep(0.6)
                    continue

                if recvd != 0:
                    time.sleep(1.0)
                    try:
                        bal = checker.get_balance(addr)
                    except Exception as e:
                        with print_lock:
                            print("\n" + "=" * 53, flush=True)
                            print("!!! FOUND (BALANCE CHECK FAILED) !!!", flush=True)
                            print("", flush=True)
                            print("WIF:", wif_c, flush=True)
                            print("ADDRESS:", addr, flush=True)
                            print("FULL_PRIV_HEX:", priv_hex, flush=True)
                            print("SUFFIX_HEX:", suffix_hex, flush=True)
                            print("RECEIVED (sats):", f"{YELLOW}{recvd}{RESET}", flush=True)
                            print("BALANCE CHECK ERROR:", str(e), flush=True)
                            print("=" * 53 + "\n", flush=True)
                    else:
                        with print_lock:
                            print("\n" + "=" * 53, flush=True)
                            print("!!!!! FOUND ADDRESS WITH RECEIVED FUNDS !!!!!", flush=True)
                            print("", flush=True)
                            print("WIF:", wif_c, flush=True)
                            print("ADDRESS:", addr, flush=True)
                            print("FULL_PRIV_HEX:", priv_hex, flush=True)
                            print("SUFFIX_HEX:", suffix_hex, flush=True)
                            print("RECEIVED (sats):", f"{YELLOW}{recvd}{RESET}", flush=True)
                            print("BALANCE (sats):", f"{LIGHT_GREEN}{bal}{RESET}", flush=True)
                            print("=" * 53 + "\n", flush=True)

                time.sleep(0.6)

        except Exception as e:
            with print_lock:
                print(f"[ERROR] [{name}] private derivation or worker error: {e}", flush=True)
            time.sleep(0.6)

    if debug:
        with print_lock:
            print(f"[{name}] exiting", flush=True)

def parse_args():
    p = argparse.ArgumentParser(description="BTC scanner: fixed prefix + deterministic non-repeating suffix private-keys")
    p.add_argument("-t", "--threads", type=int, default=3, help="number of worker threads (default 3)")
    p.add_argument("-c", "--concurrency", type=int, default=2, help="max concurrent HTTP requests across threads (default 2)")
    p.add_argument("-d", "--debug", action="store_true", help="debug mode: prints each GET status and suffix")
    p.add_argument("--prefix", type=str, default="FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF",
                   help="fixed 42-hex-char prefix (default shown)")
    p.add_argument("--mode", type=str, default="hex", choices=["hex", "digits", "letters"],
                   help="suffix generation mode: hex (counter in hex), digits (decimal digits only), letters (A-F only)")
    p.add_argument("--start-counter", type=int, default=0, help="start counter (default 0)")
    p.add_argument("--persist-counter", type=str, default=None,
                   help="optional file to persist last used counter (prevents repeats across runs)")
    return p.parse_args()

def main():
    global last_priv_hex
    args = parse_args()
    try:
        provider = PrefixCounterProvider(prefix_hex=args.prefix, mode=args.mode,
                                         start_counter=args.start_counter, persist_file=args.persist_counter)
    except Exception as e:
        print(f"[FATAL] failed to initialize provider: {e}", flush=True)
        sys.exit(1)

    session = requests.Session()
    sem = threading.Semaphore(max(1, args.concurrency))
    checker = AddrChecker(session=session, sem=sem, debug=args.debug)

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
            executor.submit(worker_thread, f"worker-{i+1}", provider, checker, print_lock, args.debug)
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