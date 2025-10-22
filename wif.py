#!/usr/bin/env python3
"""
btc_scanner_threadpool_blockcypher_semaphore_wif_base58_suffix.py

Modified deterministic multi-threaded BTC address scanner that:
- Iterates WIF strings formed as: <WIF_PREFIX>7<9-char base58 random suffix>
  e.g. KwDiBf89...M7rFU7<9-random-base58-chars>, KwDiBf89...M7rFU7<next-random-9chars>, ...
  (the single character '7' is fixed; the trailing 9 chars are random and guaranteed
   not to repeat within the same run)
- Decodes each WIF to a 32-byte private key (supports compressed WIFs).
- Derives compressed pubkey and addresses:
  P2PKH (1...), P2SH-P2WPKH (3...), P2WPKH (bc1q...).
- For every address:
    - GET https://blockchain.info/q/getreceivedbyaddress/{address}
    - (sleep 0.6s after each address check)
    - If received != 0: sleep 1.0s, then GET BlockCypher:
      https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance
    - Print nicely formatted "FOUND" block for hits.
- Retries up to 3 times on network errors (0.6s between retries).
- 0.6s sleeps apply per address per thread.
- Uses a global threading.Semaphore to limit concurrent HTTP requests (--concurrency).
- Ctrl+C prints a checkpoint (last private key hex & last WIF tried).
- Use -d for debug (prints GET status lines).
"""
import argparse
import time
import signal
import sys
import requests
import threading
import secrets
from concurrent.futures import ThreadPoolExecutor, as_completed
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


def base58_decode(s: str) -> bytes:
    """Decode base58 string to bytes (no checksum verification)."""
    num = 0
    for ch in s:
        idx = BASE58_ALPHABET.find(ch)
        if idx == -1:
            raise ValueError(f"Invalid base58 char: {ch}")
        num = num * 58 + idx
    # determine leading zero bytes from '1's
    npad = 0
    for ch in s:
        if ch == "1":
            npad += 1
        else:
            break
    full = num.to_bytes((num.bit_length() + 7) // 8, "big") if num != 0 else b""
    return b"\x00" * npad + full


def base58check_decode(s: str) -> bytes:
    """
    Decode base58check and verify checksum.
    Returns payload (without 4-byte checksum) if valid, else raises ValueError.
    """
    raw = base58_decode(s)
    if len(raw) < 4:
        raise ValueError("Invalid base58check: too short")
    payload, chk = raw[:-4], raw[-4:]
    calc = sha256(sha256(payload))[:4]
    if calc != chk:
        raise ValueError("Invalid base58check checksum")
    return payload


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


# ----------------- deterministic WIF index provider (random non-repeating suffix) -----------------
class WIFIndexProvider:
    """
    Produces random, non-repeating base58 9-character suffixes for WIF strings.
    WIF strings are constructed as: prefix + '7' + <9-char base58 random suffix>
    The provider guarantees no repeats within a single program run by tracking seen suffixes.
    """
    SUFFIX_LEN = 9  # variable random part length (the single '7' is fixed)

    def __init__(self, prefix: str):
        if not isinstance(prefix, str) or len(prefix) == 0:
            raise ValueError("prefix must be a non-empty string")
        self._prefix = prefix
        self._lock = threading.Lock()
        # set of suffix strings already returned (keeps uniqueness within run)
        self._seen = set()

    def _gen_random_suffix(self) -> str:
        # cryptographically secure random picks
        return "".join(secrets.choice(BASE58_ALPHABET) for _ in range(self.SUFFIX_LEN))

    def next_suffix(self) -> str:
        """
        Return a new random SUFFIX_LEN-length base58 suffix that hasn't been produced before.
        This will loop until it finds an unused suffix (practical unless the search space
        is exhausted or extremely large runs are performed).
        """
        with self._lock:
            # try until an unseen suffix is generated
            # (given 58^9 possibilities, collision probability is tiny for reasonable runs)
            while True:
                s = self._gen_random_suffix()
                if s not in self._seen:
                    self._seen.add(s)
                    return s

    def construct_wif(self, suffix_base58: str) -> str:
        if len(suffix_base58) != self.SUFFIX_LEN:
            raise ValueError("suffix must be length " + str(self.SUFFIX_LEN))
        # fixed single '7' inserted between prefix and variable suffix
        return f"{self._prefix}7{suffix_base58}"


# ----------------- network checker with retries, sleeps & semaphore -----------------
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

    def get_received(self, address: str) -> int:
        """
        Uses blockchain.info quick API to get total received (satoshis).
        Returns int (total received in satoshis) or raises on failure.
        """
        url = f"https://blockchain.info/q/getreceivedbyaddress/{address}"
        resp = self._get_with_retries(url)
        return int(resp.text.strip())

    def get_balance(self, address: str) -> int:
        """
        Uses BlockCypher address balance endpoint.
        Returns int(final_balance in satoshis) or raises on failure.
        """
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance"
        resp = self._get_with_retries(url)
        data = resp.json()
        if "final_balance" in data:
            return int(data["final_balance"])
        elif "balance" in data:
            return int(data["balance"])
        else:
            return int(data.get("total_received", 0))


# ----------------- globals / checkpoint -----------------
stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()
last_wif_tried = None
last_wif_lock = threading.Lock()


# ----------------- WIF decoding helper -----------------
def wif_to_privbytes(wif: str) -> (bytes, bool):
    """
    Decode WIF string to (priv_bytes (32 bytes), compressed (bool)).
    Raises ValueError on invalid WIF.
    Expects payload format: 0x80 + 32 bytes (+ optional 0x01 for compressed)
    """
    payload = base58check_decode(wif)  # may raise ValueError
    # payload: prefix byte (0x80), then 32 bytes privkey, optionally 0x01
    if len(payload) not in (33, 34):
        raise ValueError(f"Invalid WIF payload length: {len(payload)}")
    if payload[0] != 0x80:
        raise ValueError(f"Invalid WIF prefix byte: {payload[0]:02x}")
    if len(payload) == 33:
        priv = payload[1:]
        compressed = False
    else:
        # length 34, last byte should be 0x01 per compressed WIF convention
        if payload[-1] != 0x01:
            raise ValueError("Invalid compressed WIF flag byte")
        priv = payload[1:-1]
        compressed = True
    if len(priv) != 32:
        raise ValueError("Invalid private key length after WIF decode")
    # ensure priv is within valid range (1..order-1)
    ival = int.from_bytes(priv, "big")
    if ival == 0 or ival >= SECP256K1_ORDER:
        raise ValueError("Invalid private scalar from WIF")
    return priv, compressed


# ----------------- worker thread -----------------
def worker_thread(name: str, wif_provider: WIFIndexProvider, checker: AddrChecker, print_lock: threading.Lock, debug: bool):
    global last_priv_hex, last_wif_tried
    while not stop_event.is_set():
        suffix = wif_provider.next_suffix()
        wif = wif_provider.construct_wif(suffix)
        with last_wif_lock:
            last_wif_tried = wif

        try:
            # decode WIF to priv bytes
            try:
                priv_bytes, compressed_flag = wif_to_privbytes(wif)
            except Exception as e:
                with print_lock:
                    print(f"[ERROR] [{name}] WIF decode failed for '{wif}': {e}", flush=True)
                # set checkpoint placeholder
                with last_priv_lock:
                    last_priv_hex = None
                # per-address sleep to avoid hot-loop
                time.sleep(0.6)
                continue

            priv_hex = priv_bytes.hex()
            with last_priv_lock:
                last_priv_hex = priv_hex

            pk = PrivateKey(priv_bytes)
            pub_compressed = pk.public_key.format(compressed=True)
            wif_c = wif  # original WIF string

            addresses = [
                p2pkh(pub_compressed),  # 1...
                p2sh_p2wpkh(pub_compressed),  # 3...
                p2wpkh_bech32(pub_compressed),  # bc1q...
            ]

            if debug:
                with print_lock:
                    print(f"[{name}] scanning suffix={suffix} wif={wif} priv={priv_hex}", flush=True)

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
                            print("RECEIVED (sats):", str(recvd), flush=True)
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
                            print("RECEIVED (sats):", str(recvd), flush=True)
                            print("BALANCE (sats):", str(bal), flush=True)
                            print("=" * 53 + "\n", flush=True)

                # 3) mandatory sleep 0.6s after each address check (per thread)
                time.sleep(0.6)

        except Exception as e:
            with print_lock:
                print(f"[ERROR] [{name}] suffix={suffix} worker failed: {e}", flush=True)
            time.sleep(0.6)

    if debug:
        with print_lock:
            print(f"[{name}] exiting", flush=True)


# ----------------- CLI / main -----------------
def parse_args():
    p = argparse.ArgumentParser(description="BTC scanner using WIF prefix + fixed '7' + random non-repeating 9-char base58 suffix (ThreadPoolExecutor) + BlockCypher balance (with semaphore)")
    p.add_argument("-t", "--threads", type=int, default=3, help="number of worker threads (default 3)")
    p.add_argument("-c", "--concurrency", type=int, default=2, help="max concurrent HTTP requests across threads (default 2)")
    p.add_argument("-d", "--debug", action="store_true", help="debug mode: prints each GET status")
    p.add_argument("--wif-prefix", type=str, default="KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU", help="WIF prefix to use (default long prefix you provided)")
    return p.parse_args()


def main():
    global last_priv_hex, last_wif_tried
    args = parse_args()

    wif_provider = WIFIndexProvider(prefix=args.wif_prefix)

    session = requests.Session()
    # semaphore controlling concurrent HTTP requests across all threads
    sem = threading.Semaphore(max(1, args.concurrency))
    checker = AddrChecker(session=session, sem=sem, debug=args.debug)

    print_lock = threading.Lock()

    # signal handler: set stop and print checkpoint
    def _signal_handler(sig, frame):
        stop_event.set()
        with last_wif_lock:
            wif_checkpoint = last_wif_tried
        with last_priv_lock:
            hex_checkpoint = last_priv_hex
        print("\n[INFO] Interrupted by user.", flush=True)
        if wif_checkpoint:
            print("[INFO] Last WIF tried (checkpoint):", flush=True)
            print(wif_checkpoint, flush=True)
        if hex_checkpoint:
            print("[INFO] Last private key hex tried (checkpoint):", flush=True)
            print(hex_checkpoint, flush=True)
        if not wif_checkpoint and not hex_checkpoint:
            print("[INFO] No key processed yet.", flush=True)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    # start worker threads via ThreadPoolExecutor
    num_threads = max(1, args.threads)
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [
            executor.submit(worker_thread, f"worker-{i+1}", wif_provider, checker, print_lock, args.debug)
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
            with last_wif_lock:
                wif_checkpoint = last_wif_tried
            with last_priv_lock:
                hex_checkpoint = last_priv_hex
            print("\n[INFO] Interrupted by user.", flush=True)
            if wif_checkpoint:
                print("[INFO] Last WIF tried (checkpoint):", flush=True)
                print(wif_checkpoint, flush=True)
            if hex_checkpoint:
                print("[INFO] Last private key hex tried (checkpoint):", flush=True)
                print(hex_checkpoint, flush=True)
            if not wif_checkpoint and not hex_checkpoint:
                print("[INFO] No key processed yet.", flush=True)

        # allow threads a moment to see stop_event and exit
        executor.shutdown(wait=True)

    print("[INFO] All workers stopped. Exiting.", flush=True)


if __name__ == "__main__":
    main()