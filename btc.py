#!/usr/bin/env python3
"""
Optimized Offline Bitcoin-address scanner
- Threaded workers (default 5)
- batch size = 1000 keys per task
- uses coincurve for fast secp256k1 operations
- reads three files: btc1.txt, btc2.txt, btc3.txt (addresses, one per line)
- prints found blocks only when there’s a hit
- debug mode (-d) prints startup & progress every 10s
"""

import os
import sys
import time
import argparse
import threading

# External dependencies: coincurve, base58
try:
    from coincurve import PrivateKey
except ImportError:
    print("Missing dependency: coincurve. Install with `pip install coincurve`", file=sys.stderr)
    raise

try:
    import base58
except ImportError:
    print("Missing dependency: base58. Install with `pip install base58`", file=sys.stderr)
    raise

import hashlib

#########################
# Bech32 minimal helpers
#########################
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
CHARSET_MAP = {c: i for i, c in enumerate(CHARSET)}

def bech32_polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25)
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if ((b >> i) & 1):
                chk ^= GEN[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    out = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            out.append((acc >> bits) & maxv)
    if pad and bits:
        out.append((acc << (tobits - bits)) & maxv)
    return out

def encode_bech32(hrp, witver, witprog):
    data = [witver] + convertbits(witprog, 8, 5)
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + "1" + "".join([CHARSET[d] for d in combined])

# Minimal Bech32 decode (does not validate checksum thoroughly but suits our use)
def bech32_decode(addr):
    addr = addr.strip().lower()
    if '1' not in addr:
        return None, None
    hrp, data_part = addr.rsplit('1', 1)
    data_vals = []
    for ch in data_part:
        v = CHARSET_MAP.get(ch)
        if v is None:
            return None, None
        data_vals.append(v)
    if len(data_vals) < 6:
        return None, None
    return hrp, data_vals

#########################
# Base58Check encode helper (use base58 lib for speed)
#########################
def base58check_encode(payload: bytes, version: bytes = b"\x00") -> str:
    data = version + payload
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    return base58.b58encode(data + checksum).decode()

#########################
# Hash helpers and address derivation
#########################
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(hashlib.sha256(b).digest())

def pubkey_to_p2pkh(pubkey_bytes: bytes) -> str:
    return base58check_encode(hash160(pubkey_bytes), version=b"\x00")

def pubkey_to_p2sh_p2wpkh(pubkey_bytes: bytes) -> str:
    redeem_script = b"\x00\x14" + hash160(pubkey_bytes)
    return base58check_encode(hash160(redeem_script), version=b"\x05")

def pubkey_to_bech32(pubkey_bytes: bytes) -> str:
    witprog = hash160(pubkey_bytes)
    return encode_bech32("bc", 0, witprog)

def priv_to_wif(priv_bytes: bytes, compressed: bool = True) -> str:
    payload = priv_bytes + (b"\x01" if compressed else b"")
    return base58check_encode(payload, version=b"\x80")

#########################
# Key generation
#########################
SECP256K1_ORDER = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

def generate_valid_privkey_bytes() -> bytes:
    while True:
        candidate = os.urandom(32)
        i = int.from_bytes(candidate, "big")
        if 1 <= i < SECP256K1_ORDER:
            return candidate

#########################
# Scanner state
#########################
class ScannerState:
    def __init__(self):
        self.total_keys = 0
        self.total_found = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.errors = 0

    def inc_keys(self, n=1):
        with self.lock:
            self.total_keys += n

    def inc_found(self, n=1):
        with self.lock:
            self.total_found += n

    def inc_errors(self, n=1):
        with self.lock:
            self.errors += n

state = ScannerState()

def format_border(text: str) -> str:
    border = "=" * (len(text) + 4)
    return f"\n{border}\n| {text} |\n{border}\n"

def pretty_found_block(priv_hex: str, wif: str, addr: str) -> str:
    lines = [
        "+" + "-" * 50 + "+",
        "|          MATCH FOUND! (address present in input)          |",
        "+" + "-" * 50 + "+",
        f"PRIV: {priv_hex}",
        f"WIF : {wif}",
        f"ADDR: {addr}",
        "+" + "-" * 50 + "+",
    ]
    return "\n".join(lines)

#########################
# Load BTC addresses into hash sets (h160 for P2PKH/P2WPKH, p2sh hashes for 3... addrs)
#########################
def load_address_hashes(filename: str):
    """
    Returns (h160_set, bech32_witprog_set)
    - For base58 addresses (1... or 3...) we decode the Base58Check and store payload bytes for fast comparison.
    - For bech32 (bc1...) we decode the witness program bytes and store them.
    """
    h160_set = set()     # contains 20-byte payloads used for P2PKH check or P2SH check (we store payloads as bytes)
    bech32_set = set()   # contains witness program bytes (20 bytes for P2WPKH)
    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                addr = line.strip()
                if not addr:
                    continue
                # P2PKH / P2SH (base58)
                if addr.startswith("1") or addr.startswith("3"):
                    try:
                        decoded = base58.b58decode_check(addr)  # bytes: version + payload
                        # store payload (skip version byte)
                        payload = decoded[1:]
                        # payload length for P2PKH is 20; for P2SH it's also 20 (hash160)
                        if len(payload) in (20,):
                            h160_set.add(bytes(payload))
                    except Exception:
                        # skip malformed/unknown
                        continue
                # Bech32 (assume bc1..., v0 P2WPKH)
                elif addr.startswith("bc1"):
                    hrp, data_vals = bech32_decode(addr)
                    if data_vals:
                        # data_vals includes [witver + data + checksum(6)]
                        # remove witver (first) and checksum (last 6)
                        core = data_vals[1:-6]
                        witprog = convertbits(core, 5, 8, False)
                        if witprog:
                            bech32_set.add(bytes(witprog))
                else:
                    # unknown format -> skip
                    continue
    except FileNotFoundError:
        print(f"[WARN] file not found: {filename}. Continuing with empty set.", file=sys.stderr)
    return h160_set, bech32_set

#########################
# Optimized batch check: compute h160 once, test with sets, only encode strings on hit
#########################
def check_batch_and_print(batch_privs: list, found_sets: tuple, debug: bool = False):
    for priv_bytes in batch_privs:
        try:
            pk = PrivateKey(priv_bytes)
            pub_compressed = pk.public_key.format(compressed=True)  # 33 bytes
            h160 = hash160(pub_compressed)
            hit_addr = None

            # check against each provided set pair
            for hset, bset in found_sets:
                # P2PKH direct match (1...)
                if h160 in hset:
                    hit_addr = pubkey_to_p2pkh(pub_compressed)
                    break
                # P2SH-P2WPKH: redeem_script = 0x00 0x14 <20-byte keyhash>; then hash160(redeem_script) is the P2SH payload
                redeem_script = b"\x00\x14" + h160
                p2sh_hash = hash160(redeem_script)
                if p2sh_hash in hset:
                    hit_addr = pubkey_to_p2sh_p2wpkh(pub_compressed)
                    break
                # Native segwit P2WPKH (bech32) match: compare witness program
                if h160 in bset:
                    hit_addr = pubkey_to_bech32(pub_compressed)
                    break

            if hit_addr:
                priv_hex = priv_bytes.hex()
                wif = priv_to_wif(priv_bytes, compressed=True)  # compute WIF only on hit
                state.inc_found(1)
                print(pretty_found_block(priv_hex, wif, hit_addr))

        except Exception as e:
            state.inc_errors(1)
            if debug:
                print(format_border(f"ERROR deriving addresses: {e}"))
    # Count keys processed (batch length)
    state.inc_keys(len(batch_privs))

#########################
# Worker thread and reporter
#########################
def worker_loop(batch_size: int, found_sets: tuple, stop_event: threading.Event, debug: bool):
    while not stop_event.is_set():
        batch = [generate_valid_privkey_bytes() for _ in range(batch_size)]
        check_batch_and_print(batch, found_sets, debug)

def reporter(period: int, stop_event: threading.Event, debug: bool):
    last_total = 0
    last_time = state.start_time
    while not stop_event.is_set():
        time.sleep(period)
        with state.lock:
            total = state.total_keys
            found = state.total_found
            errors = state.errors
        now = time.time()
        elapsed = max(now - state.start_time, 1e-6)
        keys_s = total / elapsed
        delta = total - last_total
        delta_t = max(now - last_time, 1e-6)
        if debug:
            text = (f"[DEBUG] elapsed={elapsed:.1f}s total_keys={total} "
                    f"keys/s={keys_s:.1f} recent_keys={delta}/{delta_t:.1f}s "
                    f"found={found} errors={errors}")
            print(format_border(text))
        last_total = total
        last_time = now

#########################
# Argument parser
#########################
def parse_args():
    p = argparse.ArgumentParser(description="Optimized Bitcoin address scanner (threaded)")
    p.add_argument("-d", "--debug", action="store_true", help="debug mode: print startup + progress every 10s")
    p.add_argument("-w", "--workers", type=int, default=5, help="number of worker threads (default 5)")
    p.add_argument("-b", "--batch", type=int, default=1000, help="batch size per worker iteration (default 1000)")
    return p.parse_args()

#########################
# Main
#########################
def main():
    args = parse_args()

    # Load address sets
    s1_h160, s1_bech32 = load_address_hashes("btc1.txt")
    s2_h160, s2_bech32 = load_address_hashes("btc2.txt")
    s3_h160, s3_bech32 = load_address_hashes("btc3.txt")
    found_sets = ((s1_h160, s1_bech32),
                  (s2_h160, s2_bech32),
                  (s3_h160, s3_bech32))

    # Startup prints
    print(format_border("Starting Bitcoin address scanner"))
    print("Loaded addresses from input files:")
    print(f"  btc1.txt: {len(s1_h160) + len(s1_bech32)} addresses")
    print(f"  btc2.txt: {len(s2_h160) + len(s2_bech32)} addresses")
    print(f"  btc3.txt: {len(s3_h160) + len(s3_bech32)} addresses")
    workers = max(1, args.workers)
    batch_size = max(1, args.batch)
    print(f"Using {workers} worker threads, batch size={batch_size}")
    print("="*60)

    stop_event = threading.Event()

    # Start worker threads
    threads = []
    for i in range(workers):
        t = threading.Thread(target=worker_loop, args=(batch_size, found_sets, stop_event, args.debug), daemon=True)
        t.start()
        threads.append(t)

    # Start reporter thread if debug
    if args.debug:
        rep_thread = threading.Thread(target=reporter, args=(10, stop_event, args.debug), daemon=True)
        rep_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_event.set()
        print("\nStopping workers...")
        for t in threads:
            t.join(timeout=1)
        if args.debug:
            rep_thread.join(timeout=1)

        elapsed = time.time() - state.start_time
        with state.lock:
            total = state.total_keys
            found = state.total_found
            errors = state.errors

        print("="*40)
        print("Interrupted by user (Ctrl+C)")
        print(f"Elapsed    : {elapsed:.1f} s")
        print(f"Total keys : {total}")
        print(f"Keys/s     : {total/elapsed:.1f}")
        print(f"Found      : {found}")
        print(f"Errors     : {errors}")
        print("="*40)

if __name__ == "__main__":
    main()
