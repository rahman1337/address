#!/usr/bin/env python3
import argparse
import hashlib
import threading
import time
import sys
import secrets

import requests
from coincurve import PrivateKey

# ---------------------------
# base58check helpers
# ---------------------------
B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58encode(b: bytes) -> str:
    n = int.from_bytes(b, 'big')
    res = bytearray()
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_ALPHABET[r])
    res.reverse()
    pad = 0
    for c in b:
        if c == 0:
            pad += 1
        else:
            break
    return (B58_ALPHABET[0:1] * pad + bytes(res)).decode()

def base58check_encode(payload: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return b58encode(payload + checksum)

# ---------------------------
# hash160
# ---------------------------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

# ---------------------------
# WIF
# ---------------------------
def privkey_to_wif(privkey_bytes: bytes, compressed: bool = True) -> str:
    prefix = b'\x80' + privkey_bytes
    if compressed:
        prefix = prefix + b'\x01'
    return base58check_encode(prefix)

# ---------------------------
# Addresses
# ---------------------------
def pubkey_to_p2pkh_address(pubkey_bytes: bytes) -> str:
    h160 = hash160(pubkey_bytes)
    prefix = b'\x00' + h160
    return base58check_encode(prefix)

def pubkey_to_p2sh_p2wpkh_address(pubkey_bytes: bytes) -> str:
    h160 = hash160(pubkey_bytes)
    redeem_script = b'\x00\x14' + h160
    redeem_h160 = hash160(redeem_script)
    prefix = b'\x05' + redeem_h160
    return base58check_encode(prefix)

# Bech32 (v0 P2WPKH only)
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GENERATORS = [
        0x3b6a57b2,
        0x26508e6d,
        0x1ea119fa,
        0x3d4233dd,
        0x2a1462b3
    ]
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xFF
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    checksum = []
    for i in range(6):
        checksum.append((polymod >> (5 * (5 - i))) & 31)
    return checksum

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        if b < 0 or (b >> frombits):
            return None
        acc = (acc << frombits) | b
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

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([BECH32_CHARSET[d] for d in combined])

def pubkey_to_bech32_p2wpkh(pubkey_bytes: bytes, hrp='bc') -> str:
    h160 = hash160(pubkey_bytes)
    data = [0] + convertbits(h160, 8, 5)
    return bech32_encode(hrp, data)

# ---------------------------
# API base & sleep
# ---------------------------
API_BASE = "https://blockchain.info/q"
SLEEP_BETWEEN_CHECKS = 0.5

# ---------------------------
# Printing helpers
# ---------------------------
def print_error(msg):
    print(f"[ERROR] {msg}", flush=True)

def print_found(text):
    print("=== FOUND ===", flush=True)
    print(text, flush=True)
    print("=== /FOUND ===", flush=True)

# ---------------------------
# Worker
# ---------------------------
def worker(worker_id: int, args, stop_event: threading.Event):
    session = requests.Session()
    while not stop_event.is_set():
        # generate a valid private key
        while True:
            priv_bytes = secrets.token_bytes(32)
            try:
                priv = PrivateKey(priv_bytes)
                break
            except Exception:
                continue

        pub_compressed = priv.public_key.format(compressed=True)

        try:
            secret_bytes = priv.secret
        except Exception:
            secret_bytes = priv_bytes

        wif = privkey_to_wif(secret_bytes, compressed=True)

        addr_p2pkh = pubkey_to_p2pkh_address(pub_compressed)
        addr_p2sh = pubkey_to_p2sh_p2wpkh_address(pub_compressed)
        addr_bech32 = pubkey_to_bech32_p2wpkh(pub_compressed, hrp='bc')

        addresses = [
            ("P2PKH", addr_p2pkh),
            ("P2SH-P2WPKH", addr_p2sh),
            ("BECH32", addr_bech32),
        ]

        for a_type, addr in addresses:
            if args.debug:
                print(f"[T{worker_id}] Checking {a_type} {addr} ...", flush=True)

            # check received (plain-text endpoint)
            url_received = f"{API_BASE}/getreceivedbyaddress/{addr}"
            try:
                r = session.get(url_received, timeout=10)
            except requests.RequestException as e:
                print_error(f"network error when checking received for {addr}: {e}")
                time.sleep(SLEEP_BETWEEN_CHECKS)
                continue

            # debug output: show status and body (first 300 chars)
            if args.debug:
                body = r.text.strip()[:300].replace('\n',' ')
                print(f"[T{worker_id}] Received API ({addr}) HTTP {r.status_code} -> {body}", flush=True)

            if r.status_code != 200:
                # treat non-200 as API error (don't assume zero)
                print_error(f"getreceivedbyaddress HTTP {r.status_code} for {addr}")
                time.sleep(SLEEP_BETWEEN_CHECKS)
                continue

            # parse plain-text integer satoshis
            try:
                received_sat = int(r.text.strip())
            except ValueError:
                print_error(f"Unexpected getreceivedbyaddress body for {addr}: {r.text!r}")
                time.sleep(SLEEP_BETWEEN_CHECKS)
                continue

            if received_sat <= 0:
                if args.debug:
                    print(f"[T{worker_id}] {addr} received_sat={received_sat} -> skipping balance check.", flush=True)
                time.sleep(SLEEP_BETWEEN_CHECKS)
                continue

            # received > 0 -> check balance (plain-text)
            url_balance = f"{API_BASE}/addressbalance/{addr}"
            try:
                r2 = session.get(url_balance, timeout=10)
            except requests.RequestException as e:
                print_error(f"network error when checking balance for {addr}: {e}")
                time.sleep(SLEEP_BETWEEN_CHECKS)
                continue

            if args.debug:
                body2 = r2.text.strip()[:300].replace('\n',' ')
                print(f"[T{worker_id}] Balance API ({addr}) HTTP {r2.status_code} -> {body2}", flush=True)

            if r2.status_code != 200:
                print_error(f"addressbalance HTTP {r2.status_code} for {addr}")
                time.sleep(SLEEP_BETWEEN_CHECKS)
                continue

            try:
                balance_sat = int(r2.text.strip())
            except ValueError:
                print_error(f"Unexpected addressbalance body for {addr}: {r2.text!r}")
                time.sleep(SLEEP_BETWEEN_CHECKS)
                continue

            # Print found result
            out = f"{wif}\n{addr}\n{received_sat}\n{balance_sat}"
            print_found(out)

            time.sleep(SLEEP_BETWEEN_CHECKS)

    if args.debug:
        print(f"[T{worker_id}] stopping.", flush=True)

# ---------------------------
# Main
# ---------------------------
def main():
    parser = argparse.ArgumentParser(description="Generate bitcoin keys and check addresses for funds.")
    parser.add_argument("-d", "--debug", action="store_true", help="debug mode - print addresses checking and API responses")
    parser.add_argument("-t", "--threads", type=int, default=3, help="number of worker threads (default 3)")
    args = parser.parse_args()

    stop_event = threading.Event()
    threads = []
    try:
        for i in range(args.threads):
            t = threading.Thread(target=worker, args=(i+1, args, stop_event), daemon=True)
            t.start()
            threads.append(t)

        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Stopping...", flush=True)
        stop_event.set()
        for t in threads:
            t.join(timeout=1)
        print("Stopped.", flush=True)
        sys.exit(0)

if __name__ == "__main__":
    main()