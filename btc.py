#!/usr/bin/env python3
import secrets
import hashlib
import binascii
import threading
import time
import sys
import argparse

try:
    from coincurve import PrivateKey
except Exception as e:
    print("ERROR: missing dependency 'coincurve'. Install with: pip install coincurve")
    sys.exit(1)

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def base58check(data):
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    payload = data + checksum
    num = int.from_bytes(payload, 'big')
    res = ""
    while num > 0:
        num, mod = divmod(num, 58)
        res = BASE58_ALPHABET[mod] + res
    n_pad = len(payload) - len(payload.lstrip(b'\0'))
    return '1' * n_pad + res

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return ret

def polymod(values):
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= GEN[i]
    return chk

def hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def create_checksum(hrp, data):
    values = hrp_expand(hrp) + data + [0]*6
    polymod_result = polymod(values) ^ 1
    return [(polymod_result >> 5*(5-i)) & 31 for i in range(6)]

def encode_bech32(hrp, witver, witprog):
    data = [witver] + convertbits(witprog, 8, 5)
    combined = data + create_checksum(hrp, data)
    return hrp + "1" + ''.join([BECH32_CHARSET[d] for d in combined])

def generate_addresses(priv_bytes, hrp="bc"):
    pk = PrivateKey(priv_bytes)
    pub_compressed = pk.public_key.format(compressed=True)
    h160 = hash160(pub_compressed)
    addr_p2pkh = base58check(b'\x00' + h160)
    redeem = b'\x00\x14' + h160
    addr_p2sh = base58check(b'\x05' + hash160(redeem))
    addr_bech32 = encode_bech32(hrp, 0, h160)
    return addr_p2pkh, addr_p2sh, addr_bech32

def load_targets(paths):
    targets = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    targets.add(line)
        except FileNotFoundError:
            continue
    print("Loaded", len(targets), "targets")
    return targets

total_keys = 0
per_thread = {}
total_lock = threading.Lock()
stop_event = threading.Event()
start_time = None

def worker(thread_id, targets, report_every):
    global total_keys, per_thread, start_time
    per_thread[thread_id] = 0
    local_count = 0
    while not stop_event.is_set():
        priv = secrets.token_bytes(32)
        p2pkh, p2sh, bech32 = generate_addresses(priv)
        local_count += 1
        with total_lock:
            total_keys += 1
            per_thread[thread_id] = local_count
            now = time.time()
            elapsed = now - start_time if start_time else 1.0
            overall_rate = total_keys / elapsed if elapsed > 0 else 0.0
        if p2pkh in targets or p2sh in targets or bech32 in targets:
            wif = base58check(b'\x80' + priv + b'\x01')
            print("\n=== MATCH FOUND ===")
            print("PRIV:", binascii.hexlify(priv).decode())
            print("WIF: ", wif)
            print("ADDR MATCHED:", p2pkh if p2pkh in targets else (p2sh if p2sh in targets else bech32))
            print("===================\n")
            sys.stdout.flush()
            stop_event.set()
            break
        if report_every and (local_count % report_every == 0):
            with total_lock:
                per_thread_counts = [per_thread.get(i,0) for i in sorted(per_thread.keys())]
                print("[DEBUG] total_keys_tried:", total_keys, "| per_thread:", per_thread_counts, "| keys/s:", f"{overall_rate:.2f}")

def main():
    global start_time
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", "-f", nargs="+", default=["btc1.txt", "btc2.txt", "btc3.txt"])
    parser.add_argument("--report-every", "-r", type=int, default=2000)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--threads", "-t", type=int, default=3)
    args = parser.parse_args()

    targets = load_targets(args.file)
    if not targets:
        print("No valid addresses loaded.")
        return

    num_threads = max(1, args.threads)
    start_time = time.time()
    threads = []
    for i in range(num_threads):
        t = threading.Thread(target=worker, args=(i+1, targets, args.report_every if args.debug else 0), daemon=True)
        threads.append(t)
        t.start()

    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()
        print("\nInterrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()