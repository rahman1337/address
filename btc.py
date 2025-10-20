#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import binascii
import argparse
import multiprocessing as mp
from coincurve import PrivateKey

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def base58check(data: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    full = data + checksum
    num = int.from_bytes(full, 'big')
    res = ""
    while num:
        num, mod = divmod(num, 58)
        res = BASE58_ALPHABET[mod] + res
    pad = len(full) - len(full.lstrip(b'\0'))
    return '1' * pad + res

def encode_bech32(hrp, witver, witprog):
    def convertbits(data, frombits, tobits, pad=True):
        acc = bits = 0
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
        GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
        chk = 1
        for v in values:
            top = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in range(5):
                if (top >> i) & 1:
                    chk ^= GEN[i]
        return chk
    def hrp_expand(hrp): return [ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]
    def create_checksum(hrp, data):
        values = hrp_expand(hrp)+data+[0]*6
        mod = polymod(values)^1
        return [(mod>>5*(5-i))&31 for i in range(6)]
    data = [witver]+convertbits(witprog,8,5)
    combined = data+create_checksum(hrp,data)
    return hrp+"1"+''.join([BECH32_CHARSET[d] for d in combined])

def generate_addresses(priv_bytes, hrp="bc"):
    pk = PrivateKey(priv_bytes)
    pub = pk.public_key.format(compressed=True)
    h160 = hash160(pub)
    p2pkh = base58check(b'\x00' + h160)
    redeem = b'\x00\x14' + h160
    p2sh = base58check(b'\x05' + hash160(redeem))
    bech32 = encode_bech32(hrp, 0, h160)
    return p2pkh, p2sh, bech32

def load_targets(paths):
    targets = set()
    counts = {"p2pkh": 0, "p2sh": 0, "bech32": 0}
    for path in paths:
        if not os.path.exists(path): continue
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                addr = line.strip()
                if not addr or addr.startswith("#"): continue
                targets.add(addr)
                if addr.startswith("1"): counts["p2pkh"] += 1
                elif addr.startswith("3"): counts["p2sh"] += 1
                elif addr.lower().startswith("bc1"): counts["bech32"] += 1
    print(f"Loaded {len(targets)} targets: "
          f"P2PKH={counts['p2pkh']} P2SH={counts['p2sh']} Bech32={counts['bech32']}")
    return targets

def worker(proc_id, targets, report_every, hrp, debug, start_time):
    total = 0
    last_report = time.time()
    while True:
        priv = os.urandom(32)
        p2pkh, p2sh, bech32 = generate_addresses(priv, hrp)
        if p2pkh in targets or p2sh in targets or bech32 in targets:
            wif = base58check(b'\x80' + priv + b'\x01')
            print(f"\n=== MATCH FOUND ===\n"
                  f"[P{proc_id}] PRIV: {binascii.hexlify(priv).decode()}\n"
                  f"[P{proc_id}] WIF : {wif}\n"
                  f"[P{proc_id}] ADDR: {p2pkh if p2pkh in targets else p2sh if p2sh in targets else bech32}\n"
                  f"===================\n", flush=True)
        total += 1
        if total % report_every == 0:
            now = time.time()
            rate = report_every / (now - last_report)
            total_time = now - start_time
            avg_rate = total / total_time
            last_report = now
            if debug:
                print(f"[P{proc_id}] {total:,} keys — {rate:,.1f} keys/s (avg {avg_rate:,.1f})")
            else:
                print(f"[P{proc_id}] {total:,} keys — {rate:,.1f} keys/s")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", "-f", nargs="+", default=["btc1.txt"])
    parser.add_argument("--threads", "-t", type=int, default=4)
    parser.add_argument("--report-every", "-r", type=int, default=10000)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--hrp", default="bc")
    args = parser.parse_args()

    targets = load_targets(args.file)
    if not targets:
        print("No valid addresses loaded.")
        return

    print(f"Starting with {args.threads} processes...")
    start_time = time.time()
    processes = []
    for i in range(args.threads):
        p = mp.Process(target=worker, args=(i+1, targets, args.report_every, args.hrp, args.debug, start_time))
        p.start()
        processes.append(p)

    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        for p in processes:
            p.terminate()

if __name__ == "__main__":
    mp.set_start_method("spawn", force=True)
    main()