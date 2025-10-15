#!/usr/bin/env python3
import secrets, time, sys, argparse, hashlib, glob
import secp256k1
import base58
from bech32 import bech32_encode, convertbits

def hash160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

def b58check(prefix, h):
    payload = prefix + h
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def bech32_addr(hrp, h160):
    return bech32_encode(hrp, [0] + convertbits(h160, 8, 5))

def generate(priv_bytes, hrp="bc"):
    priv = secp256k1.PrivateKey(priv_bytes, raw=True)
    pub = priv.pubkey.serialize(compressed=True)
    h160 = hash160(pub)
    return (
        b58check(b'\x80', priv_bytes + b'\x01'),           # WIF
        b58check(b'\x00', h160),                           # P2PKH
        b58check(b'\x05', hash160(b'\x00\x14' + h160)),    # P2SH-P2WPKH
        bech32_addr(hrp, h160)                             # Bech32
    )

def load_targets(paths):
    t = set()
    for p in paths:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                l = line.strip()
                if l:
                    t.add(l.lower())
    return t

def main():
    parser = argparse.ArgumentParser(description="Fast Bitcoin scanner with progress logs")
    parser.add_argument("-f","--file",nargs="+",required=True)
    parser.add_argument("-r","--report-every",type=int,default=10000)
    parser.add_argument("-m","--max",type=int,default=0)
    parser.add_argument("--show-each",action="store_true")
    parser.add_argument("--network",choices=["mainnet","testnet"],default="mainnet")
    args = parser.parse_args()

    # Expand wildcards like btc*.txt
    files = []
    for p in args.file:
        files.extend(sorted(glob.glob(p)))
    if not files:
        print("No files matched the patterns:", args.file)
        return

    hrp = "bc" if args.network=="mainnet" else "tb"
    targets = load_targets(files)
    if not targets:
        print("No valid addresses loaded.")
        return

    print(f"Loaded {len(targets):,} target addresses.\nStarting generation loop...")

    total = 0
    start = time.time()

    try:
        while True:
            total += 1
            priv_bytes = secrets.token_bytes(32)
            wif, a1, a2, a3 = generate(priv_bytes, hrp)

            if args.show_each:
                print(f"[{total}] WIF:{wif} P2PKH:{a1} P2SH:{a2} Bech32:{a3}")

            check = {a1.lower(), a2.lower(), a3.lower()}
            if check & targets:
                hit = (check & targets).pop()
                print("\n=== MATCH FOUND ===")
                print("WIF")
                print(wif)
                print("ADDRESS")
                print(hit)
                print("===================\n")
                sys.stdout.flush()
                return

            if args.report_every and total % args.report_every == 0:
                elapsed = time.time() - start
                rate = total / elapsed if elapsed > 0 else 0
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Tried {total:,} keys — {rate:,.1f} keys/s (elapsed {int(elapsed)}s)")

            if args.max and total >= args.max:
                print(f"Reached max attempts ({args.max}). Exiting.")
                return

    except KeyboardInterrupt:
        elapsed = time.time() - start
        print("\nInterrupted by user.")
        print(f"Total tried: {total:,}")
        if elapsed > 0:
            print(f"Average speed: {total/elapsed:,.1f} keys/s")

if __name__ == "__main__":
    main()