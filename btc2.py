#!/usr/bin/env python3
import secrets, time, sys, argparse, hashlib, glob
import secp256k1, base58
from bech32 import bech32_decode, convertbits

# --- Helpers ---
def hash160(b):
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

def decode_addr_to_h160(addr):
    """Convert any Bitcoin address (1..., 3..., bc1...) to hash160."""
    a = addr.strip()
    if not a:
        return None
    # Base58
    try:
        dec = base58.b58decode_check(a)
        if len(dec) == 21:
            return dec[1:]
    except Exception:
        pass
    # Bech32
    try:
        hrp, data = bech32_decode(a)
        if hrp and data:
            witver = data[0]
            witprog = convertbits(data[1:], 5, 8, False)
            if witver == 0 and witprog and len(witprog) == 20:
                return bytes(witprog)
    except Exception:
        pass
    return None

def load_targets(paths):
    targets = set()
    for p in paths:
        with open(p, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                h = decode_addr_to_h160(line)
                if h:
                    targets.add(h)
    return targets

# --- Generate addresses ---
def generate(priv_bytes):
    priv = secp256k1.PrivateKey(priv_bytes, raw=True)
    pub = priv.pubkey.serialize(compressed=True)
    h160 = hash160(pub)
    # WIF compressed
    payload = b'\x80' + priv_bytes + b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    wif = base58.b58encode(payload + checksum).decode()
    return wif, h160

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Ultra-fast Bitcoin scanner")
    parser.add_argument("-f","--file",nargs="+",required=True)
    parser.add_argument("-r","--report-every",type=int,default=1000)
    parser.add_argument("-m","--max",type=int,default=0)
    args = parser.parse_args()

    # expand wildcards like btc*.txt
    files = []
    for p in args.file:
        files.extend(sorted(glob.glob(p)))
    if not files:
        print("No files matched:", args.file)
        return

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
            wif, h160 = generate(priv_bytes)

            # compute nested hash160 used by P2SH-P2WPKH (3... addresses)
            nested = hash160(b'\x00\x14' + h160)

            # check if either the direct pubkey-hash or the nested script-hash is a target
            if h160 in targets or nested in targets:
                print("\n=== MATCH FOUND ===")
                print("WIF")
                print(wif)
                print("ADDRESS")

                # if direct pubkey-hash matched, print the P2PKH (1...) address (same as before)
                if h160 in targets:
                    payload = b'\x00' + h160
                    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
                    addr = base58.b58encode(payload + checksum).decode()
                    print(addr)

                # if nested script-hash matched, print the P2SH (3...) address
                if nested in targets:
                    payload3 = b'\x05' + nested
                    checksum3 = hashlib.sha256(hashlib.sha256(payload3).digest()).digest()[:4]
                    addr3 = base58.b58encode(payload3 + checksum3).decode()
                    print(addr3)

                print("===================\n")
                sys.stdout.flush()
                return

            if total % args.report_every == 0:
                elapsed = time.time() - start
                rate = total / elapsed if elapsed > 0 else 0
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Tried {total:,} keys — {rate:,.1f} keys/s")

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