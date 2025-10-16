#!/usr/bin/env python3

# btc2.py - faster: use coincurve if present for ECC (private -> compressed pubkey)
# Same behavior as previous: prints matches as WIF / ADDRESS and live progress.

import os, time, sys, argparse, hashlib
try:
    from coincurve import PublicKey
    HAVE_COINCURVE = True
except Exception:
    HAVE_COINCURVE = False

# If coincurve not present, fall back to pure-Python EC (previous implementation).
# We'll import that implementation only if needed to avoid overhead.
if not HAVE_COINCURVE:
    # lightweight pure-Python ECC functions (same as before)
    # Put minimal implementation here (we import the same code from previous script)
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    Gy = 3267051002075881697808308513050704318447127338065924327593890433575733741481

    def modinv(a: int, p: int = P) -> int:
        return pow(a, p - 2, p)

    def ec_point_add(x1, y1, x2, y2):
        if x1 is None:
            return x2, y2
        if x2 is None:
            return x1, y1
        if x1 == x2 and (y1 + y2) % P == 0:
            return None, None
        if x1 == x2 and y1 == y2:
            lam = (3 * x1 * x1) * modinv(2 * y1, P) % P
        else:
            lam = (y2 - y1) * modinv(x2 - x1, P) % P
        x3 = (lam * lam - x1 - x2) % P
        y3 = (lam * (x1 - x3) - y1) % P
        return x3, y3

    def ec_point_mul(k: int, x: int = Gx, y: int = Gy):
        k = k % N
        if k == 0:
            return None, None
        rx = None
        ry = None
        px, py = x, y
        while k:
            if k & 1:
                rx, ry = ec_point_add(rx, ry, px, py)
            px, py = ec_point_add(px, py, px, py)
            k >>= 1
        return rx, ry

# BASE58 / BECH32 constants (same as before)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160")
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, "big")

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")

def base58check(data: bytes) -> str:
    checksum = sha256(sha256(data))[:4]
    data_cs = data + checksum
    num = int.from_bytes(data_cs, "big")
    res_chars = []
    while num > 0:
        num, mod = divmod(num, 58)
        res_chars.append(BASE58_ALPHABET[mod])
    res = ''.join(reversed(res_chars))
    n_pad = len(data) - len(data.lstrip(b'\0'))
    if n_pad:
        return '1' * n_pad + res
    return res

def encode_bech32(hrp: str, witver: int, witprog: bytes) -> str:
    def convertbits(data, frombits, tobits, pad=True):
        acc = 0; bits = 0; ret = []; maxv = (1 << tobits) - 1
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
        chk = 1
        for v in values:
            top = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in range(5):
                if (top >> i) & 1:
                    chk ^= BECH32_GEN[i]
        return chk
    def hrp_expand(hrp):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    def create_checksum(hrp, data):
        values = hrp_expand(hrp) + data + [0] * 6
        pm = polymod(values) ^ 1
        return [(pm >> (5 * (5 - i))) & 31 for i in range(6)]
    data = [witver] + convertbits(witprog, 8, 5)
    checksum = create_checksum(hrp, data)
    combined = data + checksum
    return hrp + "1" + ''.join([BECH32_CHARSET[d] for d in combined])

def p2pkh_from_pub(pub_compressed: bytes) -> str:
    return base58check(b'\x00' + hash160(pub_compressed))

def p2wpkh_from_pub(pub_compressed: bytes, hrp="bc") -> str:
    return encode_bech32(hrp, 0, hash160(pub_compressed))

def p2wpkh_in_p2sh_from_pub(pub_compressed: bytes) -> str:
    redeem = b'\x00\x14' + hash160(pub_compressed)
    return base58check(b'\x05' + hash160(redeem))

def wif_from_priv(priv_bytes: bytes) -> str:
    return base58check(b'\x80' + priv_bytes + b'\x01')

# derive compressed pubkey using coincurve if available, else fallback to Python EC
def pubkey_compressed_from_priv_bytes(priv_bytes: bytes) -> bytes:
    if HAVE_COINCURVE:
        return PublicKey.from_valid_secret(priv_bytes).format(compressed=True)
    else:
        priv_int = bytes_to_int(priv_bytes)
        x, y = ec_point_mul(priv_int)
        prefix = b'\x02' if (y & 1) == 0 else b'\x03'
        return prefix + int_to_bytes(x, 32)

# load targets (lowercased)
def load_targets(paths):
    targ = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if not s:
                        continue
                    targ.add(s.lower())
        except Exception as e:
            print("Warning: failed to open", path, ":", e, file=sys.stderr)
    return targ

def main():
    p = argparse.ArgumentParser(description="Random-key -> addresses; use coincurve if available")
    p.add_argument("-f", "--file", nargs="+", required=True, help="target address file(s)")
    p.add_argument("--report-interval", type=float, default=1.0, help="progress print interval (seconds)")
    args = p.parse_args()

    targets = load_targets(args.file)
    if not targets:
        print("No valid addresses loaded. Provide -f btc*.txt")
        return

    print(f"Loaded {len(targets):,} target addresses. Using {'coincurve' if HAVE_COINCURVE else 'pure-Python EC fallback'}")
    OUTFILE = "btc.txt"

    total = 0
    start = time.time()
    last_report = start
    last_total = 0

    try:
        while True:
            # use os.urandom (slightly faster than secrets)
            priv_bytes = os.urandom(32)
            total += 1

            # compressed pubkey via native coincurve (if available)
            try:
                pubc = pubkey_compressed_from_priv_bytes(priv_bytes)
            except Exception:
                continue

            p2pkh = p2pkh_from_pub(pubc)
            p2wpkh = p2wpkh_from_pub(pubc)
            p2sh_nested = p2wpkh_in_p2sh_from_pub(pubc)
            wif = wif_from_priv(priv_bytes)

            found_addr = None
            if p2pkh.lower() in targets:
                found_addr = p2pkh
            elif p2sh_nested.lower() in targets:
                found_addr = p2sh_nested
            elif p2wpkh.lower() in targets:
                found_addr = p2wpkh

            if found_addr:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                print("\n=== MATCH FOUND ===")
                print(ts)
                print("WIF")
                print(wif)
                print("ADDRESS")
                print(found_addr)
                print("===================\n")
                try:
                    with open(OUTFILE, "a", encoding="utf-8") as fo:
                        fo.write(f"{ts}\nWIF:{wif}\nADDRESS:{found_addr}\n\n")
                except Exception as e:
                    print("Failed to append to", OUTFILE, ":", e, file=sys.stderr)

            now = time.time()
            if now - last_report >= args.report_interval:
                elapsed = now - start
                recent = total - last_total
                avg = total / elapsed if elapsed > 0 else 0.0
                sys.stdout.write(f"[{total:,} keys checked — {avg:,.1f} keys/s]".ljust(60) + "\r")
                sys.stdout.flush()
                last_report = now
                last_total = total

    except KeyboardInterrupt:
        elapsed = time.time() - start
        avg = total / elapsed if elapsed > 0 else 0.0
        print(f"\nStopped. Total: {total:,} keys in {elapsed:.1f}s ({avg:,.1f} keys/s)")

if __name__ == "__main__":
    main()