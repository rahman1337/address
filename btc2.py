#!/usr/bin/env python3
import secrets
import hashlib
import binascii
import argparse
import time
import sys

# Try fast C-backed lib (coincurve). If not present, fall back to ecdsa.
try:
    from coincurve import PublicKey
    HAVE_COINCURVE = True
except Exception:
    HAVE_COINCURVE = False
    import ecdsa

# --- Base58 / Bech32 helpers ---
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# small micro-optimizations: localize frequently used functions later
def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def base58check(data):
    # faster integer conversion + reuse locals
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    data_cs = data + checksum
    num = int.from_bytes(data_cs, 'big')
    res = []
    alphabet = BASE58_ALPHABET
    while num > 0:
        num, mod = divmod(num, 58)
        res.append(alphabet[mod])
    res = ''.join(reversed(res))
    # preserve leading zeros (0x00 bytes)
    n_pad = len(data) - len(data.lstrip(b'\0'))
    if n_pad:
        return '1' * n_pad + res
    return res

def encode_bech32(hrp, witver, witprog):
    # keep as-is but micro-optimized locals
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
        values = hrp_expand(hrp) + data + [0] * 6
        polymod_result = polymod(values) ^ 1
        return [(polymod_result >> 5 * (5 - i)) & 31 for i in range(6)]

    data = [witver] + convertbits(witprog, 8, 5)
    combined = data + create_checksum(hrp, data)
    return hrp + "1" + ''.join([BECH32_CHARSET[d] for d in combined])

# --- Address generation (two implementations) ---

def generate_addresses_coincurve(priv_bytes, hrp="bc"):
    # fast path using coincurve (libsecp256k1)
    # pub compressed: 33 bytes
    pub = PublicKey.from_valid_secret(priv_bytes).format(compressed=True)
    h160 = hash160(pub)

    # P2PKH
    addr_p2pkh = base58check(b'\x00' + h160)
    # P2SH-P2WPKH: redeem script is 0x00 0x14 <h160>; P2SH address uses HASH160(redeem)
    redeem = b'\x00\x14' + h160
    addr_p2sh = base58check(b'\x05' + hash160(redeem))
    # Bech32
    addr_bech32 = encode_bech32(hrp, 0, h160)
    # WIF compressed
    wif = base58check(b'\x80' + priv_bytes + b'\x01')
    return wif, addr_p2pkh, addr_p2sh, addr_bech32

# Optimized pure-Python fallback using ecdsa with reduced overhead
def generate_addresses_ecdsa(priv_bytes, hrp="bc"):
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    vs = vk.to_string()
    # compressed pubkey: choose prefix based on last byte's parity
    prefix = b'\x02' if (vs[32] & 1) == 0 else b'\x03'
    pub_compressed = prefix + vs[:32]
    h160 = hash160(pub_compressed)

    addr_p2pkh = base58check(b'\x00' + h160)
    redeem = b'\x00\x14' + h160
    addr_p2sh = base58check(b'\x05' + hash160(redeem))
    addr_bech32 = encode_bech32(hrp, 0, h160)
    wif = base58check(b'\x80' + priv_bytes + b'\x01')
    return wif, addr_p2pkh, addr_p2sh, addr_bech32

def generate_addresses(priv_bytes, hrp="bc"):
    if HAVE_COINCURVE:
        return generate_addresses_coincurve(priv_bytes, hrp)
    else:
        return generate_addresses_ecdsa(priv_bytes, hrp)

# --- Targets loader ---
def load_targets(paths):
    targets = set()
    for path in paths:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip().lower()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("0x"):
                    line = line[2:]
                targets.add(line)
    return targets

# --- Main loop (kept CLI unchanged; optimized inner loop) ---
def main():
    parser = argparse.ArgumentParser(description="Fast Bitcoin scanner (optimized)")
    parser.add_argument("--file", "-f", nargs="+", required=True)
    parser.add_argument("--report-every", "-r", type=int, default=1000)
    parser.add_argument("--max", "-m", type=int, default=0)
    parser.add_argument("--show-each", action="store_true")
    parser.add_argument("--network", choices=["mainnet","testnet"], default="mainnet")
    args = parser.parse_args()

    hrp = "bc" if args.network=="mainnet" else "tb"
    targets = load_targets(args.file)
    if not targets:
        print("No valid addresses loaded.")
        return
    print(f"Loaded {len(targets):,} target addresses.\nStarting generation loop...")

    total = 0
    start = time.time()

    # localize for speed
    targ = targets
    gen = generate_addresses
    rpt = args.report_every
    mx = args.max

    try:
        while True:
            total += 1
            priv = secrets.token_bytes(32)
            wif, p2pkh, p2sh, bc1 = gen(priv, hrp)

            if args.show_each:
                print(f"[{total}] WIF:{wif} P2PKH:{p2pkh} P2SH:{p2sh} Bech32:{bc1}")

            checks = (p2pkh.lower(), p2sh.lower(), bc1.lower())
            # direct membership test against set
            hit = checks[0] if checks[0] in targ else (checks[1] if checks[1] in targ else (checks[2] if checks[2] in targ else None))
            if hit:
                print("\n=== MATCH FOUND ===")
                print("WIF")
                print(wif)
                print("ADDRESS")
                print(hit)
                print("===================\n")
                sys.stdout.flush()
                return

            if rpt > 0 and total % rpt == 0:
                elapsed = time.time() - start
                rate = total / elapsed if elapsed > 0 else 0
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Tried {total:,} keys — {rate:,.1f} keys/s (elapsed {int(elapsed)}s)")

            if mx > 0 and total >= mx:
                print(f"Reached max attempts ({mx}). Exiting.")
                return

    except KeyboardInterrupt:
        elapsed = time.time() - start
        print("\nInterrupted by user.")
        print(f"Total tried: {total:,}")
        if elapsed > 0:
            print(f"Average speed: {total/elapsed:,.1f} keys/s")

if __name__ == "__main__":
    if HAVE_COINCURVE:
        print("Using coincurve (fast native secp256k1).")
    else:
        print("coincurve not found — using fallback ecdsa (slower).")
    main()