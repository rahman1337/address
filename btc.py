#!/usr/bin/env python3
import secrets
import ecdsa
import hashlib
import binascii
import threading
import time
import sys
import argparse

# --- Base58 / Bech32 helpers ---
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def base58check(data):
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    num = int.from_bytes(data + checksum, 'big')
    res = ""
    while num > 0:
        num, mod = divmod(num, 58)
        res = BASE58_ALPHABET[mod] + res
    n_pad = len(data) - len(data.lstrip(b'\0'))
    return '1' * n_pad + res

def encode_bech32(hrp, witver, witprog):
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

    data = [witver] + convertbits(witprog, 8, 5)
    combined = data + create_checksum(hrp, data)
    return hrp + "1" + ''.join([BECH32_CHARSET[d] for d in combined])

def generate_addresses(priv_bytes, hrp="bc"):
    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pub_raw = vk.to_string()
    prefix = b'\x02' if pub_raw[32] < 128 else b'\x03'
    pub_compressed = prefix + pub_raw[:32]
    h160 = hash160(pub_compressed)
    addr_p2pkh = base58check(b'\x00' + h160)
    redeem = b'\x00\x14' + h160
    addr_p2sh = base58check(b'\x05' + hash160(redeem))
    addr_bech32 = encode_bech32(hrp, 0, h160)
    return addr_p2pkh, addr_p2sh, addr_bech32

def load_targets(paths):
    targets = set()
    counts = {"p2pkh": 0, "p2sh": 0, "bech32": 0}
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    addr = line.strip()
                    targets.add(addr)
                    if addr.startswith("1"):
                        counts["p2pkh"] += 1
                    elif addr.startswith("3"):
                        counts["p2sh"] += 1
                    elif addr.lower().startswith("bc1"):
                        counts["bech32"] += 1
        except FileNotFoundError:
            continue
    print(f"Loaded {len(targets)} targets: "
          f"P2PKH={counts['p2pkh']} P2SH={counts['p2sh']} Bech32={counts['bech32']}")
    return targets

# --- Worker Thread ---
def worker(thread_id, targets, report_every=1000):
    total = 0
    start = time.time()
    while True:
        total += 1
        priv = secrets.token_bytes(32)
        p2pkh, p2sh, bech32 = generate_addresses(priv)
        checks = {p2pkh, p2sh, bech32}
        hit = next((a for a in checks if a in targets), None)
        if hit:
            wif = base58check(b'\x80' + priv + b'\x01')
            print("\n=== MATCH FOUND ===")
            print(f"PRIV: {binascii.hexlify(priv).decode()}")
            print(f"WIF:  {wif}")
            print(f"ADDR: {hit}")
            print("===================\n")
            sys.stdout.flush()
            break
        if total % report_every == 0:
            elapsed = time.time() - start
            rate = total / elapsed if elapsed else 0
            print(f"[Thread {thread_id}] {total:,} keys — {rate:,.1f} keys/s")

def main():
    parser = argparse.ArgumentParser(description="Fast Bitcoin scanner (2-thread, optimized, offline)")
    parser.add_argument("--file", "-f", nargs="+", default=["btc1.txt", "btc2.txt", "btc3.txt"])
    parser.add_argument("--report-every", "-r", type=int, default=2000)
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    targets = load_targets(args.file)
    if not targets:
        print("No valid addresses loaded.")
        return

    print("Starting generation loop with 2 threads...\n")
    threads = []
    for i in range(2):
        t = threading.Thread(target=worker, args=(i+1, targets, args.report_every), daemon=True)
        threads.append(t)
        t.start()

    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()