#!/usr/bin/env python3
import sys, secrets, hashlib, time, multiprocessing, signal
import coincurve

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
REPORT_EVERY = 5000  # progress log frequency

# ---------- helpers ----------
def hash160(data):
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def base58check(data: bytes) -> str:
    chk = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    full = data + chk
    num = int.from_bytes(full, 'big')
    if num == 0:
        return BASE58_ALPHABET[0]
    res = []
    while num:
        num, mod = divmod(num, 58)
        res.append(BASE58_ALPHABET[mod])
    n_pad = len(full) - len(full.lstrip(b'\0'))
    return '1'*n_pad + ''.join(reversed(res))

def encode_bech32(hrp, witver, witprog):
    def convertbits(data, frombits, tobits, pad=True):
        acc = 0; bits = 0; ret = []
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
    GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    def polymod(values):
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

# ---------- address generation ----------
def gen_addresses(priv_bytes, hrp="bc"):
    key = coincurve.PrivateKey(priv_bytes)
    pub = key.public_key.format(compressed=True)
    h160 = hash160(pub)
    p2pkh = base58check(b'\x00' + h160)
    redeem = b'\x00\x14' + h160
    p2sh = base58check(b'\x05' + hash160(redeem))
    bech = encode_bech32(hrp, 0, h160)
    wif = base58check(b'\x80' + priv_bytes + b'\x01')
    return wif, p2pkh, p2sh, bech

# ---------- load targets ----------
def load_targets(paths):
    t = set()
    for p in paths:
        with open(p,'r',encoding='utf-8',errors='ignore') as f:
            for line in f:
                s = line.strip().lower()
                if not s or s.startswith('#'):
                    continue
                if s.startswith('0x'):
                    s = s[2:]
                t.add(s)
    return t

# ---------- worker ----------
def worker(targets, hrp, worker_id, stop_flag):
    total = 0
    next_report = REPORT_EVERY
    start = time.time()
    while not stop_flag.value:
        priv = secrets.token_bytes(32)
        total += 1
        wif, p2pkh, p2sh, bech = gen_addresses(priv, hrp)
        if (p2pkh.lower() in targets) or (p2sh.lower() in targets) or (bech.lower() in targets):
            print("\n=== MATCH FOUND ===")
            print("WIF"); print(wif)
            print("ADDRESS")
            if p2pkh.lower() in targets: print(p2pkh)
            if p2sh.lower() in targets: print(p2sh)
            if bech.lower() in targets: print(bech)
            print("===================\n")
            stop_flag.value = 1
            return
        if total >= next_report:
            elapsed = time.time()-start
            rate = total/elapsed if elapsed>0 else 0
            ts = time.strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{ts}] Worker {worker_id}: Tried {total:,} keys — {rate:,.0f} keys/s (elapsed {int(elapsed)}s)")
            next_report += REPORT_EVERY

# ---------- main ----------
def main():
    if len(sys.argv) < 3 or sys.argv[1] != '--file':
        print("Usage: python3 btc.py --file file1.txt [file2.txt ...]")
        return
    paths = sys.argv[2:]
    targets = load_targets(paths)
    if not targets:
        print("No valid addresses loaded.")
        return

    hrp = "bc"
    stop_flag = multiprocessing.Value('i', 0)
    cpu_count = multiprocessing.cpu_count()
    print(f"Starting {cpu_count} worker processes...")
    workers = []
    for i in range(cpu_count):
        p = multiprocessing.Process(target=worker, args=(targets, hrp, i+1, stop_flag))
        p.start()
        workers.append(p)

    # graceful shutdown on Ctrl-C
    def sigint_handler(sig, frame):
        stop_flag.value = 1
    signal.signal(signal.SIGINT, sigint_handler)

    for p in workers:
        p.join()

if __name__=="__main__":
    main()