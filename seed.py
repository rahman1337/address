#!/usr/bin/env python3
# btc2.py - mnemonic -> addresses scanner (multi-worker, continuous, clean output)
import os, sys, time, hashlib, multiprocessing, argparse, signal
from mnemonic import Mnemonic

# Try to use coincurve (faster); fallback to ecdsa
try:
    from coincurve import PublicKey
    HAVE_COINCURVE = True
except Exception:
    import ecdsa
    HAVE_COINCURVE = False

# ===== CONFIG =====
REPORT_EVERY = 300         # per-worker status print interval
BATCH_SIZE = 4             # mnemonics per inner loop
OUTFILE = "btc.txt"   # append matches here
MNEMONIC_GEN = Mnemonic("english")
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]

# ===== HELPERS =====
def sha256(x): return hashlib.sha256(x).digest()
def ripemd160(x): return hashlib.new('ripemd160', x).digest()
def hash160(x): return ripemd160(sha256(x))

def base58check(data):
    checksum = sha256(sha256(data))[:4]
    data_cs = data + checksum
    num = int.from_bytes(data_cs, "big")
    out = ""
    while num > 0:
        num, mod = divmod(num, 58)
        out = BASE58_ALPHABET[mod] + out
    pad = 0
    for c in data_cs:
        if c == 0: pad += 1
        else: break
    return "1"*pad + out

def encode_bech32(hrp, witver, witprog):
    def convertbits(data, frombits, tobits, pad=True):
        acc = bits = 0; ret=[]; maxv=(1<<tobits)-1
        for b in data:
            acc=(acc<<frombits)|b; bits+=frombits
            while bits>=tobits:
                bits-=tobits; ret.append((acc>>bits)&maxv)
        if pad and bits: ret.append((acc<<(tobits-bits))&maxv)
        return ret
    def polymod(v):
        chk=1
        for val in v:
            top=chk>>25
            chk=((chk&0x1ffffff)<<5)^val
            for i in range(5):
                if (top>>i)&1: chk^=GEN[i]
        return chk
    def hrp_expand(h): return [ord(x)>>5 for x in h]+[0]+[ord(x)&31 for x in h]
    def create_checksum(hrp, data):
        vals=hrp_expand(hrp)+data+[0]*6
        pm=polymod(vals)^1
        return [(pm>>(5*(5-i)))&31 for i in range(6)]
    data=[witver]+convertbits(witprog,8,5)
    comb=data+create_checksum(hrp,data)
    return hrp+"1"+"".join([BECH32_CHARSET[d] for d in comb])

def generate_addresses(priv_bytes, hrp="bc"):
    if HAVE_COINCURVE:
        pub = PublicKey.from_valid_secret(priv_bytes).format(compressed=True)
    else:
        sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        vs = vk.to_string()
        prefix = b'\x02' if (vs[32]&1)==0 else b'\x03'
        pub = prefix + vs[:32]
    h160 = hash160(pub)
    p2pkh = base58check(b'\x00'+h160)
    redeem = b'\x00\x14'+h160
    p2sh = base58check(b'\x05'+hash160(redeem))
    bech = encode_bech32(hrp,0,h160)
    wif = base58check(b'\x80'+priv_bytes+b'\x01')
    return wif, p2pkh, p2sh, bech

def load_targets(paths):
    s=set()
    for path in paths:
        try:
            with open(path,"r",encoding="utf-8",errors="ignore") as f:
                for line in f:
                    l=line.strip()
                    if not l: continue
                    s.add(l.lower())
        except Exception as e:
            print(f"Warning: failed to open {path}: {e}", file=sys.stderr)
    return s

# ===== WORKER =====
def worker(proc_id, targets):
    hrp="bc"
    total=0
    start=time.time()
    while True:
        for _ in range(BATCH_SIZE):
            total += 1
            mnemonic = MNEMONIC_GEN.generate(strength=128)
            seed = hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048)
            priv = seed[:32]
            wif,p2pkh,p2sh,bech = generate_addresses(priv,hrp)
            for addr in (p2pkh.lower(),p2sh.lower(),bech.lower()):
                if addr in targets:
                    ts=time.strftime("%Y-%m-%d %H:%M:%S")
                    print(f"\n\033[92m{'='*50}")
                    print(f"🎯 MATCH FOUND (Worker {proc_id} @ {ts})")
                    print(f"{'='*50}\033[0m")
                    print(f"\033[96mMnemonic :\033[0m {mnemonic}")
                    print(f"\033[96mWIF      :\033[0m {wif}")
                    print(f"\033[96mAddress  :\033[0m {addr}")
                    print(f"\033[92m{'='*50}\033[0m\n")
                    try:
                        with open(OUTFILE,"a",encoding="utf-8") as f:
                            f.write(f"{ts}\nMNEMONIC:{mnemonic}\nWIF:{wif}\nADDRESS:{addr}\n\n")
                    except Exception as e:
                        print("Failed to write hit:", e, file=sys.stderr)
        if total % REPORT_EVERY == 0:
            rate = total / (time.time() - start) if (time.time()-start)>0 else 0.0
            print(f"[Worker {proc_id}] {total:,} mnemonics tried — {rate:,.1f}/s")

# ===== MAIN =====
def main():
    # Ensure spawn start method for iSH compatibility
    try:
        multiprocessing.set_start_method("spawn")
    except RuntimeError:
        # already set
        pass

    p=argparse.ArgumentParser(description="Mnemonic BTC address scanner (multi-worker, continuous)")
    p.add_argument("-f","--file",nargs="+",required=True,help="target btc*.txt files (shell usually expands glob)")
    p.add_argument("--workers","-w",type=int,default=None,help="override number of worker processes")
    args=p.parse_args()

    targets=load_targets(args.file)
    if not targets:
        print("No targets loaded; provide at least one target file with addresses.")
        return
    print(f"Loaded {len(targets):,} target addresses.")
    print("Using coincurve" if HAVE_COINCURVE else "Using ecdsa fallback")

    # determine CPU/worker count; user override allowed
    cpu = args.workers if args.workers and args.workers>0 else max(1, os.cpu_count() or 1)

    print(f"Launching {cpu} worker(s)...\n")

    procs = []
    for i in range(cpu):
        p = multiprocessing.Process(target=worker, args=(i, targets))
        p.daemon = True
        p.start()
        procs.append(p)

    def handle_sigint(signum, frame):
        print("\nShutting down...")
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        sys.exit(0)

    signal.signal(signal.SIGINT, handle_sigint)
    # keep main process alive while workers run
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        handle_sigint(None, None)

if __name__=="__main__":
    main()