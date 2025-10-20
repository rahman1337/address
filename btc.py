#!/usr/bin/env python3
"""
btc2-fast.py - Random-key -> addresses; multithreaded with coincurve (or fallback)
Optimized for speed (3 threads), optional --debug prints
Default input files: btc1.txt, btc2.txt, btc3.txt
"""

import os, time, sys, argparse, hashlib
from threading import Thread, Lock

try:
    from coincurve import PublicKey
    HAVE_COINCURVE = True
except Exception:
    HAVE_COINCURVE = False

# --- Base58 / Bech32 ---
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]

# --- Hash helpers ---
def sha256(b: bytes) -> bytes: return hashlib.sha256(b).digest()
def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160"); h.update(b); return h.digest()
def hash160(b: bytes) -> bytes: return ripemd160(sha256(b))
def int_to_bytes(i: int, length: int) -> bytes: return i.to_bytes(length, "big")
def bytes_to_int(b: bytes) -> int: return int.from_bytes(b, "big")

# --- Base58 / WIF ---
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
    return '1' * n_pad + res if n_pad else res

def wif_from_priv(priv_bytes: bytes) -> str:
    return base58check(b'\x80' + priv_bytes + b'\x01')

# --- Address encoders ---
def encode_bech32(hrp: str, witver: int, witprog: bytes) -> str:
    def convertbits(data, frombits, tobits, pad=True):
        acc=0; bits=0; ret=[]; maxv=(1<<tobits)-1
        for b in data:
            acc=(acc<<frombits)|b; bits+=frombits
            while bits>=tobits: bits-=tobits; ret.append((acc>>bits)&maxv)
        if pad and bits: ret.append((acc<<(tobits-bits))&maxv)
        return ret
    def polymod(values):
        chk=1
        for v in values:
            top=chk>>25
            chk=((chk&0x1ffffff)<<5)^v
            for i in range(5):
                if(top>>i)&1: chk^=BECH32_GEN[i]
        return chk
    def hrp_expand(hrp): return [ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]
    def create_checksum(hrp,data): return [(polymod(hrp_expand(hrp)+data+[0]*6)^1>>(5*(5-i))&31 for i in range(6))]
    data=[witver]+convertbits(witprog,8,5)
    chk=create_checksum(hrp,data)
    return hrp+'1'+''.join([BECH32_CHARSET[d] for d in data+chk])

def p2pkh_from_pub(pubc: bytes) -> str: return base58check(b'\x00'+hash160(pubc))
def p2wpkh_from_pub(pubc: bytes, hrp="bc") -> str: return encode_bech32(hrp,0,hash160(pubc))
def p2wpkh_in_p2sh_from_pub(pubc: bytes) -> str: return base58check(b'\x05'+hash160(b'\x00\x14'+hash160(pubc)))

# --- Compressed pubkey ---
def pubkey_compressed_from_priv_bytes(priv_bytes: bytes) -> bytes:
    if HAVE_COINCURVE:
        return PublicKey.from_valid_secret(priv_bytes).format(compressed=True)
    else:
        from ecdsa import SigningKey, SECP256k1
        sk = SigningKey.from_string(priv_bytes, curve=SECP256k1)
        return sk.get_verifying_key().to_string("compressed")

# --- Load targets ---
def load_targets(paths):
    targ = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if s: targ.add(s.lower())
        except Exception as e:
            print("Warning:", e, file=sys.stderr)
    return targ

# --- Worker ---
def worker(targets, debug, lock, outfile):
    total=0; start=time.time()
    while True:
        priv_bytes=os.urandom(32)
        pubc = pubkey_compressed_from_priv_bytes(priv_bytes)
        p2pkh = p2pkh_from_pub(pubc)
        p2wpkh = p2wpkh_from_pub(pubc)
        p2sh_nested = p2wpkh_in_p2sh_from_pub(pubc)
        wif = wif_from_priv(priv_bytes)

        found_addr = None
        for addr in [p2pkh,p2sh_nested,p2wpkh]:
            if addr.lower() in targets:
                found_addr = addr; break

        if found_addr:
            ts=time.strftime("%Y-%m-%d %H:%M:%S")
            with lock:
                print(f"\n=== MATCH FOUND ===\n{ts}\nWIF:{wif}\nADDRESS:{found_addr}\n===================\n")
                try:
                    with open(outfile,"a") as fo:
                        fo.write(f"{ts}\nWIF:{wif}\nADDRESS:{found_addr}\n\n")
                except Exception as e: print("Append failed:", e, file=sys.stderr)

        total+=1
        if debug:
            now=time.time()
            if now-start>=1.0:
                rate=total/(now-start)
                print(f"[{rate:.1f} keys/s]", end='\r', flush=True)

# --- Main ---
def main():
    p=argparse.ArgumentParser(description="Random-key -> addresses; fast 3-threaded")
    p.add_argument("-f","--file", nargs="+", help="target address file(s)")
    p.add_argument("--threads",type=int,default=3,help="number of threads")
    p.add_argument("--debug",action="store_true",help="print key rate")
    args=p.parse_args()

    # Default input files if none provided
    files = args.file if args.file else ["btc1.txt","btc2.txt","btc3.txt"]
    targets=load_targets(files)
    if not targets: print("No valid addresses loaded."); return
    print(f"Loaded {len(targets):,} targets from {', '.join(files)}. Using {'coincurve' if HAVE_COINCURVE else 'Python fallback'}")

    lock = Lock()
    OUTFILE="found.txt"

    threads = [Thread(target=worker, args=(targets,args.debug,lock,OUTFILE), daemon=True) for _ in range(args.threads)]
    for t in threads: t.start()
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopped by user.")

if __name__=="__main__":
    main()