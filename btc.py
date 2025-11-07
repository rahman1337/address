#!/usr/bin/env python3
"""
vanity_loop_threads.py

Vanity Bitcoin address generator (threaded version):
- Uses ThreadPoolExecutor with 5 threads
- No output file (prints results only)
- Generates batches of 100 private keys
- Continuous looping
- Prefix matching from file

Requirements:
    pip install coincurve base58
"""

import os
import sys
import time
import hashlib
import argparse
from concurrent.futures import ThreadPoolExecutor
from coincurve import PrivateKey
import base58

# ------------------ constants ------------------

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
THREADS = 5
BATCH_SIZE = 100

# ------------------ helpers ------------------

def ripemd160(x: bytes) -> bytes:
    h = hashlib.new('ripemd160'); h.update(x); return h.digest()

def hash160(x: bytes) -> bytes:
    return ripemd160(hashlib.sha256(x).digest())

def base58check(payload: bytes) -> str:
    return base58.b58encode_check(payload).decode()

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk=1
    for v in values:
        b = (chk>>25)
        chk = ((chk & 0x1ffffff)<<5) ^ v
        for i in range(5):
            if (b>>i)&1: chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp: str):
    return [ord(x)>>5 for x in hrp] + [0] + [ord(x)&31 for x in hrp]

def bech32_create_checksum(hrp: str, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values+[0]*6)^1
    return [(polymod>>(5*(5-i)))&31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    acc=0; bits=0; ret=[]; maxv=(1<<tobits)-1
    for value in data:
        acc=(acc<<frombits)|value
        bits+=frombits
        while bits>=tobits:
            bits-=tobits
            ret.append((acc>>bits)&maxv)
    if pad and bits: ret.append((acc<<(tobits-bits))&maxv)
    return ret

def p2wpkh_bech32_address(hash20: bytes) -> str:
    data=[0]+convertbits(list(hash20),8,5)
    combined=data+bech32_create_checksum('bc', data)
    return 'bc1'+''.join([CHARSET[d] for d in combined])

def pub_to_p2pkh(pub: bytes) -> str:
    return base58check(b'\x00'+hash160(pub))

def pub_to_p2sh_p2wpkh(pub: bytes) -> str:
    h = hash160(pub)
    redeem = b'\x00\x14'+h
    redeem_hash = ripemd160(hashlib.sha256(redeem).digest())
    return base58check(b'\x05'+redeem_hash)

def pub_to_bech32(pub: bytes) -> str:
    return p2wpkh_bech32_address(hash160(pub))

def priv_to_wif(priv_bytes: bytes) -> str:
    return base58check(b'\x80'+priv_bytes+b'\x01')

def generate_priv_batch(batch_size: int):
    out=[]
    while len(out)<batch_size:
        need=batch_size-len(out)
        chunk=os.urandom(32*need*2)
        for i in range(0,len(chunk),32):
            priv=chunk[i:i+32]
            v=int.from_bytes(priv,'big')
            if 1<=v<SECP256K1_N:
                out.append(priv)
                if len(out)>=batch_size: break
    return out

def print_found(priv_hex, wif, addr, target):
    line = "="*72
    print(line)
    print(f"FOUND MATCH for prefix: {target}")
    print(line)
    print("PRIV:", priv_hex)
    print("WIF :", wif)
    print("ADDR:", addr)
    print(line, "\n")

# ------------------ worker ------------------

def worker(prefixes_by_first):
    checked = 0
    while True:
        privs = generate_priv_batch(BATCH_SIZE)
        for priv in privs:
            pk = PrivateKey(priv)
            pub = pk.public_key.format(compressed=True)
            addrs = [pub_to_p2pkh(pub), pub_to_p2sh_p2wpkh(pub), pub_to_bech32(pub)]
            for addr in addrs:
                candidates = prefixes_by_first.get(addr[0], [])
                for t in candidates:
                    addr_to_check = addr.lower() if addr.startswith('bc1') else addr
                    t_cmp = t.lower() if addr.startswith('bc1') else t
                    if addr_to_check.startswith(t_cmp):
                        print_found(priv.hex(), priv_to_wif(priv), addr, t)
            checked += 1

# ------------------ main ------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vanity Bitcoin address generator (threaded)")
    parser.add_argument('targets_file', help='File with addresses or prefixes')
    parser.add_argument('--prefix-length', type=int, default=6, help='Chars to use as prefix')
    args = parser.parse_args()

    prefix_length = max(1, args.prefix_length)
    prefixes_by_first = {}

    with open(args.targets_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            prefix = line[:prefix_length]
            prefixes_by_first.setdefault(prefix[0], []).append(prefix)

    print("="*72)
    print("Vanity loop generator (threads)")
    print(f"Loaded prefixes: {sum(len(v) for v in prefixes_by_first.values())}")
    print(f"Threads: {THREADS} | Batch size: {BATCH_SIZE}")
    print("="*72)

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        for _ in range(THREADS):
            executor.submit(worker, prefixes_by_first)
        try:
            while True:
                time.sleep(10)
        except KeyboardInterrupt:
            print("\nInterrupted. Stopping...")
            sys.exit(0)
