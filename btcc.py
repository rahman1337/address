#!/usr/bin/env python3
"""
Working BTC live-balance scanner — immediate live keys and MATCH print
Requires:
  pip install coincurve requests
"""

import os, time, hashlib, requests
from coincurve import PublicKey

# ---------- Settings ----------
MATCH_OUTFILE = "btc_matches.txt"
REPORT_INTERVAL = 1.0

# ---------- ECC / BTC helpers ----------
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def sha256(b): return hashlib.sha256(b).digest()
def ripemd160(b): h=hashlib.new("ripemd160"); h.update(b); return h.digest()
def hash160(b): return ripemd160(sha256(b))
def base58check(data):
    checksum = sha256(sha256(data))[:4]
    num = int.from_bytes(data + checksum, "big")
    res_chars = []
    while num > 0:
        num, mod = divmod(num, 58)
        res_chars.append(BASE58_ALPHABET[mod])
    n_pad = len(data) - len(data.lstrip(b'\0'))
    return '1'*n_pad + ''.join(reversed(res_chars)) if n_pad else ''.join(reversed(res_chars))
def wif_from_priv(priv_bytes): return base58check(b'\x80'+priv_bytes+b'\x01')
def p2pkh_from_pub(pub_compressed): return base58check(b'\x00'+hash160(pub_compressed))
def pubkey_compressed_from_priv_bytes(priv_bytes): return PublicKey.from_valid_secret(priv_bytes).format(compressed=True)

# ---------- Balance check ----------
def check_balance(addr):
    backoff = 0.5
    while True:
        try:
            r = requests.get(f"https://blockchain.info/q/addressbalance/{addr}?confirmations=0", timeout=5)
            return int(r.text)/1e8
        except:
            time.sleep(backoff)
            backoff = min(backoff*1.5,5.0)

# ---------- Main ----------
total = 0
start = time.time()
last_report = start

while True:
    priv = os.urandom(32)
    pubc = pubkey_compressed_from_priv_bytes(priv)
    addr = p2pkh_from_pub(pubc)
    wif = wif_from_priv(priv)
    bal = check_balance(addr)

    total += 1
    elapsed = time.time() - start
    avg = total / elapsed if elapsed>0 else 0.0
    print(f"[live keys: {total} — {avg:.1f} keys/s]".ljust(60), end="\r")

    if bal and bal > 0.0:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n=== MATCH FOUND ===\n{ts}\nWIF\n{wif}\nADDRESS\n{addr}\nBALANCE: {bal:.8f} BTC\n===================\n")
        with open(MATCH_OUTFILE, "a", encoding="utf-8") as fo:
            fo.write(f"{ts}\nWIF:{wif}\nADDRESS:{addr}\nBALANCE:{bal:.8f}\n\n")