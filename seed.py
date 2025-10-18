#!/usr/bin/env python3
"""
seed.py
Sequential scanner: reads seed.txt (1 word per line),
generates 12-word BIP39 mnemonic, derives BTC addresses (legacy, wrapped segwit, native segwit),
checks blockchain.info /q endpoints.

Requirements:
    pip3 install coincurve requests base58

Usage:
    python3 seed.py --out found.txt
"""
from __future__ import annotations
import argparse, io, sys, time, random, logging, hmac
import binascii, hashlib, struct
import requests, base58
from coincurve import PrivateKey

# ---------- constants ----------
BIP32_SEED_KEY = b"Bitcoin seed"
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# ---------- crypto helpers ----------
def pbkdf2_hmac_sha512(password: str, salt: str, iterations: int = 2048, dklen: int = 64) -> bytes:
    return hashlib.pbkdf2_hmac("sha512", password.encode("utf-8"), salt.encode("utf-8"), iterations, dklen)

def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return pbkdf2_hmac_sha512(mnemonic, "mnemonic"+passphrase)

def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha512).digest()

def int_from_bytes(b: bytes) -> int:
    return int.from_bytes(b, "big")

def bytes_from_int(i: int, length: int) -> bytes:
    return i.to_bytes(length, "big")

def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

def base58check_encode(prefix: bytes, payload20: bytes) -> str:
    raw = prefix + payload20
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return base58.b58encode(raw + checksum).decode()

def wif_from_privhex(priv_hex: str, compressed: bool = True) -> str:
    b = binascii.unhexlify(priv_hex)
    payload = b'\x80' + b
    if compressed:
        payload += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

# ---------- bech32 ----------
def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk=1
    for v in values:
        top=chk>>25
        chk=((chk & 0x1ffffff)<<5)^v
        for i in range(5):
            if (top>>i)&1:
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp): return [ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]

def bech32_create_checksum(hrp,data):
    values=bech32_hrp_expand(hrp)+data
    polymod=bech32_polymod(values+[0]*6)^1
    return [(polymod>>(5*(5-i)))&31 for i in range(6)]

def bech32_encode(hrp,data):
    return hrp+'1'+''.join([CHARSET[d] for d in data+bech32_create_checksum(hrp,data)])

def convertbits(data: bytes, frombits: int, tobits: int, pad: bool=True):
    acc=bits=0; ret=[]
    maxv=(1<<tobits)-1
    for b in data:
        acc=(acc<<frombits)|b; bits+=frombits
        while bits>=tobits: bits-=tobits; ret.append((acc>>bits)&maxv)
    if pad and bits: ret.append((acc<<(tobits-bits))&maxv)
    return ret

def p2wpkh_bech32_from_pubkey(pub: bytes, hrp: str='bc') -> str:
    prog = hash160(pub)
    data = [0]+convertbits(prog,8,5)
    return bech32_encode(hrp,data)

# ---------- BIP32 ----------
def bip32_master_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    I = hmac_sha512(BIP32_SEED_KEY, seed)
    return I[:32], I[32:]

def ser32(i: int) -> bytes: return struct.pack(">I", i)

def bip32_ckd_priv(k_par: bytes, c_par: bytes, index: int) -> tuple[bytes, bytes]:
    if index & 0x80000000: data=b'\x00'+k_par+ser32(index)
    else: data=PrivateKey(k_par).public_key.format(compressed=True)+ser32(index)
    I = hmac_sha512(c_par,data); IL,IR=I[:32],I[32:]
    child=(int_from_bytes(IL)+int_from_bytes(k_par))%CURVE_ORDER
    return bytes_from_int(child,32), IR

def derive_path(master_k: bytes, master_c: bytes, path: str) -> tuple[bytes, bytes]:
    k,c=master_k, master_c
    for e in path.lstrip("m/").split("/"):
        idx=int(e[:-1])|0x80000000 if e.endswith("'") else int(e)
        k,c=bip32_ckd_priv(k,c,idx)
    return k,c

# ---------- address builders ----------
def p2pkh_from_privkey_bytes(priv32: bytes) -> str:
    pk=PrivateKey(priv32); return base58check_encode(b'\x00', hash160(pk.public_key.format(compressed=True)))

def p2sh_p2wpkh_from_privkey_bytes(priv32: bytes) -> str:
    pk=PrivateKey(priv32); redeem=b'\x00\x14'+hash160(pk.public_key.format(compressed=True))
    return base58check_encode(b'\x05', hash160(redeem))

def p2wpkh_bech32_from_privkey_bytes(priv32: bytes) -> str:
    pk=PrivateKey(priv32); return p2wpkh_bech32_from_pubkey(pk.public_key.format(compressed=True))

# ---------- blockchain fetch ----------
def _get_raw_numeric(session: requests.Session, url: str, timeout: float = 15.0) -> float:
    r = session.get(url,timeout=timeout); r.raise_for_status()
    try: return float(r.text.strip())
    except: return 0.0

# ---------- main ----------
def main():
    ap=argparse.ArgumentParser(description="Seed scanner (1 word->12-word BIP39)")
    ap.add_argument("--dict","-d",default="seed.txt")
    ap.add_argument("--out","-o",default="found.txt")
    ap.add_argument("--sleep",type=float,default=0.6)
    ap.add_argument("--jitter",type=float,default=0.05)
    ap.add_argument("--debug",action="store_true")
    args=ap.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    
    session = requests.Session()
    with open(args.dict,"r",encoding="utf-8") as fdict, open(args.out,"a",encoding="utf-8",buffering=1) as fout:
        total=checked=found=0; start_time=time.time()
        for line in fdict:
            word=line.strip()
            if not word: continue
            total+=1
            mnemonic=" ".join([word]*12)
            try:
                seed=mnemonic_to_seed(mnemonic)
                master_k,master_c=bip32_master_from_seed(seed)
                k44,_=derive_path(master_k,master_c,"m/44'/0'/0'/0/0")
                k49,_=derive_path(master_k,master_c,"m/49'/0'/0'/0/0")
                k84,_=derive_path(master_k,master_c,"m/84'/0'/0'/0/0")
                addr_list=[
                    ("p2pkh",p2pkh_from_privkey_bytes(k44),k44),
                    ("p2sh-p2wpkh",p2sh_p2wpkh_from_privkey_bytes(k49),k49),
                    ("p2wpkh",p2wpkh_bech32_from_privkey_bytes(k84),k84)
                ]
            except Exception as e:
                logging.debug("Derivation failed for '%s': %s",mnemonic,e)
                continue

            for atype, addr, priv32 in addr_list:
                try: wif=wif_from_privhex(binascii.hexlify(priv32).decode())
                except: wif=""
                received=0.0
                try: received=_get_raw_numeric(session,f"https://blockchain.info/q/getreceivedbyaddress/{addr}")
                except: pass
                checked+=1
                if received==0.0:
                    time.sleep(args.sleep+random.random()*args.jitter)
                    continue
                print(f"\nFOUND: {atype} {addr} | WIF: {wif} | RECEIVED: {received}\n")
                fout.write(f"{mnemonic},{atype},{addr},{wif},{received}\n"); fout.flush(); found+=1
                time.sleep(args.sleep+random.random()*args.jitter)

            if total%100==0: logging.info("Processed %d words, checked:%d, found:%d", total, checked, found)
        logging.info("Done. Total words:%d, checked:%d, found:%d", total, checked, found)

if __name__=="__main__":
    main()