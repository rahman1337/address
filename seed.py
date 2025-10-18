#!/usr/bin/env python3
"""
seed.py
Sequential scanner: generates valid 12-word BIP39 mnemonics using seed.txt as wordlist,
derives BTC addresses (legacy, wrapped segwit, native segwit),
checks blockchain.info /q endpoints.

Requirements:
    pip3 install coincurve requests base58 mnemonic
"""
from __future__ import annotations
import argparse, io, sys, time, random, logging, hmac
import binascii, hashlib, struct
import requests, base58
from coincurve import PrivateKey
from mnemonic import Mnemonic

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
        while bits>=tobits:
            bits-=tobits; ret.append((acc>>bits)&maxv)
    if pad and bits: ret.append((acc<<(tobits-bits))&maxv)
    return ret

def p2wpkh_bech32_from_pubkey(pub: bytes, hrp: str='bc') -> str:
    prog = hash160(pub)
    data = [0] + convertbits(prog,8,5)
    return bech32_encode(hrp, data)

# ---------- BIP32 ----------
def bip32_master_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    I = hmac_sha512(BIP32_SEED_KEY, seed)
    return I[:32], I[32:]

def ser32(i: int) -> bytes: return struct.pack(">I", i)

def bip32_ckd_priv(k_par: bytes, c_par: bytes, index: int) -> tuple[bytes, bytes]:
    if index & 0x80000000:
        data = b'\x00' + k_par + ser32(index)
    else:
        data = PrivateKey(k_par).public_key.format(compressed=True) + ser32(index)
    I = hmac_sha512(c_par, data)
    IL, IR = I[:32], I[32:]
    child = (int_from_bytes(IL) + int_from_bytes(k_par)) % CURVE_ORDER
    return bytes_from_int(child, 32), IR

def derive_path(master_k: bytes, master_c: bytes, path: str) -> tuple[bytes, bytes]:
    k, c = master_k, master_c
    for e in path.lstrip("m/").split("/"):
        idx = int(e[:-1]) | 0x80000000 if e.endswith("'") else int(e)
        k, c = bip32_ckd_priv(k, c, idx)
    return k, c

# ---------- address builders ----------
def p2pkh_from_privkey_bytes(priv32: bytes) -> str:
    pk = PrivateKey(priv32)
    return base58check_encode(b'\x00', hash160(pk.public_key.format(compressed=True)))

def p2sh_p2wpkh_from_privkey_bytes(priv32: bytes) -> str:
    pk = PrivateKey(priv32)
    redeem = b'\x00\x14' + hash160(pk.public_key.format(compressed=True))
    return base58check_encode(b'\x05', hash160(redeem))

def p2wpkh_bech32_from_privkey_bytes(priv32: bytes) -> str:
    pk = PrivateKey(priv32)
    return p2wpkh_bech32_from_pubkey(pk.public_key.format(compressed=True))

# ---------- blockchain fetch ----------
def _get_raw_numeric(session: requests.Session, url: str, timeout: float = 15.0, max_retries: int = 3) -> float:
    for attempt in range(max_retries):
        try:
            r = session.get(url, timeout=timeout)
            r.raise_for_status()
            text = r.text.strip()
            try:
                return float(text)
            except Exception:
                try:
                    j = r.json()
                    for key in ("total_received","totalReceived","final_balance","finalBalance","balance","received"):
                        if isinstance(j, dict) and key in j:
                            return float(j[key])
                except Exception:
                    pass
                raise ValueError("Unable to parse numeric from response")
        except Exception:
            backoff = (0.5 + random.random()) * (2 ** attempt)
            time.sleep(backoff)
    return 0.0

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description="Valid 12-word BIP39 mnemonic BTC scanner")
    ap.add_argument("--dict", "-d", default="seed.txt", help="BIP39 wordlist (1 word per line)")
    ap.add_argument("--out", "-o", default="found.txt")
    ap.add_argument("--sleep", type=float, default=0.6)
    ap.add_argument("--jitter", type=float, default=0.05)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--base-received", default="https://blockchain.info/q/getreceivedbyaddress")
    ap.add_argument("--base-balance", default="https://blockchain.info/q/addressbalance")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # check coincurve
    try:
        _ = PrivateKey(b'\x01'*32)
    except Exception as e:
        logging.error("coincurve unavailable: %s", e)
        sys.exit(1)

    # BIP39 wordlist
    try:
        words = [w.strip() for w in io.open(args.dict, "rt", encoding="utf-8") if w.strip()]
        mnemo = Mnemonic("english")
    except Exception as e:
        logging.error("Cannot load wordlist: %s", e)
        sys.exit(1)

    session = requests.Session()
    try:
        fout = open(args.out, "a", encoding="utf-8", buffering=1)
    except Exception as e:
        logging.error("Cannot open output file: %s", e)
        sys.exit(1)

    total = checked = found = 0
    start_time = time.time()

    try:
        while True:
            # generate **valid 12-word mnemonic** using BIP39 library
            mnemonic = mnemo.generate(strength=128)  # 128 bits = 12 words
            if not mnemo.check(mnemonic):
                continue
            total += 1

            # derive seed / master
            try:
                seed = mnemonic_to_seed(mnemonic)
                master_k, master_c = bip32_master_from_seed(seed)
            except Exception:
                continue

            # derive 3 addresses
            try:
                k44,_ = derive_path(master_k, master_c, "m/44'/0'/0'/0/0")
                k49,_ = derive_path(master_k, master_c, "m/49'/0'/0'/0/0")
                k84,_ = derive_path(master_k, master_c, "m/84'/0'/0'/0/0")
                addr_list = [
                    ("p2pkh", p2pkh_from_privkey_bytes(k44), k44),
                    ("p2sh-p2wpkh", p2sh_p2wpkh_from_privkey_bytes(k49), k49),
                    ("p2wpkh", p2wpkh_bech32_from_privkey_bytes(k84), k84)
                ]
            except Exception:
                continue

            # check addresses sequentially
            for atype, addr, priv32 in addr_list:
                try:
                    wif = wif_from_privhex(binascii.hexlify(priv32).decode())
                except Exception:
                    wif = ""

                received = _get_raw_numeric(session, f"{args.base_received}/{addr}")
                checked += 1
                if received == 0.0:
                    time.sleep(args.sleep + random.random()*args.jitter)
                    continue

                balance = _get_raw_numeric(session, f"{args.base_balance}/{addr}")

                # print & append block line-by-line
                block_lines = [
                    "============================",
                    mnemonic,
                    addr,
                    wif,
                    str(received),
                    str(balance),
                    "============================"
                ]
                for line in block_lines:
                    print(line)
                print()
                try:
                    for line in block_lines:
                        fout.write(line+"\n")
                    fout.write("\n")
                    fout.flush()
                except Exception:
                    pass

                found += 1
                time.sleep(args.sleep + random.random()*args.jitter)

            if total % 10 == 0:
                elapsed = time.time() - start_time
                logging.info("Generated %d mnemonics — addresses checked:%d found:%d — avg %.2f mnemonics/s",
                             total, checked, found, total/max(1.0,elapsed))

    except KeyboardInterrupt:
        logging.info("Interrupted by user")
    finally:
        try: fout.close()
        except Exception: pass
        session.close()
        elapsed = time.time()-start_time
        logging.info("Finished. Total mnemonics: %d, addresses checked:%d found:%d, elapsed %.1fs",
                     total, checked, found, elapsed)

if __name__=="__main__":
    main()