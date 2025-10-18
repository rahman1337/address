#!/usr/bin/env python3
"""
seed.py
Sequential scanner: generates valid 12-word BIP39 mnemonics using seed.txt as wordlist,
derives BTC addresses (legacy, wrapped segwit, native segwit),
and now also derives Ethereum and Solana addresses,
checks blockchain endpoints (configurable).

Requirements:
    pip3 install coincurve requests base58 mnemonic
Optional (for full ETH/SOL support):
    pip3 install pynacl pysha3 pycryptodome
"""
from __future__ import annotations
import argparse, io, sys, time, random, logging, hmac
import binascii, hashlib, struct
import requests, base58
from coincurve import PrivateKey
from mnemonic import Mnemonic

# Optional imports for Ethereum and Solana support
try:
    import sha3 as _sha3  # pysha3 (provides keccak_256)
    def keccak_256(x: bytes) -> bytes:
        k = _sha3.keccak_256()
        k.update(x)
        return k.digest()
except Exception:
    try:
        # pycryptodome style
        from Crypto.Hash import keccak as _keccak
        def keccak_256(x: bytes) -> bytes:
            k = _keccak.new(digest_bits=256)
            k.update(x)
            return k.digest()
    except Exception:
        try:
            # rare Python builds expose keccak through hashlib.new
            def keccak_256(x: bytes) -> bytes:
                k = hashlib.new("keccak256")
                k.update(x)
                return k.digest()
        except Exception:
            keccak_256 = None  # will check later

try:
    import nacl.signing, nacl.encoding
    PYNACL_AVAILABLE = True
except Exception:
    PYNACL_AVAILABLE = False

# ---------- constants ----------
BIP32_SEED_KEY = b"Bitcoin seed"
SLIP10_ED25519_SEED_KEY = b"ed25519 seed"
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

# ---------- BIP32 (secp256k1) ----------
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

# ---------- SLIP-0010 for ed25519 (Solana) ----------
def slip10_master_from_seed(seed: bytes) -> tuple[bytes, bytes]:
    I = hmac_sha512(SLIP10_ED25519_SEED_KEY, seed)
    return I[:32], I[32:]

def slip10_ckd_priv_ed25519(k_par: bytes, c_par: bytes, index: int) -> tuple[bytes, bytes]:
    # ed25519 SLIP-0010 supports *only* hardened derivation
    if not (index & 0x80000000):
        raise ValueError("ed25519 derivation only supports hardened indexes")
    data = b'\x00' + k_par + ser32(index)
    I = hmac_sha512(c_par, data)
    return I[:32], I[32:]

def derive_path_ed25519(master_k: bytes, master_c: bytes, path: str) -> tuple[bytes, bytes]:
    k, c = master_k, master_c
    for e in path.lstrip("m/").split("/"):
        if not e.endswith("'"):
            raise ValueError("ed25519 path must use hardened notation (') for each level")
        idx = int(e[:-1]) | 0x80000000
        k, c = slip10_ckd_priv_ed25519(k, c, idx)
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

def ethereum_address_from_privkey(priv32: bytes) -> str | None:
    # returns 0x-prefixed hex address, lowercase (no EIP-55 checks)
    if keccak_256 is None:
        logging.debug("keccak_256 not available; cannot compute Ethereum address")
        return None
    pk = PrivateKey(priv32)
    # get uncompressed public key (65 bytes, 0x04 prefix)
    pub_uncompressed = pk.public_key.format(compressed=False)
    # drop 0x04 prefix
    pub_raw = pub_uncompressed[1:]
    h = keccak_256(pub_raw)
    addr = h[-20:]
    return "0x" + binascii.hexlify(addr).decode()

def solana_address_from_ed25519_privkey(ed_priv32: bytes) -> str | None:
    if not PYNACL_AVAILABLE:
        logging.debug("PyNaCl not available; cannot compute Solana address")
        return None
    # ed_priv32 is 32 bytes seed for the signing key (SLIP-0010 IL)
    sk = nacl.signing.SigningKey(ed_priv32)
    vk = sk.verify_key
    pub = vk.encode()  # 32 bytes
    # Solana address is base58 of the 32-byte public key
    return base58.b58encode(pub).decode()

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
                    for key in ("total_received","totalReceived","final_balance","finalBalance","balance","received","lamports","amount"):
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
    ap = argparse.ArgumentParser(description="Valid 12-word BIP39 mnemonic BTC/Ethereum/Solana scanner")
    ap.add_argument("--dict", "-d", default="seed.txt", help="BIP39 wordlist (1 word per line)")
    ap.add_argument("--out", "-o", default="found.txt")
    ap.add_argument("--sleep", type=float, default=0.6)
    ap.add_argument("--jitter", type=float, default=0.05)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--base-btc-received", default="https://blockchain.info/q/getreceivedbyaddress")
    ap.add_argument("--base-btc-balance", default="https://blockchain.info/q/addressbalance")
    # simple default endpoints (replace with your APIs if desired)
    ap.add_argument("--base-eth-balance", default="https://api.blockcypher.com/v1/eth/main/addrs")
    ap.add_argument("--base-sol-balance", default="https://public-api.solscan.io/account")
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

            # derive BTC addresses (BIP44, BIP49, BIP84)
            try:
                k44,_ = derive_path(master_k, master_c, "m/44'/0'/0'/0/0")
                k49,_ = derive_path(master_k, master_c, "m/49'/0'/0'/0/0")
                k84,_ = derive_path(master_k, master_c, "m/84'/0'/0'/0/0")
                btc_addrs = [
                    ("BTC-p2pkh", p2pkh_from_privkey_bytes(k44), k44),
                    ("BTC-p2sh-p2wpkh", p2sh_p2wpkh_from_privkey_bytes(k49), k49),
                    ("BTC-p2wpkh", p2wpkh_bech32_from_privkey_bytes(k84), k84)
                ]
            except Exception:
                continue

            # derive Ethereum (BIP44 m/44'/60'/0'/0/0)
            eth_addr = None
            eth_wif = ""
            try:
                k_eth, _ = derive_path(master_k, master_c, "m/44'/60'/0'/0/0")
                eth_addr = ethereum_address_from_privkey(k_eth)
                try:
                    eth_wif = wif_from_privhex(binascii.hexlify(k_eth).decode())  # WIF isn't standard for ETH but we keep similar form
                except Exception:
                    eth_wif = ""
            except Exception:
                eth_addr = None

            # derive Solana (ed25519 using SLIP-0010) m/44'/501'/0'/0'
            sol_addr = None
            sol_seed_hex = ""
            try:
                if PYNACL_AVAILABLE:
                    ed_master_k, ed_master_c = slip10_master_from_seed(seed)
                    ed_k, ed_c = derive_path_ed25519(ed_master_k, ed_master_c, "m/44'/501'/0'/0'")
                    sol_addr = solana_address_from_ed25519_privkey(ed_k)
                    sol_seed_hex = binascii.hexlify(ed_k).decode()
                else:
                    sol_addr = None
            except Exception as e:
                logging.debug("Solana derivation failed: %s", e)
                sol_addr = None

            # assemble addr_list mixing BTC, ETH, SOL
            addr_list = []
            addr_list.extend(btc_addrs)
            if eth_addr:
                addr_list.append(("ETH", eth_addr, k_eth))
            if sol_addr:
                # store ed25519 seed in place of "priv32" for SOL entry (different curve)
                addr_list.append(("SOL", sol_addr, sol_seed_hex.encode()))

            # check addresses sequentially
            for atype, addr, priv32 in addr_list:
                try:
                    if atype.startswith("BTC"):
                        wif = wif_from_privhex(binascii.hexlify(priv32).decode())
                    elif atype == "ETH":
                        try:
                            wif = wif_from_privhex(binascii.hexlify(priv32).decode())
                        except Exception:
                            wif = ""
                    elif atype == "SOL":
                        # priv32 here is hex-encoded ed25519 seed bytes saved above
                        try:
                            wif = priv32.decode()
                        except Exception:
                            wif = ""
                    else:
                        wif = ""
                except Exception:
                    wif = ""

                # choose the appropriate balance endpoint
                received = 0.0
                balance = 0.0
                if atype.startswith("BTC"):
                    received = _get_raw_numeric(session, f"{args.base_btc_received}/{addr}")
                    checked += 1
                    if received == 0.0:
                        time.sleep(args.sleep + random.random()*args.jitter)
                        continue
                    balance = _get_raw_numeric(session, f"{args.base_btc_balance}/{addr}")
                elif atype == "ETH":
                    # BlockCypher returns JSON; for convenience use route: {base}/{addr}/balance
                    received = _get_raw_numeric(session, f"{args.base_eth_balance}/{addr}/balance".replace(" ", ""))
                    # if API doesn't support "received", we try balance endpoint
                    if received == 0.0:
                        received = 0.0
                    checked += 1
                    if received == 0.0:
                        # also try direct balance query (some providers)
                        balance = _get_raw_numeric(session, f"{args.base_eth_balance}/{addr}/balance")
                        if balance == 0.0:
                            time.sleep(args.sleep + random.random()*args.jitter)
                            continue
                elif atype == "SOL":
    # Check via Solana JSON-RPC
    try:
        payload = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [addr]
        }
        r = session.post("https://api.mainnet-beta.solana.com", json=payload, timeout=10)
        j = r.json()
        lamports = j.get("result", {}).get("value", 0)
        received = lamports / 1e9  # convert lamports to SOL
        checked += 1
        if received == 0.0:
            time.sleep(args.sleep + random.random() * args.jitter)
            continue
        balance = received
    except Exception as e:
        logging.debug("Solana balance check failed: %s", e)
        continue

                # print & append block line-by-line
                block_lines = [
                    "============================",
                    f"coin: {atype}",
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