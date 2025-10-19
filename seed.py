#!/usr/bin/env python3
import os
import sys
import time
import json
import hmac
import struct
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from mnemonic import Mnemonic

import bip32utils
import ecdsa
import base58
import bech32
import sha3

_ED25519_IMPL = None
try:
    import ed25519
    _ED25519_IMPL = "ed25519"
except Exception:
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed
        from cryptography.hazmat.primitives import serialization
        _ED25519_IMPL = "cryptography"
    except Exception:
        _ED25519_IMPL = None

BIP39_WORDLIST_PATH = "seed.txt"
FOUND_FILE = "found.txt"
SLEEP_TIME = 0.6
THREADS = 4
DEBUG = "--debug" in sys.argv

ETH_RPC = "https://stylish-neat-scion.quiknode.pro/4e897c028407135cf67fe7b589d8d6f25945c1a0/"
BTC_API = "https://blockchain.info/q/addressbalance/"
SOL_RPC = "https://api.mainnet-beta.solana.com"
BNB_RPC = "https://bsc-dataseed.binance.org"
HARDEN = 0x80000000

if not os.path.exists(BIP39_WORDLIST_PATH):
    sys.exit(f"Missing BIP39 wordlist file: {BIP39_WORDLIST_PATH}")

with open(BIP39_WORDLIST_PATH, "r", encoding="utf-8") as f:
    wl = [w.strip() for w in f.readlines() if w.strip()]

if len(wl) != 2048 and DEBUG:
    print(f"[DEBUG] wordlist length is {len(wl)} (expected 2048 for standard BIP39).")

mnemo = Mnemonic("english")
mnemo.wordlist = wl

def derive_btc_addresses(seed_bytes):
    root = bip32utils.BIP32Key.fromEntropy(seed_bytes)
    k44 = root.ChildKey(44 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    legacy = k44.Address()
    k49 = root.ChildKey(49 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    pub49 = k49.PublicKey()
    h160 = hashlib.new("ripemd160", hashlib.sha256(pub49).digest()).digest()
    redeem_script = b'\x00\x14' + h160
    redeem_hash = hashlib.new("ripemd160", hashlib.sha256(redeem_script).digest()).digest()
    p2sh = base58.b58encode_check(b'\x05' + redeem_hash).decode()
    k84 = root.ChildKey(84 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    pub84 = k84.PublicKey()
    h160_84 = hashlib.new("ripemd160", hashlib.sha256(pub84).digest()).digest()
    conv = bech32.convertbits(h160_84, 8, 5)
    bech32_addr = bech32.bech32_encode("bc", [0] + conv)
    return [legacy, p2sh, bech32_addr]

def derive_eth_address(seed_bytes):
    root = bip32utils.BIP32Key.fromEntropy(seed_bytes)
    k = root.ChildKey(44 + HARDEN).ChildKey(60 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    priv = k.PrivateKey()
    sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    uncompressed = b'\x04' + vk.to_string()
    keccak = sha3.keccak_256()
    keccak.update(uncompressed[1:])
    addr = "0x" + keccak.hexdigest()[-40:]
    return checksum_eth_address(addr)

def checksum_eth_address(addr: str) -> str:
    addr_noprefix = addr.lower().replace('0x', '')
    keccak = sha3.keccak_256()
    keccak.update(addr_noprefix.encode('ascii'))
    hash_hex = keccak.hexdigest()
    out = "0x"
    for c, h in zip(addr_noprefix, hash_hex):
        out += c.upper() if int(h, 16) >= 8 else c
    return out

def derive_bnb_address(seed_bytes):
    return derive_eth_address(seed_bytes)

def slip10_ed25519_master_key(seed: bytes):
    I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]

def ed25519_ckd_priv(k_par: bytes, c_par: bytes, index: int):
    data = b'\x00' + k_par + struct.pack(">L", index)
    I = hmac.new(c_par, data, hashlib.sha512).digest()
    return I[:32], I[32:]

def derive_sol_address(mnemonic: str):
    seed = mnemo.to_seed(mnemonic, passphrase="")
    k, c = slip10_ed25519_master_key(seed)
    for idx in (44 + HARDEN, 501 + HARDEN, 0 + HARDEN, 0 + HARDEN):
        k, c = ed25519_ckd_priv(k, c, idx)
    if _ED25519_IMPL == "ed25519":
        signing_key = ed25519.SigningKey(k)
        pub = signing_key.get_verifying_key().to_bytes()
    elif _ED25519_IMPL == "cryptography":
        from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed
        from cryptography.hazmat.primitives import serialization
        sk = crypto_ed.Ed25519PrivateKey.from_private_bytes(k)
        pub = sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    else:
        raise RuntimeError("No ed25519 implementation found. Install 'ed25519' or 'cryptography' package.")
    return base58.b58encode(pub).decode()

def retry_balance(fn, addr, retries=3, delay=0.5, label=""):
    last_exc = None
    for attempt in range(retries):
        try:
            return fn(addr)
        except Exception as e:
            last_exc = e
            print(f"[Retry][{label}] attempt {attempt+1}/{retries} for {addr} failed: {e}")
            if attempt < retries - 1:
                time.sleep(delay)
    print(f"[Error][{label}] giving up after {retries} retries for {addr}: {last_exc}")
    return None

def _check_btc_once(addr):
    r = requests.get(BTC_API + addr, timeout=15)
    r.raise_for_status()
    return int(r.text.strip()) / 1e8

def _check_eth_once(addr):
    payload = {"jsonrpc": "2.0", "method": "eth_getBalance", "params": [addr, "latest"], "id": 1}
    r = requests.post(ETH_RPC, json=payload, timeout=15)
    r.raise_for_status()
    resp = r.json()
    if "error" in resp:
        raise ValueError(f"RPC error: {resp['error']}")
    if "result" not in resp:
        raise ValueError(f"Unexpected ETH RPC response: {resp}")
    return int(resp["result"], 16) / 1e18

def _check_sol_once(addr):
    payload = {"jsonrpc": "2.0","id":1,"method":"getBalance","params":[addr]}
    r = requests.post(SOL_RPC, json=payload, timeout=15)
    r.raise_for_status()
    resp = r.json()
    if "result" not in resp or "value" not in resp["result"]:
        raise ValueError(f"Unexpected Solana response: {resp}")
    return int(resp["result"]["value"]) / 1e9

def _check_bnb_once(addr):
    payload = {"jsonrpc":"2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1}
    r = requests.post(BNB_RPC, json=payload, timeout=15)
    r.raise_for_status()
    resp = r.json()
    if "result" not in resp:
        raise ValueError(f"Unexpected BNB response: {resp}")
    return int(resp["result"], 16) / 1e18

def check_btc(addr):
    val = retry_balance(_check_btc_once, addr, retries=3, delay=0.5, label="BTC")
    time.sleep(SLEEP_TIME)
    return val

def check_eth(addr):
    val = retry_balance(_check_eth_once, addr, retries=3, delay=0.5, label="ETH")
    time.sleep(SLEEP_TIME)
    return val

def check_sol(addr):
    val = retry_balance(_check_sol_once, addr, retries=3, delay=0.5, label="SOL")
    time.sleep(SLEEP_TIME)
    return val

def check_bnb(addr):
    val = retry_balance(_check_bnb_once, addr, retries=3, delay=0.5, label="BNB")
    time.sleep(SLEEP_TIME)
    return val

def check_all_balances(addresses):
    results = {"BTC": None,"ETH": None,"SOL": None,"BNB": None}
    checks = [
        ("BTC", check_btc, addresses["BTC"][0]),
        ("ETH", check_eth, addresses["ETH"]),
        ("SOL", check_sol, addresses["SOL"]),
        ("BNB", check_bnb, addresses["BNB"]),
    ]
    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        future_to_coin = {executor.submit(fn, addr): coin for (coin, fn, addr) in checks}
        for fut in as_completed(future_to_coin):
            coin = future_to_coin[fut]
            try:
                val = fut.result()
                if val is None:
                    results[coin] = None
                else:
                    results[coin] = float(val) if val > 0 else 0.0
            except Exception as e:
                results[coin] = None
                print(f"[Error][{coin}] {e}")
    return results

def append_found(mnemonic, balances):
    with open(FOUND_FILE, "a", encoding="utf-8") as f:
        f.write(f"Words: {mnemonic}\n")
        for c in ("BTC","ETH","SOL","BNB"):
            b = balances.get(c)
            if b is None:
                f.write(f"{c} BALANCE:\n")
            elif b > 0:
                f.write(f"{c} BALANCE: {b}\n")
            else:
                f.write(f"{c} BALANCE:\n")
        f.write("\n")

def main():
    tried = 0
    try:
        while True:
            mnemonic = mnemo.generate(strength=128)
            seed_bytes = mnemo.to_seed(mnemonic)
            try:
                btc_addrs = derive_btc_addresses(seed_bytes)
                eth_addr = derive_eth_address(seed_bytes)
                sol_addr = derive_sol_address(mnemonic)
                bnb_addr = derive_bnb_address(seed_bytes)
            except Exception as e:
                if DEBUG:
                    print(f"[DEBUG][DerivationError] {e}")
                tried += 1
                print(f"Tried {tried}")
                continue
            addresses = {"BTC": btc_addrs,"ETH": eth_addr,"SOL": sol_addr,"BNB": bnb_addr}
            if DEBUG:
                print(json.dumps({"mnemonic":mnemonic,"addresses":addresses}, indent=2))
            balances = check_all_balances(addresses)
            tried += 1
            print(f"Tried {tried}")
            hit = any(isinstance(v,(int,float)) and v>0 for v in balances.values())
            if hit:
                print(mnemonic)
                for c in ("BTC","ETH","SOL","BNB"):
                    val = balances.get(c)
                    if val is None or val==0:
                        print(f"{c} BALANCE:")
                    else:
                        print(f"{c} BALANCE: {val}")
                append_found(mnemonic, balances)
    except KeyboardInterrupt:
        print("\nCancelled by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()