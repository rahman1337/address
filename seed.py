#!/usr/bin/env python3
"""
scanner.py - bip32utils + pure-ed25519 Solana derivation (no PyNaCl)
Generates 12-word BIP39 mnemonics (using seed.txt wordlist), derives:
 - BTC (legacy 1..., P2SH nested segwit 3..., bech32 bc1q...)
 - ETH (m/44'/60'/0'/0/0)
 - BNB (same derivation as ETH)
 - SOL (m/44'/501'/0'/0/0) using pure-python Ed25519 derivation (no PyNaCl)

Checks balances with public endpoints. Sleeps 0.7s per request.
Writes hits to found.txt, prints only "Tried N" normally; --debug shows addresses/APIs.
"""
import os, sys, time, json
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from mnemonic import Mnemonic
from bip32utils import BIP32Key
import hashlib, hmac, struct
import binascii
import ecdsa
import base58
import bech32
import sha3          # pysha3 (keccak_256)
from typing import Tuple

# CONFIG
BIP39_WORDLIST_PATH = "seed.txt"
FOUND_FILE = "found.txt"
SLEEP_TIME = 0.7
THREADS = 4
DEBUG = "--debug" in sys.argv

# Use a public ETH RPC — you can replace with another if you prefer
ETH_RPC = "https://rpc.ankr.com/eth"   # fallback to a generally reliable public RPC
BTC_API = "https://blockchain.info/q/addressbalance/"
SOL_RPC = "https://api.mainnet-beta.solana.com"
BNB_RPC = "https://bsc-dataseed.binance.org"

# Load wordlist
if not os.path.exists(BIP39_WORDLIST_PATH):
    sys.exit(f"Missing {BIP39_WORDLIST_PATH}")
with open(BIP39_WORDLIST_PATH, "r", encoding="utf-8") as f:
    wl = [w.strip() for w in f if w.strip()]
if len(wl) != 2048 and DEBUG:
    print(f"[DEBUG] wordlist length: {len(wl)} (expected 2048)")

mnemo = Mnemonic("english")
mnemo.wordlist = wl

# Helpers for hardened index
HARDEN = 0x80000000

# ---------- BTC derivation using bip32utils ----------
def derive_btc_addresses_from_seed(seed_bytes: bytes) -> Tuple[str,str,str]:
    root = BIP32Key.fromEntropy(seed_bytes)

    # Derive m/44'/0'/0'/0/0 (legacy P2PKH)
    k = root.ChildKey(44 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    legacy = k.Address()

    # Nested segwit (P2SH-P2WPKH) m/49'/0'/0'/0/0
    k49 = root.ChildKey(49 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    pubkey49 = k49.PublicKey()
    h160 = hashlib.new("ripemd160", hashlib.sha256(pubkey49).digest()).digest()
    redeem_script = b'\x00\x14' + h160
    redeem_hash = hashlib.new("ripemd160", hashlib.sha256(redeem_script).digest()).digest()
    p2sh = base58.b58encode_check(b'\x05' + redeem_hash).decode()

    # Bech32 native segwit (BIP84) m/84'/0'/0'/0/0
    k84 = root.ChildKey(84 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    pubkey84 = k84.PublicKey()
    h160_84 = hashlib.new("ripemd160", hashlib.sha256(pubkey84).digest()).digest()
    conv = bech32.convertbits(h160_84, 8, 5)
    bech32_addr = bech32.bech32_encode("bc", [0] + conv)
    return legacy, p2sh, bech32_addr

# ---------- ETH / BNB derivation ----------
def derive_eth_address_from_seed(seed_bytes: bytes) -> str:
    root = BIP32Key.fromEntropy(seed_bytes)
    k = root.ChildKey(44 + HARDEN).ChildKey(60 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    priv = k.PrivateKey()
    sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    uncompressed = b'\x04' + vk.to_string()
    keccak = sha3.keccak_256()
    keccak.update(uncompressed[1:])  # drop 0x04 prefix
    addr = keccak.hexdigest()[-40:]
    addr = "0x" + addr
    checksum = checksum_eth_address(addr)
    return checksum

def checksum_eth_address(addr: str) -> str:
    addr_noprefix = addr.lower().replace('0x','')
    keccak = sha3.keccak_256()
    keccak.update(addr_noprefix.encode('ascii'))
    hash_hex = keccak.hexdigest()
    out = "0x"
    for c, h in zip(addr_noprefix, hash_hex):
        if int(h, 16) >= 8:
            out += c.upper()
        else:
            out += c
    return out

# ---------- SOL derivation (pure Python, no PyNaCl) ----------
def slip10_ed25519_master_key(seed: bytes):
    I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]

def ed25519_ckd_priv(k_par: bytes, c_par: bytes, index: int):
    data = b'\x00' + k_par + struct.pack(">L", index)
    I = hmac.new(c_par, data, hashlib.sha512).digest()
    return I[:32], I[32:]

def derive_sol_pubkey_from_mnemonic(mnemonic: str) -> str:
    seed = mnemo.to_seed(mnemonic, passphrase="")  # bytes
    k, c = slip10_ed25519_master_key(seed)
    for idx in (44 + HARDEN, 501 + HARDEN, 0 + HARDEN, 0 + HARDEN):
        k, c = ed25519_ckd_priv(k, c, idx)
    # compute ed25519 public key using available libs
    try:
        import ed25519
        signing_key = ed25519.SigningKey(k)
        verify_key = signing_key.get_verifying_key()
        pub = verify_key.to_bytes()
    except Exception:
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed
            from cryptography.hazmat.primitives import serialization
            sk = crypto_ed.Ed25519PrivateKey.from_private_bytes(k)
            pub = sk.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
        except Exception:
            raise RuntimeError("No ed25519 implementation found. Install 'ed25519' or 'cryptography' packages.")
    return base58.b58encode(pub).decode()

# ---------- Balance checkers ----------
def check_btc(addr):
    try:
        r = requests.get(BTC_API + addr, timeout=15)
        if r.status_code == 200:
            sat = int(r.text.strip())
            return sat / 1e8
        else:
            raise ValueError(f"HTTP {r.status_code}")
    except Exception as e:
        if DEBUG: print(f"[Error][BTC] {e}")
        return None
    finally:
        time.sleep(SLEEP_TIME)

def check_eth(addr, max_retries: int = 3):
    """Try up to max_retries times to get a valid balance; returns float balance, 0.0, or None on final error."""
    payload = {"jsonrpc":"2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1}
    backoffs = [0.5, 1.0, 2.0]
    last_exc = None
    for attempt in range(max_retries):
        try:
            r = requests.post(ETH_RPC, json=payload, timeout=15)
            r.raise_for_status()
            resp = r.json()
            # Some RPCs return an 'error' dict; treat it as failure and retry
            if "result" not in resp:
                last_exc = ValueError(f"No result: {resp}")
                if DEBUG:
                    print(f"[Debug][ETH] attempt {attempt+1}/{max_retries} response missing result: {resp}")
                raise last_exc
            # parse and return
            val = int(resp["result"], 16) / 1e18
            return val
        except Exception as e:
            last_exc = e
            if attempt < max_retries - 1:
                # short backoff before next attempt
                if DEBUG:
                    print(f"[Debug][ETH] attempt {attempt+1} failed: {e}; backing off {backoffs[min(attempt, len(backoffs)-1)]}s")
                time.sleep(backoffs[min(attempt, len(backoffs)-1)])
                continue
            else:
                # final attempt failed
                if DEBUG:
                    print(f"[Error][ETH] final attempt failed: {e}")
                return None
        finally:
            # enforce base per-address throttle once per call (only on final attempt we want the sleep to happen once)
            # but to keep behavior consistent we sleep only after finishing retry loop (handled by outer finally below)
            pass
    # fallback
    if DEBUG and last_exc:
        print(f"[Error][ETH] giving up after {max_retries} attempts: {last_exc}")
    # final throttle
    time.sleep(SLEEP_TIME)
    return None

def check_sol(addr):
    try:
        payload = {"jsonrpc":"2.0","id":1,"method":"getBalance","params":[addr]}
        r = requests.post(SOL_RPC, json=payload, timeout=15)
        r.raise_for_status()
        resp = r.json()
        if "result" not in resp or "value" not in resp["result"]:
            raise ValueError(f"Unexpected response: {resp}")
        return int(resp["result"]["value"]) / 1e9
    except Exception as e:
        if DEBUG: print(f"[Error][SOL] {e}")
        return None
    finally:
        time.sleep(SLEEP_TIME)

def check_bnb(addr):
    try:
        payload = {"jsonrpc":"2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1}
        r = requests.post(BNB_RPC, json=payload, timeout=15)
        r.raise_for_status()
        resp = r.json()
        if "result" not in resp:
            raise ValueError(f"No result: {resp}")
        val = int(resp["result"], 16) / 1e18
        return val
    except Exception as e:
        if DEBUG: print(f"[Error][BNB] {e}")
        return None
    finally:
        time.sleep(SLEEP_TIME)

# ---------- Orchestration ----------
def check_all_balances(mnemonic, addrs):
    results = {"BTC": None, "ETH": None, "SOL": None, "BNB": None}
    checks = [
        ("BTC", check_btc, addrs["BTC"][0]),
        ("ETH", check_eth, addrs["ETH"]),
        ("SOL", check_sol, addrs["SOL"]),
        ("BNB", check_bnb, addrs["BNB"]),
    ]
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        fut_map = {ex.submit(fn, a): coin for (coin, fn, a) in checks}
        for fut in as_completed(fut_map):
            coin = fut_map[fut]
            try:
                val = fut.result()
                results[coin] = (float(val) if (val is not None and val > 0) else (0.0 if val == 0 else None))
            except Exception as e:
                results[coin] = None
                if DEBUG: print(f"[Error][{coin}] {e}")
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

# ---------- Main loop ----------
def main():
    tried = 0
    try:
        while True:
            mnemonic = mnemo.generate(strength=128)
            seed = mnemo.to_seed(mnemonic)
            try:
                btc_addrs = derive_btc_addresses_from_seed(seed)
                eth_addr = derive_eth_address_from_seed(seed)
                sol_addr = derive_sol_pubkey_from_mnemonic(mnemonic)
                bnb_addr = derive_eth_address_from_seed(seed)
            except Exception as e:
                if DEBUG: print(f"[DEBUG][DerivationError] {e}")
                tried += 1
                print(f"Tried {tried}")
                continue

            addrs = {"BTC": btc_addrs, "ETH": eth_addr, "SOL": sol_addr, "BNB": bnb_addr}
            if DEBUG:
                print(json.dumps({"mnemonic": mnemonic, "addresses": addrs}, indent=2))

            balances = check_all_balances(mnemonic, addrs)
            tried += 1
            print(f"Tried {tried}")

            hit = any(isinstance(v, (int, float)) and v > 0 for v in balances.values())
            if hit:
                print(mnemonic)
                for c in ("BTC","ETH","SOL","BNB"):
                    val = balances.get(c)
                    if val is None:
                        print(f"{c} BALANCE:")
                    elif val > 0:
                        print(f"{c} BALANCE: {val}")
                    else:
                        print(f"{c} BALANCE:")
                append_found(mnemonic, balances)

    except KeyboardInterrupt:
        print("\nCancelled by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()