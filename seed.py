import os, sys, time, json, math
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

BTC_API = "https://blockchain.info/q/addressbalance/"
ETH_RPC = "https://cloudflare-eth.com"
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
    """
    Derive BIP44 (legacy 1...), BIP49 (3...), BIP84 (bc1q...) first address
    using bip32utils for BIP32 child derivation and constructing scripts manually.
    """
    # bip32utils expects entropy-like seed for fromEntropy; use HMAC-SHA512 seed as entropy input
    # But bip32utils.BIP32Key.fromEntropy expects raw entropy (not BIP39 seed). However many examples
    # pass Mnemonic.to_seed(mnemonic) directly to BIP32Key.fromEntropy(). Works in practice for many libs.
    root = BIP32Key.fromEntropy(seed_bytes)

    # Derive m/44'/0'/0'/0/0 (legacy P2PKH)
    k = root.ChildKey(44 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    legacy = k.Address()

    # For nested segwit (P2SH-P2WPKH): m/49'/0'/0'/0/0 -> get compressed pubkey then build redeemscript
    k49 = root.ChildKey(49 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    pubkey49 = k49.PublicKey()  # compressed pubkey bytes
    # Build witness program: OP_0 <20-byte HASH160(pubkey)>
    h160 = hashlib.new("ripemd160", hashlib.sha256(pubkey49).digest()).digest()
    redeem_script = b'\x00\x14' + h160  # 0x0014{20}
    # P2SH address is base58check(0x05 + HASH160(redeem_script))
    redeem_hash = hashlib.new("ripemd160", hashlib.sha256(redeem_script).digest()).digest()
    p2sh = base58.b58encode_check(b'\x05' + redeem_hash).decode()

    # For bech32 native segwit (BIP84) m/84'/0'/0'/0/0 -> witness v0 program is HASH160(pubkey)
    k84 = root.ChildKey(84 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    pubkey84 = k84.PublicKey()
    h160_84 = hashlib.new("ripemd160", hashlib.sha256(pubkey84).digest()).digest()
    # Convert to 5-bit words and bech32 encode (witness version 0)
    witver = 0
    conv = bech32.convertbits(h160_84, 8, 5)
    bech32_addr = bech32.bech32_encode("bc", [witver] + conv)
    return legacy, p2sh, bech32_addr

# ---------- ETH / BNB derivation ----------
def derive_eth_address_from_seed(seed_bytes: bytes) -> str:
    """
    ETH: m/44'/60'/0'/0/0 -> take private key, compute address keccak(pubkey)[-20:], checksumed.
    """
    root = BIP32Key.fromEntropy(seed_bytes)
    k = root.ChildKey(44 + HARDEN).ChildKey(60 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(0)
    priv = k.PrivateKey()  # bytes
    sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    uncompressed = b'\x04' + vk.to_string()
    keccak = sha3.keccak_256()
    keccak.update(uncompressed[1:])  # drop 0x04 prefix
    addr = keccak.hexdigest()[-40:]
    addr = "0x" + addr
    # EIP-55 checksum
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
# We'll implement SLIP-0010 / ed25519-BIP32 style derivation for Solana:
def slip10_ed25519_master_key(seed: bytes):
    I = hmac.new(b"ed25519 seed", seed, hashlib.sha512).digest()
    return I[:32], I[32:]  # (k, c)

def ed25519_ckd_priv(k_par: bytes, c_par: bytes, index: int):
    # Only support hardened child derivation as per ed25519/BIP32-Ed25519
    data = b'\x00' + k_par + struct.pack(">L", index)
    I = hmac.new(c_par, data, hashlib.sha512).digest()
    return I[:32], I[32:]

def derive_sol_pubkey_from_mnemonic(mnemonic: str) -> str:
    # Seed per BIP39
    seed = mnemo.to_seed(mnemonic, passphrase="")  # bytes
    k, c = slip10_ed25519_master_key(seed)
    # Derivation path: m/44'/501'/0'/0' -> indexes hardened
    for idx in (44 + HARDEN, 501 + HARDEN, 0 + HARDEN, 0 + HARDEN):
        k, c = ed25519_ckd_priv(k, c, idx)
    # k is private key (32 bytes) -> ed25519 public key = point(k)
    # Use pure-python ed25519 to compute public key (no PyNaCl)
    # We'll use ecdsa library doesn't support ed25519; instead use 'ed25519' pure python if available
    try:
        import ed25519  # often pure python implementation
        priv = k
        signing_key = ed25519.SigningKey(priv)
        verify_key = signing_key.get_verifying_key()
        pub = verify_key.to_bytes()
    except Exception:
        # fallback to pure python implementation using pynacl-like operations is complex.
        # Try using cryptography's ed25519 if available
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519 as crypto_ed
            sk = crypto_ed.Ed25519PrivateKey.from_private_bytes(k)
            pub = sk.public_key().public_bytes()
        except Exception:
            # Last resort: raise helpful error
            raise RuntimeError("No ed25519 implementation found. Install 'ed25519' or 'cryptography' packages.")
    # Solana address = base58(pubkey)
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

def check_eth(addr):
    try:
        payload = {"jsonrpc":"2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1}
        r = requests.post(ETH_RPC, json=payload, timeout=15)
        r.raise_for_status()
        resp = r.json()
        if "result" not in resp: raise ValueError(f"No result: {resp}")
        return int(resp["result"], 16) / 1e18
    except Exception as e:
        if DEBUG: print(f"[Error][ETH] {e}")
        return None
    finally:
        time.sleep(SLEEP_TIME)

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
        if "result" not in resp: raise ValueError(f"No result: {resp}")
        return int(resp["result"], 16) / 1e18
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
            # seed bytes (BIP39)
            seed = mnemo.to_seed(mnemonic)
            # derive addresses
            try:
                btc_addrs = derive_btc_addresses_from_seed(seed)
                eth_addr = derive_eth_address_from_seed(seed)
                sol_addr = derive_sol_pubkey_from_mnemonic(mnemonic)
                bnb_addr = derive_eth_address_from_seed(seed)  # same as ETH
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