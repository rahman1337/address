#!/usr/bin/env python3
"""
vanity_loop_threads_balance.py

Threaded vanity generator (1... and 3... only). On hit: query balance and print PRIV, WIF, ADDR, BALANCE.

Requirements:
    pip install coincurve base58 requests
"""

import os
import sys
import time
import hashlib
import argparse
import base58
import requests
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from coincurve import PrivateKey

# ---------------- config ----------------
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
THREADS = 5
BATCH_SIZE = 100
STATS_INTERVAL = 10.0
DEFAULT_INPUTS = ["btc1.txt", "btc2.txt", "btc3.txt"]

# public node endpoints (try publicnode first, then fall back to blockstream)
PUBLICNODE_BASE = "https://bitcoin.publicnode.com"   # attempt (may require specific endpoint)
BLOCKSTREAM_BASE = "https://blockstream.info/api"    # reliable fallback

# ---------------- helpers ----------------
def ripemd160(x: bytes) -> bytes:
    h = hashlib.new('ripemd160'); h.update(x); return h.digest()

def hash160(x: bytes) -> bytes:
    return ripemd160(hashlib.sha256(x).digest())

def base58check(payload: bytes) -> str:
    return base58.b58encode_check(payload).decode()

def pub_to_p2pkh(pub: bytes) -> str:
    return base58check(b'\x00' + hash160(pub))

def pub_to_p2sh_p2wpkh(pub: bytes) -> str:
    h = hash160(pub)
    redeem = b'\x00\x14' + h
    redeem_hash = ripemd160(hashlib.sha256(redeem).digest())
    return base58check(b'\x05' + redeem_hash)

def priv_to_wif(priv_bytes: bytes) -> str:
    return base58check(b'\x80' + priv_bytes + b'\x01')

def generate_priv_batch(batch_size: int):
    out = []
    while len(out) < batch_size:
        need = batch_size - len(out)
        chunk = os.urandom(32 * need * 2)
        for i in range(0, len(chunk), 32):
            priv = chunk[i:i+32]
            v = int.from_bytes(priv, 'big')
            if 1 <= v < SECP256K1_N:
                out.append(priv)
                if len(out) >= batch_size:
                    break
    return out

def print_found(priv_hex, wif, addr, target, balance_btc):
    line = "=" * 72
    print(line)
    print(f"FOUND MATCH for prefix: {target}")
    print(line)
    print("PRIV :", priv_hex)
    print("WIF  :", wif)
    print("ADDR :", addr)
    print(f"BAL  : {balance_btc:.8f} BTC")
    print(line, "\n")

# ---------------- balance checking ----------------
def _try_publicnode_balance(address: str, timeout=6.0):
    """
    Attempt a best-effort fetch from PublicNode.
    PublicNode exposes many services; they may not have a simple REST address endpoint.
    We try some reasonable HTTP paths (best-effort). If none respond, raise Exception.
    """
    # Candidate endpoints to try on publicnode (best-effort guesses)
    candidates = [
        f"{PUBLICNODE_BASE}/api/address/{address}",
        f"{PUBLICNODE_BASE}/address/{address}",
        f"{PUBLICNODE_BASE}/v1/address/{address}",
        f"{PUBLICNODE_BASE}/v1/addresses/{address}/balance",
        f"{PUBLICNODE_BASE}/address/{address}/balance",
    ]
    headers = {"User-Agent": "vanity-checker/1.0"}
    for url in candidates:
        try:
            r = requests.get(url, headers=headers, timeout=timeout)
        except Exception:
            continue
        if r.status_code != 200:
            continue
        try:
            j = r.json()
        except Exception:
            # if plain text or unknown format, skip
            continue
        # Try common shapes: { "balance": ..., "balance_satoshi": ... } or blockbook-style
        if isinstance(j, dict):
            # blockbook-like keys
            if 'balance' in j:
                # could be in satoshis or BTC — try to infer
                bal = j['balance']
                # heuristics: if > 1e6 assume satoshis
                try:
                    balf = float(bal)
                except Exception:
                    continue
                if balf > 1e6:
                    return balf / 1e8
                else:
                    # if small, assume already BTC
                    return balf
            # Blockbook style: { "balance": "123", "totalReceived": "..." }
            if 'chain_stats' in j and isinstance(j['chain_stats'], dict):
                cs = j['chain_stats']
                funded = cs.get('funded_txo_sum', 0)
                spent  = cs.get('spent_txo_sum', 0)
                try:
                    bal_sat = int(funded) - int(spent)
                    return bal_sat / 1e8
                except Exception:
                    continue
        # else unknown shape, continue to next candidate
    raise RuntimeError("PublicNode endpoint not available / no usable response")

def _blockstream_balance(address: str, timeout=6.0):
    """
    Use Blockstream's public Esplora API as fallback.
    GET /api/address/{address} -> JSON with chain_stats.
    compute balance = funded_txo_sum - spent_txo_sum (satoshis)
    Docs: Blockstream Explorer API (esplora). 
    """
    url = f"{BLOCKSTREAM_BASE}/address/{address}"
    headers = {"User-Agent": "vanity-checker/1.0"}
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    j = r.json()
    cs = j.get('chain_stats', {})
    funded = cs.get('funded_txo_sum', 0)
    spent  = cs.get('spent_txo_sum', 0)
    bal_sat = int(funded) - int(spent)
    return bal_sat / 1e8  # BTC

def check_balance(address: str):
    """
    Try PublicNode first, then Blockstream. Return float BTC (0.0 on no funds).
    Errors are handled and returned as None.
    """
    # only check mainnet base58 addresses (1... and 3...)
    try:
        # try publicnode best-effort
        try:
            return _try_publicnode_balance(address)
        except Exception:
            # fallback
            return _blockstream_balance(address)
    except Exception as e:
        # If everything fails, return None to indicate unknown/unavailable
        return None

# ---------------- worker ----------------
def worker(prefixes_by_first, counters, lock):
    while True:
        privs = generate_priv_batch(BATCH_SIZE)
        for priv in privs:
            pk = PrivateKey(priv)
            pub = pk.public_key.format(compressed=True)
            p2pkh = pub_to_p2pkh(pub)   # 1...
            p2sh  = pub_to_p2sh_p2wpkh(pub)  # 3...
            for addr in (p2pkh, p2sh):
                candidates = prefixes_by_first.get(addr[0], [])
                for t in candidates:
                    if addr.startswith(t):
                        # we have a match — check balance synchronously
                        bal = check_balance(addr)
                        # present balance as BTC (or "unknown")
                        bal_str = f"{bal:.8f}" if isinstance(bal, float) else "unknown"
                        print_found(priv.hex(), priv_to_wif(priv), addr, t, bal if isinstance(bal, float) else 0.0)
                        # if you prefer one-line output:
                        # print(priv.hex(), priv_to_wif(priv), addr, bal_str)
                        with lock:
                            counters['found'] += 1
                with lock:
                    counters['checked'] += 1

# ---------------- main ----------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vanity generator (1... & 3... only). On hit: check balance.")
    parser.add_argument('--prefix-length', type=int, default=6, help='Chars to use as prefix')
    parser.add_argument('-d','--debug', action='store_true', help='Show perf stats every 10s')
    parser.add_argument('inputs', nargs='*', help='Optional input files (default: btc1.txt btc2.txt btc3.txt)')
    args = parser.parse_args()

    prefix_length = max(1, args.prefix_length)
    input_files = args.inputs if args.inputs else DEFAULT_INPUTS

    prefixes_by_first = {}
    total_loaded = 0
    for path in input_files:
        if not os.path.exists(path):
            continue
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                # ignore bech32 lines that start with bc1 (you said it's okay)
                if line.lower().startswith("bc1"):
                    continue
                prefix = line[:prefix_length]
                prefixes_by_first.setdefault(prefix[0], []).append(prefix)
                total_loaded += 1

    if total_loaded == 0:
        print("ERROR: No valid prefixes loaded (only addresses starting with '1' or '3' are used).")
        sys.exit(1)

    print("="*72)
    print("Vanity loop generator (1... & 3... only, threaded), checks balance on hit")
    print(f"Loaded prefixes: {total_loaded} from {len(input_files)} input file(s)")
    print(f"Threads: {THREADS} | Batch size: {BATCH_SIZE}")
    print("="*72)

    counters = {'checked': 0, 'found': 0}
    lock = Lock()

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        for _ in range(THREADS):
            executor.submit(worker, prefixes_by_first, counters, lock)

        start_time = time.time()
        last_checked = 0
        last_time = start_time
        try:
            while True:
                time.sleep(STATS_INTERVAL)
                if args.debug:
                    with lock:
                        checked = counters['checked']
                        found = counters['found']
                    now = time.time()
                    delta = checked - last_checked
                    dt = now - last_time if now > last_time else 1.0
                    kps = delta / dt
                    print("="*72)
                    print(f"DEBUG | elapsed {now - start_time:.1f}s | checked: {checked} | keys/s: {kps:.2f} | found: {found}")
                    print("="*72)
                    last_checked = checked
                    last_time = now
        except KeyboardInterrupt:
            print("\nInterrupted. Stopping...")
            sys.exit(0)
