#!/usr/bin/env python3
"""
solana_quick_probe_ed25519.py

Same behavior as before but uses the `ed25519` package (pure Python) to generate
valid Ed25519 seeds and derive the Solana address (base58 of the 32-byte pubkey).

Install:
  pip install ed25519 base58 requests
"""

import os
import sys
import time
import threading
import queue
import argparse
from concurrent.futures import ThreadPoolExecutor
import requests
import secrets
import ed25519
import base58

SOL_FILE = "sol.txt"
DEFAULT_RPC = "https://api.mainnet-beta.solana.com"
RPC_TIMEOUT = 10.0
SLEEP_BETWEEN = 0.6   # seconds per thread between checks
MAX_QUEUE_SIZE = 1000

def load_tried(sol_file):
    s = set()
    if os.path.exists(sol_file):
        try:
            with open(sol_file, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if ln:
                        s.add(ln)
        except Exception:
            pass
    return s

def append_tried(sol_file, seed_hex, file_lock):
    file_lock.acquire()
    try:
        with open(sol_file, "a", encoding="utf-8") as f:
            f.write(seed_hex + "\n")
            f.flush()
            os.fsync(f.fileno())
    finally:
        file_lock.release()

def derive_pubkey_from_seed(seed_bytes):
    # seed_bytes must be 32 bytes
    if len(seed_bytes) != 32:
        raise ValueError("seed must be 32 bytes")
    # Create signing key from seed, then get verifying key (public key)
    sk = ed25519.SigningKey(seed_bytes)
    vk = sk.get_verifying_key()
    pub_bytes = vk.to_bytes()
    return base58.b58encode(pub_bytes).decode()

def rpc_post(url, payload, timeout=RPC_TIMEOUT):
    headers = {"Content-Type": "application/json"}
    r = requests.post(url, json=payload, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()

def worker(q, rpc_url, stop_event, tried_set, tried_lock, file_lock):
    while not stop_event.is_set():
        try:
            seed_hex = q.get(timeout=0.5)
        except queue.Empty:
            return
        try:
            # Convert seed hex to bytes and derive pubkey
            seed_bytes = bytes.fromhex(seed_hex)
            pubkey = derive_pubkey_from_seed(seed_bytes)

            # Query getSignaturesForAddress with limit=1 (fast "ever received?" check)
            payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getSignaturesForAddress",
                "params": [pubkey, {"limit": 1}]
            }
            resp = rpc_post(rpc_url, payload)
            results = resp.get("result") or []

            if len(results) > 0:
                # FOUND -> print only privkey and address, and a blank line
                print(seed_hex)
                print(pubkey)
                print("")   # blank line for visual separation
                sys.stdout.flush()
        except KeyboardInterrupt:
            stop_event.set()
            return
        except Exception as e:
            # Keep stdout clean for FOUND items; print errors to stderr
            sys.stderr.write(f"ERROR for seed {seed_hex[:16]}...: {repr(e)}\n")
            sys.stderr.flush()
        finally:
            q.task_done()
            # respect per-thread rate limit, stop early if asked
            for _ in range(int(SLEEP_BETWEEN * 10)):
                if stop_event.is_set():
                    break
                time.sleep(0.1)

def generate_and_enqueue(q, tried_set, tried_lock, file_lock, stop_event):
    """
    Continuously generate valid 32-byte Ed25519 seeds (via secrets.token_bytes)
    and enqueue their hex representation if not already tried.
    """
    while not stop_event.is_set():
        # Generate a secure random 32-byte seed
        seed_bytes = secrets.token_bytes(32)
        seed_hex = seed_bytes.hex()

        # Avoid duplicates across runs by checking tried_set
        with tried_lock:
            if seed_hex in tried_set:
                continue
            tried_set.add(seed_hex)

        # persist immediately
        append_tried(SOL_FILE, seed_hex, file_lock)

        # enqueue (block if queue is large)
        while not stop_event.is_set():
            try:
                q.put(seed_hex, timeout=0.5)
                break
            except queue.Full:
                continue

def main(rpc_url):
    q = queue.Queue(maxsize=MAX_QUEUE_SIZE)
    stop_event = threading.Event()
    tried_lock = threading.Lock()
    file_lock = threading.Lock()

    # load already-tried seeds to avoid repeats
    tried_set = load_tried(SOL_FILE)

    # ensure sol.txt exists
    if not os.path.exists(SOL_FILE):
        open(SOL_FILE, "a").close()

    # start generator thread
    gen_thread = threading.Thread(target=generate_and_enqueue, args=(q, tried_set, tried_lock, file_lock, stop_event), daemon=True)
    gen_thread.start()

    # start pool of 3 workers
    with ThreadPoolExecutor(max_workers=3) as ex:
        futures = []
        for _ in range(3):
            futures.append(ex.submit(worker, q, rpc_url, stop_event, tried_set, tried_lock, file_lock))
        try:
            # run until generator stops or user interrupts
            while True:
                time.sleep(0.2)
        except KeyboardInterrupt:
            stop_event.set()
            sys.stderr.write("Interrupted by user. Stopping immediately...\n")
        finally:
            # wait for queue to be processed by workers (they will return if stop_event set)
            q.join()
            stop_event.set()
            time.sleep(0.05)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate valid Solana seeds with ed25519 and check if addresses ever received txs. Prints FOUND seed+address (one per line) and a blank line.")
    parser.add_argument("--rpc", type=str, default=DEFAULT_RPC, help="Solana RPC URL (default public mainnet endpoint)")
    args = parser.parse_args()

    try:
        main(args.rpc)
    except Exception as e:
        sys.stderr.write("Fatal error: " + repr(e) + "\n")
        sys.exit(1)
