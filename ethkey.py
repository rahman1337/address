#!/usr/bin/env python3
"""
ethereum_quick_probe_secp256k1.py

Generates random valid Ethereum private keys (secp256k1),
derives the addresses, and checks via a free public RPC
(https://ethereum.publicnode.com) if the address holds a nonzero ETH balance.

Install:
  pip install requests eth_keys eth_utils
"""

import os
import sys
import time
import threading
import queue
import argparse
import signal
from concurrent.futures import ThreadPoolExecutor
import requests
import secrets
from eth_keys import keys
from eth_utils import keccak

ETH_FILE = "eth.txt"
DEFAULT_RPC = "https://ethereum.publicnode.com"

RPC_TIMEOUT = 10.0
SLEEP_BETWEEN = 0.5
MAX_QUEUE_SIZE = 1000


def load_tried(eth_file):
    s = set()
    if os.path.exists(eth_file):
        try:
            with open(eth_file, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if ln:
                        s.add(ln)
        except Exception:
            pass
    return s


def append_tried(eth_file, priv_hex, file_lock):
    with file_lock:
        with open(eth_file, "a", encoding="utf-8") as f:
            f.write(priv_hex + "\n")
            f.flush()
            os.fsync(f.fileno())


def derive_eth_address_from_privkey(priv_bytes):
    if len(priv_bytes) != 32:
        raise ValueError("private key must be 32 bytes")
    pk = keys.PrivateKey(priv_bytes)
    pubkey_bytes = pk.public_key.to_bytes()
    addr = keccak(pubkey_bytes[1:])[-20:]
    return "0x" + addr.hex()


def rpc_post(url, payload, timeout=RPC_TIMEOUT):
    headers = {"Content-Type": "application/json"}
    r = requests.post(url, json=payload, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.json()


def worker(q, rpc_url, stop_event, tried_set, tried_lock, file_lock, debug):
    while not stop_event.is_set():
        try:
            priv_hex = q.get(timeout=0.2)
        except queue.Empty:
            continue
        if stop_event.is_set():
            break
        try:
            priv_bytes = bytes.fromhex(priv_hex)
            eth_addr = derive_eth_address_from_privkey(priv_bytes)

            bal_payload = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_getBalance",
                "params": [eth_addr, "latest"]
            }
            bal_resp = rpc_post(rpc_url, bal_payload)
            balance_wei = int(bal_resp.get("result", "0x0"), 16)
            balance_eth = balance_wei / 1e18

            if debug:
                print(f"{eth_addr}  {balance_eth:.18f} ETH")

            if balance_wei > 0:
                print("FOUND")
                print(priv_hex)
                print(eth_addr)
                print(f"Balance: {balance_eth:.18f} ETH")
                print("")
                sys.stdout.flush()

        except Exception as e:
            if debug:
                sys.stderr.write(f"Error {priv_hex[:16]}... {repr(e)}\n")
            else:
                sys.stderr.write(f"Error {priv_hex[:16]}... {repr(e)}\n")
            sys.stderr.flush()
        finally:
            q.task_done()
            for _ in range(int(SLEEP_BETWEEN * 10)):
                if stop_event.is_set():
                    break
                time.sleep(0.05)


def generate_and_enqueue(q, tried_set, tried_lock, file_lock, stop_event, debug):
    while not stop_event.is_set():
        priv_bytes = secrets.token_bytes(32)
        priv_hex = priv_bytes.hex()

        with tried_lock:
            if priv_hex in tried_set:
                continue
            tried_set.add(priv_hex)

        append_tried(ETH_FILE, priv_hex, file_lock)

        if debug:
            print(f"Enqueued {priv_hex[:16]}...")

        while not stop_event.is_set():
            try:
                q.put(priv_hex, timeout=0.2)
                break
            except queue.Full:
                continue


def main(rpc_url, debug):
    q = queue.Queue(maxsize=MAX_QUEUE_SIZE)
    stop_event = threading.Event()
    tried_lock = threading.Lock()
    file_lock = threading.Lock()

    def handle_sigint(sig, frame):
        print("Ctrl+C detected, stopping.")
        stop_event.set()

    signal.signal(signal.SIGINT, handle_sigint)

    tried_set = load_tried(ETH_FILE)
    if not os.path.exists(ETH_FILE):
        open(ETH_FILE, "a").close()

    gen_thread = threading.Thread(
        target=generate_and_enqueue,
        args=(q, tried_set, tried_lock, file_lock, stop_event, debug),
        daemon=True
    )
    gen_thread.start()

    with ThreadPoolExecutor(max_workers=3) as ex:
        for _ in range(3):
            ex.submit(worker, q, rpc_url, stop_event, tried_set, tried_lock, file_lock, debug)

        try:
            while not stop_event.is_set():
                time.sleep(0.1)
        finally:
            stop_event.set()
            while not q.empty():
                try:
                    q.get_nowait()
                    q.task_done()
                except queue.Empty:
                    break
            sys.stderr.write("Stopped.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Generate valid Ethereum private keys and check via ethereum.publicnode.com if the address has a nonzero balance."
    )
    parser.add_argument("--rpc", type=str, default=DEFAULT_RPC, help="Ethereum RPC URL (default: ethereum.publicnode.com)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode to print all progress.")
    args = parser.parse_args()

    try:
        main(args.rpc, args.debug)
    except Exception as e:
        sys.stderr.write("Fatal error: " + repr(e) + "\n")
        sys.exit(1)
