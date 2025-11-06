#!/usr/bin/env python3
"""
Fast Ethereum key scanner with coincurve + threading + resume.
- 5 threads (ThreadPoolExecutor)
- Saves resume.txt (last index)
- Prints and saves ALL balances (even zero)
- Uses coincurve + keccak for address derivation
- Writes only found.txt (for any checked key)
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from coincurve import PrivateKey
from eth_utils import keccak, to_checksum_address
from decimal import Decimal, getcontext
from colorama import Fore, Style, init as colorama_init
from datetime import datetime
import requests
import threading
import time
import os
import argparse
import signal
import sys

getcontext().prec = 40
colorama_init(autoreset=True)

RPC_URL = "https://ethereum.publicnode.com"
THREADS = 5
BATCH_SIZE = 20
SLEEP_BETWEEN_BATCHES = 0.2
RETRY_SLEEP = [1, 2, 3]
BASE_HEX = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
RESUME_FILE = "resume.txt"
FOUND_FILE = "found.txt"

file_lock = threading.Lock()
counter_lock = threading.Lock()
print_lock = threading.Lock()
running = True
total_tried = 0


def signal_handler(sig, frame):
    global running
    print("\nStopping scanner...")
    running = False
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def wei_hex_to_eth(wei_hex: str) -> Decimal:
    return Decimal(int(wei_hex, 16)) / Decimal(10**18)


def derive_address(priv_int: int):
    priv_bytes = priv_int.to_bytes(32, "big")
    pub = PrivateKey(priv_bytes).public_key.format(compressed=False)[1:]
    address = to_checksum_address("0x" + keccak(pub)[-20:].hex())
    priv_hex = f"0x{priv_int:064x}"
    return priv_hex, address


def eth_get_balance_with_retries(session: requests.Session, address: str, debug=False) -> Decimal:
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1,
    }
    for attempt, sleep_time in enumerate([0] + RETRY_SLEEP):
        try:
            resp = session.post(RPC_URL, json=payload, timeout=10)
            resp.raise_for_status()
            j = resp.json()
            if "result" not in j:
                raise ValueError(f"Bad RPC response: {j}")
            return wei_hex_to_eth(j["result"])
        except Exception as e:
            if debug:
                print(f"[DEBUG] RPC retry {attempt+1} for {address}: {e}")
            time.sleep(sleep_time)
    raise Exception("RPC failed after retries")


def format_block(idx: int, priv_hex: str, address: str, balance: Decimal):
    bal_str = f"{balance:.18f}"  # full precision, no threshold
    border = "+" + "-" * 60 + "+"
    block = (
        f"{border}\n"
        f"| Index  : {idx}\n"
        f"| Priv   : {priv_hex}\n"
        f"| Address: {address}\n"
        f"| Balance: {bal_str} ETH\n"
        f"{border}\n"
    )
    return block


def save_resume(idx: int):
    with open(RESUME_FILE, "w") as f:
        f.write(str(idx))


def load_resume() -> int:
    if os.path.exists(RESUME_FILE):
        try:
            with open(RESUME_FILE) as f:
                return int(f.read().strip())
        except ValueError:
            return 1
    return 1


def append_found_block(block: str):
    with file_lock:
        with open(FOUND_FILE, "a") as f:
            f.write(block)


def worker_task(priv_int: int, idx: int, debug: bool):
    global total_tried
    try:
        priv_hex, address = derive_address(priv_int)
        with requests.Session() as session:
            balance = eth_get_balance_with_retries(session, address, debug)
        block = format_block(idx, priv_hex, address, balance)
        with print_lock:
            print(block, end="")
        append_found_block(block)
    except Exception as e:
        if debug:
            with print_lock:
                print(f"[DEBUG] idx={idx} error: {e}")
    with counter_lock:
        total_tried += 1


def stats_monitor(debug: bool, stop_event: threading.Event):
    last = 0
    last_time = time.time()
    while not stop_event.is_set():
        time.sleep(10)
        if not debug:
            continue
        now = time.time()
        with counter_lock:
            curr = total_tried
        rate = (curr - last) / (now - last_time)
        print(Fore.GREEN + f"[STATS] {rate:.2f} keys/s (total {curr})" + Style.RESET_ALL)
        last, last_time = curr, now


def main_loop(base_hex: str, start_offset: int, batch_size: int, debug: bool):
    base_int = int(base_hex, 16)
    offset = start_offset
    stop_event = threading.Event()
    threading.Thread(target=stats_monitor, args=(debug, stop_event), daemon=True).start()

    print(f"Starting scanner from offset {offset}, threads={THREADS}, batch={batch_size}")
    while running:
        items = []
        for i in range(batch_size):
            priv_int = base_int - (offset + i)
            if priv_int <= 0:
                print("Reached end of range.")
                stop_event.set()
                return
            items.append((priv_int, offset + i))

        with ThreadPoolExecutor(max_workers=THREADS) as exe:
            futures = [exe.submit(worker_task, priv, idx, debug) for priv, idx in items]
            for _ in as_completed(futures):
                pass

        offset += batch_size
        save_resume(offset)
        time.sleep(SLEEP_BETWEEN_BATCHES)

    stop_event.set()
    print("Scanner stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fast Ethereum key scanner")
    parser.add_argument("-d", "--debug", action="store_true", help="enable debug mode")
    parser.add_argument("--batch", type=int, default=BATCH_SIZE, help="batch size per cycle")
    args = parser.parse_args()

    start_offset = load_resume()
    try:
        main_loop(BASE_HEX, start_offset, args.batch, debug=args.debug)
    except KeyboardInterrupt:
        print("\nStopped by user.")
