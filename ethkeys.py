#!/usr/bin/env python3
"""
Ethereum sequential key scanner
- 5 threads (ThreadPoolExecutor)
- Retries with backoff: 1s, 2s, 3s
- Resumable (resume.txt)
- Normal mode: only found (>0) + errors
- Debug mode (-d): prints all + stats
"""

import requests
import time
import threading
import signal
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal, getcontext
from colorama import init as colorama_init, Fore, Style
from eth_utils import keccak, to_checksum_address
from coincurve import PrivateKey
from datetime import datetime
import argparse

# precision for Decimal
getcontext().prec = 40

BASE_HEX = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
RPC_URL = "https://ethereum.publicnode.com"
THREADS = 5
RETRY_SLEEP = [1, 2, 3]  # seconds between retries

colorama_init(autoreset=True)

# globals
running = True
counter_lock = threading.Lock()
print_lock = threading.Lock()
file_lock = threading.Lock()
total_tried = 0


def signal_handler(sig, frame):
    """
    On signal, set running=False so main loop can exit cleanly.
    Do NOT call sys.exit here; allow graceful shutdown.
    """
    global running
    running = False
    with print_lock:
        print("\nSignal received — stopping scanner... (waiting for threads to finish)")


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


def wei_hex_to_eth(wei_hex):
    return Decimal(int(wei_hex, 16)) / Decimal(10**18)


def derive_address(priv_int):
    priv_bytes = priv_int.to_bytes(32, "big")
    pubkey = PrivateKey(priv_bytes).public_key.format(compressed=False)[1:]
    addr = to_checksum_address(keccak(pubkey)[-20:])
    return f"0x{priv_int:064x}", addr


def rpc_get_balance_with_retries(session, address, debug=False):
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getBalance",
        "params": [address, "latest"],
        "id": 1,
    }
    last_exc = None
    # attempts: initial (delay 0) + retries with delays in RETRY_SLEEP
    for attempt, delay in enumerate([0] + RETRY_SLEEP, start=1):
        try:
            resp = session.post(RPC_URL, json=payload, timeout=10)
            resp.raise_for_status()
            j = resp.json()
            if "result" not in j:
                raise RuntimeError(f"Invalid RPC response: {j}")
            return wei_hex_to_eth(j["result"])
        except Exception as e:
            last_exc = e
            if debug:
                with print_lock:
                    print(f"[DEBUG] RPC attempt {attempt} for {address} failed: {e}")
            # only sleep if we will retry
            if attempt < len(RETRY_SLEEP) + 1:
                time.sleep(delay)
    raise last_exc


def format_found(idx, priv_hex, address, bal):
    bal_str = f"{bal:.18f}"
    color = Fore.GREEN
    border = "+" + "-" * 70 + "+"
    lines = [
        f"| Index  : {idx}",
        f"| Priv   : {priv_hex}",
        f"| Address: {address}",
        f"| Balance: {color}{bal_str} ETH{Style.RESET_ALL}",
    ]
    block = "\n".join([border] + lines + [border])
    return block


def append_found(block):
    with file_lock:
        with open("found.txt", "a") as f:
            f.write(block + "\n")


def save_resume(offset):
    with file_lock:
        with open("resume.txt", "w") as f:
            f.write(str(offset))


def load_resume():
    try:
        with open("resume.txt") as f:
            return int(f.read().strip())
    except Exception:
        return 1


def worker(priv_int, idx, debug=False):
    """
    Worker runs in a thread: derive address, query balance with retries,
    print according to mode, and persist found blocks.
    """
    global total_tried
    priv_hex, addr = derive_address(priv_int)
    try:
        with requests.Session() as s:
            bal = rpc_get_balance_with_retries(s, addr, debug)
    except Exception as e:
        with print_lock:
            print(f"[ERROR] idx={idx} addr={addr} {e}")
        return None

    with counter_lock:
        total_tried += 1

    if debug:
        with print_lock:
            print(f"[DEBUG] idx={idx} addr={addr} balance={bal}")

    if bal > 0:
        block = format_found(idx, priv_hex, addr, bal)
        with print_lock:
            print(block)
        append_found(block)
    return None


def stats_monitor(start_time, debug_flag, stop_event):
    last_count = 0
    last_time = start_time
    while not stop_event.is_set():
        time.sleep(10)
        if not debug_flag:
            continue
        now = time.time()
        with counter_lock:
            curr = total_tried
        delta = curr - last_count
        dt = now - last_time
        kps = delta / dt if dt > 0 else 0
        with print_lock:
            print(Fore.GREEN + f"[STATS] {kps:.2f} keys/s (total: {curr})" + Style.RESET_ALL)
        last_count = curr
        last_time = now


def main(base_hex, debug=False):
    global running  # IMPORTANT: assign to the module-level flag
    base_int = int(base_hex, 16)
    offset = load_resume()
    stop_event = threading.Event()

    monitor_thread = threading.Thread(
        target=stats_monitor, args=(time.time(), debug, stop_event), daemon=True
    )
    monitor_thread.start()

    with print_lock:
        print(f"Starting scanner with {THREADS} threads. Debug={debug}")
        print("Press Ctrl+C to stop.\n")

    try:
        with ThreadPoolExecutor(max_workers=THREADS) as exe:
            while running:
                futures = []
                # feed exactly THREADS tasks so the pool stays busy
                for _ in range(THREADS):
                    priv_int = base_int - offset
                    if priv_int <= 0:
                        with print_lock:
                            print("Reached end of key range.")
                        running = False
                        break
                    futures.append(exe.submit(worker, priv_int, offset, debug))
                    offset += 1

                # wait for this set to finish (keeps steady number of concurrent tasks)
                for _ in as_completed(futures):
                    # we don't need results, worker printed/persisted as needed
                    pass

                # persist progress frequently
                save_resume(offset)
                # tiny sleep so signal handler can run promptly
                time.sleep(0.05)
    finally:
        stop_event.set()
        monitor_thread.join(timeout=1)
        save_resume(offset)
        with print_lock:
            print("Scanner stopped.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ethereum key scanner (5-thread continuous)")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug mode")
    args = parser.parse_args()
    try:
        main(BASE_HEX, debug=args.debug)
    except KeyboardInterrupt:
        # signal handler should handle graceful stop; catch double Ctrl+C here
        print("\nInterrupted by user, exiting.")
