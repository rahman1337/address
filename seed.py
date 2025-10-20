#!/usr/bin/env python3
import os
import sys
import time
import hashlib
import requests
import argparse
from threading import Thread
from mnemonic import Mnemonic
import bip32utils
import base58
import bech32

# ---------- Defaults (can be overridden via CLI) ----------
WORDLIST_FILE = "seed.txt"    # 2048-word BIP39 list (one per line)
THREAD_COUNT = 3
DEFAULT_INDICES_PER_MNEMONIC = 25   # recommended default (changeable)
SLEEP_BETWEEN_CHECKS = 0.5    # seconds (between each address check)
RECEIVED_API = "https://blockchain.info/q/receivedbyaddress/"
BALANCE_API  = "https://blockchain.info/q/addressbalance/"
HARDEN = 0x80000000
FOUND_FILE = "found.txt"
# ---------------------------------------------------------

def parse_args():
    ap = argparse.ArgumentParser(description="Scan 3 address types for N indices per generated mnemonic (received-first).")
    ap.add_argument("-d", "--debug", action="store_true", help="debug mode: print each address and HTTP responses")
    ap.add_argument("--indices", type=int, default=DEFAULT_INDICES_PER_MNEMONIC,
                    help=f"how many indices to scan per mnemonic (default {DEFAULT_INDICES_PER_MNEMONIC})")
    ap.add_argument("--wordlist", type=str, default=WORDLIST_FILE, help="path to 2048-word BIP39 wordlist (default seed.txt)")
    return ap.parse_args()

args = parse_args()
DEBUG = args.debug
INDICES_PER_MNEMONIC = args.indices
WORDLIST_FILE = args.wordlist

# Load and validate wordlist
if not os.path.exists(WORDLIST_FILE):
    sys.exit(f"Missing {WORDLIST_FILE} (should contain 2048 BIP39 words, one per line)")

with open(WORDLIST_FILE, "r", encoding="utf-8") as f:
    wl = [w.strip() for w in f.readlines() if w.strip()]

if len(wl) != 2048:
    print(f"[Warning] {WORDLIST_FILE} contains {len(wl)} words (expected 2048). Proceeding anyway.", flush=True)

mnemo = Mnemonic("english")
mnemo.wordlist = wl

session = requests.Session()
session.headers.update({"User-Agent": "btc-scan-per-mnemonic/1.0"})

# Helpers
def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()

def derive_btc_addresses_from_seed(seed_bytes, index):
    """
    Returns (p2pkh, p2sh_p2wpkh, bech32) for the given index using strict BIP paths.
    """
    root = bip32utils.BIP32Key.fromEntropy(seed_bytes)

    # BIP44: m/44'/0'/0'/0/index -> P2PKH
    k44 = root.ChildKey(44 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(index)
    addr_p2pkh = k44.Address()

    # BIP49: m/49'/0'/0'/0/index -> P2SH-P2WPKH
    k49 = root.ChildKey(49 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(index)
    pub49 = k49.PublicKey()
    keyhash49 = hash160(pub49)
    redeem_script = b'\x00\x14' + keyhash49
    redeem_hash = hashlib.new("ripemd160", hashlib.sha256(redeem_script).digest()).digest()
    addr_p2sh = base58.b58encode_check(b'\x05' + redeem_hash).decode()

    # BIP84: m/84'/0'/0'/0/index -> bech32 p2wpkh
    k84 = root.ChildKey(84 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0 + HARDEN).ChildKey(0).ChildKey(index)
    pub84 = k84.PublicKey()
    prog = hash160(pub84)
    conv = bech32.convertbits(prog, 8, 5)
    addr_bech = bech32.bech32_encode("bc", [0] + conv)

    return addr_p2pkh, addr_p2sh, addr_bech

def check_received_sats(addr):
    url = RECEIVED_API + addr
    r = session.get(url, timeout=12)
    if DEBUG:
        body = (r.text or "").strip()
        if len(body) > 200:
            body = body[:200] + "..."
        print(f"[DEBUG] GET {url} -> {r.status_code} | {body}", flush=True)
    r.raise_for_status()
    return int(r.text.strip())

def check_balance_sats(addr):
    url = BALANCE_API + addr
    r = session.get(url, timeout=12)
    if DEBUG:
        body = (r.text or "").strip()
        if len(body) > 200:
            body = body[:200] + "..."
        print(f"[DEBUG] GET {url} -> {r.status_code} | {body}", flush=True)
    r.raise_for_status()
    return int(r.text.strip())

def partition_indices(n_indices, n_parts):
    parts = [[] for _ in range(n_parts)]
    for i in range(n_indices):
        parts[i % n_parts].append(i)
    return parts

def worker_scan_partition(thread_id, seed_bytes, mnemonic, indices_part):
    """
    Worker scans the provided list of indices for the given seed/mnemonic.
    For each derived address: check received first, only check balance if received>0.
    Sleep SLEEP_BETWEEN_CHECKS after each address check.
    """
    for index in indices_part:
        try:
            addr1, addr2, addr3 = derive_btc_addresses_from_seed(seed_bytes, index)
        except Exception as e:
            print(f"[Error][Derive] idx={index} thread={thread_id}: {e}", flush=True)
            continue

        for addr in (addr1, addr2, addr3):
            try:
                received = check_received_sats(addr)
            except Exception as e:
                print(f"[Error][Received] {addr}: {e}", flush=True)
                time.sleep(SLEEP_BETWEEN_CHECKS)
                continue

            # always sleep between address checks (as requested)
            time.sleep(SLEEP_BETWEEN_CHECKS)

            if received and received > 0:
                try:
                    balance = check_balance_sats(addr)
                except Exception as e:
                    print(f"[Error][Balance] {addr}: {e}", flush=True)
                    # still continue scanning
                    continue

                # Immediate print PASSPHRASE\nADDRESS\nBALANCE (sats)
                print(mnemonic, flush=True)
                print(addr, flush=True)
                print(str(balance), flush=True)

                # write to found file as best-effort
                try:
                    with open(FOUND_FILE, "a", encoding="utf-8") as fh:
                        fh.write(f"Mnemonic: {mnemonic}\nAddress: {addr}\nBalance(sats): {balance}\n\n")
                except Exception:
                    pass
            else:
                if DEBUG:
                    print(f"[DEBUG] idx={index} addr={addr} -> received=0", flush=True)

def main_loop():
    round_ctr = 0
    while True:
        round_ctr += 1
        # generate new mnemonic per round
        mnemonic = mnemo.generate(strength=128)  # 12 words
        seed_bytes = mnemo.to_seed(mnemonic, passphrase="")

        if DEBUG:
            print(f"[DEBUG] Round {round_ctr}: mnemonic={mnemonic}", flush=True)

        # partition indices 0..INDICES_PER_MNEMONIC-1 across threads
        parts = partition_indices(INDICES_PER_MNEMONIC, THREAD_COUNT)

        threads = []
        for t in range(THREAD_COUNT):
            th = Thread(target=worker_scan_partition, args=(t, seed_bytes, mnemonic, parts[t]), daemon=False)
            threads.append(th)
            th.start()

        # wait for threads to finish scanning the indices for this mnemonic
        for th in threads:
            th.join()

        if DEBUG:
            print(f"[DEBUG] Completed round {round_ctr} (scanned {INDICES_PER_MNEMONIC} indices).", flush=True)

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)
        sys.exit(0)