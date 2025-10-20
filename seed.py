#!/usr/bin/env python3
"""
btc_scan_20permnemonic.py

Generate 12-word mnemonics from seed.txt (2048 words). For each mnemonic:
 - scan indices i = 0..19 (20 indices) using strict paths:
     m/44'/0'/0'/0/i   -> P2PKH (1...)
     m/49'/0'/0'/0/i   -> P2SH-P2WPKH (3...)
     m/84'/0'/0'/0/i   -> P2WPKH (bc1q...)
 - use 3 threads, partition indices by i % 3 == thread_id
 - check balance immediately via blockchain.info/q/addressbalance/<addr> (satoshis)
 - sleep 0.5s between checks
 - if balance > 0 print immediately:
     PASSPHRASE
     ADDRESS
     BALANCE
 - quiet mode prints only hits and errors; -d prints debug info
"""
import os
import sys
import time
import hashlib
import requests
from threading import Thread
from mnemonic import Mnemonic
import bip32utils
import base58
import bech32
import argparse

# ---------- Config ----------
WORDLIST_FILE = "seed.txt"    # 2048-word BIP39 list (one per line)
THREAD_COUNT = 3
INDICES_PER_MNEMONIC = 20     # scan i = 0..19 for each mnemonic
SLEEP_BETWEEN_CHECKS = 0.5    # seconds
BALANCE_API = "https://blockchain.info/q/addressbalance/"
HARDEN = 0x80000000
FOUND_FILE = "found.txt"
# ----------------------------

ap = argparse.ArgumentParser()
ap.add_argument("-d", "--debug", action="store_true", help="debug mode: print each address checked and HTTP responses")
args = ap.parse_args()
DEBUG = args.debug

# Load custom wordlist
if not os.path.exists(WORDLIST_FILE):
    sys.exit(f"Missing {WORDLIST_FILE} (should contain 2048 BIP39 words, one per line)")

with open(WORDLIST_FILE, "r", encoding="utf-8") as f:
    wl = [w.strip() for w in f.readlines() if w.strip()]

if len(wl) != 2048:
    print(f"[Warning] {WORDLIST_FILE} contains {len(wl)} words (expected 2048). Proceeding anyway.", flush=True)

mnemo = Mnemonic("english")
mnemo.wordlist = wl

session = requests.Session()
session.headers.update({"User-Agent": "btc-scan-20permnemonic/1.0"})

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

def check_balance_sats(addr):
    """
    Query blockchain.info/q/addressbalance/<addr>
    Returns integer satoshis (>=0) or raises.
    """
    url = BALANCE_API + addr
    r = session.get(url, timeout=12)
    if DEBUG:
        body = (r.text or "").strip()
        if len(body) > 300:
            body = body[:300] + "..."
        print(f"[DEBUG] GET {url} -> {r.status_code} | {body}", flush=True)
    r.raise_for_status()
    txt = r.text.strip()
    return int(txt)

def worker_scan_indices(thread_id, seed_bytes, mnemonic, indices_part, found_flag_container):
    """
    Each worker processes its assigned indices (a list) for the given seed/mnemonic.
    found_flag_container is a single-item list used as a shared flag (mutable) to note finds.
    """
    for index in indices_part:
        # derive 3 addresses for this index
        try:
            addr1, addr2, addr3 = derive_btc_addresses_from_seed(seed_bytes, index)
        except Exception as e:
            print(f"[Error][Derive] idx={index} thread={thread_id} exception: {e}", flush=True)
            continue

        for addr in (addr1, addr2, addr3):
            try:
                sats = check_balance_sats(addr)
            except Exception as e:
                # print errors even in quiet mode per your requirement
                print(f"[Error][Balance] {addr}: {e}", flush=True)
                time.sleep(SLEEP_BETWEEN_CHECKS)
                continue

            if sats and sats > 0:
                # immediate print: PASSPHRASE\nADDRESS\nBALANCE (satoshis)
                print(mnemonic, flush=True)
                print(addr, flush=True)
                print(str(sats), flush=True)
                # record to file (best-effort)
                try:
                    with open(FOUND_FILE, "a", encoding="utf-8") as fh:
                        fh.write(f"Mnemonic: {mnemonic}\nAddress: {addr}\nBalance(sats): {sats}\n\n")
                except Exception:
                    pass
                # set shared flag so main could (optionally) react
                try:
                    found_flag_container[0] = True
                except Exception:
                    pass
            else:
                if DEBUG:
                    print(f"[DEBUG] idx={index} addr={addr} -> {sats} sats", flush=True)

            time.sleep(SLEEP_BETWEEN_CHECKS)

def partition_indices(n_indices, n_parts):
    parts = [[] for _ in range(n_parts)]
    for i in range(n_indices):
        parts[i % n_parts].append(i)
    return parts

def main():
    round_ctr = 0
    while True:
        round_ctr += 1
        # 1) generate a new 12-word mnemonic
        mnemonic = mnemo.generate(strength=128)  # 12 words
        seed_bytes = mnemo.to_seed(mnemonic, passphrase="")

        if DEBUG:
            print(f"[DEBUG] Round {round_ctr}: mnemonic={mnemonic}", flush=True)

        # 2) build index partitions for THREAD_COUNT threads
        parts = partition_indices(INDICES_PER_MNEMONIC, THREAD_COUNT)

        # shared flag container to indicate if any positive found this round
        found_flag = [False]

        # 3) spawn threads, each scanning its partition of indices for this mnemonic
        threads = []
        for t in range(THREAD_COUNT):
            th = Thread(target=worker_scan_indices, args=(t, seed_bytes, mnemonic, parts[t], found_flag), daemon=False)
            threads.append(th)
            th.start()

        # wait for all threads to finish scanning these 20 indices
        for th in threads:
            th.join()

        if DEBUG:
            print(f"[DEBUG] Completed round {round_ctr}. found_any={found_flag[0]}", flush=True)

        # after scanning INDICES_PER_MNEMONIC indices for this mnemonic, move on to next mnemonic
        # (per your spec). repeat.

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)
        sys.exit(0)