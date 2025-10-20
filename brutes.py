#!/usr/bin/env python3
"""
btc_scan_bip44_49_84.py

- Generates 12-word mnemonics (BIP39). Uses optional seed.txt (2048 words) if present.
- For each mnemonic, scans indices i = 0..(N-1) (default N=20).
- For each index derives:
    m/44'/0'/0'/0/i -> P2PKH (1...)
    m/49'/0'/0'/0/i -> P2SH-P2WPKH (3...)
    m/84'/0'/0'/0/i -> P2WPKH bech32 (bc1q...)
- Checks received first (blockchain.info/q/receivedbyaddress/). Only if >0 checks balance.
- Uses THREAD_COUNT threads (default 3). Indices partitioned by i % THREAD_COUNT.
- Sleeps 0.5s between address checks.
- Quiet default; -d prints debug info.
"""
import os
import sys
import time
import argparse
import hashlib
import requests
from threading import Thread
from mnemonic import Mnemonic
import bip32utils
import base58

# -------------------- Config / Defaults --------------------
THREAD_COUNT = 3
DEFAULT_INDICES_PER_MNEMONIC = 20
SLEEP_BETWEEN_CHECKS = 0.5
RECEIVED_API = "https://blockchain.info/q/receivedbyaddress/"
BALANCE_API  = "https://blockchain.info/q/addressbalance/"
HARDEN = 0x80000000
FOUND_FILE = "found.txt"
DEFAULT_WORDLIST = "seed.txt"  # optional custom 2048-word file
# ----------------------------------------------------------

# ----- minimal bech32 helpers (BIP173) -----
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        if b < 0 or (b >> frombits):
            return None
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

# -------------------- CLI --------------------
parser = argparse.ArgumentParser(description="Scan BIP44/49/84 addresses per generated mnemonic (received-first).")
parser.add_argument("-d", "--debug", action="store_true", help="debug mode: print each address and API responses")
parser.add_argument("--indices", type=int, default=DEFAULT_INDICES_PER_MNEMONIC,
                    help=f"how many indices to scan per mnemonic (default {DEFAULT_INDICES_PER_MNEMONIC})")
parser.add_argument("--wordlist", type=str, default=DEFAULT_WORDLIST,
                    help="optional path to 2048-word BIP39 wordlist (default seed.txt if present)")
args = parser.parse_args()

DEBUG = args.debug
INDICES_PER_MNEMONIC = args.indices
WORDLIST_FILE = args.wordlist

# -------------------- Wordlist / Mnemonic --------------------
mnemo = Mnemonic("english")
if os.path.exists(WORDLIST_FILE):
    with open(WORDLIST_FILE, "r", encoding="utf-8") as f:
        wl = [w.strip() for w in f.readlines() if w.strip()]
    if wl:
        if len(wl) != 2048:
            print(f"[Warning] {WORDLIST_FILE} contains {len(wl)} words (expected 2048). Proceeding anyway.", flush=True)
        mnemo.wordlist = wl

session = requests.Session()
session.headers.update({"User-Agent": "btc-scan-bip44-49-84/1.0"})

# -------------------- helpers --------------------
def hash160(b: bytes) -> bytes:
    return hashlib.new("ripemd160", hashlib.sha256(b).digest()).digest()

def derive_node_from_seed(seed_bytes):
    # bip32utils.BIP32Key.fromEntropy accepts seed; some versions require shorter entropy
    try:
        master = bip32utils.BIP32Key.fromEntropy(seed_bytes)
    except Exception:
        master = bip32utils.BIP32Key.fromEntropy(seed_bytes[:32])
    return master

def derive_child_node(master, purpose, index):
    # derive m/<purpose>'/0'/0'/0/index  where purpose is 44,49,84
    node = (master
            .ChildKey(purpose + HARDEN)
            .ChildKey(0 + HARDEN)
            .ChildKey(0 + HARDEN)
            .ChildKey(0)
            .ChildKey(index))
    return node

def pub_to_p2pkh(pub_bytes: bytes) -> str:
    h160 = hash160(pub_bytes)
    return base58.b58encode_check(b'\x00' + h160).decode()

def pub_to_p2sh_p2wpkh(pub_bytes: bytes) -> str:
    h160 = hash160(pub_bytes)
    redeem = b'\x00\x14' + h160
    redeem_h = hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest()
    return base58.b58encode_check(b'\x05' + redeem_h).decode()

def pub_to_bech32_p2wpkh(pub_bytes: bytes, hrp='bc') -> str:
    prog = hash160(pub_bytes)
    conv = convertbits(prog, 8, 5)
    data = [0] + conv
    return bech32_encode(hrp, data)

def check_received(addr: str):
    url = RECEIVED_API + addr
    r = session.get(url, timeout=12)
    if DEBUG:
        body = (r.text or "").strip()
        if len(body) > 200:
            body = body[:200] + "..."
        print(f"[DEBUG] GET {url} -> {r.status_code} | {body}", flush=True)
    r.raise_for_status()
    return int(r.text.strip())

def check_balance(addr: str):
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

# -------------------- worker --------------------
def worker(thread_id: int):
    """
    For each round:
     - generate a mnemonic, build seed and master
     - derive indices 0..INDICES_PER_MNEMONIC-1, partitioned among threads
     - for each assigned index derive BIP44/BIP49/BIP84 child and addresses
     - check received -> if >0 then check balance
     - sleep SLEEP_BETWEEN_CHECKS after each address check
    """
    mnemo_local = Mnemonic("english")
    while True:
        try:
            mnemonic = mnemo_local.generate(strength=128)
            seed = mnemo_local.to_seed(mnemonic, passphrase="")
            master = derive_node_from_seed(seed)

            if DEBUG:
                print(f"[DEBUG] thread={thread_id} mnemonic={mnemonic}", flush=True)

            parts = partition_indices(INDICES_PER_MNEMONIC, THREAD_COUNT)
            my_indices = parts[thread_id]

            for index in my_indices:
                # derive three nodes for three purposes
                try:
                    node44 = derive_child_node(master, 44, index)
                    node49 = derive_child_node(master, 49, index)
                    node84 = derive_child_node(master, 84, index)
                except Exception as e:
                    print(f"[Error][Derive] thread={thread_id} idx={index}: {e}", flush=True)
                    continue

                # get public keys (bip32utils may return hex string)
                pub44 = node44.PublicKey()
                pub49 = node49.PublicKey()
                pub84 = node84.PublicKey()
                if isinstance(pub44, str): pub44 = bytes.fromhex(pub44)
                if isinstance(pub49, str): pub49 = bytes.fromhex(pub49)
                if isinstance(pub84, str): pub84 = bytes.fromhex(pub84)

                # build addresses
                try:
                    addr1 = pub_to_p2pkh(pub44)
                    addr2 = pub_to_p2sh_p2wpkh(pub49)
                    addr3 = pub_to_bech32_p2wpkh(pub84, hrp='bc')
                except Exception as e:
                    print(f"[Error][AddrBuild] thread={thread_id} idx={index}: {e}", flush=True)
                    continue

                for addr in (addr1, addr2, addr3):
                    # 1) check received
                    try:
                        received = check_received(addr)
                    except Exception as e:
                        print(f"[Error][Received] {addr}: {e}", flush=True)
                        time.sleep(SLEEP_BETWEEN_CHECKS)
                        continue

                    # always sleep between address checks
                    time.sleep(SLEEP_BETWEEN_CHECKS)

                    if received and received > 0:
                        # check balance
                        try:
                            balance = check_balance(addr)
                        except Exception as e:
                            print(f"[Error][Balance] {addr}: {e}", flush=True)
                            time.sleep(SLEEP_BETWEEN_CHECKS)
                            continue

                        # Immediate print: mnemonic, address, received, balance (satoshis)
                        print(mnemonic, flush=True)
                        print(addr, flush=True)
                        print(str(received), flush=True)
                        print(str(balance), flush=True)

                        # save
                        try:
                            with open(FOUND_FILE, "a", encoding="utf-8") as fh:
                                fh.write(f"Mnemonic: {mnemonic}\nAddress: {addr}\nReceived(sats): {received}\nBalance(sats): {balance}\n\n")
                        except Exception:
                            pass

                        # sleep after balance check too
                        time.sleep(SLEEP_BETWEEN_CHECKS)
                    else:
                        if DEBUG:
                            print(f"[DEBUG] {addr} -> received=0", flush=True)

            if DEBUG:
                print(f"[DEBUG] thread={thread_id} completed scanning {INDICES_PER_MNEMONIC} indices for mnemonic.", flush=True)

        except KeyboardInterrupt:
            return
        except Exception as e:
            print(f"[Error][Thread-{thread_id}] {e}", flush=True)
            time.sleep(1)

# -------------------- main --------------------
def main():
    # start workers with thread ids 0..THREAD_COUNT-1
    threads = []
    for t in range(THREAD_COUNT):
        th = Thread(target=worker, args=(t,), daemon=False)
        threads.append(th)
        th.start()

    try:
        for th in threads:
            th.join()
    except KeyboardInterrupt:
        print("\nStopped by user.", flush=True)
        sys.exit(0)

if __name__ == "__main__":
    main()