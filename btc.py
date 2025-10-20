#!/usr/bin/env python3
"""
btc.py - threaded (5 threads default) Bitcoin address scanner
- Uses coincurve (libsecp256k1) for fast pubkey derivation
- 5 threads by default (change with --threads / -t)
- --debug prints throughput every 5s
- Default target files: btc1.txt, btc2.txt, btc3.txt
- WIF generated only on match
"""

import os
import sys
import time
import argparse
import hashlib
import threading
import queue

# require coincurve
try:
    from coincurve import PublicKey
except Exception:
    print("ERROR: coincurve required. Install with: pip install coincurve")
    raise

# --- base58/bech32 helpers ---
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58_ALPHABET)}
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CHAR_MAP = {c: i for i, c in enumerate(BECH32_CHARSET)}

def sha256(x): return hashlib.sha256(x).digest()
def ripemd160(x): return hashlib.new("ripemd160", x).digest()

def base58check_encode(payload_bytes, version_byte=0):
    data = bytes([version_byte]) + payload_bytes
    checksum = sha256(sha256(data))[:4]
    full = data + checksum
    n = int.from_bytes(full, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(B58_ALPHABET[r])
    n_pad = 0
    for b in full:
        if b == 0:
            n_pad += 1
        else:
            break
    return '1' * n_pad + ''.join(reversed(res))

def base58check_decode(s):
    # Decode base58 string to payload and version, validating checksum.
    # Handles leading '1' padding correctly.
    n = 0
    for ch in s:
        if ch not in B58_MAP:
            raise ValueError("Invalid Base58 character")
        n = n * 58 + B58_MAP[ch]
    # convert to minimal bytes
    full = n.to_bytes((n.bit_length() + 7) // 8, 'big') if n != 0 else b''
    # add leading zero bytes for each leading '1'
    leading_ones = 0
    for ch in s:
        if ch == '1':
            leading_ones += 1
        else:
            break
    full = b'\x00' * leading_ones + full
    if len(full) < 5:
        raise ValueError("Invalid base58 length")
    payload, checksum = full[:-4], full[-4:]
    if sha256(sha256(payload))[:4] != checksum:
        raise ValueError("Bad checksum")
    version = payload[0]
    return version, payload[1:]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []; maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif not pad and bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def bech32_polymod(values):
    GEN = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1: chk ^= GEN[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_verify_checksum(hrp, data):
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == 1

def bech32_decode(bech):
    bech = bech.strip()
    if bech.lower() != bech and bech.upper() != bech:
        raise ValueError("Mixed case in bech32")
    bech = bech.lower()
    if '1' not in bech:
        raise ValueError("No separator")
    pos = bech.rfind('1')
    hrp = bech[:pos]
    data_part = bech[pos+1:]
    data = [BECH32_CHAR_MAP.get(c, -1) for c in data_part]
    if any(d == -1 for d in data):
        raise ValueError("Invalid bech32 character")
    if not bech32_verify_checksum(hrp, data):
        raise ValueError("Invalid bech32 checksum")
    data = data[:-6]
    if not data:
        raise ValueError("Empty bech32 data")
    witver = data[0]
    prog = convertbits(data[1:], 5, 8, False)
    if prog is None:
        raise ValueError("Invalid witness program")
    return hrp, witver, bytes(prog)

def encode_bech32(hrp, witver, witprog):
    data = [witver] + convertbits(witprog, 8, 5)
    values = bech32_hrp_expand(hrp) + data + [0]*6
    polymod = bech32_polymod(values) ^ 1
    checksum = [(polymod >> (5*(5-i))) & 31 for i in range(6)]
    combined = data + checksum
    return hrp + '1' + ''.join(BECH32_CHARSET[d] for d in combined)

def wif_from_priv(priv32, compressed=True, testnet=False):
    payload = priv32 + (b'\x01' if compressed else b'')
    version_byte = 0x80 if not testnet else 0xef
    return base58check_encode(payload, version_byte)

# --- targets ---
def load_targets(paths):
    p2pkh=set(); p2sh=set(); bech=set()
    for path in paths:
        try:
            with open(path,"r",encoding="utf-8",errors="ignore") as f:
                for line in f:
                    s=line.strip().split()[0] if line.strip() else ""
                    if not s: continue
                    s_low=s.lower()
                    try:
                        if s_low.startswith("bc1") or s_low.startswith("tb1"):
                            hrp,witver,prog = bech32_decode(s_low)
                            bech.add((hrp,witver,prog))
                        else:
                            version,payload = base58check_decode(s_low)
                            if version in (0x00,0x6f):
                                p2pkh.add(bytes(payload))
                            elif version in (0x05,0xc4):
                                p2sh.add(bytes(payload))
                            else:
                                p2pkh.add(bytes(payload))
                    except Exception:
                        continue
        except FileNotFoundError:
            continue
    return p2pkh,p2sh,bech

# --- threaded worker ---
def pubkey_from_priv(priv32):
    return PublicKey.from_valid_secret(priv32).format(compressed=True)

def worker_thread(thread_id, stop_evt, result_q, targets_p2pkh, targets_p2sh, targets_bech,
                  report_every, network, batch_size, debug_state):
    print(f"[thread {thread_id}] started (tid={threading.get_ident()})")
    sys.stdout.flush()
    rng = os.urandom
    is_testnet = (network=="testnet")
    hrp_main = "tb" if is_testnet else "bc"
    t0 = time.time()
    local_tried = 0

    while not stop_evt.is_set():
        for _ in range(batch_size):
            priv = rng(32)
            try:
                pubc = pubkey_from_priv(priv)
            except Exception:
                continue
            h160 = hashlib.new("ripemd160", hashlib.sha256(pubc).digest()).digest()

            # P2PKH
            if h160 in targets_p2pkh:
                wif = wif_from_priv(priv, compressed=True, testnet=is_testnet)
                addr = base58check_encode(h160, version_byte=(0x6f if is_testnet else 0x00))
                result_q.put((priv.hex(), wif, addr))
                stop_evt.set()
                return

            # Bech32 P2WPKH
            if targets_bech:
                for (hrp,witver,prog) in targets_bech:
                    if hrp != hrp_main: continue
                    if witver == 0 and len(prog) == 20 and prog == h160:
                        wif = wif_from_priv(priv, compressed=True, testnet=is_testnet)
                        addr = encode_bech32(hrp_main, 0, h160)
                        result_q.put((priv.hex(), wif, addr))
                        stop_evt.set()
                        return

            # P2SH-P2WPKH
            if targets_p2sh:
                redeem = b'\x00\x14' + h160
                script_hash = hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest()
                if script_hash in targets_p2sh:
                    wif = wif_from_priv(priv, compressed=True, testnet=is_testnet)
                    addr = base58check_encode(script_hash, version_byte=(0xc4 if is_testnet else 0x05))
                    result_q.put((priv.hex(), wif, addr))
                    stop_evt.set()
                    return

            # update debug counters
            local_tried += 1
            if debug_state is not None:
                with debug_state['lock']:
                    debug_state['total'] += 1
                    debug_state['per_thread'][thread_id-1] += 1

        if report_every and local_tried and local_tried % report_every == 0:
            elapsed = time.time() - t0
            rate = local_tried / elapsed if elapsed > 0 else 0
            print(f"[thread {thread_id}] Tried {local_tried:,} keys — {rate:,.1f} keys/s (elapsed {int(elapsed)}s)")
            sys.stdout.flush()

# --- debug monitor thread ---
def debug_monitor_thread(stop_evt, debug_state, interval):
    last = 0
    last_t = time.time()
    while not stop_evt.is_set():
        time.sleep(interval)
        with debug_state['lock']:
            total = debug_state['total']
            per = list(debug_state['per_thread'])
        now = time.time()
        rate = (total - last) / (now - last_t) if now != last_t else 0
        last, last_t = total, now
        print(f"[DEBUG] Total keys: {total:,} Rate: {rate:,.1f} keys/s | per-thread: {per}")
        sys.stdout.flush()

# --- main ---
def main():
    default_files = ["btc1.txt","btc2.txt","btc3.txt"]
    parser = argparse.ArgumentParser()
    parser.add_argument("--file","-f", nargs="+", default=default_files)
    parser.add_argument("--network", choices=["mainnet","testnet"], default="mainnet")
    parser.add_argument("--threads","-t", type=int, default=5, help="number of threads (default 5)")
    parser.add_argument("--report-every","-r", type=int, default=100000)
    parser.add_argument("--batch", type=int, default=64)
    parser.add_argument("--debug", action="store_true", help="enable debug throughput every 5s")
    parser.add_argument("--max","-m", type=int, default=0)
    args = parser.parse_args()

    targets_p2pkh, targets_p2sh, targets_bech = load_targets(args.file)
    total_targets = len(targets_p2pkh) + len(targets_p2sh) + len(targets_bech)
    if total_targets == 0:
        print("No valid targets found in:", ", ".join(args.file))
        return

    print(f"Loaded {total_targets:,} targets: P2PKH={len(targets_p2pkh):,} P2SH={len(targets_p2sh):,} Bech32={len(targets_bech):,}")
    print(f"Network: {args.network}, Threads: {args.threads}, Batch: {args.batch}, Debug: {args.debug}")

    stop_evt = threading.Event()
    result_q = queue.Queue()
    threads = []

    debug_state = None
    if args.debug:
        debug_state = {'total': 0, 'per_thread': [0]*args.threads, 'lock': threading.Lock()}
        mon = threading.Thread(target=debug_monitor_thread, args=(stop_evt, debug_state, 5), daemon=True)
        mon.start()
        threads.append(mon)  # keep reference for join

    # start worker threads
    for i in range(args.threads):
        t = threading.Thread(target=worker_thread, args=(i+1, stop_evt, result_q,
                                                         targets_p2pkh, targets_p2sh, targets_bech,
                                                         args.report_every, args.network, args.batch, debug_state))
        t.daemon = True
        t.start()
        threads.append(t)

    # wait for match or ctrl-c
    try:
        while True:
            try:
                priv_hex, wif, addr = result_q.get(timeout=1)
                print("\n=== MATCH FOUND ===")
                print("PRIV"); print(priv_hex)
                print("WIF"); print(wif)
                print("ADDRESS"); print(addr)
                print("===================\n")
                stop_evt.set()
                break
            except queue.Empty:
                if stop_evt.is_set():
                    break
                continue
    except KeyboardInterrupt:
        print("\nInterrupted by user — stopping threads")
        stop_evt.set()
    finally:
        for t in threads:
            t.join(timeout=1)
        print("Threads stopped. Exiting.")

if __name__ == "__main__":
    main()