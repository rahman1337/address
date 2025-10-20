#!/usr/bin/env python3
import sys
import time
import secrets
import hashlib
import binascii
import argparse
import threading
import os
import tempfile

tempfile.tempdir = "/tmp"

try:
    from coincurve import PrivateKey
except Exception:
    print("ERROR: coincurve required. Install with: pip install coincurve")
    raise

BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_MAP = {c: i for i, c in enumerate(BECH32_CHARSET)}
MATCH_LOG = "matches.txt"

total_counter = 0
total_lock = threading.Lock()
match_counter = 0
match_lock = threading.Lock()
stop_event = threading.Event()
start_time_global = time.time()

def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def base58_decode(addr: str):
    num = 0
    try:
        for ch in addr:
            num = num * 58 + BASE58_ALPHABET.index(ch)
    except ValueError:
        return None
    b = num.to_bytes((num.bit_length() + 7) // 8, 'big')
    n_pad = len(addr) - len(addr.lstrip('1'))
    return b'\x00' * n_pad + b

def base58check_payload(addr: str):
    payload = base58_decode(addr)
    if not payload or len(payload) < 5:
        return None
    # If payload length >= 25 assume payload includes checksum; strip checksum
    if len(payload) >= 25:
        # version(1) + data(20) + checksum(4)
        return payload[1:21]
    # fallback: if length == 21, payload is version+20
    if len(payload) == 21:
        return payload[1:21]
    return None

def bech32_decode_humanprog(addr: str):
    a = addr.strip().lower()
    if '1' not in a:
        return None
    pos = a.rfind('1')
    hrp = a[:pos]
    data_part = a[pos+1:]
    try:
        vals = [BECH32_MAP[c] for c in data_part]
    except KeyError:
        return None
    if len(vals) < 7:
        return None
    data_vals = vals[:-6]  # drop checksum
    if len(data_vals) < 1:
        return None
    witver = data_vals[0]
    # convert 5-bit groups to bytes
    acc = 0
    bits = 0
    prog = []
    for v in data_vals[1:]:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            prog.append((acc >> bits) & 0xff)
    prog_bytes = bytes(prog)
    if witver == 0 and len(prog_bytes) in (20, 32):
        return prog_bytes
    return None

def load_targets_as_hashes(paths):
    targets_h160 = set()
    targets_p2sh = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    a = line.strip()
                    if not a or a.startswith("#"):
                        continue
                    if a[0] == '1':
                        h = base58check_payload(a)
                        if h and len(h) == 20:
                            targets_h160.add(h)
                    elif a[0] == '3':
                        h = base58check_payload(a)
                        if h and len(h) == 20:
                            # payload for P2SH is the script-hash (20 bytes)
                            targets_p2sh.add(h)
                    elif a.lower().startswith('bc1') or a.lower().startswith('tb1'):
                        prog = bech32_decode_humanprog(a)
                        if prog and len(prog) == 20:
                            targets_h160.add(prog)
        except FileNotFoundError:
            continue
    return targets_h160, targets_p2sh

def base58check_encode(payload: bytes):
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    full = payload + checksum
    num = int.from_bytes(full, 'big')
    res = ""
    while num > 0:
        num, mod = divmod(num, 58)
        res = BASE58_ALPHABET[mod] + res
    n_pad = len(full) - len(full.lstrip(b'\0'))
    return '1' * n_pad + res

def encode_bech32(hrp: str, witver: int, witprog: bytes) -> str:
    def convertbits(data, frombits, tobits, pad=True):
        acc = 0
        bits = 0
        ret = []
        maxv = (1 << tobits) - 1
        for b in data:
            acc = (acc << frombits) | b
            bits += frombits
            while bits >= tobits:
                bits -= tobits
                ret.append((acc >> bits) & maxv)
        if pad and bits:
            ret.append((acc << (tobits - bits)) & maxv)
        return ret
    def polymod(values):
        GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
        chk = 1
        for v in values:
            top = chk >> 25
            chk = ((chk & 0x1ffffff) << 5) ^ v
            for i in range(5):
                if (top >> i) & 1:
                    chk ^= GEN[i]
        return chk
    def hrp_expand(hrp):
        return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]
    def create_checksum(hrp, data):
        values = hrp_expand(hrp) + data + [0]*6
        polymod_result = polymod(values) ^ 1
        return [(polymod_result >> 5*(5-i)) & 31 for i in range(6)]
    data = [witver] + convertbits(witprog, 8, 5)
    combined = data + create_checksum(hrp, data)
    return hrp + "1" + ''.join([BECH32_CHARSET[d] for d in combined])

def log_match_line(line):
    with match_lock:
        with open(MATCH_LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except Exception:
                pass

def worker(thread_id, targets_h160, targets_p2sh, report_every, debug, hrp, stop_after):
    global total_counter, match_counter
    local_count = 0
    last_report_time = time.time()
    last_local = 0
    while not stop_event.is_set():
        priv = secrets.token_bytes(32)
        pk = PrivateKey(priv)
        pub_compressed = pk.public_key.format(compressed=True)
        h160 = hash160(pub_compressed)

        matched = False
        if h160 in targets_h160:
            matched = True
            addr_p2pkh = base58check_encode(b'\x00' + h160)
            addr_bech32 = encode_bech32(hrp, 0, h160)
            wif = base58check_encode(b'\x80' + priv + b'\x01')
            now_s = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
            line = f"{now_s} [T{thread_id}] MATCH h160 ADDR_P2PKH={addr_p2pkh} ADDR_BECH32={addr_bech32} PRIV={binascii.hexlify(priv).decode()} WIF={wif}"
            log_match_line(line)
            print("\n=== MATCH FOUND ===")
            print(line)
            print("===================\n")
            sys.stdout.flush()
            with match_lock:
                match_counter += 1
                if stop_after and match_counter >= stop_after:
                    stop_event.set()

        else:
            redeem = b'\x00\x14' + h160
            redeem_hash = hashlib.new('ripemd160', hashlib.sha256(redeem).digest()).digest()
            if redeem_hash in targets_p2sh:
                matched = True
                addr_p2sh = base58check_encode(b'\x05' + redeem_hash)
                wif = base58check_encode(b'\x80' + priv + b'\x01')
                now_s = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
                line = f"{now_s} [T{thread_id}] MATCH p2sh ADDR_P2SH={addr_p2sh} PRIV={binascii.hexlify(priv).decode()} WIF={wif}"
                log_match_line(line)
                print("\n=== MATCH FOUND ===")
                print(line)
                print("===================\n")
                sys.stdout.flush()
                with match_lock:
                    match_counter += 1
                    if stop_after and match_counter >= stop_after:
                        stop_event.set()

        local_count += 1

        if local_count % report_every == 0:
            now = time.time()
            interval = now - last_report_time if last_report_time else 1.0
            with total_lock:
                total_counter += (local_count - last_local)
                total = total_counter
            elapsed = now - start_time_global
            avg_rate = total / elapsed if elapsed > 0 else 0.0
            local_rate = (local_count - last_local) / interval if interval > 0 else 0.0
            last_report_time = now
            last_local = local_count
            if debug:
                print(f"[T{thread_id}] {local_count:,} keys — {local_rate:,.1f} keys/s (total {total:,} avg {avg_rate:,.1f})")
            else:
                print(f"[T{thread_id}] {local_count:,} keys — {local_rate:,.1f} keys/s")

def reporter(refresh):
    prev = 0
    prev_t = time.time()
    while not stop_event.is_set():
        time.sleep(refresh)
        with total_lock:
            total = total_counter
        with match_lock:
            matches = match_counter
        now = time.time()
        rate = (total - prev) / (now - prev_t) if now > prev_t else 0.0
        elapsed = now - start_time_global
        overall = total / elapsed if elapsed > 0 else 0.0
        print(f"[TOTAL] {total:,} keys — {rate:,.1f} k/s (avg {overall:,.1f} k/s) MATCHES={matches}")
        prev = total
        prev_t = now

def add_test_priv_to_targets(hexpriv, targets_h160, targets_p2sh):
    try:
        b = bytes.fromhex(hexpriv)
        p2 = PrivateKey(b)
        pub_compressed = p2.public_key.format(compressed=True)
        h = hash160(pub_compressed)
        targets_h160.add(h)
        redeem = b'\x00\x14' + h
        redeem_hash = hashlib.new('ripemd160', hashlib.sha256(redeem).digest()).digest()
        targets_p2sh.add(redeem_hash)
        return True
    except Exception:
        return False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file", "-f", nargs="+", default=["btc1.txt", "btc2.txt", "btc3.txt"])
    parser.add_argument("--threads", "-t", type=int, default=3)
    parser.add_argument("--report-every", "-r", type=int, default=2000)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--hrp", default="bc")
    parser.add_argument("--stop-after", type=int, default=0, help="Stop after N matches (0=never)")
    parser.add_argument("--test-priv", type=str, default=None, help="Hex private key to add to targets for testing")
    args = parser.parse_args()

    targets_h160, targets_p2sh = load_targets_as_hashes(args.file)
    if args.test_priv:
        ok = add_test_priv_to_targets(args.test_priv, targets_h160, targets_p2sh)
        if not ok:
            print("Invalid --test-priv hex.")
            return
        print("Added --test-priv addresses to targets for verification.")

    if not targets_h160 and not targets_p2sh:
        print("No valid addresses loaded.")
        return

    try:
        open(MATCH_LOG, "a").close()
    except Exception as e:
        print("Cannot create match log:", e)
        return

    print(f"Starting {args.threads} threads; reporting every {args.report_every} keys.")
    threads = []
    rep = threading.Thread(target=reporter, args=(2.0,), daemon=True)
    rep.start()

    for i in range(args.threads):
        t = threading.Thread(target=worker, args=(i+1, targets_h160, targets_p2sh, args.report_every, args.debug, args.hrp, args.stop_after), daemon=True)
        threads.append(t)
        t.start()

    try:
        while not stop_event.is_set():
            alive = any(t.is_alive() for t in threads)
            if not alive:
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Stopping...")
        stop_event.set()

    # wait briefly for threads to finish current loop
    time.sleep(0.5)
    with total_lock:
        final_total = total_counter
    with match_lock:
        final_matches = match_counter
    elapsed = time.time() - start_time_global
    avg = final_total / elapsed if elapsed > 0 else 0.0
    print(f"\nFinished. Total keys tried: {final_total:,} — avg {avg:,.1f} keys/s over {elapsed:.1f}s MATCHES={final_matches}")

if __name__ == "__main__":
    main()