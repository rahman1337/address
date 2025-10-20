#!/usr/bin/env python3
"""
Multiprocessing Bitcoin address scanner using libsecp256k1 (coincurve).
Continuous mode: does NOT stop on first match — prints matches and continues.
Default: 3 worker processes, keep All features (P2PKH, P2SH, Bech32).
"""

import sys
import time
import secrets
import hashlib
import binascii
import argparse
from multiprocessing import Process, Value, Lock, get_context

# coincurve for secp256k1 (C-backed)
try:
    from coincurve import PrivateKey
except Exception:
    print("ERROR: coincurve is required. Install with `pip install coincurve`")
    raise

# --- Base58 / Bech32 helpers (kept inline) ---
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

def base58check(data: bytes) -> str:
    checksum = hashlib.sha256(hashlib.sha256(data).digest()).digest()[:4]
    full = data + checksum
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

def generate_addresses(priv_bytes: bytes, hrp="bc"):
    pk = PrivateKey(priv_bytes)
    pub_compressed = pk.public_key.format(compressed=True)  # 33 bytes
    h160 = hash160(pub_compressed)
    addr_p2pkh = base58check(b'\x00' + h160)
    redeem = b'\x00\x14' + h160
    addr_p2sh = base58check(b'\x05' + hash160(redeem))
    addr_bech32 = encode_bech32(hrp, 0, h160)
    return addr_p2pkh, addr_p2sh, addr_bech32

def load_targets(paths):
    targets = set()
    counts = {"p2pkh": 0, "p2sh": 0, "bech32": 0}
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    addr = line
                    targets.add(addr)
                    if addr.startswith("1"):
                        counts["p2pkh"] += 1
                    elif addr.startswith("3"):
                        counts["p2sh"] += 1
                    elif addr.lower().startswith("bc1"):
                        counts["bech32"] += 1
        except FileNotFoundError:
            continue
    print(f"Loaded {len(targets)} targets: "
          f"P2PKH={counts['p2pkh']} P2SH={counts['p2sh']} Bech32={counts['bech32']}")
    return targets

# --- Worker process (continuous) ---
def worker_main(proc_index: int, targets, total_counter: Value, counter_lock: Lock,
                report_every: int, debug: bool, hrp: str):
    local_count = 0
    last_report = time.time()
    last_local = 0
    proc_name = f"P{proc_index}"

    while True:
        priv = secrets.token_bytes(32)
        p2pkh, p2sh, bech32 = generate_addresses(priv, hrp)

        # if any of the generated addresses is in targets, print it — but KEEP RUNNING
        match = None
        if p2pkh in targets:
            match = p2pkh
        elif p2sh in targets:
            match = p2sh
        elif bech32 in targets:
            match = bech32

        if match is not None:
            wif = base58check(b'\x80' + priv + b'\x01')
            print("\n=== MATCH FOUND (continuing) ===")
            print(f"[{proc_name}] PRIV: {binascii.hexlify(priv).decode()}")
            print(f"[{proc_name}] WIF : {wif}")
            print(f"[{proc_name}] ADDR: {match}")
            print("===============================\n")
            # **DO NOT** exit; continue scanning

        local_count += 1

        # batch update the shared total occasionally to reduce lock contention
        if local_count % report_every == 0:
            now = time.time()
            interval = now - last_report if last_report else 1.0
            with counter_lock:
                total_counter.value += (local_count - last_local)
            elapsed = now - start_time_global
            total_keys = total_counter.value
            total_rate = (total_keys / elapsed) if elapsed > 0 else 0.0
            interval_rate = (local_count - last_local) / interval if interval > 0 else 0.0

            if debug:
                print(f"[{proc_name}] {local_count:,} keys tried — {interval_rate:,.1f} keys/s (total {total_keys:,} — {total_rate:,.1f} keys/s)")
            else:
                print(f"[{proc_name}] {local_count:,} keys — {interval_rate:,.1f} keys/s")
            last_report = now
            last_local = local_count

# --- Reporter (prints global totals periodically) ---
def reporter_main(total_counter: Value, counter_lock: Lock, refresh: float):
    prev = 0
    prev_t = time.time()
    while True:
        time.sleep(refresh)
        with counter_lock:
            total = total_counter.value
        now = time.time()
        rate = (total - prev) / (now - prev_t) if now > prev_t else 0.0
        elapsed = now - start_time_global
        overall_rate = total / elapsed if elapsed > 0 else 0.0
        print(f"[TOTAL] {total:,} keys — {rate:,.1f} k/s (avg {overall_rate:,.1f} k/s)")
        prev = total
        prev_t = now

# --- Main ---
def main():
    parser = argparse.ArgumentParser(description="Multiprocess Bitcoin scanner (secp256k1 via coincurve) — continuous mode")
    parser.add_argument("--file", "-f", nargs="+", default=["btc1.txt", "btc2.txt", "btc3.txt"])
    parser.add_argument("--processes", "-p", type=int, default=3, help="Number of worker processes (default 3)")
    parser.add_argument("--report-every", "-r", type=int, default=2000, help="Local report interval per process")
    parser.add_argument("--debug", action="store_true", help="Show detailed debug prints ([keys tried] [keys/s])")
    parser.add_argument("--hrp", default="bc", help="Bech32 HRP (default 'bc' for mainnet)")
    args = parser.parse_args()

    targets = load_targets(args.file)
    if not targets:
        print("No valid addresses loaded.")
        return

    ctx = get_context("fork")  # platform default
    total_counter = ctx.Value('Q', 0)  # unsigned long long
    counter_lock = ctx.Lock()

    # spawn reporter
    reporter_proc = ctx.Process(target=reporter_main, args=(total_counter, counter_lock, 2.0), daemon=True)
    reporter_proc.start()

    # spawn workers
    processes = []
    for i in range(args.processes):
        p = ctx.Process(target=worker_main,
                        args=(i+1, targets, total_counter, counter_lock, args.report_every, args.debug, args.hrp),
                        daemon=True)
        processes.append(p)
        p.start()

    try:
        # run until user interrupts
        while True:
            live = any(p.is_alive() for p in processes)
            if not live:
                print("All worker processes exited unexpectedly.")
                break
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Stopping processes...")
    finally:
        # ensure termination
        for p in processes:
            try:
                p.terminate()
            except Exception:
                pass
            p.join(timeout=1)
        try:
            reporter_proc.terminate()
            reporter_proc.join(timeout=1)
        except Exception:
            pass

        with counter_lock:
            final = total_counter.value
        elapsed = time.time() - start_time_global
        avg = final / elapsed if elapsed > 0 else 0.0
        print(f"\nFinished. Total keys tried: {final:,} — avg {avg:,.1f} keys/s over {elapsed:.1f}s")

if __name__ == "__main__":
    # global start time used by workers and reporter
    start_time_global = time.time()
    main()