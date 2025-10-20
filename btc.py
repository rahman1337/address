#!/usr/bin/env python3
"""
btc.py - high-performance Bitcoin address scanner (cross-platform)
- Uses coincurve (libsecp256k1) if available for fast pubkey derivation
- spawn start method for multiprocessing (works safely on Windows/macOS/Linux)
- Optional --debug prints global & per-worker throughput every 5s
- Default files: btc1.txt, btc2.txt, btc3.txt
- WIF generated only on match
"""

import os
import sys
import time
import argparse
import hashlib
import multiprocessing as mp

# Try to import coincurve; if not present we print an error and exit.
try:
    from coincurve import PublicKey
except Exception as e:
    print("ERROR: coincurve is required. Install with: pip install coincurve")
    raise

# --- Base58 / Bech32 helpers (pure-python, lightweight) ---
B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
B58_MAP = {c: i for i, c in enumerate(B58_ALPHABET)}
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
BECH32_CHAR_MAP = {c: i for i, c in enumerate(BECH32_CHARSET)}

def sha256(x): return hashlib.sha256(x).digest()
def ripemd160(x): return hashlib.new("ripemd160", x).digest()
def hash160(x): return ripemd160(sha256(x))

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
    num = 0
    for ch in s:
        num = num * 58 + B58_MAP[ch]
    full = num.to_bytes((num.bit_length() + 7) // 8, 'big') if num != 0 else b'\0'
    n_pad = 0
    for c in s:
        if c == '1':
            n_pad += 1
        else:
            break
    data = b'\0' * n_pad + full
    if len(data) < 5:
        raise ValueError("Invalid base58 length")
    payload, chk = data[:-4], data[-4:]
    if sha256(sha256(payload))[:4] != chk:
        raise ValueError("Invalid base58 checksum")
    return payload[0], payload[1:]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
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
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GEN[i]
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
    values = bech32_hrp_expand(hrp) + data + [0] * 6
    polymod = bech32_polymod(values) ^ 1
    checksum = [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]
    combined = data + checksum
    return hrp + "1" + ''.join(BECH32_CHARSET[d] for d in combined)

def wif_from_priv(priv32, compressed=True, testnet=False):
    payload = priv32 + (b'\x01' if compressed else b'')
    version_byte = 0x80 if not testnet else 0xef
    return base58check_encode(payload, version_byte)

# --- Target loading & decoding ---
def load_targets(paths):
    p2pkh = set()
    p2sh = set()
    bech = set()
    for path in paths:
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    s = line.strip().split()[0] if line.strip() else ""
                    if not s:
                        continue
                    s_low = s.lower()
                    try:
                        if s_low.startswith("bc1") or s_low.startswith("tb1"):
                            hrp, witver, prog = bech32_decode(s_low)
                            bech.add((hrp, witver, prog))
                        else:
                            version, payload = base58check_decode(s_low)
                            if version in (0x00, 0x6f):  # P2PKH main/test
                                p2pkh.add(bytes(payload))
                            elif version in (0x05, 0xc4):  # P2SH main/test
                                p2sh.add(bytes(payload))
                            else:
                                # fallback: treat as P2PKH payload
                                p2pkh.add(bytes(payload))
                    except Exception:
                        # ignore invalid target lines
                        continue
        except FileNotFoundError:
            continue
    return p2pkh, p2sh, bech

# --- Debug counters (shared) ---
class DebugCounters:
    def __init__(self, workers):
        self.total_keys = mp.Value('Q', 0)
        self.worker_keys = [mp.Value('Q', 0) for _ in range(workers)]

# --- Helper: convert priv -> compressed pubkey (top-level, picklable) ---
def pubkey_from_priv(priv32):
    # coincurve PublicKey.from_valid_secret returns object; format(compressed=True) returns bytes
    return PublicKey.from_valid_secret(priv32).format(compressed=True)

# --- Worker (top-level so picklable) ---
def worker_main(worker_id, stop_event, result_queue,
                targets_p2pkh, targets_p2sh, targets_bech,
                report_every, network, batch_size, debug_counters):
    # Print startup immediately so user knows worker launched
    print(f"[worker {worker_id}] started (pid={os.getpid()})")
    sys.stdout.flush()

    t0 = time.time()
    tried = 0
    is_testnet = (network == "testnet")
    hrp_main = "tb" if is_testnet else "bc"

    # local bindings
    rng = os.urandom
    sha256_local = hashlib.sha256
    ripemd160_local = lambda x: hashlib.new("ripemd160", x).digest()
    hash160_local = lambda x: ripemd160_local(sha256_local(x).digest())

    # inner loop
    while not stop_event.is_set():
        for _ in range(batch_size):
            priv = rng(32)
            try:
                pub_compressed = pubkey_from_priv(priv)
            except Exception:
                # extremely unlikely - skip this private and continue
                continue
            h160 = hash160_local(pub_compressed)

            # P2PKH check
            if h160 in targets_p2pkh:
                wif = wif_from_priv(priv, compressed=True, testnet=is_testnet)
                addr = base58check_encode(h160, version_byte=(0x6f if is_testnet else 0x00))
                result_queue.put((priv.hex(), wif, addr))
                stop_event.set()
                return

            # Bech32 P2WPKH check (witnessprog == h160)
            if targets_bech:
                for (hrp, witver, prog) in targets_bech:
                    if hrp != hrp_main:
                        continue
                    if witver == 0 and len(prog) == 20 and prog == h160:
                        wif = wif_from_priv(priv, compressed=True, testnet=is_testnet)
                        addr = encode_bech32(hrp_main, 0, h160)
                        result_queue.put((priv.hex(), wif, addr))
                        stop_event.set()
                        return

            # P2SH-P2WPKH: script hash = HASH160(redeem) where redeem = 0x00 0x14 <h160>
            if targets_p2sh:
                redeem = b'\x00\x14' + h160
                script_hash = hashlib.new("ripemd160", hashlib.sha256(redeem).digest()).digest()
                if script_hash in targets_p2sh:
                    wif = wif_from_priv(priv, compressed=True, testnet=is_testnet)
                    addr = base58check_encode(script_hash, version_byte=(0xc4 if is_testnet else 0x05))
                    result_queue.put((priv.hex(), wif, addr))
                    stop_event.set()
                    return

            tried += 1
            if debug_counters is not None:
                # increment shared counters with locks
                with debug_counters.worker_keys[worker_id - 1].get_lock():
                    debug_counters.worker_keys[worker_id - 1].value += 1
                with debug_counters.total_keys.get_lock():
                    debug_counters.total_keys.value += 1

        # per-worker periodic log if requested
        if report_every and tried and tried % report_every == 0:
            elapsed = time.time() - t0
            rate = tried / elapsed if elapsed > 0 else 0
            print(f"[worker {worker_id}] Tried {tried:,} keys — {rate:,.1f} keys/s (elapsed {int(elapsed)}s)")
            sys.stdout.flush()

# --- Debug monitor (top-level) ---
def debug_monitor(counters, stop_event, interval):
    last_total = 0
    last_time = time.time()
    while not stop_event.is_set():
        time.sleep(interval)
        with counters.total_keys.get_lock():
            total = counters.total_keys.value
        now = time.time()
        rate = (total - last_total) / (now - last_time) if now != last_time else 0
        last_total, last_time = total, now
        per_worker = [c.value for c in counters.worker_keys]
        print(f"[DEBUG] Total keys: {total:,} Rate: {rate:,.1f} keys/s | per-worker: {per_worker}")
        sys.stdout.flush()

# --- Main CLI ---
def main():
    default_files = ["btc1.txt", "btc2.txt", "btc3.txt"]
    parser = argparse.ArgumentParser(description="High-performance Bitcoin scanner (cross-platform)")
    parser.add_argument("--file", "-f", nargs="+", default=default_files, help="target file(s)")
    parser.add_argument("--network", choices=["mainnet", "testnet"], default="mainnet")
    parser.add_argument("--workers", "-w", type=int, default=mp.cpu_count(), help="number of worker processes")
    parser.add_argument("--report-every", "-r", type=int, default=100_000, help="per-worker report every N tries (0=disable)")
    parser.add_argument("--batch", type=int, default=64, help="privates per inner loop batch")
    parser.add_argument("--debug", action="store_true", help="enable debug throughput output (every 5s)")
    parser.add_argument("--max", "-m", type=int, default=0, help="not used in multi-process run (keeps infinite by default)")
    args = parser.parse_args()

    debug_mode = args.debug
    debug_interval = 5  # seconds (fixed)

    targets_p2pkh, targets_p2sh, targets_bech = load_targets(args.file)
    total_targets = len(targets_p2pkh) + len(targets_p2sh) + len(targets_bech)
    if total_targets == 0:
        print("No valid targets found in:", ", ".join(args.file))
        return

    print(f"Loaded {total_targets:,} targets: P2PKH={len(targets_p2pkh):,} P2SH={len(targets_p2sh):,} Bech32={len(targets_bech):,}")
    print(f"Network: {args.network}, Workers: {args.workers}, Batch: {args.batch}, Debug: {debug_mode}")

    # Use spawn for cross-platform stability
    ctx = mp.get_context("spawn")

    stop_event = ctx.Event()
    result_queue = ctx.Queue()

    debug_counters = DebugCounters(args.workers) if debug_mode else None

    # Start debug monitor if requested
    monitor_proc = None
    if debug_mode:
        monitor_proc = ctx.Process(target=debug_monitor, args=(debug_counters, stop_event, debug_interval), daemon=True)
        monitor_proc.start()

    # Start worker processes
    processes = []
    for i in range(args.workers):
        p = ctx.Process(
            target=worker_main,
            args=(i + 1, stop_event, result_queue,
                  targets_p2pkh, targets_p2sh, targets_bech,
                  args.report_every, args.network, args.batch, debug_counters),
            daemon=True
        )
        p.start()
        processes.append(p)

    # Wait for a match (blocks until result or ctrl-c)
    try:
        while True:
            try:
                priv_hex, wif, addr = result_queue.get(timeout=1)
                print("\n=== MATCH FOUND ===")
                print("PRIV")
                print(priv_hex)
                print("WIF")
                print(wif)
                print("ADDRESS")
                print(addr)
                print("===================\n")
                stop_event.set()
                break
            except Exception:
                # no result yet - loop and check stop_event
                if stop_event.is_set():
                    break
                continue
    except KeyboardInterrupt:
        print("\nInterrupted by user — stopping workers")
        stop_event.set()
    finally:
        # Give children a moment to exit cleanly
        for p in processes:
            p.join(timeout=1)
        if monitor_proc is not None:
            monitor_proc.join(timeout=1)
        print("Workers stopped. Exiting.")

if __name__ == "__main__":
    # Ensure spawn method set (safe to call; if already set this is a no-op)
    try:
        mp.set_start_method("spawn")
    except RuntimeError:
        # start method already set in this interpreter; ignore
        pass
    main()