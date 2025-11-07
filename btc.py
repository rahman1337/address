#!/usr/bin/env python3
"""
vanity_loop.py

Vanity Bitcoin address generator:
- Automatically truncates input lines to first N chars for prefix matching
- Continuous looping (does not stop at first match)
- Prints full PRIV, WIF, and ADDRESS for each hit
- Multi-processing and batch generation
- Normal and debug (-d) modes

Requirements:
    pip install coincurve
    pip install base58 (optional for speed)
"""

from __future__ import annotations
import os, sys, time, argparse, hashlib, csv
from multiprocessing import Process, Value, Lock, Event, cpu_count, Manager

try:
    from coincurve import PrivateKey
except Exception:
    print("ERROR: coincurve is required. Install with: pip install coincurve")
    sys.exit(1)

USE_BASE58_LIB = False
try:
    import base58 as _b58
    USE_BASE58_LIB = True
except Exception:
    pass

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
DEFAULT_PROCESSES = max(1, cpu_count())
DEFAULT_BATCH = 100
STATS_INTERVAL = 10.0  # debug interval seconds

# ------------------ helpers ------------------

B58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
def base58check(payload: bytes) -> str:
    if USE_BASE58_LIB:
        return _b58.b58encode_check(payload).decode()
    # fast manual
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(payload + chk, 'big')
    res = bytearray()
    while n:
        n, r = divmod(n, 58)
        res.append(B58_ALPHABET[r])
    pad = 0
    for b in payload:
        if b == 0:
            pad += 1
        else:
            break
    return (B58_ALPHABET[0:1]*pad + bytes(reversed(res))).decode()

def ripemd160(x: bytes) -> bytes:
    h = hashlib.new('ripemd160'); h.update(x); return h.digest()

def hash160(x: bytes) -> bytes:
    return ripemd160(hashlib.sha256(x).digest())

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk=1
    for v in values:
        b = (chk>>25)
        chk = ((chk & 0x1ffffff)<<5) ^ v
        for i in range(5):
            if (b>>i)&1: chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp: str):
    return [ord(x)>>5 for x in hrp] + [0] + [ord(x)&31 for x in hrp]

def bech32_create_checksum(hrp: str, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values+[0]*6)^1
    return [(polymod>>(5*(5-i)))&31 for i in range(6)]

def convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []; maxv=(1<<tobits)-1
    for value in data:
        if value<0 or (value>>frombits): return None
        acc=(acc<<frombits)|value; bits+=frombits
        while bits>=tobits: bits-=tobits; ret.append((acc>>bits)&maxv)
    if pad and bits: ret.append((acc<<(tobits-bits))&maxv)
    elif not pad and (bits>=frombits or ((acc<<(tobits-bits))&maxv)): return None
    return ret

def p2wpkh_bech32_address(hash20: bytes) -> str:
    data = [0]+convertbits(list(hash20),8,5)
    combined = data + bech32_create_checksum('bc', data)
    return 'bc1' + ''.join([CHARSET[d] for d in combined])

def pub_to_p2pkh(pub: bytes) -> str:
    return base58check(b'\x00'+hash160(pub))

def pub_to_p2sh_p2wpkh(pub: bytes) -> str:
    h = hash160(pub)
    redeem = b'\x00\x14'+h
    redeem_hash = ripemd160(hashlib.sha256(redeem).digest())
    return base58check(b'\x05'+redeem_hash)

def pub_to_bech32(pub: bytes) -> str:
    return p2wpkh_bech32_address(hash160(pub))

def priv_to_wif(priv_bytes: bytes) -> str:
    return base58check(b'\x80'+priv_bytes+b'\x01')

def generate_priv_batch(batch_size: int):
    out=[]
    while len(out)<batch_size:
        need=batch_size-len(out)
        chunk=os.urandom(32*max(4,need*2))
        for i in range(0,len(chunk),32):
            priv=chunk[i:i+32]
            v=int.from_bytes(priv,'big')
            if 1<=v<SECP256K1_N:
                out.append(priv)
                if len(out)>=batch_size: break
    return out

def print_found_block(priv_hex, wif, address, target):
    line="="*72
    print(line)
    print(f"FOUND MATCH for prefix: {target}")
    print(line)
    print("PRIV\n", priv_hex, "\n")
    print("WIF\n", wif, "\n")
    print("ADDRESS\n", address)
    print(line)

# ------------------ worker ------------------

def worker_proc(pid, prefixes_by_first, batch_size, checked_counter, errors_counter, found_event, result_proxy, csv_path, csv_lock, stop_event):
    while not stop_event.is_set():
        try:
            privs=generate_priv_batch(batch_size)
            for priv in privs:
                pk=PrivateKey(priv)
                pub=pk.public_key.format(compressed=True)
                addrs=[pub_to_p2pkh(pub), pub_to_p2sh_p2wpkh(pub), pub_to_bech32(pub)]
                for addr in addrs:
                    candidates=prefixes_by_first.get(addr[0], [])
                    for t in candidates:
                        # bech32 lowercase
                        addr_to_check = addr.lower() if addr.startswith('bc1') else addr
                        t_cmp = t.lower() if addr.startswith('bc1') else t
                        if addr_to_check.startswith(t_cmp):
                            priv_hex=priv.hex()
                            wif=priv_to_wif(priv)
                            with csv_lock:
                                with open(csv_path,'a',newline='',encoding='utf-8') as cf:
                                    cw=csv.writer(cf)
                                    cw.writerow([time.time(), t, addr, priv_hex, wif])
                            result_proxy.append((t, addr, priv_hex, wif))
                            print_found_block(priv_hex, wif, addr, t)
                with checked_counter.get_lock(): checked_counter.value+=1
        except Exception:
            with errors_counter.get_lock(): errors_counter.value+=1
            continue

# ------------------ main ------------------

if __name__=="__main__":
    parser=argparse.ArgumentParser(description="vanity_loop.py - prefix-only vanity generator")
    parser.add_argument('targets_file', help='file with full addresses; first N chars used as prefix')
    parser.add_argument('--prefix-length', type=int, default=6, help='number of chars from each line to use as vanity prefix')
    parser.add_argument('--processes', type=int, default=DEFAULT_PROCESSES)
    parser.add_argument('--batch', type=int, default=DEFAULT_BATCH)
    parser.add_argument('-d','--debug', action='store_true')
    parser.add_argument('--no-csv', action='store_true')
    args=parser.parse_args()

    prefix_length=max(1,args.prefix_length)
    prefixes_list=[]
    prefixes_by_first={}
    try:
        with open(args.targets_file,'r',encoding='utf-8') as f:
            for line in f:
                line=line.strip()
                if not line: continue
                prefix=line[:prefix_length]
                prefixes_list.append(prefix)
                prefixes_by_first.setdefault(prefix[0],[]).append(prefix)
    except FileNotFoundError:
        print(f"ERROR: file not found: {args.targets_file}")
        sys.exit(1)

    csv_path="found_hits.csv"
    if not args.no_csv:
        try:
            if not os.path.exists(csv_path) or os.path.getsize(csv_path)==0:
                with open(csv_path,'a',newline='',encoding='utf-8') as cf:
                    cw=csv.writer(cf)
                    cw.writerow(["timestamp","target_prefix","matched_address","priv_hex","wif"])
        except Exception: pass

    manager=Manager()
    result_list=manager.list()
    csv_lock=manager.Lock()
    checked_counter=Value('Q',0)
    errors_counter=Value('Q',0)
    stop_event=Event()
    found_event=Event()

    print("="*72)
    print("Vanity loop generator (prefix-only)")
    print(f"Loaded prefixes: {len(prefixes_list)}")
    print("Starting generation...")
    print("="*72)

    workers=[]
    try:
        for i in range(max(1,args.processes)):
            p=Process(target=worker_proc,args=(i,prefixes_by_first,args.batch,checked_counter,errors_counter,found_event,result_list,csv_path,csv_lock,stop_event))
            p.daemon=True
            p.start()
            workers.append(p)

        start_time=time.time()
        if args.debug:
            try:
                last_checked=0
                last_time=start_time
                while True:
                    time.sleep(STATS_INTERVAL)
                    now=time.time()
                    with checked_counter.get_lock(): checked=checked_counter.value
                    with errors_counter.get_lock(): errors=errors_counter.value
                    delta=checked-last_checked
                    dt=now-last_time if now-last_time>0 else 1.0
                    kps=delta/dt
                    print("="*72)
                    print(f"DEBUG | elapsed {now-start_time:.1f}s | checked: {checked} | keys/s: {kps:.2f} | errors: {errors} | found matches: {len(result_list)}")
                    print("="*72)
                    last_checked=checked
                    last_time=now
            except KeyboardInterrupt:
                print("Interrupted by user. Stopping...")
                stop_event.set()
        else:
            try:
                while True: time.sleep(1)
            except KeyboardInterrupt:
                print("Interrupted by user. Stopping...")
                stop_event.set()
    finally:
        stop_event.set()
        for p in workers:
            if p.is_alive(): p.terminate()
        time.sleep(0.2)

    print("Total keys checked:", checked_counter.value)
    print("Total errors:", errors_counter.value)
    print("Exiting.")
