#!/usr/bin/env python3
import argparse
import json
import signal
import sys
import threading
import time
from typing import Tuple

import requests
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160

SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ---- hash/base58/bech32 helpers ----
def sha256(b: bytes) -> bytes:
    return SHA256.new(b).digest() if hasattr(SHA256.new(), 'update') else SHA256.new(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = RIPEMD160.new()
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def base58_encode(b: bytes) -> str:
    zeros = 0
    for c in b:
        if c == 0:
            zeros += 1
        else:
            break
    num = int.from_bytes(b, "big")
    chars = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(BASE58_ALPHABET[rem])
    return "1"*zeros + "".join(reversed(chars)) if chars else "1"*zeros

def base58check_encode(payload: bytes) -> str:
    chk = sha256(sha256(payload))[:4]
    return base58_encode(payload + chk)

def privkey_to_wif(priv_bytes: bytes, compressed: bool = False) -> str:
    prefix = b"\x80"
    payload = prefix + priv_bytes
    if compressed:
        payload += b'\x01'
    return base58check_encode(payload)

# ---- bech32 helpers (BIP-173) ----
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk=1
    for v in values:
        b=(chk >> 25) & 0xFF
        chk=((chk & 0x1FFFFFF)<<5)^v
        for i in range(5):
            if (b>>i)&1:
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp: str):
    return [ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]

def bech32_create_checksum(hrp: str, data: bytes):
    values=bech32_hrp_expand(hrp)+list(data)+[0,0,0,0,0,0]
    polymod=bech32_polymod(values)^1
    return bytes([(polymod >> (5*(5-i))) & 31 for i in range(6)])

def bech32_encode(hrp: str, data: bytes) -> str:
    combined=bytes(list(data)+list(bech32_create_checksum(hrp, data)))
    return hrp+'1'+''.join([BECH32_CHARSET[b] for b in combined])

def convertbits(data: bytes, frombits: int, tobits: int, pad: bool=True) -> bytes:
    acc=0; bits=0; ret=[]; maxv=(1<<tobits)-1
    for b in data:
        if b>>frombits: raise ValueError
        acc=(acc<<frombits)|b; bits+=frombits
        while bits>=tobits: bits-=tobits; ret.append((acc>>bits)&maxv)
    if pad:
        if bits: ret.append((acc<<(tobits-bits))&maxv)
    else:
        if bits>=frombits or ((acc<<(tobits-bits))&maxv): raise ValueError
    return bytes(ret)

def bech32_p2wpkh_from_h160(h160: bytes) -> str:
    version=0; data=bytes([version])+convertbits(h160,8,5); return bech32_encode('bc', data)

# ---- address builders ----
def p2pkh(pub: bytes) -> str: return base58check_encode(b'\x00'+hash160(pub))
def p2sh_p2wpkh(pub: bytes) -> str: return base58check_encode(b'\x05'+hash160(b'\x00\x14'+hash160(pub)))
def p2wpkh_bech32(pub: bytes) -> str: return bech32_p2wpkh_from_h160(hash160(pub))

# ---- deterministic index provider (thread-safe) ----
class IndexProvider:
    def __init__(self,start=1): self._lock=threading.Lock(); self._i=start
    def next_index(self):
        with self._lock:
            val=self._i; self._i+=1
            if self._i>=SECP256K1_ORDER: self._i=1
            return val

# ---- network checker with retry ----
class AddrChecker:
    def __init__(self, session, debug=False, timeout=10.0): self.session=session; self.debug=debug; self.timeout=timeout
    def _get(self, url, retries=3):
        last_exc=None
        for attempt in range(1,retries+1):
            try: r=self.session.get(url,timeout=self.timeout)
            except Exception as e: last_exc=e; r=None
            else:
                if self.debug: print(f"[DEBUG] GET {url} -> {r.status_code} {r.reason}",flush=True)
                if r.status_code==200: return r
                else: last_exc=RuntimeError(f"HTTP {r.status_code}")
            if attempt<retries: time.sleep(0.5)
        raise last_exc
    def get_received(self,address): return int(self._get(f"https://blockchain.info/q/getreceivedbyaddress/{address}").text.strip())
    def get_balance(self,address): return int(self._get(f"https://blockchain.info/q/addressbalance/{address}").text.strip())

# ---- checkpoint globals ----
stop_event=threading.Event()
last_priv_hex=None
last_priv_lock=threading.Lock()

# ---- worker thread ----
def worker(name,idx_provider,checker,print_lock,debug):
    global last_priv_hex
    session=checker.session
    while not stop_event.is_set():
        idx=idx_provider.next_index()
        priv_bytes=idx.to_bytes(32,'big'); priv_hex=priv_bytes.hex()
        with last_priv_lock: last_priv_hex=priv_hex
        try:
            pk=PrivateKey(priv_bytes)
            pubc=pk.public_key.format(compressed=True)
            wif=privkey_to_wif(priv_bytes,True)
            addresses=[p2pkh(pubc), p2sh_p2wpkh(pubc), p2wpkh_bech32(pubc)]
            if debug:
                with print_lock: print(f"[{name}] scanning idx={idx} priv={priv_hex}",flush=True)
            for addr in addresses:
                if stop_event.is_set(): break
                try: recvd=checker.get_received(addr)
                except Exception as e:
                    with print_lock: print(f"[ERROR] [{name}] addr={addr} getreceived FAILED: {e}",flush=True)
                    time.sleep(0.5)
                    continue
                if recvd!=0:
                    try: bal=checker.get_balance(addr)
                    except Exception as e:
                        with print_lock: print(f"{wif}\n{addr}\n{recvd}\nBALANCE_CHECK_FAILED: {e}",flush=True)
                    else:
                        with print_lock: print(f"{wif}\n{addr}\n{recvd}\n{bal}",flush=True)
                time.sleep(0.5)
        except Exception as e:
            with print_lock: print(f"[ERROR] [{name}] idx={idx} failed: {e}",flush=True); time.sleep(0.5)
    if debug:
        with print_lock: print(f"[{name}] exiting",flush=True)

# ---- main ----
def parse_args():
    p=argparse.ArgumentParser()
    p.add_argument("-t","--threads",type=int,default=3)
    p.add_argument("-d","--debug",action="store_true")
    p.add_argument("--start",type=int,default=1)
    return p.parse_args()

def main():
    global last_priv_hex
    args=parse_args()
    idx_provider=IndexProvider(start=args.start)
    session=requests.Session()
    checker=AddrChecker(session,debug=args.debug)
    print_lock=threading.Lock()
    threads=[]
    # signal handler
    def _signal_handler(sig,frame):
        stop_event.set()
        with last_priv_lock:
            hex_checkpoint=last_priv_hex
        if hex_checkpoint:
            print("\n[INFO] Interrupted by user.\n[INFO] Last private key hex tried (checkpoint):",flush=True)
            print(hex_checkpoint,flush=True)
        else:
            print("\n[INFO] Interrupted by user. No key processed yet.",flush=True)
    signal.signal(signal.SIGINT,_signal_handler)
    signal.signal(signal.SIGTERM,_signal_handler)
    # start threads
    for i in range(args.threads):
        t=threading.Thread(target=worker,args=(f"worker-{i+1}",idx_provider,checker,print_lock,args.debug),daemon=True)
        threads.append(t); t.start()
    try:
        while any(t.is_alive() for t in threads): time.sleep(0.5)
    except KeyboardInterrupt:
        stop_event.set()
        with last_priv_lock:
            hex_checkpoint=last_priv_hex
        if hex_checkpoint:
            print("\n[INFO] Interrupted by user.\n[INFO] Last private key hex tried (checkpoint):",flush=True)
            print(hex_checkpoint,flush=True)
        else:
            print("\n[INFO] Interrupted by user. No key processed yet.",flush=True)
    for t in threads: t.join(timeout=1.0)
    print("[INFO] All workers stopped. Exiting.",flush=True)

if __name__=="__main__": main()