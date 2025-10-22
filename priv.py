#!/usr/bin/env python3
# Multi-chain scanner: BTC (all types) + ETH + BNB + Polygon
# Requirements: pip install coincurve pysha3 web3 requests pycryptodome

import argparse, time, threading, sys, signal, random
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal, getcontext
import requests
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160
import sha3
from web3 import Web3
import bech32  # pip install bech32

getcontext().prec = 40

# -------------------------
# Constants & defaults
# -------------------------
SECP256K1_ORDER = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

GREEN = "\033[92m"
RED   = "\033[91m"
RESET = "\033[0m"

DEFAULT_RPCS = {
    "eth":"https://ethereum.publicnode.com",
    "bsc":"https://bsc-dataseed.binance.org/",
    "polygon":"https://polygon-rpc.com/"
}

CHAIN_SYMBOL = {"eth":"ETH","bsc":"BNB","polygon":"MATIC"}

# -------------------------
# Utility functions
# -------------------------
def sha256_bytes(b): return SHA256.new(b).digest()
def ripemd160_bytes(b): return RIPEMD160.new(b).digest()
def hash160(b): return ripemd160_bytes(sha256_bytes(b))

def base58_encode(b):
    zeros=0
    for c in b:
        if c==0: zeros+=1
        else: break
    num=int.from_bytes(b,"big")
    chars=[]
    while num>0:
        num,rem=divmod(num,58)
        chars.append(BASE58_ALPHABET[rem])
    return "1"*zeros+"".join(reversed(chars)) if chars else "1"*zeros

def base58check_encode(payload):
    chk=sha256_bytes(sha256_bytes(payload))[:4]
    return base58_encode(payload+chk)

def privkey_to_wif(priv_bytes, compressed=True):
    p=b"\x80"+priv_bytes
    if compressed: p+=b"\x01"
    return base58check_encode(p)

def evm_address_from_priv(priv_bytes):
    pk=PrivateKey(priv_bytes)
    pub_uncompressed=pk.public_key.format(compressed=False)[1:]
    k=sha3.keccak_256()
    k.update(pub_uncompressed)
    return "0x"+k.digest()[-20:].hex()

# -------------------------
# Index provider
# -------------------------
class IndexProvider:
    def __init__(self,start=1):
        self._lock=threading.Lock()
        self._i=start
    def next_index(self):
        with self._lock:
            val=self._i
            self._i+=1
            if self._i>=SECP256K1_ORDER: self._i=1
            return val

# -------------------------
# BTC checker
# -------------------------
class BTCChecker:
    def __init__(self, session, debug=False):
        self.session=session
        self.debug=debug

    def get_received(self, addr):
        url=f"https://blockchain.info/q/getreceivedbyaddress/{addr}"
        for attempt in range(3):
            try:
                r=self.session.get(url,timeout=10)
                if self.debug: print(f"[DEBUG] GET {url} -> {GREEN if r.status_code==200 else RED}{r.status_code}{RESET}",flush=True)
                r.raise_for_status()
                return int(r.text)
            except Exception as e:
                time.sleep(1.0)
                if self.debug: print(f"[DEBUG] attempt {attempt+1} failed for get_received: {e}",flush=True)
        return 0

    def get_balance(self, addr):
        time.sleep(1.1 + random.random()*0.4)
        url=f"https://blockchain.info/q/addressbalance/{addr}"
        for attempt in range(3):
            try:
                r=self.session.get(url,timeout=10)
                if self.debug: print(f"[DEBUG] GET {url} -> {GREEN if r.status_code==200 else RED}{r.status_code}{RESET}",flush=True)
                r.raise_for_status()
                return int(r.text)
            except Exception as e:
                time.sleep(1.0)
                if self.debug: print(f"[DEBUG] attempt {attempt+1} failed for get_balance: {e}",flush=True)
        return 0

# -------------------------
# EVM checker
# -------------------------
class EVMChecker:
    def __init__(self, web3, debug=False):
        self.web3=web3
        self.debug=debug
    def get_native_balance(self, addr):
        try:
            b=self.web3.eth.get_balance(addr)
            if self.debug: print(f"[DEBUG] {self.web3.provider.endpoint_uri} balance {addr} -> {GREEN}{b}{RESET}",flush=True)
            return b
        except Exception as e:
            if self.debug: print(f"[DEBUG] {self.web3.provider.endpoint_uri} balance error {addr}: {RED}{e}{RESET}",flush=True)
            return 0

# -------------------------
# BTC addresses derivation
# -------------------------
def make_btc_addresses(pub_compressed):
    p2pkh=base58check_encode(b"\x00"+hash160(pub_compressed))
    redeem=b"\x00\x14"+hash160(pub_compressed)
    p2sh=base58check_encode(b"\x05"+hash160(redeem))
    # Bech32 P2WPKH bc1q
    h=hash160(pub_compressed)
    bc1q_addr=bech32.bech32_encode("bc", 0, h)
    # Taproot P2TR bc1p
    sha=sha256_bytes(pub_compressed)
    bc1p_addr=bech32.bech32_encode("bc", 1, sha)
    return p2pkh,p2sh,bc1q_addr,bc1p_addr

# -------------------------
# Worker thread
# -------------------------
stop_event=threading.Event()
last_priv_hex=None
last_priv_lock=threading.Lock()

def worker_thread(name, idx_provider, chains, btc_checker, evm_checkers, web3s, debug):
    global last_priv_hex
    while not stop_event.is_set():
        idx=idx_provider.next_index()
        priv_bytes=idx.to_bytes(32,"big")
        priv_hex=priv_bytes.hex()
        with last_priv_lock: last_priv_hex=priv_hex
        try:
            pk=PrivateKey(priv_bytes)
            pub_comp=pk.public_key.format(compressed=True)
            wif=privkey_to_wif(priv_bytes)

            # --- BTC ---
            if "btc" in chains:
                p2pkh,p2sh,bc1q,bc1p=make_btc_addresses(pub_comp)
                for addr in (p2pkh,p2sh,bc1q,bc1p):
                    if stop_event.is_set(): break
                    received=btc_checker.get_received(addr)
                    if received>0:
                        bal=btc_checker.get_balance(addr)
                        human=Decimal(bal)/Decimal(1e8)
                        print("\n"+"="*72)
                        print(f"!!!!! FOUND BTC ADDRESS WITH FUNDS !!!!!")
                        print("WIF:",wif)
                        print("Address:",addr)
                        print(f"Balance: {GREEN}{human}{RESET} BTC")
                        print("="*72+"\n")
                    time.sleep(0.6+random.random()*0.4)

            # --- EVM chains ---
            evm_addr=evm_address_from_priv(priv_bytes)
            for ch in chains:
                if ch=="btc": continue
                w3=web3s.get(ch)
                checker=evm_checkers.get(ch)
                if not w3 or not checker: continue
                try:
                    addr_checksum=w3.toChecksumAddress(evm_addr)
                except: continue
                native_bal=checker.get_native_balance(addr_checksum)
                if native_bal>0:
                    human=Decimal(native_bal)/Decimal(1e18)
                    print("\n"+"="*72)
                    print(f"!!!!! FOUND {ch.upper()} PRIVATE KEY WITH FUNDS !!!!!")
                    print("PrivKey (hex):",priv_hex)
                    print("Address:",addr_checksum)
                    sym=CHAIN_SYMBOL.get(ch,ch.upper())
                    print(f"Native balance: {GREEN}{human}{RESET} {sym}")
                    print("="*72+"\n")
                time.sleep(0.6+random.random()*0.4)

        except Exception as e:
            if debug: print(f"[DEBUG] Worker error idx={idx}: {RED}{e}{RESET}",flush=True)
            time.sleep(0.6+random.random()*0.4)

# -------------------------
# Main
# -------------------------
def parse_args():
    p=argparse.ArgumentParser()
    p.add_argument("-t","--threads",type=int,default=4)
    p.add_argument("--chains",type=str,default="btc,eth,bsc,polygon")
    p.add_argument("--start",type=int,default=1)
    p.add_argument("-d","--debug",action="store_true")
    return p.parse_args()

def main():
    args=parse_args()
    chains=[c.strip().lower() for c in args.chains.split(",")]

    idx_provider=IndexProvider(start=args.start)
    session=requests.Session()
    btc_checker=BTCChecker(session,debug=args.debug)

    web3s={}
    evm_checkers={}
    for c in chains:
        if c=="btc": continue
        rpc=DEFAULT_RPCS.get(c)
        w3=Web3(Web3.HTTPProvider(rpc))
        web3s[c]=w3
        evm_checkers[c]=EVMChecker(w3,debug=args.debug)

    def _signal(sig,frame):
        stop_event.set()
        with last_priv_lock: cp=last_priv_hex
        print("\n[INFO] Interrupted. Last private key hex:",cp if cp else "None")

    signal.signal(signal.SIGINT,_signal)
    signal.signal(signal.SIGTERM,_signal)

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        for i in range(args.threads):
            ex.submit(worker_thread,f"worker-{i+1}",idx_provider,chains,btc_checker,evm_checkers,web3s,args.debug)

    while not stop_event.is_set(): time.sleep(0.5)
    print("[INFO] All workers stopped. Exiting.")

if __name__=="__main__":
    main()