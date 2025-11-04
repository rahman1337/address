#!/usr/bin/env python3
import os
import sys
import time
import threading
import asyncio
import random
from hashlib import pbkdf2_hmac
from concurrent.futures import ThreadPoolExecutor

# ---------------- IMPORTS ----------------
def ensure_import(name, package=None):
    try:
        return __import__(name)
    except Exception:
        pkg = package or name
        import subprocess
        subprocess.check_call([sys.executable,"-m","pip","install",pkg])
        return __import__(name)

aiohttp = ensure_import("aiohttp")
base58 = ensure_import("base58")
coincurve = ensure_import("coincurve")
from coincurve.utils import int_to_bytes_padded
eth_utils = ensure_import("eth_utils")
from eth_utils import to_checksum_address, keccak
bip32utils = ensure_import("bip32utils")
ed25519_mod = ensure_import("ed25519")
from Crypto.Hash import SHA256, RIPEMD160

# ---------------- CONFIG ----------------
ETH_RPC = "https://ethereum.publicnode.com"
BSC_RPC = "https://bsc.publicnode.com"
POLYGON_RPC = "https://polygon.publicnode.com"
SOL_RPC = "https://solana.publicnode.com"
SUI_RPC = "https://sui.publicnode.com"

SCANNED_FILE = "scanned_mnemonics.txt"
FOUND_FILE = "found.txt"
SEED_FILE = "seed.txt"

LIGHT_GREEN="\033[92m"
RESET_COLOR="\033[0m"
HARDENED = 0x80000000
GENERATOR_MODES = ['repetitive','sequential','mixed']

# ---------------- STATE ----------------
scanned_lock = threading.Lock()
found_lock = threading.Lock()
in_memory_scanned = set()
stop_event = threading.Event()

# ---------------- LOAD WORDLIST ----------------
with open(SEED_FILE,"r",encoding="utf-8") as f:
    WORDLIST=[w.strip() for w in f if w.strip()]
if len(WORDLIST)!=2048: raise SystemExit("seed.txt must have 2048 words")

if os.path.exists(SCANNED_FILE):
    with open(SCANNED_FILE,"r",encoding="utf-8") as f:
        for l in f: l=l.strip(); in_memory_scanned.add(l) if l else None

# ---------------- HELPERS ----------------
def append_scanned(mnemonic):
    with scanned_lock:
        if mnemonic in in_memory_scanned: return
        with open(SCANNED_FILE,"a") as f: f.write(mnemonic+"\n")
        in_memory_scanned.add(mnemonic)

def append_found(line):
    with found_lock:
        with open(FOUND_FILE,"a") as f: f.write(line+"\n")

def format_found_block(chain,mnemonic,privhex,address,balance_str,wif="N/A"):
    border="="*60
    return "\n".join([
        border,
        f"MNEMONIC: {mnemonic}",
        f"WIF: {wif}",
        f"CHAIN: {chain}",
        f"PRIVATE_KEY: {privhex}",
        f"ADDRESS: {address}",
        f"BALANCE: {LIGHT_GREEN}{balance_str}{RESET_COLOR}",
        border
    ])

# ---------------- MNEMONIC GENERATORS ----------------
sequential_counter = 0
repetitive_index = 0
mixed_index = 0
MIXED_PATTERNS = WORDLIST[:32]

def gen_mnemonic():
    global sequential_counter, repetitive_index, mixed_index
    mode = random.choice(GENERATOR_MODES)
    words=[]
    for _ in range(12):
        if mode=='repetitive': words.append(WORDLIST[repetitive_index%len(WORDLIST)]); repetitive_index+=1
        elif mode=='sequential': words.append(WORDLIST[sequential_counter%len(WORDLIST)]); sequential_counter+=1
        else: words.append(MIXED_PATTERNS[mixed_index%len(MIXED_PATTERNS)]); mixed_index+=1
    return ' '.join(words)

def mnemonic_to_seed(mnemonic: str) -> bytes:
    return pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048)

# ---------------- KEY DERIVATIONS ----------------
def valid_secp256k1_privkey(seed_bytes: bytes) -> bytes:
    n = coincurve.PrivateKey().public_key.curve.order
    key_int=int.from_bytes(seed_bytes,"big")%(n-1)+1
    return int_to_bytes_padded(key_int,32)

def derive_eth_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub = pk.public_key.format(compressed=False)[1:]
    return to_checksum_address("0x"+keccak(pub)[-20:].hex())

def derive_solana_address(seed: bytes):
    sk = ed25519_mod.SigningKey(seed)
    vk = sk.get_verifying_key()
    pub_bytes = bytes(vk)
    return base58.b58encode(pub_bytes).decode()

def hash160(b: bytes) -> bytes:
    return RIPEMD160.new(SHA256.new(b).digest()).digest()

def btc_addresses(priv_bytes: bytes):
    pk = coincurve.PrivateKey(priv_bytes)
    pub = pk.public_key.format(compressed=True)
    h160 = hash160(pub)
    legacy = base58.b58encode_check(b"\x00"+h160).decode()
    redeem = b"\x00\x14"+h160
    nested = base58.b58encode_check(b"\x05"+hash160(redeem)).decode()
    bech32 = "bc1"+base58.b58encode(h160).decode().lower()
    wif = base58.b58encode_check(b"\x80"+priv_bytes+b"\x01").decode()
    return {"legacy":legacy,"nested":nested,"bech32":bech32,"wif":wif}

# ---------------- RPC ----------------
async def rpc_post_with_retry(url,json_payload,session,max_attempts=3):
    for i in range(max_attempts):
        try:
            async with session.post(url,json=json_payload,timeout=15) as r:
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            print(f"[error] RPC attempt {i+1}/{max_attempts} failed: {e}")
            await asyncio.sleep(i+1)
    return None

# ---------------- WORKER ----------------
async def worker_chain(chain_name,rpc_url,debug=False):
    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            try:
                mnemonic = gen_mnemonic()
                if mnemonic in in_memory_scanned: continue
                append_scanned(mnemonic)
                seed = mnemonic_to_seed(mnemonic)
                for account_index in range(3):
                    priv = valid_secp256k1_privkey(seed[:32])
                    privhex = priv.hex()
                    if chain_name in ["ethereum","bsc","polygon"]:
                        addr = derive_eth_address(priv)
                        balance = await rpc_post_with_retry(rpc_url,{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[addr,"latest"]},session)
                        bal_val=int(balance.get("result","0"),16) if balance else 0
                        if bal_val>0: print(format_found_block(chain_name,mnemonic,privhex,addr,f"{bal_val/1e18:.18f}",wif="N/A"))
                    elif chain_name=="solana":
                        addr = derive_solana_address(seed)
                        payload={"jsonrpc":"2.0","id":1,"method":"getBalance","params":[addr,{"commitment":"final"}]}
                        resp = await rpc_post_with_retry(SOL_RPC,payload,session)
                        bal_val=int(resp.get("result",{}).get("value",0)) if resp else 0
                        if bal_val>0: print(format_found_block(chain_name,mnemonic,privhex,addr,f"{bal_val} lamports",wif="N/A"))
                    elif chain_name=="sui":
                        addr = derive_solana_address(seed)
                        payload={"jsonrpc":"2.0","id":1,"method":"sui_getBalance","params":[addr]}
                        resp = await rpc_post_with_retry(SUI_RPC,payload,session)
                        bal_val=resp.get("result",0) if resp else 0
                        if bal_val>0: print(format_found_block(chain_name,mnemonic,privhex,addr,f"{bal_val}",wif="N/A"))
                    elif chain_name=="bitcoin":
                        addrs = btc_addresses(priv)
                        for atype in ["legacy","nested","bech32"]:
                            addr = addrs[atype]
                            try:
                                async with session.get(f"https://blockchain.info/q/getreceivedbyaddress/{addr}") as r:
                                    ever_received=int(await r.text())
                                if ever_received>0:
                                    async with session.get(f"https://blockchain.info/q/addressbalance/{addr}") as r:
                                        bal_val=int(await r.text())
                                    if bal_val>0:
                                        print(format_found_block(chain_name,mnemonic,privhex,addr,f"{bal_val/1e8:.8f} BTC",wif=addrs["wif"]))
                            except Exception as e:
                                print(f"[error][bitcoin] {e}")
            except Exception as e:
                print(f"[error][{chain_name}] Unexpected: {e}")
            await asyncio.sleep(0.02)

# ---------------- THREAD RUNNER ----------------
def run_async_worker(coro,*args):
    try: asyncio.run(coro(*args))
    except Exception as e: print(f"[worker][fatal] {e}")

# ---------------- MAIN ----------------
def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-d","--debug",action="store_true")
    args = parser.parse_args()
    debug = args.debug

    open(SCANNED_FILE,"a").close()
    open(FOUND_FILE,"a").close()

    with ThreadPoolExecutor(max_workers=6) as ex:
        ex.submit(run_async_worker,worker_chain,"ethereum",ETH_RPC,debug)
        ex.submit(run_async_worker,worker_chain,"bsc",BSC_RPC,debug)
        ex.submit(run_async_worker,worker_chain,"polygon",POLYGON_RPC,debug)
        ex.submit(run_async_worker,worker_chain,"solana",SOL_RPC,debug)
        ex.submit(run_async_worker,worker_chain,"sui",SUI_RPC,debug)
        ex.submit(run_async_worker,worker_chain,"bitcoin",None,debug)
        try:
            while not stop_event.is_set(): time.sleep(0.5)
        except KeyboardInterrupt:
            stop_event.set()
            time.sleep(0.2)
    print("[info] Scanner stopped.")

if __name__=="__main__":
    main()
