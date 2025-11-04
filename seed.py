#!/usr/bin/env python3
import os, sys, time, threading, asyncio, random
from hashlib import pbkdf2_hmac

def ensure_import(name,pkg=None):
    try: return __import__(name)
    except Exception:
        import subprocess
        subprocess.check_call([sys.executable,"-m","pip","install",pkg or name])
        return __import__(name)

aiohttp = ensure_import("aiohttp")
base58 = ensure_import("base58")
coincurve = ensure_import("coincurve")
eth_utils = ensure_import("eth_utils")
from eth_utils import to_checksum_address, keccak
ed25519_mod = ensure_import("ed25519")
bip32utils = ensure_import("bip32utils")
from Crypto.Hash import SHA256, RIPEMD160

# ---------------- CONFIG ----------------
ETH_RPC="https://ethereum.publicnode.com"
BSC_RPC="https://bsc.publicnode.com"
POLYGON_RPC="https://polygon.publicnode.com"
SOL_RPC="https://solana.publicnode.com"
SUI_RPC="https://sui.publicnode.com"

SCANNED_FILE="scanned_mnemonics.txt"
FOUND_FILE="found.txt"
SEED_FILE="seed.txt"

LIGHT_GREEN="\033[92m"
RESET_COLOR="\033[0m"
GENERATOR_MODES=['repetitive','sequential','mixed']

scanned_lock=threading.Lock()
found_lock=threading.Lock()
in_memory_scanned=set()
stop_event=threading.Event()

# ---------------- WORDLIST ----------------
with open(SEED_FILE,"r") as f:
    WORDLIST=[w.strip() for w in f if w.strip()]
if len(WORDLIST)!=2048: raise SystemExit("seed.txt must have 2048 words")

if os.path.exists(SCANNED_FILE):
    with open(SCANNED_FILE,"r") as f:
        for l in f: in_memory_scanned.add(l.strip())

# ---------------- HELPERS ----------------
def append_scanned(mnemonic):
    with scanned_lock:
        if mnemonic in in_memory_scanned: return
        with open(SCANNED_FILE,"a") as f: f.write(mnemonic+"\n")
        in_memory_scanned.add(mnemonic)

def append_found(line):
    with found_lock:
        with open(FOUND_FILE,"a") as f: f.write(line+"\n")

def format_found(chain,mnemonic,wif,privhex,address,balance_str):
    border="="*60
    return "\n".join([border,
                      f"MNEMONIC: {mnemonic}",
                      f"WIF: {wif}",
                      f"CHAIN: {chain}",
                      f"PRIVATE_KEY: {privhex}",
                      f"ADDRESS: {address}",
                      f"BALANCE: {LIGHT_GREEN}{balance_str}{RESET_COLOR}",
                      border])

# ---------------- MNEMONICS ----------------
seq_counter=0
rep_index=0
mix_index=0
MIXED_PATTERNS=WORDLIST[:32]

def gen_mnemonic():
    global seq_counter,rep_index,mix_index
    mode=random.choice(GENERATOR_MODES)
    words=[]
    for _ in range(12):
        if mode=="repetitive": words.append(WORDLIST[rep_index%2048]); rep_index+=1
        elif mode=="sequential": words.append(WORDLIST[seq_counter%2048]); seq_counter+=1
        else: words.append(MIXED_PATTERNS[mix_index%32]); mix_index+=1
    return ' '.join(words)

def mnemonic_to_seed(mnemonic):
    return pbkdf2_hmac("sha512",mnemonic.encode(),b"mnemonic",2048)

# ---------------- KEYS ----------------
SECP_N=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def priv_from_seed(seed_bytes):
    val=int.from_bytes(seed_bytes,"big")%(SECP_N-1)+1
    return val.to_bytes(32,"big")

def eth_addr(priv_bytes):
    pk=coincurve.PrivateKey(priv_bytes)
    pub=pk.public_key.format(compressed=False)[1:]
    return to_checksum_address("0x"+keccak(pub)[-20:].hex())

def sol_sui_addr(seed):
    sk=ed25519_mod.SigningKey(seed)
    vk=sk.get_verifying_key()
    return base58.b58encode(bytes(vk)).decode()

def hash160(b): return RIPEMD160.new(SHA256.new(b).digest()).digest()

def btc_addrs(priv_bytes):
    pk=coincurve.PrivateKey(priv_bytes)
    pub=pk.public_key.format(compressed=True)
    h160=hash160(pub)
    legacy=base58.b58encode_check(b"\x00"+h160).decode()
    redeem=b"\x00\x14"+h160
    nested=base58.b58encode_check(b"\x05"+hash160(redeem)).decode()
    bech32="bc1"+base58.b58encode(h160).decode().lower()
    wif=base58.b58encode_check(b"\x80"+priv_bytes+b"\x01").decode()
    return {"legacy":legacy,"nested":nested,"bech32":bech32,"wif":wif}

# ---------------- RPC ----------------
async def rpc_post(url,json_payload,session,max_attempts=3):
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
async def worker(chain,rpc_url="",debug=False):
    async with aiohttp.ClientSession() as session:
        while not stop_event.is_set():
            try:
                mnemonic=gen_mnemonic()
                if mnemonic in in_memory_scanned: continue
                append_scanned(mnemonic)
                seed=mnemonic_to_seed(mnemonic)
                for account_index in range(3):
                    priv=priv_from_seed(seed[:32])
                    privhex=priv.hex()
                    if chain in ["ethereum","bsc","polygon"]:
                        addr=eth_addr(priv)
                        bal_resp=await rpc_post(rpc_url,{"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[addr,"latest"]},session)
                        bal=int(bal_resp.get("result","0"),16) if bal_resp else 0
                        if bal>0: print(format_found(chain,mnemonic,"N/A",privhex,addr,f"{bal/1e18:.18f}"))
                    elif chain=="solana":
                        addr=sol_sui_addr(seed)
                        payload={"jsonrpc":"2.0","id":1,"method":"getBalance","params":[addr,{"commitment":"final"}]}
                        resp=await rpc_post(SOL_RPC,payload,session)
                        bal=resp.get("result",{}).get("value",0) if resp else 0
                        if bal>0: print(format_found(chain,mnemonic,"N/A",privhex,addr,f"{bal} lamports"))
                    elif chain=="sui":
                        addr=sol_sui_addr(seed)
                        payload={"jsonrpc":"2.0","id":1,"method":"sui_getBalance","params":[addr]}
                        resp=await rpc_post(SUI_RPC,payload,session)
                        bal=resp.get("result",0) if resp else 0
                        if bal>0: print(format_found(chain,mnemonic,"N/A",privhex,addr,str(bal)))
                    elif chain=="bitcoin":
                        addrs=btc_addrs(priv)
                        for atype in ["legacy","nested","bech32"]:
                            addr=addrs[atype]
                            try:
                                async with session.get(f"https://blockchain.info/q/getreceivedbyaddress/{addr}") as r:
                                    ever=int(await r.text())
                                if ever>0:
                                    async with session.get(f"https://blockchain.info/q/addressbalance/{addr}") as r:
                                        bal=int(await r.text())
                                    if bal>0:
                                        print(format_found(chain,mnemonic,addrs["wif"],privhex,addr,f"{bal/1e8:.8f} BTC"))
                            except Exception as e: print(f"[error][bitcoin] {e}")
            except Exception as e:
                print(f"[error][{chain}] Unexpected: {e}")
            await asyncio.sleep(0.02)

# ---------------- THREADS ----------------
def run_async(coro,*args): asyncio.run(coro(*args))

def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("-d","--debug",action="store_true")
    args=parser.parse_args()
    debug=args.debug

    open(SCANNED_FILE,"a").close()
    open(FOUND_FILE,"a").close()

    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=6) as ex:
        ex.submit(run_async,worker,"ethereum",ETH_RPC,debug)
        ex.submit(run_async,worker,"bsc",BSC_RPC,debug)
        ex.submit(run_async,worker,"polygon",POLYGON_RPC,debug)
        ex.submit(run_async,worker,"solana",SOL_RPC,debug)
        ex.submit(run_async,worker,"sui",SUI_RPC,debug)
        ex.submit(run_async,worker,"bitcoin","",debug)

        try:
            while not stop_event.is_set(): time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, shutting down...")
            stop_event.set()
            time.sleep(0.2)
    print("[info] Scanner stopped. Goodbye.")

if __name__=="__main__":
    main()
