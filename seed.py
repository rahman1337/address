#!/usr/bin/env python3
"""
6-chain mnemonic scanner with blockchain.info for BTC, Solana/Sui fixed
"""
import os, sys, time, threading, asyncio, random, struct, traceback
from hashlib import pbkdf2_hmac
from concurrent.futures import ThreadPoolExecutor

def ensure_import(name, package=None):
    try: return __import__(name)
    except Exception:
        pkg = package or name
        print(f"[setup] installing '{pkg}'...", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable,"-m","pip","install",pkg])
        return __import__(name)

# Third-party
aiohttp = ensure_import("aiohttp")
base58 = ensure_import("base58")
coincurve = ensure_import("coincurve")
eth_utils = ensure_import("eth_utils")
from eth_utils import to_checksum_address, keccak
bip32utils = ensure_import("bip32utils")
ed25519_mod = ensure_import("ed25519")
Crypto = ensure_import("Crypto")
from Crypto.Hash import SHA256, RIPEMD160

# ---------------- Config ----------------
ETH_RPC="https://ethereum.publicnode.com"
BSC_RPC="https://bsc.publicnode.com"
POLYGON_RPC="https://polygon.publicnode.com"
SOL_RPC="https://solana.publicnode.com"
SUI_RPC="https://sui.publicnode.com"

SCANNED_FILE="scanned_mnemonics.txt"
FOUND_FILE="found.txt"
SEED_FILE="seed.txt"  # 2048 words, one per line

# ---------------- State ----------------
scanned_lock = threading.Lock()
found_lock = threading.Lock()
in_memory_scanned = set()
stop_event = threading.Event()

LIGHT_GREEN="\033[92m"
RESET_COLOR="\033[0m"

# ---------------- Load wordlist ----------------
if not os.path.exists(SEED_FILE):
    raise SystemExit(f"'{SEED_FILE}' not found.")
with open(SEED_FILE,"r",encoding="utf-8") as f:
    WORDLIST=[w.strip() for w in f.readlines() if w.strip()]
if len(WORDLIST)!=2048:
    raise SystemExit("seed.txt must contain exactly 2048 words (BIP39 English wordlist).")

# Load scanned mnemonics
if os.path.exists(SCANNED_FILE):
    try:
        with open(SCANNED_FILE,"r",encoding="utf-8") as f:
            for ln in f: s=ln.strip(); in_memory_scanned.add(s) if s else None
    except Exception as e:
        print(f"[warn] Could not load {SCANNED_FILE}: {e}", file=sys.stderr)

# ---------------- Helpers ----------------
def append_scanned(mnemonic: str):
    with scanned_lock:
        if mnemonic in in_memory_scanned: return
        with open(SCANNED_FILE,"a",encoding="utf-8") as f: f.write(mnemonic+"\n")
        in_memory_scanned.add(mnemonic)

def append_found(line: str):
    with found_lock:
        with open(FOUND_FILE,"a",encoding="utf-8") as f: f.write(line+"\n")

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

# ---------------- Mnemonic generator ----------------
GENERATOR_MODES=['repetitive','sequential','mixed']
sequential_counter=0
repetitive_index=0
mixed_index=0
MIXED_PATTERNS=WORDLIST[:32]

def gen_mnemonic():
    global sequential_counter,repetitive_index,mixed_index
    mode=random.choice(GENERATOR_MODES)
    words=[]
    for _ in range(12):
        if mode=='repetitive': words.append(WORDLIST[repetitive_index%len(WORDLIST)]); repetitive_index+=1
        elif mode=='sequential': words.append(WORDLIST[sequential_counter%len(WORDLIST)]); sequential_counter+=1
        else: words.append(MIXED_PATTERNS[mixed_index%len(MIXED_PATTERNS)]); mixed_index+=1
    return ' '.join(words)

def mnemonic_to_seed(mnemonic: str) -> bytes:
    return pbkdf2_hmac("sha512", mnemonic.encode(), b"mnemonic", 2048)

HARDENED=0x80000000

def derive_secp256k1_bip44(seed: bytes, coin_type: int, indices=(0,1,2)):
    master=bip32utils.BIP32Key.fromEntropy(seed)
    for i in indices:
        k=master.ChildKey(44+HARDENED).ChildKey(coin_type+HARDENED).ChildKey(0+HARDENED).ChildKey(i)
        yield k.PrivateKey(), k

def btc_priv_to_addresses(priv_bytes: bytes):
    pk=coincurve.PrivateKey(priv_bytes)
    pub=pk.public_key.format(compressed=True)
    h160=RIPEMD160.new(SHA256.new(pub).digest()).digest()
    addr1=base58.b58encode_check(b"\x00"+h160).decode()
    redeem_script=b"\x00\x14"+h160
    redeem_h160=RIPEMD160.new(SHA256.new(redeem_script).digest()).digest()
    addr3=base58.b58encode_check(b"\x05"+redeem_h160).decode()
    CHARSET="qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    def bech32_polymod(values):
        GENERATORS=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
        chk=1
        for v in values:
            top=chk>>25
            chk=((chk&0x1ffffff)<<5)^v
            for i in range(5):
                if (top>>i)&1: chk^=GENERATORS[i]
        return chk
    def bech32_hrp_expand(hrp):
        return [ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]
    def bech32_create_checksum(hrp,data):
        values=bech32_hrp_expand(hrp)+data
        polymod=bech32_polymod(values+[0]*6)^1
        return [(polymod>>5*(5-i))&31 for i in range(6)]
    def convertbits(data,frombits,tobits,pad=True):
        acc=0; bits=0; ret=[]
        maxv=(1<<tobits)-1
        for v in data:
            if v<0 or v>>(frombits): return None
            acc=(acc<<frombits)|v
            bits+=frombits
            while bits>=tobits: bits-=tobits; ret.append((acc>>bits)&maxv)
        if pad and bits: ret.append((acc<<(tobits-bits))&maxv)
        return ret
    data=[0]+convertbits(h160,8,5)
    def bech32_encode(hrp,data):
        combined=data+bech32_create_checksum(hrp,data)
        return hrp+"1"+"".join([CHARSET[d] for d in combined])
    addrbc1=bech32_encode("bc",data)
    wif=base58.b58encode_check(b"\x80"+priv_bytes+b"\x01").decode()
    return {"legacy":addr1,"nested":addr3,"bech32":addrbc1,"wif":wif}

def eth_address_from_priv(priv_bytes: bytes) -> str:
    pk=coincurve.PrivateKey(priv_bytes)
    pub=pk.public_key.format(compressed=False)[1:]
    return to_checksum_address("0x"+pub.hex())

# ---------------- Bitcoin blockchain.info ----------------
async def btc_received_before(address, debug=False):
    url=f"https://blockchain.info/q/getreceivedbyaddress/{address}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url,timeout=10) as r:
                text=await r.text()
                return int(text)
    except Exception as e:
        if debug: print(f"[warn][btc] received check failed: {e}")
        return 0

async def btc_balance(address, debug=False):
    url=f"https://blockchain.info/q/addressbalance/{address}"
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url,timeout=10) as r:
                text=await r.text()
                return int(text)
    except Exception as e:
        if debug: print(f"[warn][btc] balance check failed: {e}")
        return 0

# ---------------- RPC Helper ----------------
async def rpc_post_with_retries(url: str, json_payload: dict, session:aiohttp.ClientSession, debug=False):
    last_exc=None
    backoff=[1,2,3]
    for attempt in range(3):
        try:
            async with session.post(url,json=json_payload,timeout=15) as r:
                text=await r.text()
                if debug: print(f"[debug][rpc] POST {url} payload={json_payload} status={r.status} resp={text}")
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            last_exc=e
            print(f"[warn][{url}] attempt {attempt+1}/3 failed: {e}")
            await asyncio.sleep(backoff[attempt])
    raise last_exc

# ---------------- Eth-like balance ----------------
async def eth_like_get_balance(rpc_url,address,session,debug=False):
    payload={"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[address,"latest"]}
    j=await rpc_post_with_retries(rpc_url,payload,session,debug)
    if "error" in j: raise RuntimeError(f"RPC error: {j['error']}")
    return int(j.get("result",0),16)

# ---------------- Solana / Sui ----------------
async def solana_get_balance(rpc_url,address,session,debug=False):
    payload={"jsonrpc":"2.0","id":1,"method":"getBalance","params":[address,{"commitment":"final"}]}
    j=await rpc_post_with_retries(rpc_url,payload,session,debug)
    if "error" in j: raise RuntimeError(f"RPC error: {j['error']}")
    return int(j.get("result",{}).get("value",0))

async def sui_get_balance(rpc_url,address,session,debug=False):
    payload={"jsonrpc":"2.0","id":1,"method":"sui_getBalance","params":[address]}
    j=await rpc_post_with_retries(rpc_url,payload,session,debug)
    if "error" in j: raise RuntimeError(f"RPC error: {j['error']}")
    return int(j.get("result",{}).get("totalBalance",0))

# ---------------- Worker ----------------
async def worker_chain(chain_name,rpc_url,debug=False):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        while not stop_event.is_set():
            try:
                mnemonic=gen_mnemonic()
                if mnemonic in in_memory_scanned: await asyncio.sleep(0.01); continue
                append_scanned(mnemonic)
                seed=mnemonic_to_seed(mnemonic)
                if chain_name in ["ethereum","bsc","polygon","bitcoin"]:
                    coin_map={"ethereum":60,"bsc":60,"polygon":137,"bitcoin":0}
                    for priv,_ in derive_secp256k1_bip44(seed,coin_map[chain_name],indices=(0,1,2)):
                        privhex=priv.hex()
                        if chain_name=="bitcoin":
                            addrs=btc_priv_to_addresses(priv)
                            for addr_type,addr in addrs.items():
                                if addr_type=="wif": continue
                                ever_received=await btc_received_before(addr,debug)
                                if ever_received==0: continue
                                try:
                                    bal_sats=await btc_balance(addr,debug)
                                except Exception as e:
                                    print(f"[error][bitcoin] {e}"); continue
                                if bal_sats>0:
                                    bal_str=f"{bal_sats/1e8:.8f} BTC ({bal_sats} satoshis)"
                                    print(format_found_block("bitcoin",mnemonic,privhex,addr,bal_str,addrs["wif"]))
                                    append_found(f"bitcoin | {mnemonic} | {privhex} | {addrs['wif']} | {addr_type}:{addr} | {bal_str}")
                        else:
                            try:
                                addr_eth=eth_address_from_priv(priv)
                                bal=await eth_like_get_balance(rpc_url,addr_eth,session,debug)
                            except Exception as e:
                                print(f"[error][{chain_name}] {e}"); continue
                            if bal>0:
                                bal_str=f"{bal/1e18:.18f} ETH (wei={bal})"
                                print(format_found_block(chain_name,mnemonic,privhex,addr_eth,bal_str))
                                append_found(f"{chain_name} | {mnemonic} | {privhex} | {addr_eth} | {bal_str}")
                elif chain_name in ["solana","sui"]:
                    for _ in range(3):
                        seed32=seed[:32]
                        sk=ed25519_mod.SigningKey(seed32)
                        vk=sk.get_verifying_key()
                        pub_raw=vk.to_bytes() if hasattr(vk,"to_bytes") else bytes(vk)
                        address=base58.b58encode(pub_raw).decode()
                        try:
                            if chain_name=="solana": bal=await solana_get_balance(rpc_url,address,session,debug)
                            else: bal=await sui_get_balance(rpc_url,address,session,debug)
                        except Exception as e: print(f"[error][{chain_name}] {e}"); continue
                        if bal>0:
                            bal_str=f"{bal}" if chain_name=="sui" else f"{bal} lamports ({bal/1e9:.9f} SOL)"
                            print(format_found_block(chain_name,mnemonic,seed32.hex(),address,bal_str))
                            append_found(f"{chain_name} | {mnemonic} | {seed32.hex()} | {address} | {bal_str}")
                await asyncio.sleep(0.02)
            except Exception as e:
                print(f"[error][{chain_name}] Unexpected: {e}")
                await asyncio.sleep(0.1)

def run_async_worker(coro_func,*args,**kwargs):
    try: asyncio.run(coro_func(*args,**kwargs))
    except Exception as e: print(f"[worker][fatal] {e}")

# ---------------- Main ----------------
def main():
    import argparse
    parser=argparse.ArgumentParser()
    parser.add_argument("-d","--debug",action="store_true")
    args=parser.parse_args()
    debug=args.debug
    open(SCANNED_FILE,"a").close()
    open(FOUND_FILE,"a").close()

    with ThreadPoolExecutor(max_workers=6) as ex:
        ex.submit(run_async_worker,worker_chain,"ethereum",ETH_RPC,debug)
        ex.submit(run_async_worker,worker_chain,"bsc",BSC_RPC,debug)
        ex.submit(run_async_worker,worker_chain,"polygon",POLYGON_RPC,debug)
        ex.submit(run_async_worker,worker_chain,"solana",SOL_RPC,debug)        
        ex.submit(run_async_worker,worker_chain,"sui",SUI_RPC,debug)
        ex.submit(run_async_worker,worker_chain,"bitcoin",None,debug)  # BTC uses blockchain.info, no RPC

        try:
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, stopping all workers...")
            stop_event.set()
            time.sleep(0.2)

    print("[info] Scanner stopped. Goodbye.")

if __name__=="__main__":
    main()
