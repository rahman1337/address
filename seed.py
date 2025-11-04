#!/usr/bin/env python3
"""
6-chain mnemonic scanner with predictable-ish 12-word mnemonics.
- Chains: Ethereum, BSC, Polygon, Solana, Sui, Bitcoin
- Each mnemonic scans 3 account indices
- Error/warning prints even in normal mode
- RPC retries with backoff (1,2,3s)
- Bitcoin prints 3 address types + WIF
"""
import os, sys, time, threading, asyncio, struct, traceback
from hashlib import pbkdf2_hmac
from concurrent.futures import ThreadPoolExecutor

def ensure_import(name, package=None):
    try: return __import__(name)
    except Exception:
        pkg = package or name
        print(f"[setup] package '{pkg}' not found, installing...", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        return __import__(name)

# third-party libraries
aiohttp = ensure_import("aiohttp")
base58 = ensure_import("base58")
coincurve = ensure_import("coincurve")
eth_utils = ensure_import("eth_utils")
from eth_utils import to_checksum_address, keccak
bip32utils = ensure_import("bip32utils")
ed25519_mod = ensure_import("ed25519")
Crypto = ensure_import("Crypto")
from Crypto.Hash import SHA256, RIPEMD160, HMAC, SHA512

# RPC endpoints
ETH_RPC = "https://ethereum.publicnode.com"
BSC_RPC = "https://bsc.publicnode.com"
POLYGON_RPC = "https://polygon.publicnode.com"
SOL_RPC = "https://solana.publicnode.com"
SUI_RPC = "https://sui.publicnode.com"
BTC_RPC = "https://bitcoin.publicnode.com"

SCANNED_FILE = "scanned_mnemonics.txt"
FOUND_FILE = "found.txt"
SEED_FILE = "seed.txt"  # 2048 BIP39 words, one per line

# concurrency / state
scanned_lock = threading.Lock()
found_lock = threading.Lock()
in_memory_scanned = set()
stop_event = threading.Event()

LIGHT_GREEN = "\033[92m"
RESET_COLOR = "\033[0m"

# load seed.txt
if not os.path.exists(SEED_FILE):
    raise SystemExit(f"ERROR: '{SEED_FILE}' not found.")
with open(SEED_FILE,"r",encoding="utf-8") as f:
    WORDLIST = [w.strip() for w in f.readlines() if w.strip()]
if len(WORDLIST) != 2048:
    raise SystemExit("ERROR: seed.txt must contain exactly 2048 words.")

# load scanned mnemonics
if os.path.exists(SCANNED_FILE):
    try:
        with open(SCANNED_FILE,"r",encoding="utf-8") as f:
            for ln in f:
                s = ln.strip()
                if s: in_memory_scanned.add(s)
    except Exception as e:
        print(f"[warn] could not load {SCANNED_FILE}: {e}", file=sys.stderr)

def append_scanned(mnemonic: str):
    with scanned_lock:
        if mnemonic in in_memory_scanned: return
        with open(SCANNED_FILE,"a",encoding="utf-8") as f: f.write(mnemonic+"\n")
        in_memory_scanned.add(mnemonic)

def append_found(line: str):
    with found_lock:
        with open(FOUND_FILE,"a",encoding="utf-8") as f: f.write(line+"\n")

def format_found_block(chain, mnemonic, privhex, address, balance_str, wif="N/A"):
    border = "="*60
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
GENERATOR_MODES = ['repetitive','sequential','mixed']
mode_index = repetitive_index = sequential_counter = mixed_index = 0

def gen_mnemonic_12():
    global mode_index,repetitive_index,sequential_counter,mixed_index
    mode = GENERATOR_MODES[mode_index%len(GENERATOR_MODES)]
    mode_index +=1
    if mode=='repetitive':
        idx = repetitive_index % len(WORDLIST)
        repetitive_index +=1
        word = WORDLIST[idx]
        return " ".join([word]*12)
    elif mode=='sequential':
        start = sequential_counter % len(WORDLIST)
        sequential_counter +=12
        return " ".join([WORDLIST[(start+i)%len(WORDLIST)] for i in range(12)])
    else:
        start = mixed_index % len(WORDLIST)
        mixed_index +=3
        return " ".join([WORDLIST[(start+(i*3)+(i%4))%len(WORDLIST)] for i in range(12)])

# ---------------- BIP39 -> seed ----------------
def mnemonic_to_seed(mnemonic:str, passphrase:str="")->bytes:
    salt = ("mnemonic"+passphrase).encode("utf-8")
    return pbkdf2_hmac("sha512", mnemonic.encode("utf-8"), salt, 2048)

# ---------------- BIP32 / BIP44 ----------------
def derive_secp256k1_bip44(seed_bytes: bytes, coin_type: int, indices=(0,1,2)):
    from bip32utils import BIP32Key
    master = BIP32Key.fromEntropy(seed_bytes)
    # m/44'/coin_type'/0'/0
    k = master.ChildKey(44 + 0x80000000).ChildKey(coin_type + 0x80000000).ChildKey(0 + 0x80000000).ChildKey(0)
    out = []
    for i in indices:
        ki = k.ChildKey(i)
        priv_bytes = ki.PrivateKey()
        addr = ki.Address()
        out.append((priv_bytes, addr))
    return out

def eth_address_from_priv(priv_bytes:bytes)->str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if pub_uncompressed[0]==0x04 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return to_checksum_address("0x"+addr_bytes.hex())

# ---------------- SLIP-0010 ed25519 ----------------
def hmac_sha512(key:bytes,data:bytes)->bytes: return HMAC.new(key,data,SHA512).digest()
def slip10_ed25519_master_key(seed:bytes):
    I = hmac_sha512(b"ed25519 seed",seed)
    return I[:32],I[32:]
def slip10_ed25519_ckd_priv(parent_k,parent_chain_code,index):
    assert index>=0x80000000
    data=b'\x00'+parent_k+struct.pack(">L",index)
    I=hmac_sha512(parent_chain_code,data)
    return I[:32],I[32:]
def derive_slip10_ed25519_path(seed_bytes:bytes,path:str):
    k,chain=slip10_ed25519_master_key(seed_bytes)
    parts=path.split("/")
    for p in parts[1:]:
        idx = int(p[:-1])+0x80000000 if p.endswith("'") else int(p)+0x80000000
        k,chain=slip10_ed25519_ckd_priv(k,chain,idx)
    return k

# ---------------- Bitcoin helpers ----------------
CHARSET="qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _bech32_polymod(values):
    GEN=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3];chk=1
    for v in values:top=chk>>25;chk=((chk&0x1ffffff)<<5)^v;chk^=sum([GEN[i] for i in range(5) if (top>>i)&1])
    return chk
def _bech32_hrp_expand(hrp): return [ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]
def _bech32_create_checksum(hrp,data): values=_bech32_hrp_expand(hrp)+data;polymod=_bech32_polymod(values+[0]*6)^1;return [(polymod>>(5*(5-i)))&31 for i in range(6)]
def _bech32_encode(hrp,data): return hrp+"1"+"".join([CHARSET[d] for d in data+_bech32_create_checksum(hrp,data)])
def _convertbits(data,frombits,tobits,pad=True):
    acc=bits=0;ret=[];maxv=(1<<tobits)-1
    for v in data:
        if v<0 or (v>>frombits): return None
        acc=(acc<<frombits)|v; bits+=frombits
        while bits>=tobits: bits-=tobits; ret.append((acc>>bits)&maxv)
    if pad and bits: ret.append((acc<<(tobits-bits))&maxv)
    return ret
def _hash160(b:bytes)->bytes: return RIPEMD160.new(SHA256.new(b).digest()).digest()
def btc_addresses_from_priv(priv_bytes:bytes):
    pk=coincurve.PrivateKey(priv_bytes)
    pub_compressed=pk.public_key.format(compressed=True)
    h160=_hash160(pub_compressed)
    p2pkh=base58.b58encode_check(b"\x00"+h160).decode()
    redeem_script=b"\x00\x14"+h160
    redeem_h160=_hash160(redeem_script)
    p2sh=base58.b58encode_check(b"\x05"+redeem_h160).decode()
    data=[0]+_convertbits(h160,8,5)
    bech32=_bech32_encode("bc",data)
    wif=base58.b58encode_check(b"\x80"+priv_bytes+b"\x01").decode()
    return {"legacy":p2pkh,"nested":p2sh,"bech32":bech32,"wif":wif}

# ---------------- RPC helpers ----------------
async def rpc_post_with_retries(url,json_payload,session,aio_debug=False,max_attempts=3):
    last_exc=None
    backoff=[1,2,3]
    for attempt in range(1,max_attempts+1):
        try:
            async with session.post(url,json=json_payload,timeout=15) as r:
                text = await r.text()
                if aio_debug: print(f"[debug][rpc] POST {url} payload={json_payload} status={r.status} resp={text}")
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            last_exc=e
            print(f"[warn][{url}] Attempt {attempt}/{max_attempts} failed: {e}")
            if attempt<max_attempts:
                t = backoff[attempt-1] if attempt-1<len(backoff) else 3
                print(f"[info] Backing off for {t}s before retry...")
                await asyncio.sleep(t)
    print(f"[error][{url}] All {max_attempts} attempts failed. Skipping.")
    raise last_exc

async def eth_like_get_balance(rpc_url,address,session,debug=False):
    payload={"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[address,"latest"]}
    j=await rpc_post_with_retries(rpc_url,payload,session,debug)
    if "error" in j: raise RuntimeError(f"RPC error: {j['error']}")
    return int(j.get("result","0"),16)

async def solana_get_balance(rpc_url,address,session,debug=False):
    payload={"jsonrpc":"2.0","id":1,"method":"getBalance","params":[address,{"commitment":"final"}]}
    j=await rpc_post_with_retries(rpc_url,payload,session,debug)
    if "error" in j: raise RuntimeError(f"RPC error: {j['error']}")
    return int(j.get("result",{}).get("value",0))

async def btc_get_balance(rpc_url,address,session,debug=False):
    payload={"jsonrpc":"2.0","id":1,"method":"getreceivedbyaddress","params":[address,0]}
    j=await rpc_post_with_retries(rpc_url,payload,session,debug)
    if "error" in j: raise RuntimeError(f"RPC error: {j['error']}")
    return int(j.get("result",0))

async def sui_get_balance(rpc_url,address,session,debug=False):
    payload = {
        "jsonrpc":"2.0",
        "id":1,
        "method":"sui_getBalance",
        "params":[address,"0x2::sui::SUI"]
    }
    j = await rpc_post_with_retries(rpc_url,payload,session,debug)
    if "error" in j: raise RuntimeError(f"Sui RPC error: {j['error']}")
    return int(j.get("result",{}).get("totalBalance",0))

# ---------------- Worker ----------------
async def worker_chain(chain_name,rpc_url,debug=False):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        while not stop_event.is_set():
            try:
                mnemonic = gen_mnemonic_12()
                if mnemonic in in_memory_scanned:
                    await asyncio.sleep(0.01)
                    continue
                append_scanned(mnemonic)
                seed = mnemonic_to_seed(mnemonic)

                if chain_name in ["ethereum","bsc","polygon"]:
                    coin_map={"ethereum":60,"bsc":60,"polygon":137}
                    for priv,addr in derive_secp256k1_bip44(seed,coin_map[chain_name],indices=(0,1,2)):
                        privhex=priv.hex()
                        try: bal_wei=await eth_like_get_balance(rpc_url,addr,session,debug)
                        except Exception as e: print(f"[error][{chain_name}] {e}"); continue
                        if bal_wei>0:
                            bal_str=f"{bal_wei/1e18:.18f} (wei={bal_wei})"
                            print(format_found_block(chain_name,mnemonic,privhex,addr,bal_str))
                            append_found(f"{chain_name} | {mnemonic} | {privhex} | {addr} | {bal_str}")

                elif chain_name=="solana":
                    for i in range(3):
                        path=f"m/44'/501'/{i}'/0'"
                        priv=derive_slip10_ed25519_path(seed,path)
                        sk=ed25519_mod.SigningKey(priv)
                        vk=sk.get_verifying_key()
                        pub_raw=vk.to_bytes()
                        addr=base58.b58encode(pub_raw).decode()
                        try: lamports=await solana_get_balance(rpc_url,addr,session,debug)
                        except Exception as e: print(f"[error][solana] {e}"); continue
                        if lamports>0:
                            bal_str=f"{lamports} lamports ({lamports/1e9:.9f} SOL)"
                            print(format_found_block("solana",mnemonic,priv.hex(),addr,bal_str))
                            append_found(f"solana | {mnemonic} | {priv.hex()} | {addr} | {bal_str}")

                elif chain_name=="sui":
                    for i in range(3):
                        path=f"m/44'/784'/{i}'/0'"
                        priv=derive_slip10_ed25519_path(seed,path)
                        sk=ed25519_mod.SigningKey(priv)
                        vk=sk.get_verifying_key()
                        pub_raw=vk.to_bytes()
                        addr=base58.b58encode(pub_raw).decode()
                        try: balance=await sui_get_balance(rpc_url,addr,session,debug)
                        except Exception as e: print(f"[error][sui] {e}"); continue
                        if balance>0:
                            bal_str=f"{balance} (SUI)"
                            print(format_found_block("sui",mnemonic,priv.hex(),addr,bal_str))
                            append_found(f"sui | {mnemonic} | {priv.hex()} | {addr} | {bal_str}")

                elif chain_name=="bitcoin":
                    for priv,addr in derive_secp256k1_bip44(seed,0,indices=(0,1,2)):
                        privhex=priv.hex()
                        addrs=btc_addresses_from_priv(priv)
                        for t in ["legacy","nested","bech32"]:
                            a=addrs[t]
                            try: sat=await btc_get_balance(rpc_url,a,session,debug)
                            except Exception as e: print(f"[error][bitcoin] {e}"); continue
                            if sat>0:
                                bal_str=f"{sat/1e8:.8f} BTC ({sat} satoshis)"
                                print(format_found_block("bitcoin",mnemonic,privhex,a,bal_str,addrs['wif']))
                                append_found(f"bitcoin | {mnemonic} | {privhex} | {a} | {bal_str} | {addrs['wif']}")

            except Exception as e:
                print(f"[error][{chain_name}] Unexpected exception: {e}")
                print(traceback.format_exc())
                await asyncio.sleep(0.5)

def run_async_worker(coro_func,*args,**kwargs):
    try: asyncio.run(coro_func(*args,**kwargs))
    except Exception as e: print(f"[worker][fatal] {e}")

# ---------------- Main ----------------
def main():
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("-d","--debug",action="store_true")
    args = parser.parse_args()
    debug=args.debug

    print(f"[info] Starting scanner. Debug={debug}. Press Ctrl+C to stop.")
    open(SCANNED_FILE,"a").close()
    open(FOUND_FILE,"a").close()

    with ThreadPoolExecutor(max_workers=6) as ex:
        ex.submit(run_async_worker, worker_chain,"ethereum",ETH_RPC,debug)
        ex.submit(run_async_worker, worker_chain,"bsc",BSC_RPC,debug)
        ex.submit(run_async_worker, worker_chain,"polygon",POLYGON_RPC,debug)
        ex.submit(run_async_worker, worker_chain,"solana",SOL_RPC,debug)
        ex.submit(run_async_worker, worker_chain,"sui",SUI_RPC,debug)
        ex.submit(run_async_worker, worker_chain,"bitcoin",BTC_RPC,debug)
        try:
            while not stop_event.is_set(): time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, shutting down...")
            stop_event.set()
            time.sleep(0.2)
    print("[info] Scanner stopped. Goodbye.")

if __name__=="__main__":
    main()
