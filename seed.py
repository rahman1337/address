#!/usr/bin/env python3
"""
Scanner using BIP39 + bip32utils + SLIP-0010 (ed25519) derivation.
- 12-word valid mnemonics (mnemonic package)
- BIP32/BIP44 derivation for secp256k1 via bip32utils
- SLIP-0010 hardened ed25519 derivation for Solana / Sui
- 3 indices per mnemonic: m/44'/coin'/0'/0/i  (i = 0,1,2)
  - For ed25519 we derive hardened path m/44'/coin'/0'/0'/i'
- Three BTC address formats per key: P2PKH (1...), P2SH(P2WPKH) (3...), bech32 (bc1q...)
- Use publicnode RPCs provided
- Found block prints WIF for BTC below mnemonic
"""
import os
import sys
import time
import threading
import asyncio
import struct
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

def ensure_import(name, package=None):
    try:
        return __import__(name)
    except Exception:
        pkg = package or name
        print(f"[setup] package '{pkg}' not found, installing...", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        return __import__(name)

# 3rd-party libs
aiohttp = ensure_import("aiohttp")
base58 = ensure_import("base58")
coincurve = ensure_import("coincurve")
eth_utils = ensure_import("eth_utils")
from eth_utils import to_checksum_address, keccak
mnemonic_lib = ensure_import("mnemonic")        # python-mnemonic
bip32utils = ensure_import("bip32utils")      # bip32utils
ed25519_mod = ensure_import("ed25519")        # ed25519 for ed25519 key usage
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
SEED_FILE = "seed.txt"

# concurrency / state
scanned_lock = threading.Lock()
found_lock = threading.Lock()
in_memory_scanned = set()
stop_event = threading.Event()

LIGHT_GREEN = "\033[92m"
RESET_COLOR = "\033[0m"

# load BIP39 wordlist
if not os.path.exists(SEED_FILE):
    raise SystemExit(f"ERROR: '{SEED_FILE}' not found. Place BIP39 English wordlist there (2048 words).")
with open(SEED_FILE, "r", encoding="utf-8") as f:
    WORDLIST = [w.strip() for w in f.readlines() if w.strip()]
if len(WORDLIST) != 2048:
    raise SystemExit("ERROR: seed.txt must contain exactly 2048 words (BIP39 English wordlist).")

# load scanned mnemonics into memory
if os.path.exists(SCANNED_FILE):
    try:
        with open(SCANNED_FILE, "r", encoding="utf-8") as f:
            for ln in f:
                s = ln.strip()
                if s:
                    in_memory_scanned.add(s)
    except Exception as e:
        print(f"[warn] could not load {SCANNED_FILE}: {e}", file=sys.stderr)

def append_scanned(mnemonic: str):
    with scanned_lock:
        if mnemonic in in_memory_scanned:
            return
        with open(SCANNED_FILE, "a", encoding="utf-8") as f:
            f.write(mnemonic + "\n")
        in_memory_scanned.add(mnemonic)

def append_found(line: str):
    with found_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def format_found_block(chain, mnemonic, privhex, address, balance_str, wif="N/A"):
    border = "=" * 60
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

# ---------- BIP39 mnemonic ----------
mnemo = mnemonic_lib.Mnemonic("english")
def gen_mnemonic_12():
    return mnemo.generate(128)
def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return mnemo.to_seed(mnemonic, passphrase)

# ---------- BIP32/BIP44 derivation (secp256k1) ----------
def derive_secp256k1_bip44(seed_bytes: bytes, coin_type: int, indices=(0,1,2)):
    from bip32utils import BIP32Key
    master = BIP32Key.fromEntropy(seed_bytes)
    results = []
    k = master.ChildKey(44 + BIP32Key.HARDEN)
    k = k.ChildKey(coin_type + BIP32Key.HARDEN)
    k = k.ChildKey(0 + BIP32Key.HARDEN)
    k = k.ChildKey(0)
    for i in indices:
        ki = k.ChildKey(i)
        try:
            priv_bytes = ki.PrivateKey()
        except Exception:
            priv_bytes = ki.K.to_string()
        addr = ki.Address()
        results.append((priv_bytes, addr))
    return results

def eth_address_from_priv(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if len(pub_uncompressed)==65 and pub_uncompressed[0]==0x04 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return to_checksum_address("0x"+addr_bytes.hex())

# ---------- SLIP-0010 ed25519 ----------
def hmac_sha512(key: bytes, data: bytes) -> bytes:
    return HMAC.new(key, data, digestmod=SHA512).digest()
def slip10_ed25519_master_key(seed: bytes):
    I = hmac_sha512(b"ed25519 seed", seed)
    kL, kR = I[:32], I[32:]
    return kL, kR
def slip10_ed25519_ckd_priv(parent_k, parent_chain_code, index):
    assert index >= 0x80000000
    data = b'\x00'+parent_k+struct.pack(">L", index)
    I = hmac_sha512(parent_chain_code, data)
    child_k = I[:32]
    child_chain = I[32:]
    return child_k, child_chain
def derive_slip10_ed25519_path(seed_bytes: bytes, path: str):
    k, chain = slip10_ed25519_master_key(seed_bytes)
    parts = path.split("/")
    for p in parts[1:]:
        idx = int(p[:-1]) + 0x80000000 if p.endswith("'") else int(p)+0x80000000
        k, chain = slip10_ed25519_ckd_priv(k, chain, idx)
    return k

# ---------- BTC address helpers ----------
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _bech32_polymod(values):
    GENERATORS = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5)^v
        for i in range(5):
            if (top>>i)&1:
                chk ^= GENERATORS[i]
    return chk
def _bech32_hrp_expand(hrp):
    return [ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]
def _bech32_create_checksum(hrp,data):
    values=_bech32_hrp_expand(hrp)+data
    polymod=_bech32_polymod(values+[0]*6)^1
    return [(polymod>>(5*(5-i)))&31 for i in range(6)]
def _bech32_encode(hrp,data):
    combined=data+_bech32_create_checksum(hrp,data)
    return hrp+"1"+"".join([CHARSET[d] for d in combined])
def _convertbits(data,frombits,tobits,pad=True):
    acc=0
    bits=0
    ret=[]
    maxv=(1<<tobits)-1
    for value in data:
        if value<0 or (value>>frombits):
            return None
        acc=(acc<<frombits)|value
        bits+=frombits
        while bits>=tobits:
            bits-=tobits
            ret.append((acc>>bits)&maxv)
    if pad and bits:
        ret.append((acc<<(tobits-bits))&maxv)
    return ret
def hash160(b: bytes) -> bytes:
    return RIPEMD160.new(SHA256.new(b).digest()).digest()
def pubkey_compressed_from_priv(priv_bytes: bytes) -> bytes:
    pk = coincurve.PrivateKey(priv_bytes)
    return pk.public_key.format(compressed=True)
def btc_p2pkh_from_pub(pub_compressed: bytes) -> str:
    h160=hash160(pub_compressed)
    return base58.b58encode_check(b"\x00"+h160).decode()
def btc_p2sh_p2wpkh_from_pub(pub_compressed: bytes) -> str:
    h160=hash160(pub_compressed)
    redeem_script=b"\x00\x14"+h160
    redeem_h160=hash160(redeem_script)
    return base58.b58encode_check(b"\x05"+redeem_h160).decode()
def btc_bech32_p2wpkh_from_pub(pub_compressed: bytes) -> str:
    h160=hash160(pub_compressed)
    data=[0]+_convertbits(h160,8,5)
    return _bech32_encode("bc",data)
def btc_wif_from_priv(priv_bytes: bytes) -> str:
    return base58.b58encode_check(b"\x80"+priv_bytes+b"\x01").decode()

# ---------- RPC helpers ----------
async def rpc_post_with_retries(url,json_payload,session,debug=False,max_attempts=3):
    last_exc=None
    for attempt in range(1,max_attempts+1):
        try:
            async with session.post(url,json=json_payload,timeout=15) as r:
                text=await r.text()
                if debug: print(f"[debug][rpc] POST {url} payload={json_payload} status={r.status} resp={text}")
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            last_exc=e
            if attempt<max_attempts: await asyncio.sleep(attempt)
    raise last_exc

async def eth_like_get_balance(rpc_url,address,session,debug=False):
    payload={"jsonrpc":"2.0","id":1,"method":"eth_getBalance","params":[address,"latest"]}
    j=await rpc_post_with_retries(rpc_url,payload,session,debug)
    if "error" in j: raise RuntimeError(f"RPC error: {j['error']}")
    return int(j.get("result",0),16)

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

# ---------- Worker ----------
async def worker_generic(chain_name,rpc_url,debug=False):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        while not stop_event.is_set():
            try:
                mnemonic = gen_mnemonic_12()
                if mnemonic in in_memory_scanned:
                    await asyncio.sleep(0.01)
                    continue
                append_scanned(mnemonic)
                seed_bytes = mnemonic_to_seed(mnemonic)
                indices = [0,1,2]

                # per chain
                if chain_name in ("ethereum","bsc","polygon"):
                    coin_type = {"ethereum":60,"bsc":60,"polygon":137}[chain_name]
                    derived = derive_secp256k1_bip44(seed_bytes, coin_type, indices)
                    for priv, addr in derived:
                        try:
                            bal_wei = await eth_like_get_balance(rpc_url, addr, session, debug)
                        except:
                            await asyncio.sleep(0.2)
                            continue
                        if bal_wei>0:
                            bal_str=f"{bal_wei/1e18:.18f} (wei={bal_wei})"
                            append_found(f"{chain_name} | {mnemonic} | {priv.hex()} | {addr} | {bal_str}")
                            print(format_found_block(chain_name,mnemonic,priv.hex(),addr,bal_str,wif="N/A"))
                elif chain_name in ("solana","sui"):
                    coin_idx = {"solana":501,"sui":784}[chain_name]
                    for i in indices:
                        path=f"m/44'/{coin_idx}'/0'/0'/{i}'"
                        priv = derive_slip10_ed25519_path(seed_bytes,path)
                        vk = ed25519_mod.SigningKey(priv).get_verifying_key()
                        pub_raw = vk.to_bytes() if hasattr(vk,"to_bytes") else bytes(vk)
                        addr = base58.b58encode(pub_raw).decode()
                        try:
                            bal = await solana_get_balance(rpc_url, addr, session, debug)
                        except:
                            await asyncio.sleep(0.2)
                            continue
                        if bal>0:
                            bal_str=f"{bal} lamports ({bal/1e9:.9f} SOL)"
                            append_found(f"{chain_name} | {mnemonic} | {priv.hex()} | {addr} | {bal_str}")
                            print(format_found_block(chain_name,mnemonic,priv.hex(),addr,bal_str,wif="N/A"))
                elif chain_name=="bitcoin":
                    derived = derive_secp256k1_bip44(seed_bytes,0,indices)
                    for priv, _ in derived:
                        pub = pubkey_compressed_from_priv(priv)
                        p2pkh = btc_p2pkh_from_pub(pub)
                        p2sh = btc_p2sh_p2wpkh_from_pub(pub)
                        bech32 = btc_bech32_p2wpkh_from_pub(pub)
                        wif = btc_wif_from_priv(priv)
                        for addr in [p2pkh,p2sh,bech32]:
                            try:
                                sat = await btc_get_balance(rpc_url, addr, session, debug)
                            except: sat=0; await asyncio.sleep(0.1)
                            if sat>0:
                                btc_str=f"{sat/1e8:.8f} BTC ({sat} satoshis)"
                                append_found(f"{chain_name} | {mnemonic} | {priv.hex()} | {addr} | {btc_str} | {wif}")
                                print(format_found_block(chain_name,mnemonic,priv.hex(),addr,btc_str,wif=wif))
                await asyncio.sleep(0.02)
            except Exception as e:
                await asyncio.sleep(0.05)

def run_async_worker(coro_func, *args, **kwargs):
    try: asyncio.run(coro_func(*args, **kwargs))
    except Exception as e: print(f"[worker][fatal] {e}")

# ---------- Main ----------
def main():
    parser = ArgumentParser()
    parser.add_argument("-d","--debug",action="store_true")
    args=parser.parse_args()
    debug=args.debug

    open(SCANNED_FILE,"a").close()
    open(FOUND_FILE,"a").close()
    print(f"[info] Starting scanner. Debug={debug}. Press Ctrl+C to stop.")

    with ThreadPoolExecutor(max_workers=6) as ex:
        ex.submit(run_async_worker, worker_generic,"ethereum",ETH_RPC,debug)
        ex.submit(run_async_worker, worker_generic,"bsc",BSC_RPC,debug)
        ex.submit(run_async_worker, worker_generic,"polygon",POLYGON_RPC,debug)
        ex.submit(run_async_worker, worker_generic,"solana",SOL_RPC,debug)
        ex.submit(run_async_worker, worker_generic,"sui",SUI_RPC,debug)
        ex.submit(run_async_worker, worker_generic,"bitcoin",BTC_RPC,debug)
        try:
            while not stop_event.is_set(): time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, shutting down...")
            stop_event.set()
            time.sleep(0.2)
    print("[info] Scanner stopped. Goodbye.")

if __name__=="__main__":
    main()
