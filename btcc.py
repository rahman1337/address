#!/usr/bin/env python3
"""
iSH-compatible BTC scanner — multi-API rotation for fast, valid balance checks
Requires: pip install coincurve aiohttp
"""

import os, time, json, asyncio, aiohttp
from coincurve import PublicKey

# --------------- Config ----------------
BATCH_SIZE = 20       # addresses per batch API call
CONCURRENCY = 6       # async workers
REPORT_INTERVAL = 1.0
MATCH_OUTFILE = "btc_matches.txt"

# --------------- Bitcoin helpers ----------------
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def sha256(b): return hashlib.sha256(b).digest()
def ripemd160(b): h=hashlib.new("ripemd160"); h.update(b); return h.digest()
def hash160(b): return ripemd160(sha256(b))
def base58check(data):
    checksum = sha256(sha256(data))[:4]
    num = int.from_bytes(data+checksum,"big")
    res=[]
    while num>0: num,mod=divmod(num,58); res.append(BASE58_ALPHABET[mod])
    n_pad=len(data)-len(data.lstrip(b'\0'))
    return '1'*n_pad+''.join(reversed(res)) if n_pad else ''.join(reversed(res))
def wif_from_priv(priv_bytes): return base58check(b'\x80'+priv_bytes+b'\x01')
def p2pkh_from_pub(pubc): return base58check(b'\x00'+hash160(pubc))
def pubkey_compressed_from_priv_bytes(priv_bytes): return PublicKey.from_valid_secret(priv_bytes).format(compressed=True)

# --------------- Multi-API Balance check ----------------
API_LIST = [
    "https://blockstream.info/api/address/{addr}",
    "https://blockchair.com/bitcoin/dashboards/address/{addr}",
    "https://mempool.space/api/address/{addr}",
]

async def fetch_balance(session, addr):
    for api in API_LIST:
        url = api.format(addr=addr)
        try:
            async with session.get(url, timeout=10) as resp:
                if resp.status != 200:
                    continue
                data = await resp.json()
                # Parse each API's JSON differently
                if "chain_stats" in data:  # Blockchair
                    bal = data["data"][addr]["address"]["balance"]/1e8
                elif "chain_stats" in data or "balance" in data:  # Blockstream
                    bal = (data.get("chain_stats",{}).get("funded_txo_sum",0)
                           - data.get("chain_stats",{}).get("spent_txo_sum",0))/1e8
                elif "funded_txo_sum" in data:  # Mempool.space
                    bal = data.get("chain_stats",{}).get("funded_txo_sum",0)/1e8
                else:
                    bal = None
                if bal is not None:
                    return bal
        except:
            continue
    return None  # All APIs failed, do not assume 0

# --------------- Async Worker ----------------
async def worker(queue, counters):
    async with aiohttp.ClientSession() as session:
        while True:
            batch = await queue.get()
            results=[]
            for priv_bytes in batch:
                pubc = pubkey_compressed_from_priv_bytes(priv_bytes)
                addr = p2pkh_from_pub(pubc)
                wif = wif_from_priv(priv_bytes)
                bal = await fetch_balance(session, addr)
                counters["checked"]+=1
                if bal and bal>0.0:
                    ts=time.strftime("%Y-%m-%d %H:%M:%S")
                    out = f"\n=== MATCH FOUND ===\n{ts}\nWIF\n{wif}\nADDRESS\n{addr}\nBALANCE:{bal:.8f}\n===================\n"
                    print(out,flush=True)
                    with open(MATCH_OUTFILE,"a") as fo:
                        fo.write(f"{ts}\nWIF:{wif}\nADDRESS:{addr}\nBALANCE:{bal:.8f}\n\n")
            queue.task_done()

# --------------- Generator ----------------
async def generator(queue, counters):
    while True:
        batch=[]
        for _ in range(BATCH_SIZE):
            priv=os.urandom(32)
            batch.append(priv)
            counters["generated"]+=1
        await queue.put(batch)

# --------------- Reporter ----------------
async def reporter(counters):
    start=time.time()
    while True:
        await asyncio.sleep(REPORT_INTERVAL)
        now=time.time()
        elapsed=now-start
        print(f"[live keys: {counters['generated']:,} gen — {counters['checked']:,} checked]".ljust(80), end="\r")

# --------------- Main ----------------
async def main():
    queue = asyncio.Queue(maxsize=CONCURRENCY*2)
    counters = {"generated":0,"checked":0}

    gen_task = asyncio.create_task(generator(queue,counters))
    workers=[asyncio.create_task(worker(queue,counters)) for _ in range(CONCURRENCY)]
    rep_task = asyncio.create_task(reporter(counters))

    await asyncio.gather(gen_task,*workers,rep_task)

if __name__=="__main__":
    import hashlib
    import sys
    print("Starting multi-API BTC scanner — fastest possible in iSH")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nStopped by user.")