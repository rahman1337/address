#!/usr/bin/env python3
"""
Ultra-fast BTC live-balance scanner
Requirements:
  pip install aiohttp coincurve
"""

import os, sys, time, hashlib, asyncio, aiohttp
from coincurve import PublicKey

# ---------- Settings ----------
BATCH_SIZE = 800
CONCURRENCY = 6
QUEUE_MAX = CONCURRENCY * 4
BATCH_PROVIDER = "https://blockchain.info/multiaddr?active={}"
FALLBACK_PROVIDER = "https://mempool.space/api/address/{}"
MATCH_OUTFILE = "btc_matches.txt"
REPORT_INTERVAL = 1.0

# ---------- ECC / Bitcoin helpers ----------
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def sha256(b): return hashlib.sha256(b).digest()
def ripemd160(b): h = hashlib.new("ripemd160"); h.update(b); return h.digest()
def hash160(b): return ripemd160(sha256(b))
def base58check(data):
    checksum = sha256(sha256(data))[:4]
    num = int.from_bytes(data + checksum, "big")
    res_chars = []
    while num > 0:
        num, mod = divmod(num, 58)
        res_chars.append(BASE58_ALPHABET[mod])
    n_pad = len(data) - len(data.lstrip(b'\0'))
    return '1'*n_pad + ''.join(reversed(res_chars)) if n_pad else ''.join(reversed(res_chars))
def wif_from_priv(priv_bytes): return base58check(b'\x80'+priv_bytes+b'\x01')
def p2pkh_from_pub(pub_compressed): return base58check(b'\x00'+hash160(pub_compressed))
def pubkey_compressed_from_priv_bytes(priv_bytes): return PublicKey.from_valid_secret(priv_bytes).format(compressed=True)

# ---------- Networking ----------
async def fetch_batch_blockchain(session, addrs):
    addr_str = "|".join(addrs)
    url = BATCH_PROVIDER.format(addr_str)
    backoff = 0.4
    while True:
        try:
            async with session.get(url, timeout=20) as resp:
                data = await resp.json()
                balances = {}
                if "addresses" in data:
                    for a in data["addresses"]:
                        balances[a.get("address")] = a.get("final_balance", 0)/1e8
                for a in addrs:
                    if a not in balances: balances[a] = None
                return balances
        except Exception:
            await asyncio.sleep(min(backoff,5.0))
            backoff *= 1.5

async def fetch_single_mempool(session, addr):
    url = FALLBACK_PROVIDER.format(addr)
    backoff = 0.25
    while True:
        try:
            async with session.get(url, timeout=15) as resp:
                data = await resp.json()
                cs = data.get("chain_stats") or data.get("chainstats") or {}
                if isinstance(cs, dict):
                    funded = int(cs.get("funded_txo_sum",0))
                    spent = int(cs.get("spent_txo_sum",0))
                    return float((funded-spent)/1e8)
                ft, st = data.get("funded_txo_sum"), data.get("spent_txo_sum")
                if ft is not None and st is not None:
                    return float((int(ft)-int(st))/1e8)
                raise ValueError("No balance info")
        except Exception:
            await asyncio.sleep(min(backoff,5.0))
            backoff *= 1.5

# ---------- Batch generation ----------
def generate_batch_exact(batch_size):
    priv_map = {}
    addrs = []
    while len(addrs) < batch_size:
        priv = os.urandom(32)
        pubc = pubkey_compressed_from_priv_bytes(priv)
        addr = p2pkh_from_pub(pubc)
        addrs.append(addr)
        priv_map[addr] = wif_from_priv(priv)
    return priv_map, addrs

# ---------- Worker ----------
async def worker(queue, session, counters):
    while True:
        batch_size = await queue.get()
        try:
            priv_map, addrs = generate_batch_exact(batch_size)
            balances = await fetch_batch_blockchain(session, addrs)

            need_fallback = [a for a,b in balances.items() if b is None]
            if need_fallback:
                tasks = [asyncio.create_task(fetch_single_mempool(session,a)) for a in need_fallback]
                results = await asyncio.gather(*tasks)
                for a,b in zip(need_fallback, results): balances[a]=b

            for a, bal in balances.items():
                if bal and bal > 0.0:
                    ts = time.strftime("%Y-%m-%d %H:%M:%S")
                    wif = priv_map[a]  # guaranteed
                    print("\n=== MATCH FOUND ===")
                    print(ts)
                    print("WIF")
                    print(wif)
                    print("ADDRESS")
                    print(a)
                    print(f"BALANCE: {bal:.8f} BTC")
                    print("===================\n")
                    with open(MATCH_OUTFILE, "a", encoding="utf-8") as fo:
                        fo.write(f"{ts}\nWIF:{wif}\nADDRESS:{a}\nBALANCE:{bal:.8f}\n\n")

            counters["total"] += len(addrs)
        finally:
            queue.task_done()

# ---------- Orchestrator ----------
async def main(batch_size=BATCH_SIZE, concurrency=CONCURRENCY):
    queue = asyncio.Queue(maxsize=QUEUE_MAX)
    counters = {"total":0}
    start_time = time.time()
    last_report = start_time

    conn = aiohttp.TCPConnector(limit=concurrency*50)
    async with aiohttp.ClientSession(connector=conn) as session:
        workers = [asyncio.create_task(worker(queue,session,counters)) for _ in range(concurrency)]
        try:
            while True:
                if not queue.full(): await queue.put(batch_size)

                now = time.time()
                if now-last_report>=REPORT_INTERVAL:
                    total = counters["total"]
                    elapsed = now-start_time if now-start_time>0 else 1.0
                    avg = total/elapsed
                    sys.stdout.write(f"[live keys: {total:,} — {avg:,.1f} keys/s]".ljust(80)+"\r")
                    sys.stdout.flush()
                    last_report=now

                await asyncio.sleep(0.01)

        except KeyboardInterrupt:
            for w in workers: w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            print(f"\nStopped. Total keys checked: {counters['total']:,}")

if __name__=="__main__":
    print(f"Starting btc_scanner_fast.py — batch_size: {BATCH_SIZE}, concurrency: {CONCURRENCY}")
    asyncio.run(main())