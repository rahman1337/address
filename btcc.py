#!/usr/bin/env python3

import os, sys, time, hashlib, asyncio, aiohttp
from typing import List, Dict
try:
    from coincurve import PublicKey
    HAVE_COINCURVE = True
except Exception:
    HAVE_COINCURVE = False

# ---------- ECC helpers ----------
if not HAVE_COINCURVE:
    # minimal pure-Python EC (works but slower)
    P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
    Gy = 3267051002075881697808308513050704318447127338065924327593890433575733741481

    def modinv(a: int, p: int = P) -> int:
        return pow(a, p - 2, p)

    def ec_point_add(x1, y1, x2, y2):
        if x1 is None: return x2, y2
        if x2 is None: return x1, y1
        if x1 == x2 and (y1 + y2) % P == 0: return None, None
        if x1 == x2 and y1 == y2:
            lam = (3 * x1 * x1) * modinv(2 * y1, P) % P
        else:
            lam = (y2 - y1) * modinv(x2 - x1, P) % P
        x3 = (lam * lam - x1 - x2) % P
        y3 = (lam * (x1 - x3) - y1) % P
        return x3, y3

    def ec_point_mul(k: int, x: int = Gx, y: int = Gy):
        k = k % N
        if k == 0: return None, None
        rx = ry = None
        px, py = x, y
        while k:
            if k & 1:
                rx, ry = ec_point_add(rx, ry, px, py)
            px, py = ec_point_add(px, py, px, py)
            k >>= 1
        return rx, ry

# ---------- address / WIF helpers ----------
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def ripemd160(b: bytes) -> bytes:
    h = hashlib.new("ripemd160"); h.update(b); return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def int_to_bytes(i: int, length: int) -> bytes:
    return i.to_bytes(length, "big")

def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")

def base58check(data: bytes) -> str:
    checksum = sha256(sha256(data))[:4]
    num = int.from_bytes(data + checksum, "big")
    res_chars = []
    while num > 0:
        num, mod = divmod(num, 58)
        res_chars.append(BASE58_ALPHABET[mod])
    res = ''.join(reversed(res_chars))
    n_pad = len(data) - len(data.lstrip(b'\0'))
    if n_pad:
        return '1' * n_pad + res
    return res

def wif_from_priv(priv_bytes: bytes) -> str:
    return base58check(b'\x80' + priv_bytes + b'\x01')

def p2pkh_from_pub(pub_compressed: bytes) -> str:
    return base58check(b'\x00' + hash160(pub_compressed))

def pubkey_compressed_from_priv_bytes(priv_bytes: bytes) -> bytes:
    if HAVE_COINCURVE:
        return PublicKey.from_valid_secret(priv_bytes).format(compressed=True)
    priv_int = bytes_to_int(priv_bytes)
    x, y = ec_point_mul(priv_int)
    prefix = b'\x02' if (y & 1) == 0 else b'\x03'
    return prefix + int_to_bytes(x, 32)

# ---------- API providers ----------
# Primary (batch): blockchain.info multiaddr (supports many addresses in one request)
BATCH_PROVIDER = "https://blockchain.info/multiaddr?active={}"   # join addresses with '|'

# Fallback (single): mempool.space address endpoint (per-address) — used only when batch fails for an address
# mempool.space returns JSON with chain_stats/funded_txo_sum etc (we parse tolerant)
FALLBACK_PROVIDER = "https://mempool.space/api/address/{}"

# ---------- network helpers ----------
async def fetch_batch_blockchain(session: aiohttp.ClientSession, addrs: List[str]) -> Dict[str, float]:

    addr_str = "|".join(addrs)
    url = BATCH_PROVIDER.format(addr_str)
    while True:
        try:
            async with session.get(url, timeout=20) as resp:
                # Accept non-200 too but require valid JSON
                data = await resp.json()
                balances = {}
                # If blockchain.info returns an addresses array, map them
                if isinstance(data, dict) and "addresses" in data:
                    for a in data.get("addresses", []):
                        balances[a.get("address")] = a.get("final_balance", 0) / 1e8
                # ensure all addresses present
                for a in addrs:
                    if a not in balances:
                        balances[a] = 0.0
                return balances
        except Exception:
            # short backoff and retry repeatedly (do not return zeros)
            await asyncio.sleep(0.5)

async def fetch_single_mempool(session: aiohttp.ClientSession, addr: str) -> float:

    url = FALLBACK_PROVIDER.format(addr)
    while True:
        try:
            async with session.get(url, timeout=15) as resp:
                data = await resp.json()
                # mempool.space shape may vary; try common fields
                # Try chain_stats.funded_txo_sum first (satoshis)
                bal = 0
                if isinstance(data, dict):
                    cs = data.get("chain_stats") or data.get("chainstats") or {}
                    if isinstance(cs, dict):
                        # funded_txo_sum, spent_txo_sum are satoshi totals
                        funded = cs.get("funded_txo_sum") or cs.get("funded_txo_sum", 0)
                        spent = cs.get("spent_txo_sum") or cs.get("spent_txo_sum", 0)
                        # balance = funded - spent (satoshis)
                        try:
                            bal = (int(funded) - int(spent)) / 1e8
                        except Exception:
                            bal = 0.0
                    # fallback: 'address' entries or 'chain_stats' structure different
                    if bal == 0.0:
                        # try 'funded_txo_sum' at top-level or other heuristics
                        ft = data.get("funded_txo_sum")
                        st = data.get("spent_txo_sum")
                        if ft is not None and st is not None:
                            try:
                                bal = (int(ft) - int(st)) / 1e8
                            except Exception:
                                bal = 0.0
                return float(bal)
        except Exception:
            await asyncio.sleep(0.3)  # short backoff and try again

# ---------- batch generation ----------
def generate_batch(batch_size: int):

    priv_map = {}
    addrs = []
    for _ in range(batch_size):
        priv = os.urandom(32)
        try:
            pubc = pubkey_compressed_from_priv_bytes(priv)
        except Exception:
            continue
        addr = p2pkh_from_pub(pubc)
        addrs.append(addr)
        priv_map[addr] = wif_from_priv(priv)
    return priv_map, addrs

# ---------- worker ----------
async def worker(queue: asyncio.Queue, session: aiohttp.ClientSession, counters: Dict):

    while True:
        batch_size = await queue.get()
        priv_map, addrs = generate_batch(batch_size)
        if not addrs:
            queue.task_done()
            continue

        # 1) try batch with blockchain.info
        balances = await fetch_batch_blockchain(session, addrs)

        # 2) if any address not present (or we want extra validation), do per-address fallback
        #    We never accept 'unknown' — fallback will retry until success.
        to_fallback = [a for a, b in balances.items() if b is None]  # unlikely
        # Also if blockchain.info returned zeros but we want double-check (optional):
        # to_fallback += [a for a,b in balances.items() if b == 0.0]
        # We'll only fallback for addresses that are missing in response (rare).
        if to_fallback:
            # For correctness we re-query individually (mempool.space) until valid
            tasks = [asyncio.create_task(fetch_single_mempool(session, a)) for a in to_fallback]
            done = await asyncio.gather(*tasks)
            for a, b in zip(to_fallback, done):
                balances[a] = b

        # 3) Report any non-zero balances (immediate print)
        for a, bal in balances.items():
            if bal and bal > 0.0:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                print("\n=== MATCH FOUND ===")
                print(ts)
                print("WIF")
                print(priv_map.get(a, "(missing-wif)"))
                print("ADDRESS")
                print(a)
                print(f"BALANCE: {bal:.8f} BTC")
                print("===================\n")
                # write to file (best-effort)
                try:
                    with open("btc.txt", "a", encoding="utf-8") as fo:
                        fo.write(f"{ts}\nWIF:{priv_map.get(a,'')}\nADDRESS:{a}\nBALANCE:{bal:.8f}\n\n")
                except Exception:
                    pass

        counters["total"] += len(addrs)
        queue.task_done()

# ---------- orchestrator ----------
async def main(batch_size: int = 500, concurrency: int = 6):

    queue = asyncio.Queue(maxsize=concurrency * 4)
    counters = {"total": 0}
    start_time = time.time()
    async with aiohttp.ClientSession() as session:
        # spawn workers
        workers = [asyncio.create_task(worker(queue, session, counters)) for _ in range(concurrency)]

        try:
            # continuously feed queue
            while True:
                # push one batch job
                await queue.put(batch_size)

                # print progress each second (non-blocking)
                now = time.time()
                elapsed = now - start_time if now - start_time > 0 else 1.0
                total = counters["total"]
                avg = total / elapsed
                sys.stdout.write(f"[live keys: {total:,} — {avg:,.1f} keys/s]".ljust(70) + "\r")
                sys.stdout.flush()

                # tiny sleep to let workers run and avoid tight busy loop on event loop
                await asyncio.sleep(0.01)
        except KeyboardInterrupt:
            # cancel workers gracefully
            for w in workers:
                w.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            print()
            print(f"Stopped. Total keys checked: {counters['total']:,}")

if __name__ == "__main__":
    try:
        asyncio.run(main(batch_size=500, concurrency=6))
    except Exception as e:
        print("Fatal:", e)