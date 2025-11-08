#!/usr/bin/env python3

import asyncio, sys, time, hashlib
from concurrent.futures import ThreadPoolExecutor
import aiohttp
from mnemonic import Mnemonic
import coincurve
from bip32 import BIP32

# ---------------- CONFIG ----------------
THREADS = 5
DERIVATION_PATH = "m/44'/60'/0'/0/0"
RPCS = {
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc.publicnode.com"
}
HITS_FILE = "hits.txt"
RPC_RETRIES = 3
REQUEST_TIMEOUT = 10
CANDIDATE_CHUNK = 20  # number of mnemonics to generate per loop
# ---------------------------------------

mnemo_en = Mnemonic("english")               
mnemo_cn = Mnemonic("chinese_simplified")   
executor = ThreadPoolExecutor(max_workers=THREADS)
hits_fp = open(HITS_FILE, "a", encoding="utf-8")
seen_addresses = set()  # dedupe

def derive(seed_bytes):
    bip32 = BIP32.from_seed(seed_bytes)
    priv = bip32.get_privkey_from_path(DERIVATION_PATH)
    pk = coincurve.PrivateKey(priv)
    pub = pk.public_key.format(compressed=False)[1:]
    addr_bytes = hashlib.sha3_256(pub).digest()[-20:]
    addr_hex = addr_bytes.hex()
    hash_hex = hashlib.sha3_256(pub).hexdigest()
    checksum_addr = "0x" + "".join(
        c.upper() if int(hash_hex[i], 16) >= 8 else c
        for i, c in enumerate(addr_hex)
    )
    return priv.hex(), checksum_addr

async def fetch_balance(session, addr, chain):
    url = RPCS[chain]
    payload = {"jsonrpc": "2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1}
    for attempt in range(1, RPC_RETRIES+1):
        try:
            async with session.post(url, json=payload, timeout=REQUEST_TIMEOUT) as r:
                if r.status != 200:
                    continue
                data = await r.json()
                result = data.get("result","0x0")
                bal = int(result,16)/10**18
                return bal
        except:
            await asyncio.sleep(1.2**attempt)
    return 0.0

def print_hit(mn_eth, priv_eth, addr_eth, eth_bal,
              mn_bsc, priv_bsc, addr_bsc, bsc_bal):
    border = "=" * 53
    hit_lines = [
        "+" + border + "+",
        "| MATCH FOUND".ljust(55) + "|",
        "+" + border + "+",
        f"| ETH Mnemonic: {mn_eth}".ljust(55)[:55]+"|",
        f"| ETH Address : {addr_eth}".ljust(55)[:55]+"|",
        f"| ETH PrivKey : {priv_eth}".ljust(55)[:55]+"|",
        f"| ETH Bal     : {eth_bal}".ljust(55)[:55]+"|",
        f"| BSC Mnemonic: {mn_bsc}".ljust(55)[:55]+"|",
        f"| BSC Address : {addr_bsc}".ljust(55)[:55]+"|",
        f"| BSC PrivKey : {priv_bsc}".ljust(55)[:55]+"|",
        f"| BSC Bal     : {bsc_bal}".ljust(55)[:55]+"|",
        "+" + border + "+"
    ]
    print("\n" + "\n".join(hit_lines) + "\n")
    try:
        hits_fp.write(f"{mn_eth},{priv_eth},{addr_eth},{eth_bal},{mn_bsc},{priv_bsc},{addr_bsc},{bsc_bal}\n")
        hits_fp.flush()
    except:
        pass

def print_live(addr, bal, chain):
    bal_str = f"{bal}" if bal > 0 else "0.0"
    print(f"{addr} | {chain}:{bal_str}")

async def worker_loop():
    addr_checked = 0
    start_time = time.time()
    async with aiohttp.ClientSession() as session:
        try:
            while True:
                mnemonics_eth = [mnemo_en.generate(128) for _ in range(CANDIDATE_CHUNK)]
                mnemonics_bsc = [mnemo_cn.generate(128) for _ in range(CANDIDATE_CHUNK)]

                tasks = []
                for mn_eth, mn_bsc in zip(mnemonics_eth, mnemonics_bsc):
                    seed_eth = mnemo_en.to_seed(mn_eth)
                    priv_eth, addr_eth = derive(seed_eth)

                    seed_bsc = mnemo_cn.to_seed(mn_bsc)
                    priv_bsc, addr_bsc = derive(seed_bsc)

                    # dedupe
                    if addr_eth.lower() in seen_addresses or addr_bsc.lower() in seen_addresses:
                        continue
                    seen_addresses.add(addr_eth.lower())
                    seen_addresses.add(addr_bsc.lower())

                    tasks.append((mn_eth, priv_eth, addr_eth, mn_bsc, priv_bsc, addr_bsc))

                # fetch balances concurrently
                balance_tasks = []
                for mn_eth, priv_eth, addr_eth, mn_bsc, priv_bsc, addr_bsc in tasks:
                    balance_tasks.append(asyncio.gather(
                        fetch_balance(session, addr_eth, "eth"),
                        fetch_balance(session, addr_bsc, "bsc"),
                        return_exceptions=True
                    ))
                results = await asyncio.gather(*balance_tasks)

                for i, (mn_eth, priv_eth, addr_eth, mn_bsc, priv_bsc, addr_bsc) in enumerate(tasks):
                    eth_bal, bsc_bal = results[i]
                    addr_checked += 2

                    # live prints
                    print_live(addr_eth, eth_bal, "ETH")
                    print_live(addr_bsc, bsc_bal, "BSC")

                    elapsed = max(time.time()-start_time, 1)
                    speed = addr_checked / elapsed
                    print(f"Addresses/sec: {speed:.2f}")

                    if eth_bal>0 or bsc_bal>0:
                        print_hit(mn_eth, priv_eth, addr_eth, eth_bal,
                                  mn_bsc, priv_bsc, addr_bsc, bsc_bal)

        except asyncio.CancelledError:
            return

async def main():
    print(f"START scanner: threads={THREADS}")
    tasks = [asyncio.create_task(worker_loop()) for _ in range(THREADS)]
    try:
        await asyncio.gather(*tasks)
    except KeyboardInterrupt:
        for t in tasks:
            t.cancel()
        print("\nStopping scanner (Ctrl+C received).")
    finally:
        try: hits_fp.close()
        except: pass
        sys.exit(0)

if __name__=="__main__":
    asyncio.run(main())
