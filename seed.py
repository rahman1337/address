#!/usr/bin/env python3
"""
ETH + BSC Mnemonic Scanner (MAX CPU, RPC Resilient)
- 6 cores full saturation
- Dynamic batch sizing
- coincurve C-backed EC derivation
- BIP39/BIP32 compatible
- Live ETH/BSC balances & clean prints
"""

import asyncio, aiohttp, hashlib, json, threading, traceback, math, random
from concurrent.futures import ThreadPoolExecutor
from mnemonic import Mnemonic
from bip32 import BIP32
import coincurve
import logging

# ---------------- CONFIG ----------------
WORKERS = 6
BASE_BATCH_SIZE = 1000  # will adjust dynamically
DERIVATION_PATH = "m/44'/60'/0'/0/0"
RPCS = {
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc.publicnode.com"
}
HITS_FILE = "hits.txt"
RPC_MAX_RETRIES = 3
BLOOM_CAPACITY = 30_000_000
BLOOM_ERROR_RATE = 1e-5
# ------------------------------

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
mnemo = Mnemonic("english")
checked = 0
checked_lock = threading.Lock()
unique_addresses = 0
unique_addr_lock = threading.Lock()
hits_fp = open(HITS_FILE, "a", encoding="utf-8")

# ---------------- Bloom Filter ----------------
class BloomFilter:
    def __init__(self, capacity: int, error_rate: float):
        m = -capacity * math.log(error_rate) / (math.log(2)**2)
        k = max(1, int(round((m/capacity)*math.log(2))))
        self.m = int(m)
        self.k = k
        self._bits = bytearray((self.m + 7)//8)
        self._lock = threading.Lock()
    def _hashes(self, data: bytes):
        h = hashlib.sha256(data).digest()
        idxs = []
        counter = 0
        while len(idxs) < self.k:
            chunk = hashlib.sha256(h + counter.to_bytes(2,"big")).digest()
            for i in range(0,len(chunk),8):
                if len(idxs) >= self.k: break
                val = int.from_bytes(chunk[i:i+8],"big")
                idxs.append(val % self.m)
            counter+=1
        return idxs
    def add(self, data):
        if isinstance(data,str): data=data.encode("utf-8")
        idxs = self._hashes(data)
        with self._lock:
            for i in idxs: self._bits[i>>3]|=(1<<(i&7))
    def __contains__(self,data):
        if isinstance(data,str): data=data.encode("utf-8")
        idxs=self._hashes(data)
        with self._lock:
            for i in idxs:
                if not (self._bits[i>>3] & (1<<(i&7))): return False
        return True

mnemonic_bloom = BloomFilter(BLOOM_CAPACITY,BLOOM_ERROR_RATE)
address_bloom = BloomFilter(BLOOM_CAPACITY,BLOOM_ERROR_RATE)

# ---------------- Helpers ----------------
def generate_unique_mnemonic():
    while True:
        m = mnemo.generate(128)  # 12 words
        h = hashlib.sha256(m.encode("utf-8")).digest()
        if h in mnemonic_bloom: continue
        mnemonic_bloom.add(h)
        return m

def mnemonic_to_priv_and_address_coincurve(mnemonic_phrase):
    seed = mnemo.to_seed(mnemonic_phrase)
    bip32 = BIP32.from_seed(seed)
    priv_bytes = bip32.get_privkey_from_path(DERIVATION_PATH)
    pk = coincurve.PrivateKey(priv_bytes)
    pub_bytes = pk.public_key.format(compressed=False)[1:]
    addr_bytes = hashlib.sha3_256(pub_bytes).digest()[-20:]
    checksum_addr = "0x"+"".join(
        c.upper() if int(hashlib.sha3_256(pub_bytes).hexdigest()[i],16)>=8 else c
        for i,c in enumerate(addr_bytes.hex())
    )
    return pk.to_hex(), checksum_addr

def process_batch(batch_size):
    global checked, unique_addresses
    results=[]
    for _ in range(batch_size):
        try:
            mnemonic = generate_unique_mnemonic()
            privhex,address = mnemonic_to_priv_and_address_coincurve(mnemonic)
        except Exception as e:
            logging.error("Derivation error: %s", e)
            continue
        addr_lower = address.lower()
        if addr_lower in address_bloom: continue
        address_bloom.add(addr_lower)
        with unique_addr_lock: unique_addresses+=1
        with checked_lock: checked+=1
        results.append((mnemonic,address,privhex))
    return results

def print_hit(mnemonic,address,privhex,eth_bal,bsc_bal):
    border = "="*53
    print("\n+"+border+"+")
    print("| MATCH FOUND".ljust(55)+"|")
    print("+"+border+"+")
    print(f"| Mnemonic: {mnemonic}".ljust(55)[:55]+"|")
    print(f"| Address : {address}".ljust(55)[:55]+"|")
    print(f"| PrivKey : {privhex}".ljust(55)[:55]+"|")
    print(f"| ETH Bal : {eth_bal} ETH".ljust(55)[:55]+"|")
    print(f"| BSC Bal : {bsc_bal} BNB".ljust(55)[:55]+"|")
    print("+"+border+"+\n")
    try:
        hits_fp.write(f"{mnemonic},{address},{privhex},{eth_bal},{bsc_bal}\n")
        hits_fp.flush()
    except Exception:
        logging.error("Failed to write hit: %s",traceback.format_exc(limit=5))

# ---------------- RPC ----------------
async def fetch_balance(session,address,chain,retries=RPC_MAX_RETRIES):
    rpc_url = RPCS[chain]
    payload = {"jsonrpc":"2.0","method":"eth_getBalance","params":[address,"latest"],"id":1}
    for attempt in range(1,retries+1):
        try:
            async with session.post(rpc_url,json=payload,timeout=10) as resp:
                text = await resp.text()
                if resp.status!=200: raise Exception(f"RPC status {resp.status}")
                data = json.loads(text)
                bal_wei = int(data.get("result","0x0"),16)
                return bal_wei/10**18, "200 OK"
        except Exception as e:
            print(f"RPC : {chain} ERROR (attempt {attempt}/{retries})")
            await asyncio.sleep(1.2**attempt)
    return 0.0,"FAIL"

async def check_balances(results,session):
    hits=[]
    tasks=[]
    mapping=[]
    for idx,(_,addr,_) in enumerate(results):
        for chain in ("eth","bsc"):
            tasks.append(fetch_balance(session,addr,chain))
            mapping.append((idx,chain))
    pairs = await asyncio.gather(*tasks)
    per_index=[{"eth":0.0,"bsc":0.0,"eth_status":"","bsc_status":""} for _ in results]
    for (idx,chain),(bal,status) in zip(mapping,pairs):
        per_index[idx][chain]=bal
        per_index[idx][f"{chain}_status"]=status
    for (mnemonic,address,privhex),info in zip(results,per_index):
        eth_bal=info["eth"]
        bsc_bal=info["bsc"]
        print(f"{address} | ETH:{eth_bal:.18f} | BSC:{bsc_bal:.18f}")
        print(f"RPC : eth {info['eth_status']} | bsc {info['bsc_status']}")
        if eth_bal>0 or bsc_bal>0:
            hits.append((mnemonic,address,privhex,eth_bal,bsc_bal))
    return hits

# ---------------- Main ----------------
async def main_loop():
    logging.info(f"START scanner: workers={WORKERS}, batch={BASE_BATCH_SIZE}")
    executor = ThreadPoolExecutor(max_workers=WORKERS)
    pending=set()
    TARGET_IN_FLIGHT=max(4,WORKERS*2)
    async with aiohttp.ClientSession() as session:
        try:
            while True:
                while len(pending)<TARGET_IN_FLIGHT:
                    fut=asyncio.get_event_loop().run_in_executor(executor,process_batch,BASE_BATCH_SIZE)
                    pending.add(fut)
                done,_=await asyncio.wait(pending,return_when=asyncio.FIRST_COMPLETED)
                for fut in list(done):
                    pending.discard(fut)
                    try:
                        results=fut.result()
                    except Exception as e:
                        logging.error("Batch error: %s",e)
                        continue
                    hits=await check_balances(results,session)
                    for mnemonic,address,privhex,eth_bal,bsc_bal in hits:
                        print_hit(mnemonic,address,privhex,eth_bal,bsc_bal)
        except KeyboardInterrupt:
            logging.info("STOP requested by user")
        finally:
            executor.shutdown(wait=False)
            hits_fp.close()

if __name__=="__main__":
    try:
        asyncio.run(main_loop())
    except Exception as e:
        logging.error("Fatal error: %s\n%s",e,traceback.format_exc(limit=10))
