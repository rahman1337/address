#!/usr/bin/env python3
import asyncio, aiohttp, hashlib, time
from concurrent.futures import ThreadPoolExecutor
from mnemonic import Mnemonic
import coincurve
from bip32 import BIP32

# ---------------- CONFIG ----------------
WORKERS = 6
BATCH_SIZE = 500
DERIVATION_PATH = "m/44'/60'/0'/0/0"
RPCS = {"eth":"https://ethereum.publicnode.com",
        "bsc":"https://bsc.publicnode.com"}
HITS_FILE = "hits.txt"
# ---------------------------------------

mnemo = Mnemonic("english")
executor = ThreadPoolExecutor(max_workers=WORKERS)
hits_fp = open(HITS_FILE,"a",encoding="utf-8")

# ---------------- DEDUPLICATION ----------------
seen_mnemonics = set()
seen_addresses = set()

# ---------------- SPEED MONITOR ----------------
total_checked = 0
start_time = time.time()
lock = asyncio.Lock()  # safe counter across async

# ---------------- DERIVATION ----------------
def generate_mnemonic():
    while True:
        m = mnemo.generate(128)
        if m not in seen_mnemonics:
            seen_mnemonics.add(m)
            return m

def derive_address(mnemonic):
    seed = mnemo.to_seed(mnemonic)
    bip32 = BIP32.from_seed(seed)
    priv = bip32.get_privkey_from_path(DERIVATION_PATH)
    pk = coincurve.PrivateKey(priv)
    pub = pk.public_key.format(compressed=False)[1:]
    addr_bytes = hashlib.sha3_256(pub).digest()[-20:]
    addr = "0x" + addr_bytes.hex()
    if addr in seen_addresses:
        raise ValueError("Address already derived")
    seen_addresses.add(addr)
    return priv.hex(), addr

# ---------------- HITS ----------------
def print_hit(mnemonic, priv, address, eth_bal, bsc_bal):
    border = "=" * 53
    print("\n+" + border + "+")
    print("| MATCH FOUND".ljust(55) + "|")
    print("+" + border + "+")
    print(f"| Mnemonic: {mnemonic}".ljust(55)[:55] + "|")
    print(f"| Address : {address}".ljust(55)[:55] + "|")
    print(f"| PrivKey : {priv}".ljust(55)[:55] + "|")
    print(f"| ETH Bal : {eth_bal}".ljust(55)[:55] + "|")
    print(f"| BSC Bal : {bsc_bal}".ljust(55)[:55] + "|")
    print("+" + border + "+\n")
    try:
        hits_fp.write(f"{mnemonic},{priv},{address},{eth_bal},{bsc_bal}\n")
        hits_fp.flush()
    except Exception as e:
        print("Failed to write hit:", e)

# ---------------- BALANCE CHECK ----------------
async def fetch_balance(session,address,chain):
    payload={"jsonrpc":"2.0","method":"eth_getBalance","params":[address,"latest"],"id":1}
    for attempt in range(3):
        try:
            async with session.post(RPCS[chain],json=payload,timeout=10) as resp:
                data = await resp.json()
                bal = int(data.get("result","0x0"),16)/10**18
                return bal,"OK"
        except:
            await asyncio.sleep(1.2**attempt)
    return 0.0,"FAIL"

async def check_balances(results):
    global total_checked, BATCH_SIZE
    async with aiohttp.ClientSession() as session:
        tasks=[]
        mapping=[]
        for mnemonic,priv,addr in results:
            for chain in ("eth","bsc"):
                tasks.append(fetch_balance(session,addr,chain))
                mapping.append((mnemonic,priv,addr,chain))
        start_rpc = time.time()
        res = await asyncio.gather(*tasks)
        for (mnemonic,priv,addr,chain),(bal,status) in zip(mapping,res):
            # Update counter & compute speed
            async with lock:
                total_checked += 1
                elapsed = time.time() - start_time
                speed = total_checked / elapsed if elapsed>0 else 0
            bal_str = f"{bal}" if bal>0 else "0.0"
            # Live print per address
            print(f"{addr} | {chain.upper()} balance: {bal_str} | RPC: {status} | Speed: {speed:.2f} addr/sec")
            if bal>0:
                if chain=="eth":
                    eth_bal=bal
                    bsc_bal=0
                else:
                    eth_bal=0
                    bsc_bal=bal
                print_hit(mnemonic,priv,addr,eth_bal,bsc_bal)
        # Dynamic batch adjustment
        rpc_elapsed = time.time() - start_rpc
        if rpc_elapsed < 0.8:  # RPC very fast → increase batch
            BATCH_SIZE = min(BATCH_SIZE+50, 1000)
        elif rpc_elapsed > 2.0:  # RPC slow → reduce batch
            BATCH_SIZE = max(BATCH_SIZE-50, 100)

# ---------------- BATCH GENERATION ----------------
def generate_batch():
    batch=[]
    while len(batch)<BATCH_SIZE:
        try:
            m = generate_mnemonic()
            priv,addr = derive_address(m)
            batch.append((m,priv,addr))
        except Exception:
            continue
    return batch

# ---------------- MAIN LOOP ----------------
async def main():
    loop = asyncio.get_event_loop()
    while True:
        futures = [loop.run_in_executor(executor,generate_batch) for _ in range(WORKERS)]
        results = await asyncio.gather(*futures)
        flat = [item for sublist in results for item in sublist]
        await check_balances(flat)

# ---------------- ENTRY ----------------
if __name__=="__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        hits_fp.close()
