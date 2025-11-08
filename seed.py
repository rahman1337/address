#!/usr/bin/env python3
import requests, time, hashlib
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

seen_mnemonics = set()
seen_addresses = set()
total_checked = 0
start_time = time.time()

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

# ---------------- BALANCE ----------------
def fetch_balance(addr, chain):
    payload={"jsonrpc":"2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1}
    for _ in range(3):
        try:
            r = requests.post(RPCS[chain], json=payload, timeout=10)
            data = r.json()
            bal = int(data.get("result","0x0"),16)/10**18
            return bal, "OK"
        except:
            time.sleep(1)
    return 0.0,"FAIL"

def check_balances(results):
    global total_checked
    for mnemonic, priv, addr in results:
        eth_bal, eth_status = fetch_balance(addr,"eth")
        bsc_bal, bsc_status = fetch_balance(addr,"bsc")
        total_checked += 1
        elapsed = time.time()-start_time
        speed = total_checked/elapsed if elapsed>0 else 0
        # Live prints
        print(f"{addr} | ETH: {eth_bal if eth_bal>0 else 0.0} | RPC: {eth_status} | Speed: {speed:.2f} addr/sec")
        print(f"{addr} | BSC: {bsc_bal if bsc_bal>0 else 0.0} | RPC: {bsc_status} | Speed: {speed:.2f} addr/sec")
        if eth_bal>0 or bsc_bal>0:
            print_hit(mnemonic, priv, addr, eth_bal, bsc_bal)

# ---------------- BATCH GENERATION ----------------
def generate_batch():
    batch=[]
    while len(batch)<BATCH_SIZE:
        try:
            m = generate_mnemonic()
            priv, addr = derive_address(m)
            batch.append((m, priv, addr))
        except:
            continue
    return batch

# ---------------- MAIN LOOP ----------------
def main():
    while True:
        futures = [executor.submit(generate_batch) for _ in range(WORKERS)]
        results = []
        for f in futures:
            results.extend(f.result())
        check_balances(results)

# ---------------- ENTRY ----------------
if __name__=="__main__":
    try:
        main()
    except KeyboardInterrupt:
        hits_fp.close()
