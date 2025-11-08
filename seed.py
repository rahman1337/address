#!/usr/bin/env python3
"""
Scanner:
- English mnemonics for ETH
- Chinese Simplified mnemonics for BSC
- 5 threads, batch 100
- No repeated addresses
- Retries on RPC errors
- Live printing of address/balances in gray
- Bordered hit block in light green + line-by-line hits.txt
- Live addresses/sec counter
"""

import time, sys, requests, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from mnemonic import Mnemonic
import coincurve
from bip32 import BIP32

# ---------------- CONFIG ----------------
THREADS = 5
BATCH_SIZE = 100
DERIVATION_PATH = "m/44'/60'/0'/0/0"
RPCS = {
    "eth": "https://ethereum.publicnode.com",
    "bsc": "https://bsc.publicnode.com"
}
HITS_FILE = "hits.txt"
RPC_RETRIES = 3
REQUEST_TIMEOUT = 10
# ---------------------------------------

# ANSI colors
GREEN = "\033[92m"   # light green for hits
GRAY = "\033[90m"    # dim gray for normal live prints
RESET = "\033[0m"    # reset color

mnemo_en = Mnemonic("english")               # for ETH
mnemo_cn = Mnemonic("chinese_simplified")   # for BSC
executor = ThreadPoolExecutor(max_workers=THREADS)
hits_fp = open(HITS_FILE, "a", encoding="utf-8")
seen_addresses = set()  # dedupe

# ---------------- Derivation ----------------
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

# ---------------- Batch generation ----------------
def generate_batch():
    batch = []
    while len(batch) < BATCH_SIZE:
        # ETH mnemonic (English)
        mn_eth = mnemo_en.generate(128)
        seed_eth = mnemo_en.to_seed(mn_eth)
        priv_eth, addr_eth = derive(seed_eth)
        # BSC mnemonic (Chinese)
        mn_bsc = mnemo_cn.generate(128)
        seed_bsc = mnemo_cn.to_seed(mn_bsc)
        priv_bsc, addr_bsc = derive(seed_bsc)

        # dedupe
        if addr_eth.lower() in seen_addresses or addr_bsc.lower() in seen_addresses:
            continue
        seen_addresses.add(addr_eth.lower())
        seen_addresses.add(addr_bsc.lower())

        batch.append({
            "mn_eth": mn_eth, "priv_eth": priv_eth, "addr_eth": addr_eth,
            "mn_bsc": mn_bsc, "priv_bsc": priv_bsc, "addr_bsc": addr_bsc
        })
    return batch

# ---------------- RPC / retries ----------------
def fetch_balance(addr, chain):
    url = RPCS[chain]
    payload = {"jsonrpc": "2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1}
    for attempt in range(1, RPC_RETRIES+1):
        try:
            r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
            if r.status_code != 200:
                print(f"RPC : {chain} ERROR (status {r.status_code}) attempt {attempt}/{RPC_RETRIES}")
                time.sleep(1.2**attempt)
                continue
            data = r.json()
            result = data.get("result","0x0")
            bal = int(result,16)/10**18
            print(f"RPC : {chain} OK (attempt {attempt})")
            return bal
        except Exception as e:
            print(f"RPC : {chain} ERR attempt {attempt}/{RPC_RETRIES}: {e}")
            time.sleep(1.2**attempt)
    print(f"RPC : {chain} FAIL after {RPC_RETRIES} attempts")
    return 0.0

# ---------------- Hit printing ----------------
def print_hit(mn_eth, priv_eth, addr_eth, eth_bal,
              mn_bsc, priv_bsc, addr_bsc, bsc_bal):
    border = "=" * 53
    print(GREEN + "\n+" + border + "+")
    print("| MATCH FOUND".ljust(55) + "|")
    print("+" + border + "+")
    print(f"| ETH Mnemonic: {mn_eth}".ljust(55)[:55]+"|")
    print(f"| ETH Address : {addr_eth}".ljust(55)[:55]+"|")
    print(f"| ETH PrivKey : {priv_eth}".ljust(55)[:55]+"|")
    print(f"| ETH Bal     : {eth_bal}".ljust(55)[:55]+"|")
    print(f"| BSC Mnemonic: {mn_bsc}".ljust(55)[:55]+"|")
    print(f"| BSC Address : {addr_bsc}".ljust(55)[:55]+"|")
    print(f"| BSC PrivKey : {priv_bsc}".ljust(55)[:55]+"|")
    print(f"| BSC Bal     : {bsc_bal}".ljust(55)[:55]+"|")
    print("+" + border + "+\n" + RESET)
    try:
        hits_fp.write(f"{mn_eth},{priv_eth},{addr_eth},{eth_bal},{mn_bsc},{priv_bsc},{addr_bsc},{bsc_bal}\n")
        hits_fp.flush()
    except Exception as e:
        print("Failed to write hit:", e)

# ---------------- Live printing ----------------
def print_live(addr, bal, chain):
    bal_str = f"{bal}" if bal > 0 else "0.0"
    print(GRAY + f"{addr} | {chain}:{bal_str}" + RESET)

# ---------------- Main loop ----------------
def main():
    print(f"START scanner: threads={THREADS}, batch={BATCH_SIZE}")
    start_time = time.time()
    addr_checked = 0
    try:
        while True:
            futures = [executor.submit(generate_batch) for _ in range(THREADS)]
            all_results = []
            for f in as_completed(futures):
                try:
                    all_results.extend(f.result())
                except Exception as e:
                    print("Batch generation error:", e)
            for item in all_results:
                eth_bal = fetch_balance(item["addr_eth"], "eth")
                bsc_bal = fetch_balance(item["addr_bsc"], "bsc")
                addr_checked += 2  # ETH + BSC

                # Live print
                print_live(item['addr_eth'], eth_bal, "ETH")
                print_live(item['addr_bsc'], bsc_bal, "BSC")

                # Print hit if either >0
                if eth_bal>0 or bsc_bal>0:
                    print_hit(
                        item["mn_eth"], item["priv_eth"], item["addr_eth"], eth_bal,
                        item["mn_bsc"], item["priv_bsc"], item["addr_bsc"], bsc_bal
                    )

                # Live addresses/sec counter
                elapsed = max(time.time()-start_time, 1)
                speed = addr_checked / elapsed
                print(GRAY + f"Addresses/sec: {speed:.2f}" + RESET)
    except KeyboardInterrupt:
        print("\nStopping scanner (Ctrl+C received).")
    finally:
        try: hits_fp.close()
        except: pass
        executor.shutdown(wait=False)
        sys.exit(0)

if __name__=="__main__":
    main()
