#!/usr/bin/env python3

import time, sys, requests, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed
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
CANDIDATE_CHUNK = 20  # number of mnemonics to derive per loop
# ---------------------------------------

mnemo_en = Mnemonic("english")               # ETH
mnemo_cn = Mnemonic("chinese_simplified")   # BSC
executor = ThreadPoolExecutor(max_workers=THREADS)
hits_fp = open(HITS_FILE, "a", encoding="utf-8")
seen_addresses = set()  # dedupe globally

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

def fetch_balance(addr, chain):
    url = RPCS[chain]
    payload = {"jsonrpc": "2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1}
    for attempt in range(1, RPC_RETRIES+1):
        try:
            r = requests.post(url, json=payload, timeout=REQUEST_TIMEOUT)
            if r.status_code != 200:
                continue
            data = r.json()
            result = data.get("result","0x0")
            return int(result,16)/10**18
        except:
            time.sleep(1.2**attempt)
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

def worker():
    addr_checked = 0
    start_time = time.time()
    try:
        while True:
            mnemonics_eth = [mnemo_en.generate(128) for _ in range(CANDIDATE_CHUNK)]
            mnemonics_bsc = [mnemo_cn.generate(128) for _ in range(CANDIDATE_CHUNK)]

            for mn_eth, mn_bsc in zip(mnemonics_eth, mnemonics_bsc):
                seed_eth = mnemo_en.to_seed(mn_eth)
                priv_eth, addr_eth = derive(seed_eth)

                seed_bsc = mnemo_cn.to_seed(mn_bsc)
                priv_bsc, addr_bsc = derive(seed_bsc)

                if addr_eth.lower() in seen_addresses or addr_bsc.lower() in seen_addresses:
                    continue
                seen_addresses.add(addr_eth.lower())
                seen_addresses.add(addr_bsc.lower())

                eth_bal = fetch_balance(addr_eth, "eth")
                bsc_bal = fetch_balance(addr_bsc, "bsc")

                # live prints
                print(f"RPC : eth checked\n{addr_eth} | ETH:{eth_bal}")
                print(f"RPC : bsc checked\n{addr_bsc} | BSC:{bsc_bal}")

                addr_checked += 2
                elapsed = max(time.time()-start_time, 1)
                speed = addr_checked / elapsed
                print(f"Addresses/sec: {speed:.2f}")

                if eth_bal>0 or bsc_bal>0:
                    print_hit(mn_eth, priv_eth, addr_eth, eth_bal,
                              mn_bsc, priv_bsc, addr_bsc, bsc_bal)
    except KeyboardInterrupt:
        return

def main():
    print(f"START scanner: threads={THREADS}")
    try:
        futures = [executor.submit(worker) for _ in range(THREADS)]
        for f in as_completed(futures):
            pass
    except KeyboardInterrupt:
        print("\nStopping scanner (Ctrl+C received).")
    finally:
        try: hits_fp.close()
        except: pass
        executor.shutdown(wait=False)
        sys.exit(0)

if __name__=="__main__":
    main()
