#!/usr/bin/env python3
import argparse
import time
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160, keccak

SECP256K1_ORDER = int(
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

# ANSI colors
YELLOW = "\033[33m"
LIGHT_GREEN = "\033[92m"
RESET = "\033[0m"

# ----------------- BTC helpers -----------------
def sha256(b: bytes) -> bytes:
    h = SHA256.new()
    h.update(b)
    return h.digest()

def ripemd160(b: bytes) -> bytes:
    h = RIPEMD160.new()
    h.update(b)
    return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def base58_encode(b: bytes) -> str:
    zeros = 0
    for c in b:
        if c == 0:
            zeros += 1
        else:
            break
    num = int.from_bytes(b, "big")
    chars = []
    while num > 0:
        num, rem = divmod(num, 58)
        chars.append(BASE58_ALPHABET[rem])
    return "1" * zeros + "".join(reversed(chars)) if chars else "1" * zeros

def base58check_encode(payload: bytes) -> str:
    chk = sha256(sha256(payload))[:4]
    return base58_encode(payload + chk)

def privkey_to_wif(priv_bytes: bytes, compressed: bool = False) -> str:
    prefix = b"\x80"
    payload = prefix + priv_bytes
    if compressed:
        payload += b"\x01"
    return base58check_encode(payload)

def p2pkh(pub: bytes) -> str:
    return base58check_encode(b"\x00" + hash160(pub))

def p2sh_p2wpkh(pub: bytes) -> str:
    redeem_script = b"\x00\x14" + hash160(pub)
    return base58check_encode(b"\x05" + hash160(redeem_script))

# ----------------- bech32 helpers -----------------
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xFF
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp: str):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp: str, data: bytes, bech32m: bool = False):
    values = bech32_hrp_expand(hrp) + list(data) + [0]*6
    polymod = bech32_polymod(values)
    const = 0x2bc830a3 if bech32m else 1
    polymod ^= const
    return bytes((polymod >> (5*(5-i)) & 31) for i in range(6))

def convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> bytes:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        if b >> frombits:
            raise ValueError("Invalid data for convertbits")
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("Invalid padding in convertbits")
    return bytes(ret)

def bech32_encode(hrp: str, data: bytes, bech32m: bool = False) -> str:
    combined = bytes(list(data) + list(bech32_create_checksum(hrp, data, bech32m=bech32m)))
    return hrp + "1" + "".join(BECH32_CHARSET[b] for b in combined)

def p2wpkh_bech32(pub: bytes) -> str:
    h160 = hash160(pub)
    data = bytes([0]) + convertbits(h160, 8, 5)
    return bech32_encode("bc", data, bech32m=False)

# ----------------- Taproot (P2TR) -----------------
def tagged_hash(tag: str, msg: bytes) -> bytes:
    tag_hash = sha256(tag.encode())
    return sha256(tag_hash + tag_hash + msg)

def p2tr_from_privkey(priv_bytes: bytes) -> str:
    priv_int = int.from_bytes(priv_bytes, "big")
    if priv_int == 0 or priv_int >= SECP256K1_ORDER:
        raise ValueError("Invalid private key for taproot")
    internal_pk = PrivateKey(priv_bytes)
    internal_uncomp = internal_pk.public_key.format(compressed=False)
    internal_xonly = internal_uncomp[1:33]
    tweak_bytes = tagged_hash("TapTweak", internal_xonly)
    tweak_int = int.from_bytes(tweak_bytes, "big") % SECP256K1_ORDER
    tweaked_priv_int = (priv_int + tweak_int) % SECP256K1_ORDER
    if tweaked_priv_int == 0:
        raise ValueError("Taproot tweak resulted in invalid key (0).")
    tweaked_pk = PrivateKey(tweaked_priv_int.to_bytes(32, "big"))
    tweaked_uncomp = tweaked_pk.public_key.format(compressed=False)
    tweaked_xonly = tweaked_uncomp[1:33]
    data = bytes([1]) + convertbits(tweaked_xonly, 8, 5)
    return bech32_encode("bc", data, bech32m=True)

# ----------------- EVM helpers -----------------
def eth_address_from_priv(priv_bytes: bytes) -> str:
    pk = PrivateKey(priv_bytes)
    uncompressed = pk.public_key.format(compressed=False)
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(uncompressed[1:])
    addr_bytes = keccak_hash.digest()[-20:]
    return "0x" + addr_bytes.hex()

# ----------------- Index Provider -----------------
class IndexProvider:
    def __init__(self, start: int = 1):
        self._lock = threading.Lock()
        self._i = start
    def next_index(self) -> int:
        with self._lock:
            val = self._i
            self._i += 1
            if self._i >= SECP256K1_ORDER:
                self._i = 1
            return val

# ----------------- AddrChecker -----------------
class AddrChecker:
    def __init__(self, session: requests.Session, sem: threading.Semaphore, delay: float=0.6, debug: bool=False, timeout: float=10.0):
        self.session = session
        self.sem = sem
        self.delay = delay
        self.debug = debug
        self.timeout = timeout

    def _get_with_retries(self, url, retries=3):
        last_exc = None
        for attempt in range(1, retries+1):
            try:
                self.sem.acquire()
                try:
                    resp = self.session.get(url, timeout=self.timeout)
                finally:
                    self.sem.release()
            except Exception as e:
                last_exc = e
            else:
                if resp.status_code == 200:
                    time.sleep(self.delay)
                    return resp
                elif resp.status_code == 429:
                    last_exc = RuntimeError("HTTP 429 Too Many Requests")
                else:
                    last_exc = RuntimeError(f"HTTP {resp.status_code}")
            if attempt < retries:
                time.sleep(self.delay)
        raise last_exc

    # BTC received
    def btc_received(self, addr: str) -> int:
        url = f"https://blockchain.info/q/getreceivedbyaddress/{addr}"
        resp = self._get_with_retries(url)
        return int(resp.text.strip())

    # BTC balance
    def btc_balance(self, addr: str) -> int:
        url = f"https://api.blockcypher.com/v1/btc/main/addrs/{addr}/balance"
        resp = self._get_with_retries(url)
        data = resp.json()
        return int(data.get("final_balance", 0))

    # ETH/BSC/Polygon balance
    def evm_balance(self, chain: str, address: str) -> int:
        endpoints = {
            "eth":"https://rpc.ankr.com/eth",
            "bsc":"https://bsc-dataseed.binance.org/",
            "polygon":"https://rpc.ankr.com/polygon"
        }
        if chain not in endpoints:
            raise RuntimeError("Unknown chain: "+chain)
        url = endpoints[chain]
        addr = address if address.startswith("0x") else "0x"+address
        payload = {"jsonrpc":"2.0","method":"eth_getBalance","params":[addr,"latest"],"id":1}
        self.sem.acquire()
        try:
            resp = self.session.post(url,json=payload,timeout=self.timeout)
        finally:
            self.sem.release()
        resp.raise_for_status()
        time.sleep(self.delay)
        result = resp.json()
        return int(result["result"],16)

# ----------------- Worker Thread -----------------
stop_event = threading.Event()
last_priv_hex = None
last_priv_lock = threading.Lock()

def worker_thread(name, idx_provider, checker, print_lock, chains):
    global last_priv_hex
    while not stop_event.is_set():
        idx = idx_provider.next_index()
        priv_bytes = idx.to_bytes(32,"big")
        priv_hex = priv_bytes.hex()
        priv_hex_0x = "0x"+priv_hex
        with last_priv_lock:
            last_priv_hex = priv_hex_0x
        try:
            pk = PrivateKey(priv_bytes)
            pub = pk.public_key.format(compressed=True)
            wif = privkey_to_wif(priv_bytes, compressed=True)

            # ----------------- BTC -----------------
            if "btc" in chains:
                btc_addrs = [p2pkh(pub), p2sh_p2wpkh(pub), p2wpkh_bech32(pub)]
                try:
                    btc_addrs.append(p2tr_from_privkey(priv_bytes))
                except Exception as e:
                    if checker.debug:
                        with print_lock:
                            print(f"[DEBUG] Taproot derivation skipped for idx {idx}: {e}", flush=True)

                for addr in btc_addrs:
                    if stop_event.is_set(): break
                    try:
                        recvd = checker.btc_received(addr)
                    except Exception as e:
                        with print_lock:
                            print(f"[ERROR] BTC {addr} {e}",flush=True)
                        continue
                    if recvd == 0:
                        continue
                    try:
                        bal = checker.btc_balance(addr)
                    except Exception as e:
                        with print_lock:
                            print("\n"+"="*53)
                            print("!!! FOUND BTC ADDRESS BUT BALANCE CHECK FAILED !!!")
                            print("")
                            print("WIF:", wif)
                            print("ADDRESS:", addr)
                            print("RECEIVED (sats):",f"{YELLOW}{recvd}{RESET}")
                            print("BALANCE CHECK ERROR:",str(e))
                            print("="*53+"\n")
                        continue
                    with print_lock:
                        print("\n"+"="*53)
                        print("!!!!! FOUND BITCOIN ADDRESS WITH FUNDS !!!!!")
                        print("")
                        print("WIF:", wif)
                        print("ADDRESS:", addr)
                        print("RECEIVED (sats):",f"{YELLOW}{recvd}{RESET}")
                        print("BALANCE (sats):",f"{LIGHT_GREEN}{bal}{RESET}")
                        print("="*53+"\n")

            # ----------------- ETH/BSC/Polygon -----------------
            for chain in ["eth","bsc","polygon"]:
                if chain not in chains: continue
                addr = eth_address_from_priv(priv_bytes)
                try:
                    bal = checker.evm_balance(chain,addr)
                except Exception as e:
                    with print_lock:
                        print(f"[ERROR] {chain.upper()} {addr} {e}",flush=True)
                    continue
                if bal == 0:
                    continue
                with print_lock:
                    print("\n"+"="*53)
                    print("!!!!! FOUND ADDRESS WITH FUNDS !!!!!")
                    print("")
                    print("PRIVATE KEY (hex):",priv_hex_0x)
                    print("ADDRESS:",addr)
                    print("COINS:",chain.upper())
                    print("BALANCE (wei):",bal)
                    print("BALANCE (native):",f"{bal/1e18:.6f} {chain.upper()}")
                    print("="*53+"\n")

        except Exception as e:
            with print_lock:
                print(f"[ERROR] {name} idx={idx} derivation failed: {e}",flush=True)

# ----------------- Main -----------------
def parse_args():
    p = argparse.ArgumentParser(description="Multi-chain EVM + BTC scanner")
    p.add_argument("-t","--threads",type=int,default=3)
    p.add_argument("-c","--concurrency",type=int,default=2)
    p.add_argument("--chains",type=str,default="eth,bsc,polygon,btc")
    p.add_argument("--start",type=int,default=1)
    p.add_argument("--delay",type=float,default=0.6,help="Delay in seconds between each web request")
    return p.parse_args()

def main():
    global last_priv_hex
    args = parse_args()
    chains = [x.lower() for x in args.chains.split(",")]

    idx_provider = IndexProvider(start=args.start)
    session = requests.Session()
    sem = threading.Semaphore(max(1,args.concurrency))
    checker = AddrChecker(session,sem,delay=args.delay)

    print_lock = threading.Lock()

    def _signal_handler(sig, frame):
        stop_event.set()
        with last_priv_lock:
            checkpoint = last_priv_hex
        if checkpoint:
            print("\n[INFO] Interrupted by user. Last private key hex:",checkpoint,flush=True)
        else:
            print("\n[INFO] Interrupted by user. No key processed yet.",flush=True)

    signal.signal(signal.SIGINT,_signal_handler)
    signal.signal(signal.SIGTERM,_signal_handler)

    with ThreadPoolExecutor(max_workers=max(1,args.threads)) as executor:
        futures = [executor.submit(worker_thread,f"worker-{i+1}",idx_provider,checker,print_lock,chains)
                   for i in range(max(1,args.threads))]
        try:
            for future in as_completed(futures):
                if stop_event.is_set(): break
                try:
                    future.result(timeout=0)
                except Exception:
                    pass
        except KeyboardInterrupt:
            stop_event.set()
        executor.shutdown(wait=True)

    print("[INFO] All workers stopped. Exiting.",flush=True)

if __name__ == "__main__":
    main()