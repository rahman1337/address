#!/usr/bin/env python3
"""
btc_scanner_async.py

Deterministic async BTC address scanner:
- Sequential deterministic private keys (1,2,3,...).
- For each key derives compressed pubkey and addresses:
  P2PKH (1...), P2SH-P2WPKH (3...), P2WPKH (bc1q...).
- Uses aiohttp + asyncio for concurrency.
- Sleeps ~0.6 s (with jitter) after each address check.
- Limits concurrent network calls to avoid 429.
- Retries network calls up to 3 times with backoff.
- Ctrl+C prints a checkpoint (last private key hex tried).
- Use -d for debug logging.
"""

import argparse
import asyncio
import aiohttp
import signal
import random
import sys
from coincurve import PrivateKey
from Crypto.Hash import SHA256, RIPEMD160

# --- constants ---
SECP256K1_ORDER = int("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"  # correct Base58 alphabet

# --- hashing/base58 helpers ---
def sha256(b: bytes) -> bytes:
    h = SHA256.new(); h.update(b); return h.digest()

def ripemd160(b: bytes) -> bytes:
    h = RIPEMD160.new(); h.update(b); return h.digest()

def hash160(b: bytes) -> bytes:
    return ripemd160(sha256(b))

def base58_encode(b: bytes) -> str:
    n_pad = len(b) - len(b.lstrip(b"\0"))
    num = int.from_bytes(b, "big")
    chars = []
    while num:
        num, rem = divmod(num, 58)
        chars.append(BASE58_ALPHABET[rem])
    return "1" * n_pad + "".join(reversed(chars))

def base58check_encode(payload: bytes) -> str:
    chk = sha256(sha256(payload))[:4]
    return base58_encode(payload + chk)

def privkey_to_wif(priv_bytes: bytes, compressed=True) -> str:
    prefix = b"\x80"
    payload = prefix + priv_bytes + (b"\x01" if compressed else b"")
    return base58check_encode(payload)

# --- Bech32 (BIP173) helpers ---
BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    g = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1FFFFFF) << 5) ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= g[i]
    return chk

def bech32_hrp_expand(hrp): return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + list(data) + [0]*6
    polymod = bech32_polymod(values) ^ 1
    return bytes((polymod >> 5*(5-i)) & 31 for i in range(6))

def bech32_encode(hrp, data):
    combined = bytes(list(data) + list(bech32_create_checksum(hrp, data)))
    return hrp + "1" + "".join(BECH32_CHARSET[b] for b in combined)

def convertbits(data, frombits, tobits, pad=True):
    acc = bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        if b >> frombits: raise ValueError("invalid data")
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad and bits:
        ret.append((acc << (tobits - bits)) & maxv)
    return bytes(ret)

def bech32_p2wpkh_from_h160(h160: bytes) -> str:
    return bech32_encode("bc", bytes([0]) + convertbits(h160, 8, 5))

# --- address builders ---
def p2pkh(pub): return base58check_encode(b"\x00" + hash160(pub))
def p2sh_p2wpkh(pub): return base58check_encode(b"\x05" + hash160(b"\x00\x14" + hash160(pub)))
def p2wpkh_bech32(pub): return bech32_p2wpkh_from_h160(hash160(pub))

# --- deterministic index provider ---
class IndexProvider:
    def __init__(self, start=1):
        if not (1 <= start < SECP256K1_ORDER):
            raise ValueError("start out of range")
        self._i = start
        self._lock = asyncio.Lock()
    async def next_index(self):
        async with self._lock:
            val = self._i
            self._i = 1 if self._i + 1 >= SECP256K1_ORDER else self._i + 1
            return val

# --- graceful shutdown globals ---
stop_event = asyncio.Event()
last_priv_hex = None
last_priv_lock = asyncio.Lock()

# --- network checker with rate limiting & retries ---
class AddrChecker:
    def __init__(self, session, sem, debug=False):
        self.s = session
        self.sem = sem
        self.debug = debug

    async def _get(self, url, retries=3):
        for attempt in range(1, retries+1):
            if stop_event.is_set(): return None
            try:
                async with self.sem:
                    async with self.s.get(url, timeout=15) as resp:
                        if self.debug:
                            print(f"[DEBUG] GET {url} -> {resp.status}")
                        if resp.status == 429:
                            await asyncio.sleep(5)
                            continue
                        if resp.status == 200:
                            text = await resp.text()
                            return int(text.strip())
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] Error {url}: {e}")
            await asyncio.sleep(0.6)
        return None

    async def get_received(self, address): 
        return await self._get(f"https://blockchain.info/q/getreceivedbyaddress/{address}")
    async def get_balance(self, address): 
        return await self._get(f"https://blockchain.info/q/addressbalance/{address}")

# --- worker task ---
async def worker_task(name, idx_provider, checker, debug=False):
    global last_priv_hex
    while not stop_event.is_set():
        idx = await idx_provider.next_index()
        priv_bytes = idx.to_bytes(32, "big")
        async with last_priv_lock:
            last_priv_hex = priv_bytes.hex()

        try:
            pk = PrivateKey(priv_bytes)
            pub = pk.public_key.format(compressed=True)
            wif = privkey_to_wif(priv_bytes, True)
            addresses = [p2pkh(pub), p2sh_p2wpkh(pub), p2wpkh_bech32(pub)]

            if debug:
                print(f"[{name}] scanning idx={idx} priv={priv_bytes.hex()}")

            for addr in addresses:
                if stop_event.is_set(): break
                recvd = await checker.get_received(addr)
                await asyncio.sleep(0.55 + random.random() * 0.1)

                if recvd and recvd > 0:
                    await asyncio.sleep(1.0)
                    bal = await checker.get_balance(addr)
                    print("\n" + "="*60)
                    print("!!!!! FOUND ADDRESS WITH RECEIVED FUNDS !!!!!\n")
                    print("WIF:", wif)
                    print("ADDRESS:", addr)
                    print("RECEIVED (sats):", recvd)
                    print("BALANCE (sats):", bal if bal is not None else "N/A")
                    print("="*60 + "\n")
        except Exception as e:
            print(f"[ERROR] [{name}] failed: {e}")
            await asyncio.sleep(0.6)
    if debug:
        print(f"[{name}] exiting")

# --- main ---
def parse_args():
    p = argparse.ArgumentParser(description="Deterministic async BTC scanner")
    p.add_argument("-t","--threads",type=int,default=3,help="number of async workers (default 3)")
    p.add_argument("--start",type=int,default=1,help="start index")
    p.add_argument("-d","--debug",action="store_true")
    return p.parse_args()

async def main():
    global last_priv_hex
    args = parse_args()
    idx_provider = IndexProvider(args.start)
    sem = asyncio.Semaphore(2)  # limit concurrent requests
    async with aiohttp.ClientSession() as session:
        checker = AddrChecker(session, sem, args.debug)

        def handle_signal(*_):
            stop_event.set()
            asyncio.create_task(print_checkpoint())

        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, handle_signal)

        tasks = [asyncio.create_task(worker_task(f"worker-{i+1}", idx_provider, checker, args.debug))
                 for i in range(max(1, args.threads))]

        await asyncio.wait(tasks, return_when=asyncio.ALL_COMPLETED)
        print("[INFO] All workers stopped. Exiting.")

async def print_checkpoint():
    await asyncio.sleep(0.1)
    async with last_priv_lock:
        if last_priv_hex:
            print("\n[INFO] Interrupted by user.")
            print("[INFO] Last private key hex tried (checkpoint):")
            print(last_priv_hex)
        else:
            print("\n[INFO] Interrupted by user. No key processed yet.")
    sys.exit(0)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass