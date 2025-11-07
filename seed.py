#!/usr/bin/env python3
import os
import sys
import time
import threading
import traceback
import asyncio
from concurrent.futures import ThreadPoolExecutor
from argparse import ArgumentParser

def ensure_import(name, package=None):
    try:
        return __import__(name)
    except Exception:
        pkg = package or name
        print(f"[setup] package '{pkg}' not found, attempting to install...", file=sys.stderr)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        return __import__(name)

# third-party libs (auto-installed if missing)
aiohttp = ensure_import("aiohttp")
coincurve = ensure_import("coincurve")
eth_utils = ensure_import("eth_utils")
mnemonic_mod = ensure_import("mnemonic")
bip32utils = ensure_import("bip32utils")

from eth_utils import to_checksum_address, keccak
from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN

ETH_RPC = "https://ethereum.publicnode.com"
FOUND_FILE = "found.txt"
SCANNED_MNEMONICS_FILE = "scanned_mnemonics.txt"
SEED_WORDLIST_FILE = "seed.txt"  # contains 2048 words, one per line

found_lock = threading.Lock()
mnemonics_lock = threading.Lock()
in_memory_scanned_mnemonics = set()
stop_event = threading.Event()

# Load already scanned mnemonics
if os.path.exists(SCANNED_MNEMONICS_FILE):
    try:
        with open(SCANNED_MNEMONICS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                l = line.strip()
                if l:
                    in_memory_scanned_mnemonics.add(l)
    except Exception as e:
        print(f"[warn] Could not load {SCANNED_MNEMONICS_FILE}: {e}", file=sys.stderr)

def append_found(line: str):
    with found_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def append_scanned_mnemonic(mnemonic_str: str):
    """
    Store the exact mnemonic string (12 or 24 words) to prevent reuse.
    """
    with mnemonics_lock:
        if mnemonic_str in in_memory_scanned_mnemonics:
            return
        try:
            with open(SCANNED_MNEMONICS_FILE, "a", encoding="utf-8") as f:
                f.write(mnemonic_str + "\n")
        except Exception as e:
            print(f"[warn] Could not append mnemonic to {SCANNED_MNEMONICS_FILE}: {e}", file=sys.stderr)
        in_memory_scanned_mnemonics.add(mnemonic_str)

def format_found_block(chain, mnemonic, privhex, address, balance_str):
    border = "=" * 60
    return "\n".join([
        border,
        f"CHAIN: {chain}",
        f"MNEMONIC: {mnemonic}",
        f"PRIVATE_KEY: {privhex}",
        f"ADDRESS: {address}",
        f"BALANCE: {balance_str}",
        border
    ])

# ---------------- Mnemonic-based generator (supports 12 & 24 words) ----------------
_wordlist_cache = None

def load_seed_wordlist():
    global _wordlist_cache
    if _wordlist_cache is not None:
        return _wordlist_cache
    if not os.path.exists(SEED_WORDLIST_FILE):
        raise FileNotFoundError(f"{SEED_WORDLIST_FILE} not found; it must contain 2048 words, one per line.")
    words = []
    with open(SEED_WORDLIST_FILE, "r", encoding="utf-8") as f:
        for line in f:
            w = line.strip()
            if w:
                words.append(w)
    if len(words) < 2048:
        print(f"[warn] wordlist has {len(words)} words (expected 2048). Proceeding but BIP39 expects 2048.", file=sys.stderr)
    _wordlist_cache = words
    return _wordlist_cache

def gen_mnemonic_from_wordlist(strength_bits: int = 128):
    """
    Create a BIP-39 valid mnemonic using the wordlist from seed.txt.
    strength_bits: 128 -> 12 words, 256 -> 24 words
    Avoid previously scanned mnemonics.
    Returns mnemonic string.
    """
    if strength_bits not in (128, 256):
        raise ValueError("strength_bits must be 128 (12 words) or 256 (24 words)")
    words = load_seed_wordlist()
    mnemo = Mnemonic("english")
    mnemo.wordlist = words

    # try a number of attempts to avoid duplicates (should usually succeed immediately)
    for _ in range(1000):
        m = mnemo.generate(strength=strength_bits)
        m = " ".join(m.split())
        with mnemonics_lock:
            if m in in_memory_scanned_mnemonics:
                continue
            append_scanned_mnemonic(m)
            return m
    raise RuntimeError("Couldn't generate a new mnemonic after many tries.")

def derive_eth_priv_from_mnemonic(mnemonic_str: str):
    """
    Derive Ethereum private key bytes from mnemonic using path m/44'/60'/0'/0/0
    Returns 32-byte private key (bytes).
    """
    mnemo = Mnemonic("english")
    seed_bytes = mnemo.to_seed(mnemonic_str, passphrase="")
    master_key = BIP32Key.fromEntropy(seed_bytes)
    k = master_key
    k = k.ChildKey(44 + BIP32_HARDEN)  # 44'
    k = k.ChildKey(60 + BIP32_HARDEN)  # 60'
    k = k.ChildKey(0 + BIP32_HARDEN)   # 0'
    k = k.ChildKey(0)                   # change = 0
    k = k.ChildKey(0)                   # first account index
    priv_bytes = k.PrivateKey()
    if isinstance(priv_bytes, int):
        priv_bytes = priv_bytes.to_bytes(32, "big")
    elif isinstance(priv_bytes, bytes) and len(priv_bytes) < 32:
        priv_bytes = priv_bytes.rjust(32, b'\x00')
    return priv_bytes

# ----- Address derivation -----
def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if len(pub_uncompressed) == 65 and pub_uncompressed[0] == 0x04 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return to_checksum_address("0x" + addr_bytes.hex())

# ----- RPC helpers -----
async def rpc_post_with_retries(url: str, json_payload: dict, session: aiohttp.ClientSession, debug: bool=False, max_attempts: int=3):
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            async with session.post(url, json=json_payload, timeout=15) as r:
                text = await r.text()
                if debug:
                    print(f"[debug][rpc] POST {url} payload={json_payload} status={r.status} resp={text}")
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            last_exc = e
            if attempt < max_attempts:
                await asyncio.sleep(attempt)
    raise last_exc

async def eth_like_get_balance(rpc_url: str, address: str, session: aiohttp.ClientSession, debug=False) -> int:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    j = await rpc_post_with_retries(rpc_url, payload, session=session, debug=debug, max_attempts=3)
    result = j.get("result")
    return int(result, 16) if result else 0

# ----- Worker -----
async def worker_eth_async(chain_name, rpc_url, debug=False):
    """
    Each loop this worker:
      - generates a 12-word mnemonic and checks first account
      - generates a 24-word mnemonic and checks first account
    (Both mnemonics are recorded to prevent repeats.)
    """
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            try:
                # 1) 12-word mnemonic (strength=128)
                try:
                    mnemonic_12 = gen_mnemonic_from_wordlist(strength_bits=128)
                except Exception as e:
                    if debug:
                        print(f"[{chain_name}][mnemonic12 error] {e}", file=sys.stderr)
                    await asyncio.sleep(0.5)
                    continue

                try:
                    priv12 = derive_eth_priv_from_mnemonic(mnemonic_12)
                except Exception as e:
                    if debug:
                        print(f"[{chain_name}][derive12 error] {e}", file=sys.stderr)
                    await asyncio.sleep(0.1)
                    continue

                privhex12 = priv12.hex()
                addr12 = eth_priv_to_address(priv12)
                if debug:
                    print(f"[{chain_name}] 12w mnemonic='{mnemonic_12}' priv={privhex12} -> addr={addr12}")
                try:
                    bal_wei_12 = await eth_like_get_balance(rpc_url, addr12, session, debug=debug)
                except Exception as rpc_e:
                    if debug:
                        print(f"[{chain_name}][rpc error 12] {rpc_e}")
                    await asyncio.sleep(0.2)
                    # continue to 24-word generation anyway
                else:
                    if bal_wei_12 > 0:
                        bal_eth = bal_wei_12 / 10**18
                        bal_str = f"{bal_eth:.18f} (wei={bal_wei_12})"
                        out = format_found_block(chain_name + " (12w)", mnemonic_12, privhex12, addr12, bal_str)
                        print(out)
                        append_found(f"{chain_name} (12w) | {mnemonic_12} | {privhex12} | {addr12} | {bal_str}")

                # 2) 24-word mnemonic (strength=256)
                try:
                    mnemonic_24 = gen_mnemonic_from_wordlist(strength_bits=256)
                except Exception as e:
                    if debug:
                        print(f"[{chain_name}][mnemonic24 error] {e}", file=sys.stderr)
                    await asyncio.sleep(0.5)
                    continue

                try:
                    priv24 = derive_eth_priv_from_mnemonic(mnemonic_24)
                except Exception as e:
                    if debug:
                        print(f"[{chain_name}][derive24 error] {e}", file=sys.stderr)
                    await asyncio.sleep(0.1)
                    continue

                privhex24 = priv24.hex()
                addr24 = eth_priv_to_address(priv24)
                if debug:
                    print(f"[{chain_name}] 24w mnemonic='{mnemonic_24}' priv={privhex24} -> addr={addr24}")
                try:
                    bal_wei_24 = await eth_like_get_balance(rpc_url, addr24, session, debug=debug)
                except Exception as rpc_e:
                    if debug:
                        print(f"[{chain_name}][rpc error 24] {rpc_e}")
                    await asyncio.sleep(0.2)
                else:
                    if bal_wei_24 > 0:
                        bal_eth = bal_wei_24 / 10**18
                        bal_str = f"{bal_eth:.18f} (wei={bal_wei_24})"
                        out = format_found_block(chain_name + " (24w)", mnemonic_24, privhex24, addr24, bal_str)
                        print(out)
                        append_found(f"{chain_name} (24w) | {mnemonic_24} | {privhex24} | {addr24} | {bal_str}")

                # small throttle to avoid spamming RPC
                await asyncio.sleep(0.02)
            except Exception:
                traceback.print_exc()
                await asyncio.sleep(0.05)

def run_async_worker(coro_func, *args, **kwargs):
    try:
        asyncio.run(coro_func(*args, **kwargs))
    except Exception as e:
        print(f"[worker][fatal] {e}")

def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()
    debug = args.debug

    print(f"[info] Starting Ethereum scanner (12 & 24 words, first account only). Debug={debug}. Press Ctrl+C to stop.")

    open(FOUND_FILE, "a").close()
    open(SCANNED_MNEMONICS_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = []
        for _ in range(5):
            futures.append(ex.submit(run_async_worker, worker_eth_async, "ethereum", ETH_RPC, debug))
        try:
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, shutting down...")
            stop_event.set()
            time.sleep(0.2)
    print("[info] Scanner stopped. Goodbye.")

if __name__ == "__main__":
    main()
