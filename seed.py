#!/usr/bin/env python3
"""
Robust mnemonic-based Ethereum scanner.
- Uses BIP-39 English wordlist (mnemonic package)
- Generates 12w and 24w mnemonics, derives m/44'/60'/0'/0/0
- No seed.txt; no custom wordlist
- Normal mode: prints found + errors
- Debug mode: prints every step
- Stops immediately on Ctrl+C (reliable across environments)
"""
import asyncio
import signal
import threading
import sys
import time
from argparse import ArgumentParser

# --- third-party imports (assume installed) ---
try:
    import aiohttp
    import coincurve
    from eth_utils import to_checksum_address, keccak
    from mnemonic import Mnemonic
    from bip32utils import BIP32Key, BIP32_HARDEN
except Exception as e:
    print("[fatal] missing dependency:", e, file=sys.stderr, flush=True)
    raise

# --- config ---
ETH_RPC = "https://ethereum.publicnode.com"
FOUND_FILE = "found.txt"
SCANNED_MNEMONICS_FILE = "scanned_mnemonics.txt"

# thread-safe stop event (works across signal handlers)
stop_event = threading.Event()

# in-memory set of scanned mnemonics
in_memory_scanned_mnemonics = set()
in_memory_lock = threading.Lock()

# --- load scanned mnemonics if present ---
try:
    with open(SCANNED_MNEMONICS_FILE, "r", encoding="utf-8") as f:
        for ln in f:
            s = ln.strip()
            if s:
                in_memory_scanned_mnemonics.add(s)
except FileNotFoundError:
    pass
except Exception as e:
    print(f"[warn] loading scanned file failed: {e}", flush=True)

# --- helpers ---
def append_found(line: str):
    try:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception as e:
        print(f"[warn] could not append to {FOUND_FILE}: {e}", flush=True)

def append_scanned_mnemonic(mnemonic_str: str):
    with in_memory_lock:
        if mnemonic_str in in_memory_scanned_mnemonics:
            return False
        in_memory_scanned_mnemonics.add(mnemonic_str)
        try:
            with open(SCANNED_MNEMONICS_FILE, "a", encoding="utf-8") as f:
                f.write(mnemonic_str + "\n")
        except Exception as e:
            print(f"[warn] could not append to {SCANNED_MNEMONICS_FILE}: {e}", flush=True)
        return True

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

# --- mnemonic + derivation ---
mnemo_global = Mnemonic("english")

def gen_mnemonic_once(strength_bits: int = 128, debug: bool = False):
    """
    Generate a new mnemonic (12w or 24w). Returns mnemonic string.
    Avoids previously scanned ones (fast in-memory check).
    """
    for _ in range(1000):
        m = mnemo_global.generate(strength=strength_bits)
        m = " ".join(m.split())
        with in_memory_lock:
            if m in in_memory_scanned_mnemonics:
                if debug:
                    print("[debug] generated duplicate mnemonic, retrying", flush=True)
                continue
            # register and persist
            in_memory_scanned_mnemonics.add(m)
            try:
                with open(SCANNED_MNEMONICS_FILE, "a", encoding="utf-8") as f:
                    f.write(m + "\n")
            except Exception as e:
                print(f"[warn] could not persist mnemonic: {e}", flush=True)
            return m
    raise RuntimeError("Exhausted attempts generating new mnemonic")

def derive_eth_priv(mnemonic_str: str) -> bytes:
    seed_bytes = mnemo_global.to_seed(mnemonic_str, passphrase="")
    master_key = BIP32Key.fromEntropy(seed_bytes)
    k = master_key.ChildKey(44 + BIP32_HARDEN).ChildKey(60 + BIP32_HARDEN)
    k = k.ChildKey(0 + BIP32_HARDEN).ChildKey(0).ChildKey(0)
    priv_bytes = k.PrivateKey()
    # normalize to bytes
    if isinstance(priv_bytes, int):
        priv_bytes = priv_bytes.to_bytes(32, "big")
    elif isinstance(priv_bytes, bytes) and len(priv_bytes) < 32:
        priv_bytes = priv_bytes.rjust(32, b'\x00')
    return priv_bytes

def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub = pk.public_key.format(compressed=False)
    pub_raw = pub[1:] if len(pub) == 65 and pub[0] == 0x04 else pub
    addr_bytes = keccak(pub_raw)[-20:]
    return to_checksum_address("0x" + addr_bytes.hex())

# --- RPC helpers ---
async def rpc_post(url: str, payload: dict, session: aiohttp.ClientSession, debug=False):
    last_exc = None
    for attempt in range(1, 4):
        try:
            async with session.post(url, json=payload, timeout=15) as resp:
                text = await resp.text()
                if debug:
                    print(f"[debug][rpc] attempt={attempt} status={resp.status} resp={text[:200]}", flush=True)
                resp.raise_for_status()
                return await resp.json()
        except Exception as e:
            last_exc = e
            if debug:
                print(f"[debug][rpc] attempt {attempt} failed: {e}", flush=True)
            await asyncio.sleep(0.5)
    if debug:
        print(f"[debug][rpc] all attempts failed: {last_exc}", flush=True)
    raise last_exc

async def get_balance(rpc_url: str, address: str, session: aiohttp.ClientSession, debug=False) -> int:
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    try:
        j = await rpc_post(rpc_url, payload, session, debug=debug)
    except Exception as e:
        if debug:
            print(f"[debug] get_balance rpc failure: {e}", flush=True)
        raise
    result = j.get("result")
    return int(result, 16) if result else 0

# --- worker coroutine ---
async def worker(name: str, rpc_url: str, debug: bool = False):
    # lightweight per-worker session
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        while not stop_event.is_set():
            # do 12w then 24w
            for strength, label in [(128, "12w"), (256, "24w")]:
                if stop_event.is_set():
                    break
                try:
                    # generate mnemonic
                    mnemonic = gen_mnemonic_once(strength, debug=debug)
                    # derive first account private key
                    priv = derive_eth_priv(mnemonic)
                    addr = eth_priv_to_address(priv)
                    privhex = priv.hex()
                    if debug:
                        print(f"[{name}] {label} mnemonic='{mnemonic}' priv={privhex} -> addr={addr}", flush=True)
                    # check balance
                    try:
                        bal_wei = await get_balance(rpc_url, addr, session, debug=debug)
                    except Exception as e:
                        # in normal mode print error, in debug already printed
                        print(f"[error] rpc for {addr}: {e}", flush=True)
                        # short sleep and continue
                        await asyncio.sleep(0.1)
                        continue
                    if bal_wei > 0:
                        bal_eth = bal_wei / 10**18
                        bal_str = f"{bal_eth:.18f} (wei={bal_wei})"
                        out = format_found_block(f"{name} ({label})", mnemonic, privhex, addr, bal_str)
                        print(out, flush=True)
                        append_found(f"{name} ({label}) | {mnemonic} | {privhex} | {addr} | {bal_str}")
                    # small throttle
                    await asyncio.sleep(0.02)
                except Exception as e:
                    # always print errors in normal mode
                    print(f"[worker error] {e}", flush=True)
                    if debug:
                        import traceback as _tb
                        _tb.print_exc()
                    await asyncio.sleep(0.1)
            # allow quick stop between cycles
            await asyncio.sleep(0)
    if debug:
        print(f"[{name}] exiting worker loop", flush=True)

# --- run loop and signal handling ---
def install_signal_handlers():
    # set stop_event on Ctrl+C or termination signals
    def _handler(signum, frame):
        print(f"\n[info] signal {signum} received, stopping...", flush=True)
        stop_event.set()
    try:
        signal.signal(signal.SIGINT, _handler)
        signal.signal(signal.SIGTERM, _handler)
    except Exception:
        # some environments may restrict signal handling; KeyboardInterrupt fallback will still work
        pass

async def main_async(debug: bool, workers_count: int):
    tasks = [asyncio.create_task(worker(f"eth-{i+1}", ETH_RPC, debug=debug)) for i in range(workers_count)]
    # return when stop_event set
    while not stop_event.is_set():
        await asyncio.sleep(0.1)
    # cancel tasks quickly
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

def main():
    p = ArgumentParser()
    p.add_argument("-d", "--debug", action="store_true")
    p.add_argument("-w", "--workers", type=int, default=5, help="number of concurrent workers")
    args = p.parse_args()

    debug = args.debug
    workers = max(1, args.workers)

    print(f"[info] Starting Ethereum scanner (12 & 24 words, first account only). Debug={debug}. Press Ctrl+C to stop.", flush=True)
    open(FOUND_FILE, "a").close()
    open(SCANNED_MNEMONICS_FILE, "a").close()

    install_signal_handlers()

    try:
        asyncio.run(main_async(debug=debug, workers_count=workers))
    except KeyboardInterrupt:
        # fallback: ensure stop_event set
        stop_event.set()
        print("\n[info] KeyboardInterrupt received, stopping...", flush=True)
    except Exception as e:
        print(f"[fatal] main loop error: {e}", flush=True)
    finally:
        print("[info] Scanner stopped. Goodbye.", flush=True)

if __name__ == "__main__":
    main()
