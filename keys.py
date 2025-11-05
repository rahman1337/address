#!/usr/bin/env python3
"""
Multi-chain scanner (ethereum, bsc, solana)
- Default: 6 threads (2 threads per chain)
- Normal mode: prints found balances and errors
- Debug mode (-d): prints everything (generated keys, RPC attempts/responses, tracebacks)
- Retries: exact backoff 1s,2s,3s for RPC POSTs (3 attempts)
- Solana private keys: Base58-encoded 64-byte secret (seed||pubkey)
"""
import os
import sys
import time
import threading
import traceback
import asyncio
from argparse import ArgumentParser
from concurrent.futures import ThreadPoolExecutor

# dependencies (must be installed)
try:
    import aiohttp
except Exception as e:
    print("Missing dependency 'aiohttp'. Install with: pip install aiohttp", file=sys.stderr)
    raise
try:
    import coincurve
except Exception as e:
    print("Missing dependency 'coincurve'. Install with: pip install coincurve", file=sys.stderr)
    raise
try:
    from eth_utils import keccak
except Exception as e:
    print("Missing dependency 'eth_utils'. Install with: pip install eth_utils", file=sys.stderr)
    raise
try:
    import base58
except Exception as e:
    print("Missing dependency 'base58'. Install with: pip install base58", file=sys.stderr)
    raise
try:
    import ed25519
except Exception as e:
    print("Missing dependency 'ed25519'. Install with: pip install ed25519", file=sys.stderr)
    raise

# Files
TRIED_FILE = "tried_keys.txt"
FOUND_FILE = "found.txt"

# Concurrency & locks
scanned_lock = threading.Lock()   # protects in_memory_tried and file append for tried
found_lock = threading.Lock()     # protects found file append
in_memory_tried = set()
stop_event = threading.Event()    # thread-safe stop signal

# Visuals
LIGHT_GREEN = "\033[92m"
RESET_COLOR = "\033[0m"

# RPC endpoints (publicnode)
ETH_RPC = "https://ethereum.publicnode.com"
BSC_RPC = "https://bsc.publicnode.com"
SOL_RPC = "https://solana.publicnode.com"

# Load tried keys at startup (if any)
if os.path.exists(TRIED_FILE):
    try:
        with open(TRIED_FILE, "r", encoding="utf-8") as f:
            for line in f:
                l = line.strip()
                if l:
                    in_memory_tried.add(l)
    except Exception as e:
        print(f"[warn] Could not load {TRIED_FILE}: {e}", file=sys.stderr)

def append_tried_atomic(key_repr: str):
    """Append tried key if not already present. Thread-safe and idempotent."""
    with scanned_lock:
        if key_repr in in_memory_tried:
            return False
        try:
            with open(TRIED_FILE, "a", encoding="utf-8") as f:
                f.write(key_repr + "\n")
        except Exception as e:
            # If file write fails, still add to memory to avoid retries in the same run
            print(f"[error] Failed to append tried key to file: {e}", file=sys.stderr)
        in_memory_tried.add(key_repr)
        return True

def append_found(line: str):
    with found_lock:
        with open(FOUND_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")

def format_found_block(chain, privrepr, address, balance_str):
    border = "=" * 60
    return "\n".join([
        border,
        f"CHAIN: {chain}",
        f"PRIVATE_KEY: {privrepr}",
        f"ADDRESS: {address}",
        f"BALANCE: {LIGHT_GREEN}{balance_str}{RESET_COLOR}",
        border
    ])

# ---------- Key generation / address derivation ----------
def gen_eth_privkey_bytes():
    """Return 32 bytes of a new random secp256k1 private key."""
    return coincurve.PrivateKey().secret

def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if len(pub_uncompressed) == 65 and pub_uncompressed[0] == 0x04 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return "0x" + addr_bytes.hex()  # lowercase, 0x-prefixed

# ---------- Solana: produce Base58 64-byte secret (seed||pub) ----------
def gen_solana_privkey_base58():
    """
    Generate a valid Solana private key string:
      - 32 random seed bytes
      - ed25519 SigningKey from that seed
      - secret_64 = seed || pubkey (64 bytes)
      - return base58(secret_64) and pub_raw bytes
    """
    seed = os.urandom(32)
    sk = ed25519.SigningKey(seed)
    try:
        # Some ed25519 libs expose to_bytes() for seed; otherwise fallback to original seed
        priv_seed_bytes = sk.to_bytes()
        # if to_bytes returns 32 bytes, good; else fallback
        if not (isinstance(priv_seed_bytes, (bytes, bytearray)) and len(priv_seed_bytes) == 32):
            priv_seed_bytes = seed
    except Exception:
        priv_seed_bytes = seed
    vk = sk.get_verifying_key()
    pub_raw = vk.to_bytes() if hasattr(vk, "to_bytes") else bytes(vk)
    secret_64 = priv_seed_bytes + pub_raw  # 64 bytes
    priv_b58 = base58.b58encode(secret_64).decode()
    return priv_b58, pub_raw

def solana_privbase58_to_address(priv_b58_or_pubraw):
    """
    Accept either a base58-encoded 64-byte secret or raw pub bytes and return base58 address.
    If passed base58 secret, decode and extract pubkey (last 32 bytes).
    """
    if isinstance(priv_b58_or_pubraw, str):
        try:
            decoded = base58.b58decode(priv_b58_or_pubraw)
            if len(decoded) >= 64:
                pub_raw = decoded[-32:]
            elif len(decoded) == 32:
                pub_raw = decoded
            else:
                # fall back: treat as base58 pub string
                pub_raw = decoded
        except Exception:
            # If decoding fails, treat input as already-base58 pub string and return it
            return priv_b58_or_pubraw
    else:
        pub_raw = priv_b58_or_pubraw
    return base58.b58encode(pub_raw).decode()

# ---------- RPC with retries and exact backoff ----------
async def rpc_post_with_retries(url: str, json_payload: dict, session: aiohttp.ClientSession, debug: bool=False):
    """
    Send POST with 3 attempts. Backoffs are exactly 1s, 2s, 3s between attempts.
    On each attempt, if debug: print request and response (or failure).
    """
    delays = [1, 2, 3]
    last_exc = None
    for attempt in range(1, 4):
        try:
            async with session.post(url, json=json_payload, timeout=15) as r:
                text = await r.text()
                if debug:
                    print(f"[debug][RPC attempt {attempt}] POST {url} payload={json_payload} status={r.status} response={text}")
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            last_exc = e
            if attempt == 3:
                if debug:
                    print(f"[debug][RPC attempt {attempt}] final failure: {e}")
                raise
            else:
                delay = delays[attempt - 1]
                if debug:
                    print(f"[debug][RPC attempt {attempt}] failed: {e}. retrying in {delay}s...")
                await asyncio.sleep(delay)
    raise last_exc

# Ethereum / BSC balance (eth_getBalance)
async def eth_like_get_balance(rpc_url, address, session, debug: bool=False):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    j = await rpc_post_with_retries(rpc_url, payload, session, debug)
    if isinstance(j, dict) and "error" in j:
        raise RuntimeError(f"RPC error: {j['error']}")
    result = j.get("result", 0) if isinstance(j, dict) else 0
    if result is None:
        return 0
    return int(result, 16)

# Solana balance (getBalance)
async def solana_get_balance(rpc_url, address, session, debug: bool=False):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [address, {"commitment": "final"}]}
    j = await rpc_post_with_retries(rpc_url, payload, session, debug)
    if isinstance(j, dict) and "error" in j:
        raise RuntimeError(f"RPC error: {j['error']}")
    if isinstance(j, dict):
        return int(j.get("result", {}).get("value", 0))
    return 0

# ---------- Worker implementations ----------
async def worker_generic_ethlike(chain_name: str, rpc_url: str, debug: bool=False):
    """
    Worker for chains that use eth_getBalance (ethereum, bsc).
    """
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        generated = 0
        while not stop_event.is_set():
            try:
                priv = gen_eth_privkey_bytes()
                privrepr = "0x" + priv.hex()
                key_repr = f"{chain_name}:{privrepr}"

                # Record tried atomically (with lock)
                was_new = append_tried_atomic(key_repr)
                if not was_new:
                    if debug:
                        print(f"[debug] Skipping already-tried key: {privrepr} on {chain_name}")
                    await asyncio.sleep(0.01)
                    continue

                address = eth_priv_to_address(priv)
                if debug:
                    generated += 1
                    print(f"[debug][{chain_name}][gen #{generated}] priv={privrepr} address={address}")

                try:
                    bal_wei = await eth_like_get_balance(rpc_url, address, session, debug)
                except Exception as e:
                    print(f"[error] RPC or balance error for {address} on {chain_name}: {e}")
                    if debug:
                        traceback.print_exc()
                    await asyncio.sleep(0.1)
                    continue

                if bal_wei and bal_wei > 0:
                    bal_eth = bal_wei / 10**18
                    bal_str = f"{bal_eth:.18f} {chain_name.upper()} (wei={bal_wei})"
                    out = format_found_block(chain_name, privrepr, address, bal_str)
                    print(out)
                    append_found(f"{chain_name} | {privrepr} | {address} | {bal_str}")

                await asyncio.sleep(0.005)
            except Exception as e:
                print(f"[error] Worker exception on {chain_name}: {e}")
                if debug:
                    traceback.print_exc()
                await asyncio.sleep(0.05)

async def worker_solana(chain_name: str, rpc_url: str, debug: bool=False):
    """
    Worker for Solana chain using Base58 private keys (seed+pub) and base58 addresses.
    """
    timeout = aiohttp.ClientTimeout(total=30)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        generated = 0
        while not stop_event.is_set():
            try:
                priv_b58, pub_raw = gen_solana_privkey_base58()
                key_repr = f"{chain_name}:{priv_b58}"

                was_new = append_tried_atomic(key_repr)
                if not was_new:
                    if debug:
                        print(f"[debug] Skipping already-tried solana priv: {priv_b58}")
                    await asyncio.sleep(0.01)
                    continue

                address = base58.b58encode(pub_raw).decode()
                if debug:
                    generated += 1
                    print(f"[debug][{chain_name}][gen #{generated}] priv={priv_b58} address={address}")

                try:
                    lamports = await solana_get_balance(rpc_url, address, session, debug)
                except Exception as e:
                    print(f"[error] RPC or balance error for {address} on {chain_name}: {e}")
                    if debug:
                        traceback.print_exc()
                    await asyncio.sleep(0.1)
                    continue

                if lamports and lamports > 0:
                    sol_str = f"{lamports} lamports ({lamports / 1e9:.9f} SOL)"
                    out = format_found_block(chain_name, priv_b58, address, sol_str)
                    print(out)
                    append_found(f"{chain_name} | {priv_b58} | {address} | {sol_str}")

                await asyncio.sleep(0.005)
            except Exception as e:
                print(f"[error] Worker exception on {chain_name}: {e}")
                if debug:
                    traceback.print_exc()
                await asyncio.sleep(0.05)

# ---------- Thread runner ----------
def run_worker_in_thread(chain_name: str, rpc_url: str, debug: bool=False):
    """
    Each thread runs its own asyncio event loop and runs the appropriate async worker for the chain.
    """
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        if chain_name.lower() == "solana":
            coro = worker_solana(chain_name, rpc_url, debug)
        else:
            coro = worker_generic_ethlike(chain_name, rpc_url, debug)
        loop.run_until_complete(coro)
    except Exception as e:
        print(f"[worker][fatal] Thread worker crashed for {chain_name}: {e}", file=sys.stderr)
        if debug:
            traceback.print_exc()
    finally:
        try:
            loop.stop()
            loop.close()
        except Exception:
            pass

# ---------- Main ----------
def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true", help="Print everything (debug mode)")
    parser.add_argument("-t", "--threads", type=int, default=6, help="Total number of threads to spawn (default: 6)")
    args = parser.parse_args()
    debug = args.debug
    requested = max(1, min(12, args.threads))  # clamp to reasonable bounds

    # We want 2 threads per chain: ethereum, bsc, solana
    per_chain = 2
    chains = [("ethereum", ETH_RPC), ("bsc", BSC_RPC), ("solana", SOL_RPC)]
    total_needed = per_chain * len(chains)
    if requested != total_needed:
        print(f"[info] Adjusting threads to {total_needed} (2 threads per chain for {len(chains)} chains).")
    thread_count = total_needed

    print(f"[info] Starting scanner. Debug={debug}. Threads={thread_count}. Press Ctrl+C to stop.")
    open(TRIED_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    with ThreadPoolExecutor(max_workers=thread_count) as ex:
        futures = []
        for chain_name, rpc in chains:
            for i in range(per_chain):
                futures.append(ex.submit(run_worker_in_thread, chain_name, rpc, debug))
        try:
            while not stop_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[info] Ctrl+C detected, shutting down...")
            stop_event.set()
            time.sleep(0.5)
        finally:
            # best-effort shutdown: threads will see stop_event and exit their loops
            for f in futures:
                try:
                    f.cancel()
                except Exception:
                    pass
    print("[info] Scanner stopped. Goodbye.")

if __name__ == "__main__":
    main()
