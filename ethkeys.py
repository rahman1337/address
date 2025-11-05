#!/usr/bin/env python3
import os
import asyncio
from argparse import ArgumentParser
import aiohttp
import coincurve
from eth_utils import keccak

TRIED_FILE = "triedeth.txt"
FOUND_FILE = "found.txt"
in_memory_tried = set()
stop_event = asyncio.Event()

LIGHT_GREEN = "\033[92m"
RESET_COLOR = "\033[0m"

ETH_RPC = "https://ethereum.publicnode.com"

# ----- Load tried keys -----
if os.path.exists(TRIED_FILE):
    with open(TRIED_FILE, "r", encoding="utf-8") as f:
        for line in f:
            l = line.strip()
            if l:
                in_memory_tried.add(l)

def append_tried(key_repr: str):
    if key_repr in in_memory_tried:
        return
    with open(TRIED_FILE, "a", encoding="utf-8") as f:
        f.write(key_repr + "\n")
    in_memory_tried.add(key_repr)

def append_found(line: str):
    with open(FOUND_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def format_found_block(chain, privhex, address, balance_str):
    border = "=" * 60
    return "\n".join([
        border,
        f"CHAIN: {chain}",
        f"PRIVATE_KEY: {privhex}",
        f"ADDRESS: {address}",
        f"BALANCE: {LIGHT_GREEN}{balance_str}{RESET_COLOR}",
        border
    ])

# ----- Ethereum key generation -----
def gen_eth_privkey_bytes():
    return coincurve.PrivateKey().secret  # 32 random bytes

def eth_priv_to_address(priv_bytes: bytes) -> str:
    pk = coincurve.PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_raw = pub_uncompressed[1:] if len(pub_uncompressed) == 65 else pub_uncompressed
    addr_bytes = keccak(pub_raw)[-20:]
    return "0x" + addr_bytes.hex()  # lowercase, 0x-prefixed

# ----- RPC helpers -----
async def rpc_post_with_retries(url: str, json_payload: dict, session: aiohttp.ClientSession, max_attempts: int=3):
    last_exc = None
    for attempt in range(1, max_attempts + 1):
        try:
            async with session.post(url, json=json_payload, timeout=15) as r:
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            last_exc = e
            if attempt < max_attempts:
                await asyncio.sleep(attempt)
    raise last_exc

async def eth_get_balance(rpc_url, address, session):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    j = await rpc_post_with_retries(rpc_url, payload, session)
    return int(j.get("result", 0), 16)

# ----- Ethereum worker -----
async def worker_eth(chain_name, rpc_url):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        while not stop_event.is_set():
            try:
                priv = gen_eth_privkey_bytes()
                privhex = "0x" + priv.hex()
                key_repr = f"{chain_name}:{privhex}"
                if key_repr in in_memory_tried:
                    await asyncio.sleep(0.01)
                    continue
                append_tried(key_repr)
                address = eth_priv_to_address(priv)
                try:
                    bal_wei = await eth_get_balance(rpc_url, address, session)
                except:
                    await asyncio.sleep(0.1)
                    continue
                if bal_wei > 0:
                    bal_eth = bal_wei / 10**18
                    bal_str = f"{bal_eth:.18f} ETH"
                    print(format_found_block(chain_name, privhex, address, bal_str))
                    append_found(f"{chain_name} | {privhex} | {address} | {bal_str}")
                await asyncio.sleep(0.01)
            except:
                await asyncio.sleep(0.05)

async def main_async():
    parser = ArgumentParser()
    parser.add_argument("-d","--debug", action="store_true")
    args = parser.parse_args()
    debug = args.debug

    print(f"[info] Starting Ethereum scanner. Debug={debug}. Press Ctrl+C to stop.")
    open(TRIED_FILE, "a").close()
    open(FOUND_FILE, "a").close()

    task = asyncio.create_task(worker_eth("ethereum", ETH_RPC))

    try:
        await task
    except asyncio.CancelledError:
        print("[info] Scanner stopped.")

def main():
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\n[info] Ctrl+C detected, shutting down...")

if __name__ == "__main__":
    main()
