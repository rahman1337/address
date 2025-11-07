#!/usr/bin/env python3
import asyncio
import threading
import signal
import sys
from argparse import ArgumentParser

# imports
import aiohttp
import coincurve
from eth_utils import to_checksum_address, keccak
from mnemonic import Mnemonic
from bip32utils import BIP32Key, BIP32_HARDEN

ETH_RPC = "https://ethereum.publicnode.com"
FOUND_FILE = "found.txt"
SCANNED_MNEMONICS_FILE = "scanned_mnemonics.txt"

in_memory_scanned_mnemonics = set()
lock = asyncio.Lock()
stop_event = asyncio.Event()

# ------------------- helpers -------------------
def append_found(line: str):
    with open(FOUND_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def append_scanned_mnemonic(mnemonic_str: str):
    if mnemonic_str in in_memory_scanned_mnemonics:
        return
    in_memory_scanned_mnemonics.add(mnemonic_str)
    with open(SCANNED_MNEMONICS_FILE, "a", encoding="utf-8") as f:
        f.write(mnemonic_str + "\n")

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

# ------------------- mnemonic / keys -------------------
def gen_mnemonic(strength_bits: int = 128):
    mnemo = Mnemonic("english")
    for _ in range(1000):
        m = mnemo.generate(strength=strength_bits)
        m = " ".join(m.split())
        if m not in in_memory_scanned_mnemonics:
            append_scanned_mnemonic(m)
            return m
    raise RuntimeError("Failed to generate new mnemonic")

def derive_eth_priv(mnemonic_str: str) -> bytes:
    seed_bytes = Mnemonic("english").to_seed(mnemonic_str)
    master_key = BIP32Key.fromEntropy(seed_bytes)
    k = master_key.ChildKey(44 + BIP32_HARDEN).ChildKey(60 + BIP32_HARDEN)
    k = k.ChildKey(0 + BIP32_HARDEN).ChildKey(0).ChildKey(0)
    priv_bytes = k.PrivateKey()
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

# ------------------- RPC -------------------
async def rpc_post(url, payload, session, debug=False):
    for attempt in range(3):
        try:
            async with session.post(url, json=payload, timeout=15) as r:
                r.raise_for_status()
                return await r.json()
        except Exception as e:
            if debug:
                print(f"[rpc attempt {attempt+1}] {e}")
            await asyncio.sleep(0.5)
    return None

async def get_balance(rpc_url, address, session, debug=False):
    payload = {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [address, "latest"]}
    resp = await rpc_post(rpc_url, payload, session, debug)
    if resp is None:
        return 0
    result = resp.get("result")
    return int(result, 16) if result else 0

# ------------------- worker -------------------
async def worker(name, rpc_url, debug=False):
    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
        while not stop_event.is_set():
            for strength, label in [(128, "12w"), (256, "24w")]:
                try:
                    mnemonic = gen_mnemonic(strength)
                    priv = derive_eth_priv(mnemonic)
                    addr = eth_priv_to_address(priv)
                    privhex = priv.hex()
                    if debug:
                        print(f"[{name}] {label} mnemonic='{mnemonic}' priv={privhex} -> addr={addr}")
                    bal_wei = await get_balance(rpc_url, addr, session, debug=debug)
                    if bal_wei > 0:
                        bal_eth = bal_wei / 10**18
                        bal_str = f"{bal_eth:.18f} (wei={bal_wei})"
                        out = format_found_block(f"{name} ({label})", mnemonic, privhex, addr, bal_str)
                        print(out)
                        append_found(f"{name} ({label}) | {mnemonic} | {privhex} | {addr} | {bal_str}")
                    await asyncio.sleep(0.05)
                except asyncio.CancelledError:
                    return
                except Exception as e:
                    if debug:
                        print(f"[worker error] {e}")
                        traceback.print_exc()
                    await asyncio.sleep(0.1)

# ------------------- main -------------------
async def main_async(debug=False, workers_count=5):
    tasks = [asyncio.create_task(worker(f"ethereum-{i+1}", ETH_RPC, debug)) for i in range(workers_count)]
    # wait until stop_event is set
    await stop_event.wait()
    for t in tasks:
        t.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)

def main():
    parser = ArgumentParser()
    parser.add_argument("-d", "--debug", action="store_true")
    args = parser.parse_args()
    debug = args.debug

    print(f"[info] Starting Ethereum scanner (12 & 24 words, first account only). Debug={debug}. Press Ctrl+C to stop.")

    # ensure files exist
    open(FOUND_FILE, "a").close()
    open(SCANNED_MNEMONICS_FILE, "a").close()

    # proper signal handling
    loop = asyncio.get_event_loop()

    def stop_signal(*_):
        print("\n[info] Ctrl+C detected, stopping scanner...")
        stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop_signal)

    try:
        loop.run_until_complete(main_async(debug=debug))
    finally:
        loop.close()
        print("[info] Scanner stopped. Goodbye.")

if __name__ == "__main__":
    main()
