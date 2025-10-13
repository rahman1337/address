#!/usr/bin/env python3
# USAGE: python3 btc.py --file btc1.txt btc2.txt btc3.txt

import argparse
import time
import os
import sys
import secrets
import binascii

try:
    from bitcoin import SelectParams
    from bitcoin.core import x, b2x, Hash160
    from bitcoin.core.script import CScript, OP_0
    from bitcoin.wallet import CBitcoinSecret, P2PKHBitcoinAddress, P2SHBitcoinAddress
except Exception as e:
    print("Missing dependency 'python-bitcoinlib'. Install with: pip install python-bitcoinlib")
    raise

# Try to import bech32/segwit helper from python-bitcoinlib (recent versions)
_have_segwit_addr = False
try:
    from bitcoin.wallet import P2WPKHBitcoinAddress
    _have_segwit_addr = True
except Exception:
    try:
        import segwit_addr
        _have_segwit_addr = True
    except Exception:
        _have_segwit_addr = False

_bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def _bech32_polymod(values):
    GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= GENERATORS[i]
    return chk

def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0,0,0,0,0,0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for b in data:
        if b < 0 or b >> frombits:
            return None
        acc = (acc << frombits) | b
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    else:
        if bits >= frombits or ((acc << (tobits - bits)) & maxv):
            return None
    return ret

def encode_bech32(hrp, witver, witprog):
    data = [witver] + _convertbits(witprog, 8, 5)
    checksum = _bech32_create_checksum(hrp, data)
    combined = data + checksum
    return hrp + "1" + "".join([_bech32_charset[d] for d in combined])

def pubkey_bytes_from_cbitcoinsecret(secret):
    pub = secret.pub
    try:
        return bytes(pub)
    except Exception:
        return x(b2x(pub))

def load_targets(path):
    targets = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            line = line.strip().lower()
            if line.startswith("0x"):
                line = line[2:]
            targets.add(line)
        return targets

def pubkey_hash160(pubkey_bytes):
    return Hash160(pubkey_bytes)

def make_addresses_from_secret(secret):
    wif = str(secret)
    pubkey = pubkey_bytes_from_cbitcoinsecret(secret)

    try:
        addr_p2pkh = P2PKHBitcoinAddress.from_pubkey(secret.pub)
        addr_p2pkh_str = str(addr_p2pkh)
    except Exception:
        h160 = pubkey_hash160(pubkey)
        from bitcoin.base58 import encode
        addr_p2pkh_str = encode(b'\x00' + h160)

    h160 = pubkey_hash160(pubkey)
    if _have_segwit_addr:
        try:
            from bitcoin.wallet import P2WPKHBitcoinAddress
            addr_bech = P2WPKHBitcoinAddress.from_bytes(h160)
            addr_bech32 = str(addr_bech)
        except Exception:
            try:
                import segwit_addr
                addr_bech32 = segwit_addr.encode("bc", 0, list(h160))
            except Exception:
                addr_bech32 = encode_bech32("bc", 0, bytes(h160))
    else:
        addr_bech32 = encode_bech32("bc", 0, bytes(h160))

    redeem = CScript([OP_0, h160])
    try:
        p2sh_addr = P2SHBitcoinAddress.from_redeemScript(redeem)
        p2sh_addr_str = str(p2sh_addr)
    except Exception:
        redeem_hash = Hash160(redeem)
        from bitcoin.base58 import encode
        p2sh_addr_str = encode(b'\x05' + redeem_hash)

    return wif, addr_p2pkh_str, addr_bech32, p2sh_addr_str

def main():
    parser = argparse.ArgumentParser(description="Scan for Bitcoin address matches locally.")
    parser.add_argument("--file", "-f", nargs="+", required=True, help="One or more BTC address files (space-separated).")
    parser.add_argument("--report-every", "-r", type=int, default=1000, help="Print progress every N attempts (default 1000).")
    parser.add_argument("--max", "-m", type=int, default=0, help="Stop after this many attempts (0 = infinite).")
    parser.add_argument("--show-each", action="store_true", help="Show each generated address (very verbose).")
    parser.add_argument("--network", choices=["mainnet","testnet"], default="mainnet", help="Network (default: mainnet)")
    args = parser.parse_args()

    if args.network == "mainnet":
        SelectParams('mainnet')
        hrp = "bc"
    else:
        SelectParams('testnet')
        hrp = "tb"

    # --- MULTI-FILE TARGET LOADING ---
    targets = set()
    for fpath in args.file:
        print(f"Loading addresses from {fpath} ...")
        targets |= load_targets(fpath)
    # --- END CHANGE ---

    if not targets:
        print(f"No valid addresses loaded. Make sure files have one address per line.")
        return

    print(f"Loaded {len(targets):,} target addresses.")
    print("Starting generation loop. Press Ctrl-C to stop.")
    total = 0
    start = time.time()

    try:
        while True:
            total += 1
            priv = secrets.token_bytes(32)
            try:
                seckey = CBitcoinSecret.from_secret_bytes(priv)
            except TypeError:
                seckey = CBitcoinSecret.from_secret_bytes(priv, compressed=True)

            wif, p2pkh, p2wpkh, p2sh_p2wpkh = make_addresses_from_secret(seckey)

            if args.show_each:
                print(f"[{total}] {binascii.hexlify(priv).decode()} WIF:{wif} P2PKH:{p2pkh} P2WPKH:{p2wpkh} P2SH(P2WPKH):{p2sh_p2wpkh}")

            checks = {
                p2pkh.lower(),
                p2wpkh.lower(),
                p2sh_p2wpkh.lower(),
                p2pkh.lower().lstrip(),
                p2wpkh.lower().lstrip(),
                p2sh_p2wpkh.lower().lstrip(),
                p2pkh.lower().replace(" ", ""),
                p2wpkh.lower().replace(" ", ""),
                p2sh_p2wpkh.lower().replace(" ", ""),
                p2pkh[1:].lower() if p2pkh and p2pkh[0] in ("1","3") else "",
                p2wpkh[3:].lower() if p2wpkh.lower().startswith("bc1") or p2wpkh.lower().startswith("tb1") else ""
            }

            hit = None
            for chk in checks:
                if not chk:
                    continue
                if chk in targets:
                    hit = chk
                    break

            if hit:
                # --- SIMPLIFIED MATCH PRINT ---
                print("\n=== MATCH FOUND ===")
                print("WIF")
                print(wif)
                print("ADDRESS")
                print(hit)
                print("===================\n")
                sys.stdout.flush()
                return  # exit after first match

            if args.report_every > 0 and total % args.report_every == 0:
                elapsed = time.time() - start
                rate = total / elapsed if elapsed > 0 else 0.0
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Tried {total:,} keys — {rate:,.1f} keys/s (elapsed {int(elapsed)}s)")

            if args.max > 0 and total >= args.max:
                print(f"Reached max attempts ({args.max}). Exiting.")
                return

    except KeyboardInterrupt:
        elapsed = time.time() - start
        print("\nInterrupted by user.")
        print(f"Total tried: {total:,}")
        if elapsed > 0:
            print(f"Average speed: {total/elapsed:,.1f} keys/s")
        return

if __name__ == "__main__":
    main()