# USAGE : python3 eth.py --file eth.txt
import argparse
import time
import secrets
import binascii
import sys

try:
    import ecdsa
except Exception:
    print("Missing dependency 'ecdsa'. Install with: pip install ecdsa")
    raise

try:
    import sha3  # from pysha3
except Exception:
    print("Missing dependency 'pysha3'. Install with: pip install pysha3")
    raise


def load_targets(path):
    targets = set()
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            if line.startswith("#"):
                continue
            if line.lower().startswith("0x"):
                line = line[2:]
            line = line.strip().lower()

            if len(line) != 40:

                continue
            try:
                int(line, 16)
            except ValueError:
                continue
            targets.add(line)
    return targets


def privkey_to_eth_address(privkey_bytes):
    sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pubkey_bytes = vk.to_string()  # 64 bytes: X||Y
    keccak = sha3.keccak_256()
    keccak.update(pubkey_bytes)
    addr_bytes = keccak.digest()[-20:]
    return binascii.hexlify(addr_bytes).decode("ascii")


def main():
    parser = argparse.ArgumentParser(description="Scan for Ethereum address matches locally.")
    parser.add_argument("--file", "-f", required=True, help="Path to eth.txt file (one address per line).")
    parser.add_argument("--report-every", "-r", type=int, default=1000, help="Print progress every N attempts (default 1000).")
    parser.add_argument("--max", "-m", type=int, default=0, help="Stop after this many attempts (0 = infinite).")
    parser.add_argument("--show-each", action="store_true", help="Show each generated address (very verbose).")
    args = parser.parse_args()

    targets = load_targets(args.file)
    if not targets:
        print(f"No valid addresses loaded from {args.file}. Make sure file has one address per line like '0xa7ef...'.")
        return

    print(f"Loaded {len(targets):,} target addresses from {args.file}.")
    print("Starting generation loop. Press Ctrl-C to stop.")
    total = 0
    start = time.time()

    try:
        while True:
            total += 1
            priv = secrets.token_bytes(32)
            priv_hex = binascii.hexlify(priv).decode("ascii")
            addr_hex = privkey_to_eth_address(priv)  # 40 hex chars, lowercase
            addr_display = "0x" + addr_hex

            if args.show_each:
                print(f"[{total}] {priv_hex} {addr_display}")

            # check for match
            if addr_hex in targets:
                print("\n=== MATCH FOUND ===")
                print("PRIVATE_KEY_HEX")
                print(priv_hex)
                print("ADDRESS")
                print(addr_display)
                print("===================\n")
                sys.stdout.flush()
                return  # exit after first match

            # progress report
            if args.report_every > 0 and total % args.report_every == 0:
                elapsed = time.time() - start
                rate = total / elapsed if elapsed > 0 else 0.0
                print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] Tried {total:,} keys — {rate:,.1f} keys/s (elapsed {int(elapsed)}s)")

            # max attempts
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