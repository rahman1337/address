#!/usr/bin/env python3
from __future__ import annotations
import io, sys, time, argparse, logging, hashlib
from coincurve import PrivateKey

# --- keccak (pysha3) required ---
try:
    import sha3 as _sha3
    def keccak_256(data: bytes) -> bytes:
        k = _sha3.keccak_256()
        k.update(data)
        return k.digest()
except Exception:
    raise RuntimeError("pysha3 required: pip install pysha3")

# --- helpers ---
def sha256_bytes(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def privhex_from_passphrase(word: str) -> str:
    """Deterministic private key hex from passphrase (sha256)."""
    return sha256_bytes(word.encode("utf-8")).hex()

def eth_address_from_privhex(priv_hex: str) -> str:
    """Compute EIP-55 checksum Ethereum address from private key hex (offline)."""
    pk = PrivateKey(bytes.fromhex(priv_hex))
    pub_uncompressed = pk.public_key.format(compressed=False)  # 65 bytes, 0x04 + X + Y
    if len(pub_uncompressed) != 65 or pub_uncompressed[0] != 0x04:
        raise RuntimeError("Unexpected public key format")
    h = keccak_256(pub_uncompressed[1:])  # drop 0x04
    addr_bytes = h[-20:]
    addr_hex = addr_bytes.hex()
    return checksum_eth_address("0x" + addr_hex)

def checksum_eth_address(addr: str) -> str:
    """EIP-55 checksum implementation."""
    addr_noprefix = addr.lower().replace("0x", "")
    hash_hex = keccak_256(addr_noprefix.encode("ascii")).hex()
    out = "0x"
    for c, h in zip(addr_noprefix, hash_hex):
        out += c.upper() if int(h, 16) >= 8 else c
    return out

# --- main ---
def main():
    ap = argparse.ArgumentParser(description="Offline generator: passphrase -> ETH address + privhex")
    ap.add_argument("--dict", "-d", default="dictionaryeth.txt", help="input wordlist (one passphrase per line)")
    ap.add_argument("--out", "-o", default="found.txt", help="append output (CSV lines: passphrase,address,privhex)")
    ap.add_argument("--sleep", type=float, default=0.0, help="optional small sleep between lines (default 0)")
    ap.add_argument("--quiet", "-q", action="store_true", help="do not print to stdout; only write file")
    ap.add_argument("--no-priv", action="store_true", help="do not include privhex in output (only passphrase,address)")
    ap.add_argument("--debug", action="store_true", help="debug logging")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    try:
        fdict = io.open(args.dict, "rt", encoding="utf-8", errors="ignore")
    except Exception as e:
        logging.error("Cannot open dictionary: %s", e)
        sys.exit(1)

    try:
        fout = open(args.out, "a", encoding="utf-8", buffering=1)
    except Exception as e:
        logging.error("Cannot open output file: %s", e)
        fdict.close()
        sys.exit(1)

    total = 0
    start = time.time()
    current = None

    try:
        for raw in fdict:
            word = raw.rstrip("\n\r")
            current = word
            if not word:
                continue
            total += 1
            try:
                priv_hex = privhex_from_passphrase(word)
                addr = eth_address_from_privhex(priv_hex)
            except Exception as e:
                logging.debug("Derivation failed for %r: %s", word, e)
                continue

            if args.no_priv:
                line = f"{word},{addr}\n"
            else:
                line = f"{word},{addr},{priv_hex}\n"

            if not args.quiet:
                # print without extra spaces/newlines
                sys.stdout.write(line)
                sys.stdout.flush()

            fout.write(line)

            if args.sleep:
                time.sleep(args.sleep)

            if total % 1000 == 0:
                elapsed = time.time() - start
                logging.info("Processed %d words — avg %.2f words/s", total, total / max(1e-9, elapsed))

    except KeyboardInterrupt:
        print("\n*** INTERRUPTED by user ***")
        if current:
            print(f"Stopped while processing: {current!r}")
    finally:
        fdict.close()
        fout.close()
        elapsed = time.time() - start
        logging.info("Finished. total=%d elapsed=%.1fs avg=%.2f w/s", total, elapsed, total / max(1e-9, elapsed))

if __name__ == "__main__":
    main()