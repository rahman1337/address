#!/usr/bin/env python3
# brain_bruteforce_alltypes_ish.py
# iSH-friendly bruteforce scanner that derives P2PKH, P2SH-P2WPKH, P2WPKH, and optionally P2TR (taproot).
# Dependencies: requests, ecdsa, base58
# Optional for taproot: coincurve

from __future__ import annotations
import io
import sys
import argparse
import logging
import time
import binascii
import hashlib

# Networking / crypto libs
try:
    import requests
except Exception as e:
    print("Missing dependency 'requests'. Install: pip3 install requests")
    raise

try:
    import ecdsa
except Exception as e:
    print("Missing dependency 'ecdsa'. Install: pip3 install ecdsa")
    raise

try:
    import base58
except Exception as e:
    print("Missing dependency 'base58'. Install: pip3 install base58")
    raise

# optional: coincurve for taproot point math (fast & reliable). If not available, script still runs but no taproot.
try:
    import coincurve
    HAVE_COINCURVE = True
except Exception:
    HAVE_COINCURVE = False

# --- Minimal bech32 / segwit reference implementation (BIP173 + BIP350) ---
# Adapted small functions to encode segwit addresses with bech32/bech32m
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            if ((top >> i) & 1):
                chk ^= GENERATORS[i]
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data, spec='bech32'):
    values = bech32_hrp_expand(hrp) + data
    const = 1 if spec == 'bech32' else 0x2bc830a3  # constant for bech32m
    polymod = bech32_polymod(values + [0,0,0,0,0,0]) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, spec='bech32'):
    combined = data + bech32_create_checksum(hrp, data, spec=spec)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def segwit_addr_encode(hrp, witver, witprog):
    # witprog: bytes
    if witver < 0 or witver > 16 or len(witprog) < 2 or len(witprog) > 40:
        return None
    data = [witver] + convertbits(list(witprog), 8, 5)
    # specify spec: bech32 for v0, bech32m for v1+
    spec = 'bech32' if witver == 0 else 'bech32m'
    return bech32_encode(hrp, data, spec=spec)

# --- End bech32/segwit helpers ---

# --- Minimal fallback BlockchainInfo explorer (public endpoints) ---
# You can change to insight/abe classes if you prefer
class BlockchainInfo:
    STRING_TYPE = "blockchain.info"
    def __init__(self):
        self.session = requests.Session()
    def open_session(self): pass
    def close_session(self):
        try: self.session.close()
        except: pass
    def _rawaddr(self, address):
        url = "https://blockchain.info/rawaddr/{}".format(address)
        r = self.session.get(url, timeout=12)
        r.raise_for_status()
        return r.json()
    def get_received(self, address):
        j = self._rawaddr(address)
        return float(j.get("total_received", 0)) / 1e8
    def get_balance(self, address):
        j = self._rawaddr(address)
        return float(j.get("final_balance", 0)) / 1e8

# lightweight aliases for compatibility
class Abe:
    STRING_TYPE = "abe"
    def __init__(self, server=None, port=None, chain=None):
        self.inner = BlockchainInfo()
    def open_session(self): self.inner.open_session()
    def close_session(self): self.inner.close_session()
    def get_received(self, address): return self.inner.get_received(address)
    def get_balance(self, address): return self.inner.get_balance(address)

class Insight:
    STRING_TYPE = "insight"
    def __init__(self):
        self.inner = BlockchainInfo()
    def open_session(self): self.inner.open_session()
    def close_session(self): self.inner.close_session()
    def get_received(self, address): return self.inner.get_received(address)
    def get_balance(self, address): return self.inner.get_balance(address)

class BlockExplorerCom:
    STRING_TYPE = "blockexplorer.com"
    def __init__(self):
        self.inner = BlockchainInfo()
    def open_session(self): self.inner.open_session()
    def close_session(self): self.inner.close_session()
    def get_received(self, address): return self.inner.get_received(address)
    def get_balance(self, address): return self.inner.get_balance(address)

# --- Wallet with all address derivations ---
class Wallet:
    """
    Wallet(passphrase_or_key, is_private_key=False)
    - If is_private_key: accepts hex private key (64 chars) or WIF.
    - Otherwise: treat as brainwallet passphrase -> priv = sha256(passphrase).
    Exposes:
        - addresses: dict with keys 'p2pkh','p2sh-p2wpkh','p2wpkh','p2tr' (p2tr may be None if coincurve missing)
        - private_key (hex)
        - wif (WIF)
    """
    def __init__(self, input_word, is_private_key=False):
        self.original = input_word.strip()
        self.is_private_key = bool(is_private_key)
        if self.is_private_key:
            if self._looks_like_hex(self.original):
                self.priv_hex = self.original.lower()
            else:
                self.priv_hex = self._wif_to_hex(self.original)
        else:
            self.priv_hex = binascii.hexlify(hashlib.sha256(self.original.encode('utf-8')).digest()).decode()
        self.private_key = self.priv_hex
        self.wif = self._hex_to_wif(self.priv_hex)
        # derive pubkey & addresses
        self.pubkey_compressed = self._priv_to_compressed_pubkey(self.priv_hex)  # bytes
        self.addresses = {}
        self.addresses['p2pkh'] = self._p2pkh_from_pubkey(self.pubkey_compressed)
        self.addresses['p2wpkh'] = self._p2wpkh_bech32(self.pubkey_compressed)
        self.addresses['p2sh-p2wpkh'] = self._p2sh_p2wpkh(self.pubkey_compressed)
        # taproot (p2tr)
        self.addresses['p2tr'] = self._maybe_p2tr()

    def _looks_like_hex(self, s):
        try:
            int(s, 16)
            return len(s) in (64, 66)
        except Exception:
            return False

    def _hex_to_wif(self, priv_hex, compressed=True):
        b = binascii.unhexlify(priv_hex)
        payload = b'\x80' + b
        if compressed:
            payload += b'\x01'
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return base58.b58encode(payload + checksum).decode()

    def _wif_to_hex(self, wif):
        try:
            raw = base58.b58decode(wif)
            payload = raw[:-4]
            if payload[0] != 0x80:
                # not mainnet maybe; still try
                pass
            if len(payload) == 34 and payload[-1] == 0x01:
                key = payload[1:-1]
            else:
                key = payload[1:]
            return binascii.hexlify(key).decode()
        except Exception:
            return ""

    def _priv_to_compressed_pubkey(self, priv_hex):
        priv = binascii.unhexlify(priv_hex)
        sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        px = vk.to_string()
        x = px[:32]
        y = px[32:]
        prefix = b'\x02' if (y[-1] % 2 == 0) else b'\x03'
        return prefix + x

    def _hash160(self, data_bytes):
        return hashlib.new('ripemd160', hashlib.sha256(data_bytes).digest()).digest()

    def _p2pkh_from_pubkey(self, pubkey_bytes):
        rip = self._hash160(pubkey_bytes)
        prefixed = b'\x00' + rip
        checksum = hashlib.sha256(hashlib.sha256(prefixed).digest()).digest()[:4]
        return base58.b58encode(prefixed + checksum).decode()

    def _p2wpkh_bech32(self, pubkey_bytes):
        # witness program = HASH160(pubkey) (20 bytes), version 0
        witprog = self._hash160(pubkey_bytes)
        return segwit_addr_encode("bc", 0, witprog)

    def _p2sh_p2wpkh(self, pubkey_bytes):
        # redeemScript = 0x00 0x14 <20-byte HASH160(pubkey)>
        witprog = self._hash160(pubkey_bytes)
        redeem = b'\x00\x14' + witprog
        redeem_hash = hashlib.new('ripemd160', hashlib.sha256(redeem).digest()).digest()
        pref = b'\x05' + redeem_hash
        checksum = hashlib.sha256(hashlib.sha256(pref).digest()).digest()[:4]
        return base58.b58encode(pref + checksum).decode()

    def _maybe_p2tr(self):
        # Taproot key path address (v1 bech32m). Requires point tweak per BIP340/BIP341.
        if not HAVE_COINCURVE:
            return None
        try:
            # use coincurve to do point math (handles parity and addition)
            priv_int = int(self.priv_hex, 16)
            # internal pubkey (x-only) is the x coord of the public key
            priv_bytes = binascii.unhexlify(self.priv_hex)
            pub = coincurve.PublicKey.from_valid_secret(priv_bytes)
            full = pub.format(compressed=False)  # 65 bytes 0x04 + X + Y
            x = full[1:33]
            # compute tweak = tagged_hash("TapTweak", x)
            def tagged_hash(tag, msg):
                tag_hash = hashlib.sha256(tag.encode()).digest()
                return hashlib.sha256(tag_hash + tag_hash + msg).digest()
            tweak = tagged_hash("TapTweak", x)
            tweak_int = int.from_bytes(tweak, 'big')
            # Q = P + tweak*G
            Q = pub.add(tweak)  # coincurve PublicKey.add accepts 32-byte tweak
            # get x-only pubkey of Q (32 bytes)
            Q_raw = Q.format(compressed=False)  # 65 bytes
            Qx = Q_raw[1:33]
            # segwit v1 witprog = 32-byte x-only pubkey
            return segwit_addr_encode("bc", 1, Qx)
        except Exception as e:
            logging.debug("Taproot derivation failed: %s", e)
            return None

    def __repr__(self):
        return "<Wallet {}>".format(self.addresses.get('p2wpkh'))

# --- Main scanning script (modified from original) ---
def main():
    parser = argparse.ArgumentParser(description='Bruteforce dictionary scanner (all address types).')
    parser.add_argument('-t', action='store', dest='type', required=True,
                        help='Blockchain lookup type ({}|{}|{}|{})'.format(Abe.STRING_TYPE,
                                                                             BlockchainInfo.STRING_TYPE,
                                                                             Insight.STRING_TYPE,
                                                                             BlockExplorerCom.STRING_TYPE))
    parser.add_argument('-d', action='store', dest='dict_file', required=True, help='Dictionary file (utf-8)')
    parser.add_argument('-o', action='store', dest='output_file', required=True, help='Output file')
    parser.add_argument('-s', action='store', dest='server', help='Abe server (if using abe)')
    parser.add_argument('-p', action='store', dest='port', help='Abe port (if using abe)')
    parser.add_argument('-c', action='store', dest='chain', help='Abe chain (if using abe)')
    parser.add_argument('-k', action='store_true', dest='is_private_key', default=False,
                        help='Treat dictionary entries as private keys (hex or WIF)')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-6s line %(lineno)-4s %(message)s')

    valid_types = [BlockchainInfo.STRING_TYPE, Insight.STRING_TYPE, Abe.STRING_TYPE, BlockExplorerCom.STRING_TYPE]
    if args.type not in valid_types:
        logging.error("Invalid -t option. Valid: %s", ", ".join(valid_types))
        sys.exit(1)

    # choose explorer
    if args.type == Abe.STRING_TYPE:
        blockexplorer = Abe(args.server, args.port, args.chain)
    elif args.type == BlockchainInfo.STRING_TYPE:
        blockexplorer = BlockchainInfo()
    elif args.type == Insight.STRING_TYPE:
        blockexplorer = Insight()
    elif args.type == BlockExplorerCom.STRING_TYPE:
        blockexplorer = BlockExplorerCom()
    else:
        logging.error("Invalid type.")
        sys.exit(1)

    blockexplorer.open_session()
    logging.info("Using explorer: %s", args.type)
    if not HAVE_COINCURVE:
        logging.info("coincurve not installed — taproot (p2tr) addresses will NOT be derived. Install 'coincurve' to enable.")

    # validate dictionary file
    try:
        with io.open(args.dict_file, 'rt', encoding='utf-8') as f:
            f.read(4096)
    except Exception as e:
        logging.error("Failed to open dictionary file %s: %s", args.dict_file, e)
        sys.exit(1)

    try:
        f_dictionary = io.open(args.dict_file, 'rt', encoding='utf-8')
    except Exception as e:
        logging.error("Failed to open dictionary file %s: %s", args.dict_file, e)
        sys.exit(1)

    # open output
    header = 'dictionary_word,address_type,address,received_btc,private_hex,wif,current_balance_btc'
    try:
        f_out = open(args.output_file, 'w', encoding='utf-8')
        f_out.write(header + '\n')
    except Exception as e:
        logging.error("Failed to open output file %s: %s", args.output_file, e)
        sys.exit(1)

    for raw in f_dictionary:
        word = raw.rstrip()
        if not word:
            continue

        logging.debug("processing '%s'", word)
        try:
            wallet = Wallet(word, args.is_private_key)
        except Exception as e:
            logging.warning("Failed to create wallet for '%s': %s", word, e)
            continue

        # iterate all derived addresses
        for atype, addr in wallet.addresses.items():
            if not addr:
                continue
            # Check received (with retries)
            retry = 0
            retry_count = 5
            sleep_seconds = 8
            while retry < retry_count:
                try:
                    received = blockexplorer.get_received(addr)
                    break
                except Exception as e:
                    logging.warning("Error fetching received for %s (%s): %s — retry %d/%d", addr, atype, e, retry+1, retry_count)
                    time.sleep(sleep_seconds)
                    retry += 1
            if retry == retry_count:
                logging.error("Failed to fetch received for %s after %d retries — skipping", addr, retry_count)
                continue
            if received == 0:
                logging.debug("no received for %s (%s)", addr, atype)
                continue

            # get current balance
            retry = 0
            retry_count = 4
            sleep_seconds = 10
            while retry < retry_count:
                try:
                    balance = blockexplorer.get_balance(addr)
                    break
                except Exception as e:
                    logging.warning("Error fetching balance for %s (%s): %s — retry %d/%d", addr, atype, e, retry+1, retry_count)
                    time.sleep(sleep_seconds)
                    retry += 1
            if retry == retry_count:
                logging.error("Failed to fetch balance for %s after %d retries — skipping", addr, retry_count)
                continue

            # record found
            out_line = "{word},{atype},{addr},{received:.8f},{priv},{wif},{balance:.8f}".format(
                word=word, atype=atype, addr=addr, received=received, priv=wallet.private_key, wif=wallet.wif, balance=balance)
            logging.info("Found used wallet: %s", out_line)
            f_out.write(out_line + '\n')
            f_out.flush()
            # if you want to skip checking other address families for this word, uncomment next line
            # break

    blockexplorer.close_session()
    f_out.close()
    f_dictionary.close()
    logging.info("Done.")

if __name__ == '__main__':
    main()