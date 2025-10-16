#!/usr/bin/env python3
# brute.py
# Merged/modified version of provided classes, iSH-friendly.
# Derives p2pkh, p2sh-p2wpkh, p2wpkh, optional p2tr and checks via explorer classes.

from __future__ import annotations
import io, sys, argparse, logging, time, binascii, hashlib, json, os, random
import requests

# crypto libs
try:
    import ecdsa
    import base58
except Exception as e:
    print("Missing dependencies. Install: pip3 install requests ecdsa base58")
    raise

# optional coincurve for taproot
try:
    import coincurve
    HAVE_COINCURVE = True
except Exception:
    HAVE_COINCURVE = False

# --- minimal bech32 / segwit helpers (BIP173/BIP350) ---
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
    const = 1 if spec == 'bech32' else 0x2bc830a3
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0]*6) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data, spec='bech32'):
    combined = data + bech32_create_checksum(hrp, data, spec=spec)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    acc = 0; bits = 0; ret = []; maxv = (1 << tobits) - 1
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
    if witver < 0 or witver > 16 or len(witprog) < 2 or len(witprog) > 40:
        return None
    data = [witver] + convertbits(list(witprog), 8, 5)
    spec = 'bech32' if witver == 0 else 'bech32m'
    return bech32_encode(hrp, data, spec=spec)

# ------------------ Wallet (no coinkit) ------------------
class Wallet:
    """
    Wallet(passphrase, is_private_key=False)
    - if is_private_key: accepts hex privkey or WIF
    - else: SHA256(passphrase) -> priv key
    Exposes:
      - private_key (hex)
      - wif
      - addresses dict: p2pkh, p2wpkh, p2sh-p2wpkh, p2tr (maybe None)
    """
    def __init__(self, passphrase, is_private_key=False):
        self.passphrase = passphrase
        self.is_private_key = bool(is_private_key)
        if self.is_private_key:
            if self._looks_like_hex(self.passphrase):
                self.private_key = self.passphrase.lower()
            else:
                self.private_key = self._wif_to_hex(self.passphrase)
        else:
            # derive from passphrase
            self.private_key = binascii.hexlify(hashlib.sha256(self.passphrase.encode('utf-8')).digest()).decode()
        self.wif = self._hex_to_wif(self.private_key)
        self.pubkey_compressed = self._priv_to_compressed_pubkey(self.private_key)
        self.addresses = {}
        self.addresses['p2pkh'] = self._p2pkh_from_pubkey(self.pubkey_compressed)
        self.addresses['p2wpkh'] = self._p2wpkh_bech32(self.pubkey_compressed)
        self.addresses['p2sh-p2wpkh'] = self._p2sh_p2wpkh(self.pubkey_compressed)
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
        x = px[:32]; y = px[32:]
        prefix = b'\x02' if (y[-1] % 2 == 0) else b'\x03'
        return prefix + x

    def _hash160(self, data_bytes):
        return hashlib.new('ripemd160', hashlib.sha256(data_bytes).digest()).digest()

    def _p2pkh_from_pubkey(self, pubkey_bytes):
        rip = self._hash160(pubkey_bytes)
        pref = b'\x00' + rip
        checksum = hashlib.sha256(hashlib.sha256(pref).digest()).digest()[:4]
        return base58.b58encode(pref + checksum).decode()

    def _p2wpkh_bech32(self, pubkey_bytes):
        witprog = self._hash160(pubkey_bytes)
        return segwit_addr_encode("bc", 0, witprog)

    def _p2sh_p2wpkh(self, pubkey_bytes):
        witprog = self._hash160(pubkey_bytes)
        redeem = b'\x00\x14' + witprog
        redeem_hash = hashlib.new('ripemd160', hashlib.sha256(redeem).digest()).digest()
        pref = b'\x05' + redeem_hash
        checksum = hashlib.sha256(hashlib.sha256(pref).digest()).digest()[:4]
        return base58.b58encode(pref + checksum).decode()

    def _maybe_p2tr(self):
        if not HAVE_COINCURVE:
            return None
        try:
            priv_bytes = binascii.unhexlify(self.private_key)
            pub = coincurve.PublicKey.from_valid_secret(priv_bytes)
            full = pub.format(compressed=False)
            x = full[1:33]
            def tagged_hash(tag, msg):
                tag_hash = hashlib.sha256(tag.encode()).digest()
                return hashlib.sha256(tag_hash + tag_hash + msg).digest()
            tweak = tagged_hash("TapTweak", x)
            Q = pub.add(tweak)
            Q_raw = Q.format(compressed=False)
            Qx = Q_raw[1:33]
            return segwit_addr_encode("bc", 1, Qx)
        except Exception:
            return None

    def __repr__(self):
        return "<Wallet priv=%s addr_p2wpkh=%s>" % (self.private_key[:8], self.addresses.get('p2wpkh'))

# ------------------ BaseBlockExplorer & concrete classes (modified) ------------------

class BaseBlockExplorer(object):
    def __init__(self):
        self.session = None
        self._base_url = None
        self._base_url_received = None
        self._base_url_balance = None
        self._received_suffix = ''
        self._balance_suffix = ''

    def open_session(self):
        logging.info("Opening new session")
        self.session = requests.Session()
        # do not perform GET to base url (some providers block/limit)
        return

    def close_session(self):
        logging.debug("Closing session")
        if self.session:
            try:
                self.session.close()
            except Exception:
                pass
        self.session = None

    def _get(self, url, timeout=15):
        r = self.session.get(url, timeout=timeout)
        # Try to be tolerant: return r (caller will parse)
        r.raise_for_status()
        return r

    def _parse_numeric_from_response(self, response):
        # Accept responses that are:
        # - plain number text like "12345"
        # - JSON with common keys (total_received, totalReceived, final_balance, balance)
        text = response.text.strip()
        # try direct float/int
        try:
            return float(text)
        except Exception:
            pass
        # try JSON
        try:
            j = response.json()
            # try common keys
            for key in ("total_received", "totalReceived", "final_balance", "finalBalance", "balance", "received"):
                v = None
                if isinstance(j, dict):
                    v = j.get(key)
                if v is not None:
                    return float(v)
            # blockchair format: {"data": { "ADDRESS": {"address": {"received": ...}}}}
            if isinstance(j, dict) and "data" in j:
                # get nested numeric if possible
                try:
                    # pick first entry
                    inner = next(iter(j["data"].values()))
                    if isinstance(inner, dict):
                        addr = inner.get("address", {})
                        for k in ("received", "balance"):
                            if k in addr:
                                return float(addr.get(k))
                except Exception:
                    pass
        except Exception:
            pass
        raise Exception("Unable to parse numeric from response: " + text[:200])

    def get_received(self, public_address):
        if not self.session:
            raise Exception("open_session first")
        url = "{}/{}{}".format(self._base_url_received, public_address, self._received_suffix)
        r = self._get(url)
        num = self._parse_numeric_from_response(r)
        return num

    def get_balance(self, public_address):
        if not self.session:
            raise Exception("open_session first")
        url = "{}/{}{}".format(self._base_url_balance, public_address, self._balance_suffix)
        r = self._get(url)
        num = self._parse_numeric_from_response(r)
        return num

    @staticmethod
    def text_to_float(text):
        try:
            return float(text)
        except Exception:
            raise

    @staticmethod
    def satoshi_to_btc(value):
        try:
            # value might be satoshis integer
            return float(value) / 100000000.0
        except Exception:
            raise

class Abe(BaseBlockExplorer):
    STRING_TYPE = "abe"
    def __init__(self, server, port, chain):
        super().__init__()
        self.server = server
        self.port = port
        self.chain = chain
        self._base_url = "http://{}:{}".format(self.server, self.port)
        self._base_url_received = "{}/chain/{}/q/getreceivedbyaddress".format(self._base_url, self.chain)
        self._base_url_balance = "{}/chain/{}/q/addressbalance".format(self._base_url, self.chain)

class BlockchainInfo(BaseBlockExplorer):
    STRING_TYPE = "blockchaininfo"
    def __init__(self):
        super().__init__()
        self._api_limit_seconds = 1  # lowered default; you can increase
        logging.info("Note: sleeping %s seconds before blockchain.info calls to avoid rate limits", self._api_limit_seconds)
        self._base_url = "https://blockchain.info"
        self._base_url_received = "{}/q/getreceivedbyaddress".format(self._base_url)
        self._base_url_balance = "{}/q/addressbalance".format(self._base_url)

    def get_received(self, public_address):
        time.sleep(self._api_limit_seconds)
        val = super().get_received(public_address)
        return self.satoshi_to_btc(val)

    def get_balance(self, public_address):
        time.sleep(self._api_limit_seconds)
        val = super().get_balance(public_address)
        return self.satoshi_to_btc(val)

class BlockExplorerCom(BaseBlockExplorer):
    STRING_TYPE = "blockexplorercom"
    def __init__(self):
        super().__init__()
        self._base_url = "https://blockexplorer.com"
        self._base_url_received = "{}/api/addr".format(self._base_url)
        self._base_url_balance = "{}/api/addr".format(self._base_url)
        self._received_suffix = "/totalReceived"
        self._balance_suffix = "/balance"

    def get_received(self, public_address):
        val = super().get_received(public_address)
        return self.satoshi_to_btc(val)

    def get_balance(self, public_address):
        val = super().get_balance(public_address)
        return self.satoshi_to_btc(val)

class Insight(BaseBlockExplorer):
    STRING_TYPE = "insight"
    def __init__(self):
        super().__init__()
        self._base_url = "https://insight.bitpay.com"
        self._base_url_received = "{}/api/addr".format(self._base_url)
        self._base_url_balance = "{}/api/addr".format(self._base_url)
        self._received_suffix = "/totalReceived"
        self._balance_suffix = "/balance"

    def get_received(self, public_address):
        val = super().get_received(public_address)
        return self.satoshi_to_btc(val)

    def get_balance(self, public_address):
        val = super().get_balance(public_address)
        return self.satoshi_to_btc(val)

# ------------------ Main scanning CLI ------------------

def main():
    parser = argparse.ArgumentParser(description='iSH-friendly bruteforce scanner (merged).')
    parser.add_argument('-t', '--type', required=True,
                        help='Explorer type: abe | blockchaininfo | blockexplorercom | insight')
    parser.add_argument('-d', '--dict_file', required=True, help='Dictionary file (utf-8 lines)')
    parser.add_argument('-o', '--output_file', required=True, help='Output CSV file')
    parser.add_argument('-s', '--server', help='Abe server (if using abe)')
    parser.add_argument('-p', '--port', help='Abe port')
    parser.add_argument('-c', '--chain', help='Abe chain')
    parser.add_argument('-k', '--is_private_key', action='store_true', help='Treat lines as private keys (hex or WIF)')
    parser.add_argument('--types', default='p2wpkh,p2sh-p2wpkh,p2pkh,p2tr', help='Comma list of address families to check (priority)')
    parser.add_argument('--sleep', type=float, default=0.06, help='sleep (s) between successful requests to avoid rate limits')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format='%(asctime)s %(levelname)-6s line %(lineno)-4s %(message)s')

    # Validate type and create explorer
    t = args.type.lower()
    if t == 'abe':
        if not args.server or not args.port or not args.chain:
            logging.error("When using abe, you must supply -s SERVER -p PORT -c CHAIN")
            sys.exit(1)
        explorer = Abe(args.server, args.port, args.chain)
    elif t == 'blockchaininfo':
        explorer = BlockchainInfo()
    elif t == 'blockexplorercom':
        explorer = BlockExplorerCom()
    elif t == 'insight':
        explorer = Insight()
    else:
        logging.error("Invalid -t type: %s", args.type)
        sys.exit(1)

    explorer.open_session()
    wanted_types = [x.strip() for x in args.types.split(',') if x.strip()]
    if not HAVE_COINCURVE and 'p2tr' in wanted_types:
        logging.info("coincurve not installed: p2tr will be skipped until you install coincurve")

    # Validate dict file
    try:
        with io.open(args.dict_file, 'rt', encoding='utf-8') as f:
            f.read(4096)
    except Exception as e:
        logging.error("Failed to open dict file %s : %s", args.dict_file, e)
        sys.exit(1)
    f_dictionary = io.open(args.dict_file, 'rt', encoding='utf-8')

    # Prepare output
    header = 'dictionary_word,address_type,address,received_btc,private_hex,wif,current_balance_btc'
    try:
        fout = open(args.output_file, 'w', encoding='utf-8')
        fout.write(header + '\n')
    except Exception as e:
        logging.error("Failed to open output file %s : %s", args.output_file, e)
        sys.exit(1)

    # Loop
    for raw in f_dictionary:
        word = raw.rstrip()
        if not word:
            continue
        logging.debug("processing: %s", word)
        try:
            wallet = Wallet(word, is_private_key=args.is_private_key)
        except Exception as e:
            logging.warning("Failed to create wallet for '%s': %s", word, e)
            continue

        # check desired address families in priority order
        for atype in wanted_types:
            addr = wallet.addresses.get(atype)
            if not addr:
                logging.debug("address type %s not available for %s", atype, word)
                continue

            # get received with retries/backoff
            retry = 0
            max_retries = 4
            backoff = 1.0
            received = 0
            while retry < max_retries:
                try:
                    received_raw = explorer.get_received(addr)
                    # explorer classes: Abe returns satoshis (converted by subclass if needed)
                    # some providers return in sats or BTC inconsistently; handle heuristics:
                    if received_raw > 1000000000:  # huge number -> likely satoshis
                        received = float(received_raw) / 1e8
                    elif received_raw > 1 and received_raw < 1000000000:
                        # uncertain: treat as sats if integer-like
                        if float(received_raw).is_integer():
                            received = float(received_raw) / 1e8
                        else:
                            received = float(received_raw)
                    else:
                        received = float(received_raw)
                    break
                except Exception as e:
                    retry += 1
                    sleep = backoff * (2 ** (retry-1)) * (0.5 + random.random())
                    logging.warning("Error fetching received for %s (%s): %s — retry %d/%d sleeping %.2fs",
                                    addr, atype, e, retry, max_retries, sleep)
                    time.sleep(sleep)
            if retry == max_retries:
                logging.error("Giving up fetching received for %s (%s)", addr, atype)
                continue

            if received == 0:
                logging.debug("no received for %s (%s)", addr, atype)
                # polite sleep to avoid hammering
                time.sleep(args.sleep)
                continue

            # get balance
            retry = 0
            balance = 0.0
            while retry < max_retries:
                try:
                    balance_raw = explorer.get_balance(addr)
                    if balance_raw > 1000000000:
                        balance = float(balance_raw) / 1e8
                    elif balance_raw > 1 and balance_raw < 1000000000:
                        if float(balance_raw).is_integer():
                            balance = float(balance_raw) / 1e8
                        else:
                            balance = float(balance_raw)
                    else:
                        balance = float(balance_raw)
                    break
                except Exception as e:
                    retry += 1
                    sleep = backoff * (2 ** (retry-1)) * (0.5 + random.random())
                    logging.warning("Error fetching balance for %s (%s): %s — retry %d/%d sleeping %.2fs",
                                    addr, atype, e, retry, max_retries, sleep)
                    time.sleep(sleep)
            if retry == max_retries:
                logging.error("Giving up fetching balance for %s (%s)", addr, atype)
                continue

            # record
            out_line = "{word},{atype},{addr},{received:.8f},{priv},{wif},{balance:.8f}".format(
                word=word, atype=atype, addr=addr,
                received=received, priv=wallet.private_key, wif=wallet.wif, balance=balance)
            logging.info("Found used wallet: %s", out_line)
            fout.write(out_line + '\n'); fout.flush()
            # sleep politely after a found/write
            time.sleep(args.sleep)
            # optional: break to skip checking other families for this word
            # break

    explorer.close_session()
    fout.close()
    f_dictionary.close()
    logging.info("Done.")

if __name__ == '__main__':
    main()