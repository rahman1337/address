#!/usr/bin/env python3
# brute2.py — iSH-friendly, no-args BTC scanner (defaults baked in)
from __future__ import annotations
import io, sys, time, binascii, hashlib, json, os, logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
import requests
import base58

# crypto libs (prefer native)
HAVE_COINCURVE = False
HAVE_SECP256K1 = False
HAVE_ECDSA = False
try:
    import coincurve
    HAVE_COINCURVE = True
except Exception:
    try:
        import secp256k1
        HAVE_SECP256K1 = True
    except Exception:
        try:
            import ecdsa
            HAVE_ECDSA = True
        except Exception:
            pass

# --- bech32 / segwit helpers ---
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
    return [(polymod >> (5 * (5 - i))) & 31 for i in range(6)]

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

# ------------------ Wallet ------------------
class Wallet:
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
        self.addresses['p2wpkh'] = self._p2wpkh_bech32(self.pubkey_compressed)
        self.addresses['p2sh-p2wpkh'] = self._p2sh_p2wpkh(self.pubkey_compressed)
        self.addresses['p2pkh'] = self._p2pkh_from_pubkey(self.pubkey_compressed)
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
        if HAVE_COINCURVE:
            pub = coincurve.PublicKey.from_valid_secret(priv)
            return pub.format(compressed=True)
        if HAVE_SECP256K1:
            pk = secp256k1.PrivateKey(priv)
            return pk.pubkey.serialize(compressed=True)
        if HAVE_ECDSA:
            sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            px = vk.to_string()
            x = px[:32]; y = px[32:]
            prefix = b'\x02' if (y[-1] % 2 == 0) else b'\x03'
            return prefix + x
        raise Exception("No crypto backend available. Install coincurve/secp256k1 or ecdsa")

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

# ------------------ Explorers ------------------

class Explorer:
    def __init__(self, session=None):
        self.session = session or requests.Session()
        self.name = "base"

    def get_address_info(self, address):
        raise NotImplementedError

class BlockstreamExplorer(Explorer):
    def __init__(self, session=None):
        super().__init__(session=session)
        self.base = "https://blockstream.info/api"
        self.name = "blockstream"

    def get_address_info(self, address):
        url = f"{self.base}/address/{address}"
        r = self.session.get(url, timeout=12)
        r.raise_for_status()
        j = r.json()
        cs = j.get("chain_stats") or {}
        tx_count = cs.get("tx_count", 0)
        has_used = tx_count > 0
        url_utxo = f"{self.base}/address/{address}/utxo"
        r2 = self.session.get(url_utxo, timeout=12)
        r2.raise_for_status()
        utxos = r2.json()
        sats = sum([u.get("value", 0) for u in utxos])
        return has_used, float(sats) / 1e8

class MempoolExplorer(Explorer):
    def __init__(self, session=None):
        super().__init__(session=session)
        self.base = "https://mempool.space/api"
        self.name = "mempool"

    def get_address_info(self, address):
        url = f"{self.base}/address/{address}"
        r = self.session.get(url, timeout=12)
        r.raise_for_status()
        j = r.json()
        cs = j.get("chain_stats") or {}
        tx_count = cs.get("tx_count", 0)
        has_used = tx_count > 0
        url_utxo = f"{self.base}/address/{address}/utxo"
        r2 = self.session.get(url_utxo, timeout=12)
        r2.raise_for_status()
        utxos = r2.json()
        sats = sum([u.get("value", 0) for u in utxos])
        return has_used, float(sats) / 1e8

# ------------------ Defaults (NO ARGS) ------------------
DICT_FILE = 'dictionary.txt'
OUTPUT_FILE = 'found.txt'
IS_PRIVATE_KEY = False  # change to True if dict contains private keys
WANTED_TYPES = ['p2wpkh','p2sh-p2wpkh','p2pkh','p2tr']
MAX_WORKERS = 4              # iSH-safe default
CONNECTION_POOL = 16
SLEEP_AFTER_FOUND = 0.02
DEBUG = False

# ------------------ Helpers & main scan ------------------
def setup_session(max_pool=16):
    s = requests.Session()
    adapter = HTTPAdapter(pool_connections=max_pool, pool_maxsize=max_pool)
    s.mount('https://', adapter)
    s.mount('http://', adapter)
    s.headers.update({'User-Agent': 'brute2.py/1.0'})
    return s

def check_word(word, wanted_types, explorer_primary, explorer_fallback, is_private_key):
    try:
        wallet = Wallet(word, is_private_key)
    except Exception as e:
        logging.debug("wallet create failed for %s: %s", word, e)
        return []
    results = []
    for atype in wanted_types:
        addr = wallet.addresses.get(atype)
        if not addr:
            continue
        for attempt_explorer in (explorer_primary, explorer_fallback):
            try:
                has_used, balance = attempt_explorer.get_address_info(addr)
                if has_used or balance > 0.0:
                    rec = {
                        'word': word,
                        'atype': atype,
                        'address': addr,
                        'has_used': bool(has_used),
                        'balance_btc': float(balance),
                        'private_hex': wallet.private_key,
                        'wif': wallet.wif,
                        'explorer': attempt_explorer.name
                    }
                    results.append(rec)
                break
            except Exception as e:
                logging.debug("Explorer %s error for %s (%s): %s", attempt_explorer.name, addr, atype, e)
                continue
    return results

def main():
    global DEBUG
    logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO,
                        format='%(asctime)s %(levelname)-6s %(message)s')
    if not os.path.exists(DICT_FILE):
        logging.error("Dictionary file not found: %s", DICT_FILE)
        sys.exit(1)
    session = setup_session(max_pool=CONNECTION_POOL)
    explorer_primary = BlockstreamExplorer(session=session)
    explorer_fallback = MempoolExplorer(session=session)
    # prepare output
    header = 'dictionary_word,address_type,address,has_used,balance_btc,private_hex,wif,explorer'
    fout = open(OUTPUT_FILE, 'a', encoding='utf-8')
    if os.path.getsize(OUTPUT_FILE) == 0:
        fout.write(header + '\n'); fout.flush()
    logging.info("Starting scan: workers=%d  types=%s  primary=%s fallback=%s",
                 MAX_WORKERS, ','.join(WANTED_TYPES), explorer_primary.name, explorer_fallback.name)
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futures = {}
        with io.open(DICT_FILE, 'rt', encoding='utf-8') as f:
            # submit jobs streaming
            for line in f:
                word = line.rstrip()
                if not word:
                    continue
                fut = ex.submit(check_word, word, WANTED_TYPES, explorer_primary, explorer_fallback, IS_PRIVATE_KEY)
                futures[fut] = word
            # collect results
            for fut in as_completed(futures):
                try:
                    res = fut.result()
                except Exception as e:
                    logging.debug("Worker raised: %s", e)
                    continue
                if res:
                    for rec in res:
                        out_line = "{word},{atype},{addr},{used},{bal:.8f},{priv},{wif},{explorer}".format(
                            word=rec['word'], atype=rec['atype'], addr=rec['address'],
                            used=int(rec['has_used']), bal=rec['balance_btc'],
                            priv=rec['private_hex'], wif=rec['wif'], explorer=rec['explorer'])
                        logging.info("FOUND %s", out_line)
                        fout.write(out_line + '\n'); fout.flush()
                        time.sleep(SLEEP_AFTER_FOUND)
    fout.close()
    logging.info("Done.")

if __name__ == '__main__':
    main()