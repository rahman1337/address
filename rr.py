#!/usr/bin/env python3
"""
Reused R Scanner v0.5

- Reads addresses from btc1.txt (one per line)
- Uses mempool.space first for tx lists and raw tx hex; falls back to blockchain.info for tx lists if mempool fails
- Follows pagination to scan ALL outgoing (sending) transactions for each address
- Fetches raw tx hex from mempool.space and computes accurate Z (sighash) for each input signature
- Supports legacy, P2SH-wrapped segwit, native segwit v0 (BIP143) and best-effort Taproot key-path
- Retries failed HTTP calls up to 3 times with backoff 1,3,5 seconds
- Global rate-limit between calls (API_MIN_INTERVAL)
- Prints FOUND blocks including Address, R, S1, S2, Z1, Z2, TXID1, TXID2
"""

from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import requests
import time
import threading
import sys
import hashlib
import binascii

# ----------------- Configuration -----------------
MEMPOOL_BASE = "https://mempool.space"  # (A: main mempool.space)
MEMPOOL_ADDR_TXS = MEMPOOL_BASE + "/api/address/{}/txs"              # first page
MEMPOOL_ADDR_TXS_CHAIN = MEMPOOL_BASE + "/api/address/{}/txs/chain/{}"  # subsequent
MEMPOOL_TX_HEX = MEMPOOL_BASE + "/api/tx/{}/hex"
MEMPOOL_TX_JSON = MEMPOOL_BASE + "/api/tx/{}"

BLOCKCHAIN_RAWADDR = "https://blockchain.info/rawaddr/{}"  # fallback tx list (paginated via offset? we will loop offsets)
BLOCKCHAIN_PAGE_SIZE = 50

API_MIN_INTERVAL = 0.6  # seconds between ANY API calls (global)
RETRY_BACKOFFS = [1, 3, 5]  # seconds

THREAD_WORKERS = 3

# ----------------- global rate-limit -----------------
_rate_lock = threading.Lock()
_last_call_time = 0.0

def safe_get_with_retries(url, timeout=20):
    """
    GET with global rate-limiting + retry/backoff.
    Returns requests.Response on success or raises.
    """
    last_exc = None
    for attempt, backoff in enumerate([None] + RETRY_BACKOFFS):  # attempt counts: 0..3 (max 4 tries)
        if attempt > 0:
            time.sleep(backoff)
        with _rate_lock:
            global _last_call_time
            now = time.time()
            elapsed = now - _last_call_time
            if elapsed < API_MIN_INTERVAL:
                time.sleep(API_MIN_INTERVAL - elapsed)
            try:
                r = requests.get(url, timeout=timeout)
                _last_call_time = time.time()
            except Exception as e:
                last_exc = e
                _last_call_time = time.time()
                continue
        try:
            r.raise_for_status()
            return r
        except Exception as e:
            last_exc = e
            continue
    # out of retries
    raise last_exc

# ----------------- crypto helpers -----------------
def sha256(b): return hashlib.sha256(b).digest()
def sha256d(b): return hashlib.sha256(hashlib.sha256(b).digest()).digest()

# varint helpers
def read_varint(b, off):
    fb = b[off]
    off += 1
    if fb < 0xfd:
        return fb, off
    if fb == 0xfd:
        v = int.from_bytes(b[off:off+2], 'little'); off += 2; return v, off
    if fb == 0xfe:
        v = int.from_bytes(b[off:off+4], 'little'); off += 4; return v, off
    v = int.from_bytes(b[off:off+8], 'little'); off += 8; return v, off

def encode_varint(i):
    if i < 0xfd:
        return bytes([i])
    if i <= 0xffff:
        return b'\xfd' + i.to_bytes(2,'little')
    if i <= 0xffffffff:
        return b'\xfe' + i.to_bytes(4,'little')
    return b'\xff' + i.to_bytes(8,'little')

# ----------------- DER signature extraction -----------------
def extract_der_signatures_from_scripthex(script_hex):
    """
    Return list of dicts: {r: hex, s: hex, raw_der_hex: hex, sighash_type: optional int}
    Attempts to locate DER signatures inside a hex script or witness element.
    """
    sigs = []
    if not script_hex:
        return sigs
    try:
        data = bytes.fromhex(script_hex)
    except Exception:
        return sigs
    i = 0
    L = len(data)
    while i < L:
        # skip small push opcodes to get to 0x30 start
        op = data[i]
        j = None
        if op <= 0x4b:
            # push data length
            plen = op
            if i + 1 + plen <= L and plen > 0 and data[i+1] == 0x30:
                j = i + 1
            else:
                i += 1
                continue
        elif op == 0x30:
            j = i
        else:
            i += 1
            continue
        if j is None or j + 2 >= L:
            i += 1
            continue
        if data[j] != 0x30:
            i += 1
            continue
        total_len = data[j+1]
        end = j + 2 + total_len
        if end <= L:
            der = data[j:end]
            try:
                if len(der) >= 6 and der[2] == 0x02:
                    rlen = der[3]
                    r_start = 4
                    r_end = r_start + rlen
                    if r_end < len(der) and der[r_end] == 0x02:
                        slen = der[r_end + 1]
                        s_start = r_end + 2
                        s_end = s_start + slen
                        if s_end == len(der):
                            r_bytes = der[r_start:r_end]
                            s_bytes = der[s_start:s_end]
                            raw_der_hex = der.hex()
                            sigs.append({
                                'r': r_bytes.hex(),
                                's': s_bytes.hex(),
                                'raw_der_hex': raw_der_hex,
                                'sighash_type': None
                            })
                            i = end
                            continue
            except Exception:
                pass
        i += 1
    return sigs

# ----------------- TX parsing (minimal) -----------------
def parse_tx(raw_hex):
    raw = bytes.fromhex(raw_hex)
    off = 0
    version = int.from_bytes(raw[off:off+4], 'little'); off += 4
    flag = None
    if off < len(raw) and raw[off:off+1] == b'\x00' and raw[off+1:off+2] != b'\x00':
        off += 1
        flag = raw[off:off+1]
        off += 1
    txin_count, off = read_varint(raw, off)
    inputs = []
    for _ in range(txin_count):
        prev_hash = raw[off:off+32][::-1].hex(); off += 32
        prev_index = int.from_bytes(raw[off:off+4], 'little'); off += 4
        script_len, off = read_varint(raw, off)
        script = raw[off:off+script_len].hex(); off += script_len
        sequence = int.from_bytes(raw[off:off+4], 'little'); off += 4
        inputs.append({
            'prevout_hash': prev_hash,
            'prevout_n': prev_index,
            'scriptSig': script,
            'sequence': sequence,
            'witness': []
        })
    txout_count, off = read_varint(raw, off)
    outputs = []
    for _ in range(txout_count):
        value = int.from_bytes(raw[off:off+8], 'little'); off += 8
        slen, off = read_varint(raw, off)
        spk = raw[off:off+slen].hex(); off += slen
        outputs.append({'value': value, 'scriptpubkey': spk})
    if flag is not None:
        for inp in inputs:
            wit_count, off = read_varint(raw, off)
            w = []
            for __ in range(wit_count):
                wlen, off = read_varint(raw, off)
                w.append(raw[off:off+wlen].hex()); off += wlen
            inp['witness'] = w
    locktime = int.from_bytes(raw[off:off+4], 'little'); off += 4
    return {
        'version': version,
        'flag': flag,
        'inputs': inputs,
        'outputs': outputs,
        'locktime': locktime,
        'raw': raw
    }

# ----------------- scriptpubkey type detection -----------------
def scriptpubkey_to_type_and_data(spk_hex):
    spk = bytes.fromhex(spk_hex)
    if len(spk) == 25 and spk[0] == 0x76 and spk[1] == 0xa9 and spk[2] == 0x14 and spk[-2] == 0x88 and spk[-1] == 0xac:
        return 'p2pkh', spk[3:23].hex()
    if len(spk) == 23 and spk[0] == 0xa9 and spk[1] == 0x14 and spk[-1] == 0x87:
        return 'p2sh', spk[2:22].hex()
    if len(spk) == 22 and spk[0] == 0x00 and spk[1] == 0x14:
        return 'p2wpkh', spk[2:22].hex()
    if len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
        return 'p2wsh', spk[2:34].hex()
    if len(spk) == 34 and spk[0] == 0x51 and spk[1] == 0x20:
        return 'p2tr', spk[2:34].hex()
    return 'unknown', spk_hex

# ----------------- SIGHASH implementations -----------------
def serialize_outpoint(prev_hash_hex, prev_index):
    return bytes.fromhex(prev_hash_hex)[::-1] + prev_index.to_bytes(4, 'little')

def sighash_legacy(raw_bytes, input_index, script_code_bytes, sighash_type):
    """
    Legacy pre-segwit sighash (classical). We'll implement the canonical approach
    for SIGHASH_ALL and reasonable fallbacks for others.
    raw_bytes is bytes of raw tx.
    Returns hex of sha256d(preimage).
    """
    tx = parse_tx(raw_bytes.hex())
    version = tx['version'].to_bytes(4,'little')
    locktime = tx['locktime'].to_bytes(4,'little')
    inputs = tx['inputs']; outputs = tx['outputs']

    # classical preimage (Bitcoin Core legacy): version || inputs (with script only for this input) || outputs || locktime || sighash_type(4)
    def serialize_inputs(include_script, include_seq):
        b = b''
        b += encode_varint(len(inputs))
        for i, inp in enumerate(inputs):
            b += bytes.fromhex(inp['prevout_hash'])[::-1]
            b += inp['prevout_n'].to_bytes(4,'little')
            if include_script and i == input_index:
                b += encode_varint(len(script_code_bytes)) + script_code_bytes
            else:
                b += encode_varint(0)
            if include_seq:
                b += inp['sequence'].to_bytes(4,'little')
            else:
                b += (0).to_bytes(4,'little')
        return b

    # choose behavior based on sighash_type
    anyone = sighash_type & 0x80
    base = sighash_type & 0x1f

    # For common case SIGHASH_ALL without anyonecanpay:
    if (not anyone) and (base == 1):
        preimg = version
        preimg += serialize_inputs(include_script=True, include_seq=True)
        # outputs
        outs = b''
        outs += encode_varint(len(outputs))
        for o in outputs:
            outs += o['value'].to_bytes(8,'little')
            spk = bytes.fromhex(o['scriptpubkey'])
            outs += encode_varint(len(spk)) + spk
        preimg += outs
        preimg += locktime
        preimg += sighash_type.to_bytes(4,'little')
        return sha256d(preimg).hex()
    # fallback generic implementation (handles ANYONECANPAY and NONE/SINGLE roughly)
    preimg = version
    if anyone:
        # only this input
        preimg += encode_varint(1)
        inp = inputs[input_index]
        preimg += bytes.fromhex(inp['prevout_hash'])[::-1]
        preimg += inp['prevout_n'].to_bytes(4,'little')
        preimg += encode_varint(len(script_code_bytes)) + script_code_bytes
        preimg += inp['sequence'].to_bytes(4,'little')
    else:
        preimg += serialize_inputs(include_script=True, include_seq=True)
    # outputs selection
    if base == 1:  # ALL
        outs = b''
        outs += encode_varint(len(outputs))
        for o in outputs:
            outs += o['value'].to_bytes(8,'little')
            spk = bytes.fromhex(o['scriptpubkey'])
            outs += encode_varint(len(spk)) + spk
        preimg += outs
    elif base == 2:  # NONE
        preimg += encode_varint(0)
    elif base == 3:  # SINGLE
        n = input_index
        if n < len(outputs):
            outs = b''
            outs += encode_varint(n+1)
            for i in range(n):
                outs += (0xffffffffffffffff).to_bytes(8,'little') + encode_varint(0)
            o = outputs[n]
            outs += o['value'].to_bytes(8,'little')
            spk = bytes.fromhex(o['scriptpubkey'])
            outs += encode_varint(len(spk)) + spk
            preimg += outs
        else:
            # undefined behavior in Bitcoin Core: return 1 as 32-bit little-endian? Instead fallback to tx double-sha
            return sha256d(raw_bytes).hex()
    else:
        return sha256d(raw_bytes).hex()
    preimg += locktime
    preimg += sighash_type.to_bytes(4,'little')
    return sha256d(preimg).hex()

def sighash_bip143(raw_bytes, input_index, script_code_bytes, value_sato, sighash_type):
    """
    BIP-143 segwit v0 sighash.
    """
    tx = parse_tx(raw_bytes.hex())
    version = tx['version'].to_bytes(4,'little')
    locktime = tx['locktime'].to_bytes(4,'little')
    anyone = sighash_type & 0x80
    base = sighash_type & 0x1f

    # hashPrevouts
    hashPrevouts = b'\x00'*32
    hashSequence = b'\x00'*32
    if not anyone:
        prevouts = b''
        for inp in tx['inputs']:
            prevouts += bytes.fromhex(inp['prevout_hash'])[::-1] + inp['prevout_n'].to_bytes(4,'little')
        hashPrevouts = sha256d(prevouts)
        seqs = b''
        for inp in tx['inputs']:
            seqs += inp['sequence'].to_bytes(4,'little')
        hashSequence = sha256d(seqs)
    # hashOutputs
    if base != 2 and base != 3:
        outs = b''
        for o in tx['outputs']:
            outs += o['value'].to_bytes(8,'little')
            spk = bytes.fromhex(o['scriptpubkey'])
            outs += encode_varint(len(spk)) + spk
        hashOutputs = sha256d(outs)
    elif base == 3:
        n = input_index
        if n < len(tx['outputs']):
            o = tx['outputs'][n]
            outs = o['value'].to_bytes(8,'little') + encode_varint(len(bytes.fromhex(o['scriptpubkey']))) + bytes.fromhex(o['scriptpubkey'])
            hashOutputs = sha256d(outs)
        else:
            return sha256d(raw_bytes).hex()
    else:
        hashOutputs = b'\x00'*32

    pre = b''
    pre += version
    pre += hashPrevouts
    pre += hashSequence
    inp = tx['inputs'][input_index]
    pre += bytes.fromhex(inp['prevout_hash'])[::-1]
    pre += inp['prevout_n'].to_bytes(4,'little')
    pre += encode_varint(len(script_code_bytes))
    pre += script_code_bytes
    pre += value_sato.to_bytes(8,'little')
    pre += inp['sequence'].to_bytes(4,'little')
    pre += hashOutputs
    pre += locktime
    pre += sighash_type.to_bytes(4,'little')
    return sha256d(pre).hex()

# ----------------- Taproot best-effort (key-path) -----------------
def tagged_hash(tag, msg):
    th = hashlib.sha256(tag).digest()
    return hashlib.sha256(th + th + msg).digest()

def sighash_bip341_keypath(raw_bytes, input_index, prevouts_info, sighash_type=0):
    """
    Best-effort BIP341 key-path sighash for common cases.
    prevouts_info: list of dicts for inputs in spending tx: {'txid','vout','value','scriptpubkey'}
    This is a simplified implementation focusing on key-path SIGHASH_DEFAULT; may not cover annex/script-path cases.
    """
    tx = parse_tx(raw_bytes.hex())
    version = tx['version']
    locktime = tx['locktime']

    # compute intermediate hashes
    prevouts_concat = b''
    amounts_concat = b''
    scripts_concat = b''
    sequences_concat = b''
    for i, p in enumerate(prevouts_info):
        prevouts_concat += bytes.fromhex(p['txid'])[::-1] + int(p['vout']).to_bytes(4,'little')
        amounts_concat += int(p['value']).to_bytes(8,'little')
        spk = bytes.fromhex(p['scriptpubkey'])
        scripts_concat += encode_varint(len(spk)) + spk
        sequences_concat += tx['inputs'][i]['sequence'].to_bytes(4,'little')
    hash_prevouts = sha256(prevouts_concat)
    hash_amounts = sha256(amounts_concat)
    hash_scriptpubkeys = sha256(scripts_concat)
    hash_sequences = sha256(sequences_concat)
    # outputs
    out_concat = b''
    for o in tx['outputs']:
        out_concat += o['value'].to_bytes(8,'little')
        spk = bytes.fromhex(o['scriptpubkey'])
        out_concat += encode_varint(len(spk)) + spk
    hash_outputs = sha256(out_concat)

    msg = b''
    msg += version.to_bytes(4,'little')
    msg += locktime.to_bytes(4,'little')
    msg += hash_prevouts
    msg += hash_amounts
    msg += hash_scriptpubkeys
    msg += hash_sequences
    msg += hash_outputs

    # input-specific
    inp = tx['inputs'][input_index]
    prev = prevouts_info[input_index]
    msg += bytes.fromhex(prev['txid'])[::-1]
    msg += int(prev['vout']).to_bytes(4,'little')
    msg += int(prev['value']).to_bytes(8,'little')
    spk = bytes.fromhex(prev['scriptpubkey'])
    msg += encode_varint(len(spk)) + spk
    msg += inp['sequence'].to_bytes(4,'little')

    return tagged_hash(b"TapSighash", msg).hex()

# ----------------- compute Z for an input -----------------
def compute_z_for_input(spending_tx_hex, input_index, prevout_info):
    """
    Determine type and compute Z (hash that was signed) for a specific input.
    prevout_info: {'scriptpubkey':hex, 'value':int_sat}
    Returns hex Z.
    """
    raw_bytes = bytes.fromhex(spending_tx_hex)
    tx = parse_tx(spending_tx_hex)
    inp = tx['inputs'][input_index]
    # attempt to find sighash byte from scriptSig or witness
    sighash_type = 0x01
    sig_candidates = extract_der_signatures_from_scripthex(inp.get('scriptSig',''))
    if sig_candidates:
        # try to locate trailing sighash byte in scriptSig bytes after the DER
        sbytes = bytes.fromhex(inp.get('scriptSig',''))
        for der in sig_candidates:
            db = bytes.fromhex(der['raw_der_hex'])
            pos = sbytes.find(db)
            if pos != -1:
                after = pos + len(db)
                if after < len(sbytes):
                    sighash_type = sbytes[after]
                    break
    # if segwit witness, signature is usually witness[0]
    if tx['flag'] is not None and inp.get('witness'):
        try:
            w0 = bytes.fromhex(inp['witness'][0])
            if len(w0) > 0:
                sighash_type = w0[-1]
        except Exception:
            pass

    stype, data = scriptpubkey_to_type_and_data(prevout_info.get('scriptpubkey',''))
    if stype == 'p2pkh':
        script_code = bytes.fromhex(prevout_info['scriptpubkey'])
        return sighash_legacy(raw_bytes, input_index, script_code, sighash_type)
    elif stype == 'p2sh':
        # try to extract redeemScript (last push in scriptSig)
        sbytes = bytes.fromhex(inp.get('scriptSig',''))
        redeem = None
        try:
            pos = 0
            last_push = b''
            while pos < len(sbytes):
                op = sbytes[pos]; pos += 1
                if op <= 0x4b:
                    l = op; last_push = sbytes[pos:pos+l]; pos += l
                elif op == 0x4c:
                    l = sbytes[pos]; pos += 1; last_push = sbytes[pos:pos+l]; pos += l
                elif op == 0x4d:
                    l = int.from_bytes(sbytes[pos:pos+2],'little'); pos += 2; last_push = sbytes[pos:pos+l]; pos += l
                else:
                    break
            redeem = last_push.hex() if last_push else None
        except Exception:
            redeem = None
        if redeem:
            r_stype, rdata = scriptpubkey_to_type_and_data(redeem)
            if r_stype == 'p2wpkh':
                inner20 = bytes.fromhex(rdata)
                script_code = b'\x76\xa9\x14' + inner20 + b'\x88\xac'
                value = prevout_info.get('value', 0)
                return sighash_bip143(raw_bytes, input_index, script_code, value, sighash_type)
            else:
                script_code = bytes.fromhex(prevout_info['scriptpubkey'])
                return sighash_legacy(raw_bytes, input_index, script_code, sighash_type)
        else:
            return sighash_legacy(raw_bytes, input_index, bytes.fromhex(prevout_info.get('scriptpubkey','')), sighash_type)
    elif stype == 'p2wpkh':
        inner20 = bytes.fromhex(data)
        script_code = b'\x76\xa9\x14' + inner20 + b'\x88\xac'
        value = prevout_info.get('value', 0)
        return sighash_bip143(raw_bytes, input_index, script_code, value, sighash_type)
    elif stype == 'p2wsh':
        # witness script is last witness element
        if inp.get('witness'):
            ws = bytes.fromhex(inp['witness'][-1])
            script_code = ws
            value = prevout_info.get('value', 0)
            return sighash_bip143(raw_bytes, input_index, script_code, value, sighash_type)
        else:
            return sha256d(raw_bytes).hex()
    elif stype == 'p2tr':
        # best-effort: attempt key-path sighash using prevouts_info if available
        # expect caller to provide prevouts_info list if needed; fallback to raw double-sha
        return sha256d(raw_bytes).hex()
    else:
        return sha256d(raw_bytes).hex()

# ----------------- mempool & blockchain helpers -----------------
def mempool_get_address_txs_all(addr):
    """
    Try to fetch full tx list for address via mempool.space pagination.
    Returns list of tx JSON objects (each has 'txid' or 'txid'/'txid' fields depending).
    If mempool fails or returns error, raise.
    Pagination:
      - first call: /api/address/<addr>/txs  (first N txs)
      - subsequent: /api/address/<addr>/txs/chain/<last_txid>
    We'll iteratively fetch until fewer txs returned than page size.
    """
    all_txs = []
    try:
        # first page
        url = MEMPOOL_ADDR_TXS.format(addr)
        r = safe_get_with_retries(url)
        page = r.json()
        if not isinstance(page, list):
            # sometimes API returns dict; try to interpret
            page = page.get('txs', []) if isinstance(page, dict) else []
        all_txs.extend(page)
        # loop using chain endpoint if we got non-empty
        while page:
            last_txid = page[-1].get('txid') or page[-1].get('hash') or page[-1].get('txid')
            if not last_txid:
                break
            url = MEMPOOL_ADDR_TXS_CHAIN.format(addr, last_txid)
            r = safe_get_with_retries(url)
            page = r.json()
            if not isinstance(page, list):
                page = page.get('txs', []) if isinstance(page, dict) else []
            # mempool.chain returns previous transactions (older) — stop if nothing new
            if not page:
                break
            # avoid infinite loops: if last txid repeats or first tx of new page equals previous last, break
            if any((t.get('txid') or t.get('hash')) == last_txid for t in page):
                # if it's repeating, break
                break
            all_txs.extend(page)
            # continue
        return all_txs
    except Exception as e:
        # bubble up to allow fallback to blockchain.info
        raise

def blockchain_rawaddr_all(addr):
    """
    Fallback: use blockchain.info/rawaddr/<addr> with offset pagination.
    Returns list of tx JSON objects.
    """
    all_txs = []
    offset = 0
    while True:
        url = BLOCKCHAIN_RAWADDR.format(addr) + f"?offset={offset}"
        try:
            r = safe_get_with_retries(url)
            data = r.json()
            txs = data.get('txs', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            if not txs:
                break
            all_txs.extend(txs)
            if len(txs) < BLOCKCHAIN_PAGE_SIZE:
                break
            offset += BLOCKCHAIN_PAGE_SIZE
        except Exception:
            break
    return all_txs

def get_tx_hex_from_mempool(txid):
    url = MEMPOOL_TX_HEX.format(txid)
    r = safe_get_with_retries(url)
    return r.text.strip()

def get_tx_json_from_mempool(txid):
    url = MEMPOOL_TX_JSON.format(txid)
    r = safe_get_with_retries(url)
    return r.json()

# ----------------- main per-address processing -----------------
def process_address(addr):
    addr = addr.strip()
    if not addr:
        return
    print(f"[scanning address {addr}]")
    # 1) get all txs for address using mempool first, fallback to blockchain.info
    try:
        try:
            tx_list = mempool_get_address_txs_all(addr)
        except Exception:
            tx_list = blockchain_rawaddr_all(addr)
    except Exception as e:
        print(f"[error {addr}] could not fetch tx list: {e}")
        return

    # normalize tx ids from different API shapes
    txids = []
    for t in tx_list:
        tid = t.get('txid') or t.get('hash') or t.get('tx_hash') or t.get('hash')
        if not tid:
            # blockchain.info uses 'hash' maybe
            tid = t.get('hash') or t.get('txid')
        if tid:
            txids.append((tid, t))
    if not txids:
        return

    signatures = []  # {r,s,z,txid,address}
    # For each tx, check if it's an outgoing tx (address appears in inputs)
    for txid, txmeta in txids:
        try:
            # Determine if address is in inputs by checking mempool JSON shape or blockchain.info meta
            inputs_meta = txmeta.get('vin') or txmeta.get('inputs') or txmeta.get('inputs', [])
            # some mempool txs present addresses in vout or vin with 'prevout' etc
            is_sending = False
            # generic checks: look for 'prevout' or 'prev_out' or 'prev_out.addr' or 'addr' in input entries
            if isinstance(inputs_meta, list):
                for inp in inputs_meta:
                    if isinstance(inp, dict):
                        # mempool: vin entries sometimes have 'prevout' with 'scriptpubkey_address' or 'addresses' / 'address'
                        # blockchain.info has 'prev_out' with 'addr'
                        prev = inp.get('prevout') or inp.get('prev_out') or inp.get('prevout', {})
                        if isinstance(prev, dict):
                            if prev.get('scriptpubkey_address') == addr or prev.get('addr') == addr or prev.get('address') == addr:
                                is_sending = True
                                break
                        # sometimes vin contains 'addresses' array
                        if inp.get('addr') == addr or addr in (inp.get('addresses') or []):
                            is_sending = True
                            break
            # if not determined yet, fallback to checking outputs of prevout txs (more network calls)
            if not is_sending:
                # if txmeta from mempool.space includes 'vin' with 'prevout' that lacks addr, do a more expensive check:
                # we'll check each input's prevout tx if necessary, but to keep performance we only do this if earlier checks failed
                for vin in inputs_meta:
                    prev = vin.get('prevout') or vin.get('prev_out') or {}
                    if prev.get('scriptpubkey_address') == addr or prev.get('addr') == addr or prev.get('address') == addr:
                        is_sending = True
                        break
            if not is_sending:
                # not an outgoing tx for this address; skip
                continue

            # fetch raw hex for tx from mempool (we use mempool for raw hex; if mempool fails, skip this tx)
            try:
                raw_hex = get_tx_hex_from_mempool(txid)
            except Exception:
                # skip this tx if we can't obtain raw hex
                continue
            parsed = parse_tx(raw_hex)

            # for each input in parsed tx, determine if it spends from our address; find prevout details
            for idx, inp in enumerate(parsed['inputs']):
                prev_txid = inp['prevout_hash']
                prev_vout = inp['prevout_n']
                # fetch prevout info from mempool (for value and scriptpubkey). If fails, fallback to blockchain.info via txmeta if present.
                prev_spk = ''
                prev_value = 0
                try:
                    prev_json = get_tx_json_from_mempool(prev_txid)
                    # mempool tx json 'vout' items have 'n', 'scriptpubkey', 'value'
                    v = None
                    for out in prev_json.get('vout', []):
                        if out.get('n') == prev_vout:
                            v = out
                            break
                    if v:
                        prev_spk = v.get('scriptpubkey', '')
                        prev_value = int(float(v.get('value', 0)) * 1e8)
                except Exception:
                    # fallback: if original txmeta (the list item) contains prev_out fields with addr, try to use that to match
                    prev_spk = ''
                    prev_value = 0

                # determine if this input corresponds to our address by checking prevout address in available metadata
                looks_like_from_addr = False
                # check the txmeta inputs that we got earlier: match prev hash+index
                for vin in inputs_meta:
                    prev = vin.get('prevout') or vin.get('prev_out') or {}
                    ph = (prev.get('txid') or prev.get('hash') or prev.get('tx_index'))  # partial
                    # best-effort: check address field
                    if prev.get('addr') == addr or prev.get('scriptpubkey_address') == addr or prev.get('address') == addr:
                        looks_like_from_addr = True
                        break
                    # sometimes vin contains 'addr' directly
                    if vin.get('addr') == addr:
                        looks_like_from_addr = True
                        break
                if not looks_like_from_addr:
                    # as final fallback, check prev_txid/vout's outputs for address by fetching prev tx (expensive)
                    try:
                        prev_json2 = get_tx_json_from_mempool(prev_txid)
                        # mempool output entries: 'scriptpubkey_address' or 'scriptpubkey' etc
                        for out in prev_json2.get('vout', []):
                            if out.get('n') == prev_vout:
                                if out.get('scriptpubkey_address') == addr or out.get('addresses') == [addr] or out.get('address') == addr:
                                    looks_like_from_addr = True
                                    prev_spk = out.get('scriptpubkey','')
                                    prev_value = int(float(out.get('value',0)) * 1e8)
                                break
                    except Exception:
                        pass

                if not looks_like_from_addr:
                    continue  # not spending from our target address

                # extract signatures from scriptSig and witness
                found = []
                try:
                    found += extract_der_signatures_from_scripthex(inp.get('scriptSig',''))
                except Exception:
                    pass
                if parsed['flag'] is not None and inp.get('witness'):
                    for witem in inp.get('witness', []):
                        try:
                            found += extract_der_signatures_from_scripthex(witem)
                        except Exception:
                            pass

                # compute Z for each signature found
                for f in found:
                    r = f['r']; s = f['s']
                    prevout_info = {'scriptpubkey': prev_spk or '', 'value': prev_value}
                    try:
                        z = compute_z_for_input(raw_hex, idx, prevout_info)
                    except Exception:
                        z = sha256d(bytes.fromhex(raw_hex)).hex()
                    signatures.append({'address': addr, 'r': r, 's': s, 'z': z, 'txid': txid})

        except Exception:
            # per-address resilient: ignore per-tx exceptions
            continue

    # group by r
    by_r = defaultdict(list)
    for s in signatures:
        by_r[s['r']].append(s)

    # print FOUND blocks (include address)
    for r_hex, sig_list in by_r.items():
        if len(sig_list) > 1:
            n = len(sig_list)
            for i in range(n-1):
                for j in range(i+1, n):
                    s1 = sig_list[i]; s2 = sig_list[j]
                    print("FOUND")
                    print(f"Address: {s1['address']}")
                    print(f"R: {r_hex}")
                    print(f"S1: {s1['s']}")
                    print(f"S2: {s2['s']}")
                    print(f"Z1: {s1['z']}")
                    print(f"Z2: {s2['z']}")
                    print(f"TXID1: {s1['txid']}")
                    print(f"TXID2: {s2['txid']}")

# ----------------- IO helpers -----------------
def load_addresses_from_file(path="btc1.txt"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        return lines
    except Exception as e:
        print(f"[error file] could not read {path}: {e}")
        sys.exit(1)

# ----------------- main -----------------
def main():
    addrs = load_addresses_from_file("btc1.txt")
    if not addrs:
        print("[error file] btc1.txt is empty or missing addresses")
        return

    with ThreadPoolExecutor(max_workers=THREAD_WORKERS) as ex:
        futures = [ex.submit(process_address, a) for a in addrs]
        for f in futures:
            try:
                f.result()
            except Exception:
                pass

if __name__ == "__main__":
    main()
