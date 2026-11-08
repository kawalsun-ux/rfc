"""RFC 7541 Appendix B Huffman (zero-dep, stdlib only)."""
import json, os

_LENGTHS = json.load(open(os.path.join(os.path.dirname(__file__), 'huff_lengths.json'))) if os.path.exists(os.path.join(os.path.dirname(__file__), 'huff_lengths.json')) else None

# Fallback: load from /tmp if not present
if _LENGTHS is None:
    try:
        _LENGTHS = json.load(open('/tmp/opencode/huff_lengths.json'))
    except Exception:
        _LENGTHS = [0]*257

# Build canonical Huffman codes from lengths
def _build_codes(lengths):
    # lengths: list of (symbol, length)
    # canonical: sort by length then symbol
    items = sorted([(l, s) for s, l in enumerate(lengths) if l > 0])
    codes = {}
    code = 0
    prev_len = 0
    for l, s in items:
        if l > prev_len:
            code <<= (l - prev_len)
        codes[s] = (code, l)
        code += 1
        prev_len = l
    return codes

_CODES = _build_codes(_LENGTHS)  # symbol -> (code int, bitlen)
# Reverse: bitlen -> {code: symbol}
_REV = {}
for s, (code, bl) in _CODES.items():
    _REV.setdefault(bl, {})[code] = s

def encode(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    bits = 0
    nbits = 0
    out = bytearray()
    for byte in data:
        code, bl = _CODES[byte]
        # append code (bl bits) to bitstream
        bits = (bits << bl) | code
        nbits += bl
        while nbits >= 8:
            nbits -= 8
            out.append((bits >> nbits) & 0xFF)
    # EOS padding
    if nbits > 0:
        eos_code, eos_len = _CODES[256]
        # append EOS bits, then pad with 1s (MSB) up to byte boundary
        bits = (bits << eos_len) | eos_code
        nbits += eos_len
        # pad with ones
        pad_len = (8 - (nbits % 8)) % 8
        if pad_len:
            bits = (bits << pad_len) | ((1 << pad_len) - 1)
            nbits += pad_len
        # flush
        while nbits >= 8:
            nbits -= 8
            out.append((bits >> nbits) & 0xFF)
    return bytes(out)

def decode(data):
    # returns (string, consumed_ok)
    bits = 0
    nbits = 0
    # build bitstream
    bitstream = []
    for byte in data:
        for i in range(7, -1, -1):
            bitstream.append((byte >> i) & 1)
    # decode
    out = bytearray()
    i = 0
    total = len(bitstream)
    # We'll walk bits
    node_code = 0
    node_len = 0
    pos = 0
    # use canonical decode: try all lengths
    while pos < total:
        # try to match
        matched = False
        for bl in range(1, 31):
            if pos + bl > total:
                break
            # read bl bits
            val = 0
            for k in range(bl):
                val = (val << 1) | bitstream[pos + k]
            # check if val (left-aligned? code stored MSB) matches
            # codes are stored as integers; compare val to code with same length
            # find symbol
            sym = None
            for s, (code, length) in _CODES.items():
                if length == bl and code == val:
                    sym = s
                    break
            if sym is not None:
                if sym == 256:
                    # EOS -> end
                    return out.decode('utf-8', errors='replace')
                out.append(sym)
                pos += bl
                matched = True
                break
        if not matched:
            # padding or error; stop
            break
    return out.decode('utf-8', errors='replace')