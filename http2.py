"""RFC 7540 HTTP/2 (frame layer + basic HPACK, stdlib only)."""
import struct
try:
    from . import huffman as _huffman
except Exception:
    try:
        import huffman as _huffman
    except Exception:
        _huffman = None

# Frame types
DATA = 0x0; HEADERS = 0x1; PRIORITY = 0x2; RST_STREAM = 0x3
SETTINGS = 0x4; PUSH_PROMISE = 0x5; PING = 0x6; GOAWAY = 0x7
WINDOW_UPDATE = 0x8; CONTINUATION = 0x9

# Settings
SETTINGS_HEADER_TABLE_SIZE = 0x1
SETTINGS_ENABLE_PUSH = 0x2
SETTINGS_MAX_CONCURRENT_STREAMS = 0x3
SETTINGS_INITIAL_WINDOW_SIZE = 0x4
SETTINGS_MAX_FRAME_SIZE = 0x5
SETTINGS_MAX_HEADER_LIST_SIZE = 0x6

def build_frame(ftype, flags, stream_id, payload=b""):
    assert len(payload) < (1 << 24)
    header = struct.pack("!I", len(payload))[1:] + bytes([ftype, flags]) + struct.pack("!I", stream_id & 0x7FFFFFFF)
    return header + (payload if isinstance(payload, (bytes, bytearray)) else payload.encode())

def parse_frame(data):
    if len(data) < 9:
        return None
    length = (data[0] << 16) | (data[1] << 8) | data[2]
    ftype = data[3]
    flags = data[4]
    stream_id = struct.unpack("!I", data[5:9])[0] & 0x7FFFFFFF
    payload = data[9:9+length]
    return {"type": ftype, "flags": flags, "stream_id": stream_id, "payload": payload, "length": length}

def build_settings(settings, ack=False):
    payload = b""
    for k, v in settings.items():
        payload += struct.pack("!HI", k, v)
    flags = 0x1 if ack else 0
    return build_frame(SETTINGS, flags, 0, payload)

def parse_settings(payload):
    out = {}
    for i in range(0, len(payload), 6):
        k, v = struct.unpack("!HI", payload[i:i+6])
        out[k] = v
    return out

def build_ping(data=b"\x00"*8, ack=False):
    flags = 0x1 if ack else 0
    return build_frame(PING, flags, 0, data)

def build_goaway(last_stream_id, error_code=0, debug=b""):
    payload = struct.pack("!II", last_stream_id & 0x7FFFFFFF, error_code) + debug
    return build_frame(GOAWAY, 0, 0, payload)

def build_window_update(stream_id, increment):
    return build_frame(WINDOW_UPDATE, 0, stream_id, struct.pack("!I", increment & 0x7FFFFFFF))

def build_rst_stream(stream_id, error_code=0):
    return build_frame(RST_STREAM, 0, stream_id, struct.pack("!I", error_code))

# --- HPACK (minimal: static table + literal without indexing) ---
# Static table (RFC 7541 Appendix A) - subset of common headers
STATIC_TABLE = [
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
]

def hpack_encode(headers, dynamic_table=None):
    # headers: list of (name, value). Returns bytes using literal without indexing (0x00 prefix + name + value)
    # plus static table indexing where exact match.
    out = bytearray()
    for name, value in headers:
        # try static table exact match
        idx = None
        for i, (n, v) in enumerate(STATIC_TABLE, start=1):
            if n == name and v == value:
                idx = i
                break
        if idx is not None:
            # indexed header field (1xxxxxxx)
            out.append(0x80 | (idx & 0x7F) if idx < 128 else 0x80)
            # handle idx >= 128 via continuation (simplified: only first 127)
            if idx >= 128:
                # fallback to literal
                idx = None
        if idx is None or idx >= 128:
            # literal without indexing (0x00)
            out.append(0x00)
            # name
            out.extend(_encode_string(name, huffman=True))
            out.extend(_encode_string(value, huffman=True))
    return bytes(out)

def _encode_string(s, huffman=False):
    if huffman and _huffman is not None:
        b = _huffman.encode(s)
        prefix = 0x80
    else:
        b = s.encode() if isinstance(s, str) else s
        prefix = 0x00
    if len(b) < 127:
        return bytes([prefix | len(b)]) + (b if isinstance(b, (bytes, bytearray)) else b.encode())
    out = bytearray([prefix | 127])
    length = len(b)
    while True:
        byte = length & 0x7F
        length >>= 7
        if length:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    out.extend(b if isinstance(b, (bytes, bytearray)) else b.encode())
    return bytes(out)

def _decode_string(data, i):
    if i >= len(data):
        return "", i
    first = data[i]
    huffman = bool(first & 0x80)
    length = first & 0x7F
    i += 1
    if length == 127:
        length = 0
        while True:
            b = data[i]
            length = (length << 7) | (b & 0x7F)
            i += 1
            if not (b & 0x80):
                break
    raw = data[i:i+length]
    i += length
    if huffman and _huffman is not None:
        return _huffman.decode(raw), i
    return raw.decode("utf-8", errors="replace"), i


def hpack_decode(data, dynamic_table=None):
    headers = []
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b & 0x80:
            idx = b & 0x7F
            i += 1
            if idx == 127:
                idx = 0
                while True:
                    bb = data[i]
                    idx = (idx << 7) | (bb & 0x7F)
                    i += 1
                    if not (bb & 0x80):
                        break
            if 1 <= idx <= len(STATIC_TABLE):
                name, value = STATIC_TABLE[idx-1]
                headers.append((name, value))
            else:
                headers.append(("unknown", ""))
        elif (b & 0xF0) == 0x40:
            i += 1
            name, i = _decode_string(data, i)
            value, i = _decode_string(data, i)
            headers.append((name, value))
        elif (b & 0xF0) == 0x00:
            prefix = b & 0x0F
            i += 1
            if prefix == 0:
                name, i = _decode_string(data, i)
            else:
                name = STATIC_TABLE[prefix-1][0] if 1 <= prefix <= len(STATIC_TABLE) else ""
            value, i = _decode_string(data, i)
            headers.append((name, value))
        elif (b & 0xE0) == 0x20:
            i += 1
        else:
            i += 1
    return headers
