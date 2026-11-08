"""RFC 6455 WebSocket (handshake + framing, stdlib only)."""
import base64, hashlib, struct, socket

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

def handshake_accept(key):
    return base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()

def parse_handshake_request(data):
    lines = data.split(b"\r\n")
    # request line
    method, path, version = lines[0].decode("latin-1").split(" ", 2)
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().decode("latin-1").lower()] = v.strip().decode("latin-1")
    return method, path, version, headers

def build_handshake_response(key):
    accept = handshake_accept(key)
    return ("HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n"
            "\r\n").encode()

# Frame opcodes
OP_CONT = 0x0; OP_TEXT = 0x1; OP_BINARY = 0x2
OP_CLOSE = 0x8; OP_PING = 0x9; OP_PONG = 0xA

def _encode_frame(opcode, payload, mask=False):
    if isinstance(payload, str):
        payload = payload.encode()
    b = bytearray()
    b.append(0x80 | opcode)  # FIN=1
    length = len(payload)
    if length < 126:
        b.append((0x80 if mask else 0) | length)
    elif length < 65536:
        b.append((0x80 if mask else 0) | 126)
        b.extend(struct.pack("!H", length))
    else:
        b.append((0x80 if mask else 0) | 127)
        b.extend(struct.pack("!Q", length))
    if mask:
        import os
        key = os.urandom(4)
        b.extend(key)
        masked = bytes(payload[i] ^ key[i % 4] for i in range(len(payload)))
        b.extend(masked)
    else:
        b.extend(payload)
    return bytes(b)

def encode_text(payload, mask=False):
    return _encode_frame(OP_TEXT, payload, mask)

def encode_binary(payload, mask=False):
    return _encode_frame(OP_BINARY, payload, mask)

def encode_close(code=1000, reason="", mask=False):
    payload = struct.pack("!H", code) + reason.encode()
    return _encode_frame(OP_CLOSE, payload, mask)

def encode_ping(payload=b"", mask=False):
    return _encode_frame(OP_PING, payload, mask)

def decode_frame(data):
    # returns (opcode, payload_bytes, consumed_bytes, fin)
    if len(data) < 2:
        return None
    b0 = data[0]; b1 = data[1]
    fin = bool(b0 & 0x80)
    opcode = b0 & 0x0F
    masked = bool(b1 & 0x80)
    length = b1 & 0x7F
    idx = 2
    if length == 126:
        if len(data) < 4:
            return None
        length = struct.unpack("!H", data[2:4])[0]
        idx = 4
    elif length == 127:
        if len(data) < 10:
            return None
        length = struct.unpack("!Q", data[2:10])[0]
        idx = 10
    if masked:
        if len(data) < idx + 4:
            return None
        key = data[idx:idx+4]
        idx += 4
    if len(data) < idx + length:
        return None
    payload = data[idx:idx+length]
    if masked:
        payload = bytes(payload[i] ^ key[i % 4] for i in range(len(payload)))
    return opcode, payload, idx + length, fin

def parse_extensions(header):
    out = []
    if not header:
        return out
    for part in header.split(","):
        part = part.strip()
        if not part:
            continue
        if ";" in part:
            name, rest = part.split(";", 1)
            name = name.strip()
            params = {}
            for p in rest.split(";"):
                p = p.strip()
                if "=" in p:
                    k, v = p.split("=", 1)
                    params[k.strip()] = v.strip().strip('"')
                elif p:
                    params[p] = True
        else:
            name = part.strip()
            params = {}
        out.append((name, params))
    return out

def build_extensions(extensions):
    parts = []
    for name, params in extensions:
        segs = [name]
        for k, v in (params or {}).items():
            if v is True:
                segs.append(k)
            else:
                segs.append(f"{k}={v}")
        parts.append("; ".join(segs))
    return ", ".join(parts)

def offer_permessage_deflate(server_no_context_takeover=False, client_no_context_takeover=False):
    params = {}
    if server_no_context_takeover:
        params["server_no_context_takeover"] = True
    if client_no_context_takeover:
        params["client_no_context_takeover"] = True
    return [("permessage-deflate", params)]


# --- RFC 7692 integrated compression helpers ---
try:
    from . import ws_compress as _wsc
except Exception:
    try:
        import ws_compress as _wsc
    except Exception:
        _wsc = None

def compress_message(payload, reset=False):
    if _wsc is None:
        return payload.encode() if isinstance(payload, str) else payload
    b = payload.encode() if isinstance(payload, str) else payload
    # stateless (no context takeover) by default
    return _wsc.compress(b)

def decompress_message(data, reset=False):
    if _wsc is None:
        return data
    return _wsc.decompress(data)


# --- RFC 7692 negotiation helper ---
def negotiate_extensions(client_header, server_prefs=None):
    parsed = parse_extensions(client_header)
    negotiated = []
    for name, params in parsed:
        if name.lower() == "permessage-deflate":
            sp = {}
            if server_prefs:
                sp.update(server_prefs)
            if "client_max_window_bits" in params:
                sp["client_max_window_bits"] = params["client_max_window_bits"]
            negotiated.append(("permessage-deflate", sp))
    return negotiated
