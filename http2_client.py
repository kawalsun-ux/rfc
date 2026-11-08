"""Minimal HTTP/2 (h2c) client (RFC 7540 subset, stdlib only)."""
import socket, time
from . import http2

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def request(host, port, method="GET", path="/", headers=None, body=b"", timeout=10):
    headers = headers or []
    s = socket.create_connection((host, port), timeout=timeout)
    s.sendall(PREFACE)
    s.sendall(http2.build_settings({http2.SETTINGS_MAX_FRAME_SIZE: 16384}))
    s.sendall(http2.build_window_update(0, 65535))
    # build request headers
    req_headers = [(":method", method), (":path", path), (":scheme", "http"), (":authority", host)]
    for k, v in headers:
        req_headers.append((k, v))
    s.sendall(http2.build_frame(http2.HEADERS, 0x4, 1, http2.hpack_encode(req_headers)))
    if body:
        s.sendall(http2.build_frame(http2.DATA, 0x1, 1, body))
    else:
        s.sendall(http2.build_frame(http2.DATA, 0x1, 1, b""))
    # read response
    buf = b""
    s.settimeout(timeout)
    try:
        while True:
            c = s.recv(4096)
            if not c:
                break
            buf += c
    except socket.timeout:
        pass
    s.close()
    # parse frames
    status = None
    resp_headers = []
    resp_body = b""
    off = 0
    while off + 9 <= len(buf):
        f = http2.parse_frame(buf[off:])
        if f is None:
            break
        if f["type"] == http2.HEADERS:
            resp_headers.extend(http2.hpack_decode(f["payload"]))
        elif f["type"] == http2.DATA:
            resp_body += f["payload"]
        off += 9 + f["length"]
        if off >= len(buf):
            break
    for k, v in resp_headers:
        if k == ":status":
            status = int(v)
    return status, dict(resp_headers), resp_body