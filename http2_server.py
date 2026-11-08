"""Minimal HTTP/2 (h2c) server (RFC 7540 subset, stdlib only)."""
import socket, threading, struct
from . import http2

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

def _read_frame(conn):
    buf = b""
    while len(buf) < 9:
        c = conn.recv(9 - len(buf))
        if not c:
            return None
        buf += c
    hdr = buf
    length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
    # read payload
    payload = b""
    while len(payload) < length:
        c = conn.recv(length - len(payload))
        if not c:
            return None
        payload += c
    f = http2.parse_frame(hdr + payload)
    return f

def serve_one(conn, handler):
    # read preface
    pre = b""
    while len(pre) < len(PREFACE):
        c = conn.recv(len(PREFACE) - len(pre))
        if not c:
            return
        pre += c
    # read client settings
    f = _read_frame(conn)
    if f and f["type"] == http2.SETTINGS:
        # send settings ack
        conn.sendall(http2.build_settings({}, ack=True))
    # send our settings
    conn.sendall(http2.build_settings({http2.SETTINGS_MAX_CONCURRENT_STREAMS: 100,
                                       http2.SETTINGS_INITIAL_WINDOW_SIZE: 65535}))
    # window update for connection
    conn.sendall(http2.build_window_update(0, 65535))
    # now loop reading frames until GOAWAY or close
    while True:
        f = _read_frame(conn)
        if f is None:
            break
        if f["type"] == http2.PING:
            conn.sendall(http2.build_ping(f["payload"], ack=True))
        elif f["type"] == http2.SETTINGS:
            if not (f["flags"] & 0x1):
                conn.sendall(http2.build_settings({}, ack=True))
        elif f["type"] == http2.HEADERS:
            # decode headers
            headers = http2.hpack_decode(f["payload"])  # may include CONTINUATION; simplified
            # find path/method
            hdict = dict(headers)
            method = hdict.get(":method", "GET")
            path = hdict.get(":path", "/")
            status, body = handler(method, path, headers)
            # send response headers
            resp_headers = [(":status", str(status)), ("content-length", str(len(body)))]
            conn.sendall(http2.build_frame(http2.HEADERS, 0x4, f["stream_id"],
                                          http2.hpack_encode(resp_headers)))
            # send data with END_STREAM
            conn.sendall(http2.build_frame(http2.DATA, 0x1, f["stream_id"], body))
        elif f["type"] == http2.GOAWAY:
            break
        elif f["type"] == http2.WINDOW_UPDATE:
            pass
    try:
        conn.close()
    except Exception:
        pass

class Http2Server:
    def __init__(self, host="127.0.0.1", port=0, handler=None):
        self.host = host
        self.port = port
        self.handler = handler or (lambda m, p, h: (200, b"ok"))
        self.sock = None
        self.thread = None
        self._stop = False

    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.host, self.port = self.sock.getsockname()
        self.sock.listen(16)
        self.sock.settimeout(0.5)
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return self

    def _loop(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=serve_one, args=(conn, self.handler), daemon=True).start()

    def stop(self):
        self._stop = True
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=2)