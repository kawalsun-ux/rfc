"""RFC 7230-7235 HTTP/1.1 (minimal server + client, stdlib only)."""
import socket, threading, time

CRLF = b"\r\n"

def parse_request(data):
    # returns (method, target, version, headers dict, body bytes)
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.split(b"\r\n")
    request_line = lines[0].decode("latin-1")
    parts = request_line.split(" ", 2)
    method, target, version = (parts + ["", ""])[:3]
    headers = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().decode("latin-1").lower()] = v.strip().decode("latin-1")
    return method, target, version, headers, body

def build_response(status, reason, headers=None, body=b""):
    headers = headers or {}
    if "content-length" not in {k.lower() for k in headers}:
        headers["Content-Length"] = str(len(body))
    if "connection" not in {k.lower() for k in headers}:
        headers["Connection"] = "close"
    lines = [f"HTTP/1.1 {status} {reason}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    head = "\r\n".join(lines).encode() + b"\r\n\r\n"
    return head + (body if isinstance(body, (bytes, bytearray)) else body.encode())

class HttpServer:
    def __init__(self, host="127.0.0.1", port=0, handler=None):
        self.host = host
        self.port = port
        self.handler = handler or (lambda req: (200, "OK", {}, b""))
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
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            data = b""
            conn.settimeout(5)
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
                if len(data) > 65536:
                    break
            if not data:
                return
            method, target, version, headers, body = parse_request(data)
            # read body if content-length
            cl = int(headers.get("content-length", "0") or 0)
            while len(body) < cl:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                body += chunk
            status, reason, h, b = self.handler({"method": method, "target": target,
                                                  "version": version, "headers": headers,
                                                  "body": body})
            resp = build_response(status, reason, h, b)
            conn.sendall(resp)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def stop(self):
        self._stop = True
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        if self.thread:
            self.thread.join(timeout=2)

def http_get(url, timeout=10):
    # url: http://host:port/path
    import urllib.parse
    u = urllib.parse.urlsplit(url)
    host = u.hostname
    port = u.port or 80
    path = u.path or "/"
    if u.query:
        path += "?" + u.query
    s = socket.create_connection((host, port), timeout=timeout)
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    s.sendall(req.encode())
    data = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
        data += c
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    status_line = head.split(b"\r\n", 1)[0].decode("latin-1")
    parts = status_line.split(" ", 2)
    status = int(parts[1]) if len(parts) > 1 else 0
    reason = parts[2] if len(parts) > 2 else ""
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().decode("latin-1").lower()] = v.strip().decode("latin-1")
    return status, reason, headers, body