# Zero-Dependency RFC Implementations (stdlib only)

| RFC | Topic | Module | Notes |
|-----|-------|--------|-------|
| 3986 | URI | `uri.py` | parse/build, percent-encode/decode |
| 7230-7235 | HTTP/1.1 | `http11.py` | server + client, request/response parse |
| 6455 | WebSocket | `websocket.py` | handshake, frame encode/decode |
| 1035 | DNS | `dns.py` | UDP query, A/AAAA/MX/TXT/CNAME |
| 7239 | Forwarded | `forwarded.py` | parse/build Forwarded header |
| 9110 | HTTP Semantics | `http_semantics.py` | status codes, methods, content negotiation |
| 7692 | WS Compression | `ws_compress.py` + `websocket.py` | per-message deflate + integrated helpers |
| 7233 | Range requests | `http_semantics.py` | parse_range, content_range, partial_body |
| 7540 | HTTP/2 | `http2.py` | frame layer + basic HPACK |
| 8259 | JSON | (stdlib `json`) | — |
| 4648 | Base64 | (stdlib `base64`) | — |
| 2045-2049 | MIME | (stdlib `email`) | — |
| 5321 | SMTP | (stdlib `smtplib`) | — |
| 7231 | HTTP semantics | (stdlib `http`) | — |

## Usage
```python
from rfc import uri, http11, websocket, dns
print(uri.parse("https://example.com:8080/a?b=1#frag"))
srv = http11.HttpServer(port=8080, handler=lambda r: (200, "OK", {}, b"hi"))
srv.start()
print(http11.http_get("http://127.0.0.1:8080/"))
print(dns.query("example.com"))
```