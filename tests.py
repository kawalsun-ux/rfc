import sys, os, unittest, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from rfc import uri, http11, websocket, dns, forwarded, http_semantics, ws_compress, http2, http2_server, http2_client

class TestURI(unittest.TestCase):
    def test_parse(self):
        u = uri.parse("https://example.com:8080/a?b=1#frag")
        self.assertEqual(u["scheme"], "https")
        self.assertEqual(u["host"], "example.com")
        self.assertEqual(u["port"], 8080)
        self.assertEqual(u["path"], "/a")
        self.assertEqual(u["query"], "b=1")
        self.assertEqual(u["fragment"], "frag")

class TestHTTP(unittest.TestCase):
    def test_roundtrip(self):
        srv = http11.HttpServer(port=0, handler=lambda r: (200, "OK", {}, b"hi")).start()
        time.sleep(0.2)
        status, reason, headers, body = http11.http_get(f"http://127.0.0.1:{srv.port}/")
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hi")
        srv.stop()

class TestWS(unittest.TestCase):
    def test_handshake(self):
        key = "dGhlIHNhbXBsZSBub25jZQ=="
        self.assertEqual(websocket.handshake_accept(key), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")
    def test_frame_roundtrip(self):
        frame = websocket.encode_text("hello", mask=True)
        op, payload, consumed, fin = websocket.decode_frame(frame)
        self.assertEqual(op, 1)
        self.assertEqual(payload, b"hello")
        self.assertTrue(fin)

class TestDNS(unittest.TestCase):
    def test_query(self):
        r = dns.query("example.com")
        self.assertTrue(len(r["answers"]) > 0)

class TestForwarded(unittest.TestCase):
    def test_parse_build(self):
        h = 'for=192.0.2.60;proto=http;by=203.0.113.43'
        parsed = forwarded.parse(h)
        self.assertEqual(parsed[0]["for"], "192.0.2.60")
        self.assertEqual(parsed[0]["proto"], "http")
        rebuilt = forwarded.build(parsed)
        self.assertIn("for=192.0.2.60", rebuilt)

class TestHTTPSemantics(unittest.TestCase):
    def test_status(self):
        self.assertEqual(http_semantics.reason_phrase(404), "Not Found")
    def test_negotiate(self):
        r = http_semantics.content_negotiate("text/html, application/json;q=0.9", ["application/json", "text/html"])
        self.assertEqual(r, "text/html")

class TestWSCompress(unittest.TestCase):
    def test_roundtrip(self):
        data = b"hello world " * 10
        c = ws_compress.compress(data)
        self.assertEqual(ws_compress.decompress(c), data)

class TestHTTP2(unittest.TestCase):
    def test_frame_roundtrip(self):
        f = http2.build_frame(http2.DATA, 0, 1, b"hi")
        p = http2.parse_frame(f)
        self.assertEqual(p["type"], http2.DATA)
        self.assertEqual(p["stream_id"], 1)
        self.assertEqual(p["payload"], b"hi")
    def test_settings(self):
        f = http2.build_settings({http2.SETTINGS_MAX_FRAME_SIZE: 16384})
        s = http2.parse_settings(f[9:])
        self.assertEqual(s[http2.SETTINGS_MAX_FRAME_SIZE], 16384)
    def test_hpack(self):
        data = http2.hpack_encode([(":method", "GET"), (":path", "/")])
        hdrs = http2.hpack_decode(data)
        self.assertTrue(len(hdrs) >= 1)

class TestForwardedExt(unittest.TestCase):
    def test_build_parse(self):
        e = [{"for": "192.0.2.60", "proto": "http"}]
        h = forwarded.build(e)
        self.assertIn("for=192.0.2.60", h)
        p = forwarded.parse(h)
        self.assertEqual(p[0]["for"], "192.0.2.60")

class TestWSExtensions(unittest.TestCase):
    def test_parse_build(self):
        h = "permessage-deflate; client_max_window_bits"
        parsed = websocket.parse_extensions(h)
        self.assertEqual(parsed[0][0], "permessage-deflate")
        rebuilt = websocket.build_extensions(parsed)
        self.assertIn("permessage-deflate", rebuilt)

class TestHuffman(unittest.TestCase):
    def test_roundtrip(self):
        from rfc import huffman as _h
        s = "hello world"
        enc = _h.encode(s)
        dec = _h.decode(enc)
        self.assertEqual(dec, s)

class TestCond(unittest.TestCase):
    def test_none_match(self):
        self.assertFalse(http_semantics.eval_conditional({"if-none-match": '"abc"'}, etag='"abc"'))
        self.assertTrue(http_semantics.eval_conditional({"if-none-match": '"xyz"'}, etag='"abc"'))

class TestRange(unittest.TestCase):
    def test_parse(self):
        r = http_semantics.parse_range("bytes=0-9", 100)
        self.assertEqual(r, [(0, 9)])
    def test_suffix(self):
        r = http_semantics.parse_range("bytes=-10", 100)
        self.assertEqual(r, [(90, 99)])
    def test_content_range(self):
        self.assertEqual(http_semantics.content_range(0, 9, 100), "bytes 0-9/100")

class TestWSCompressInteg(unittest.TestCase):
    def test_compress_decompress(self):
        from rfc import websocket
        msg = "hello world " * 5
        c = websocket.compress_message(msg)
        d = websocket.decompress_message(c)
        self.assertEqual(d, msg.encode())

class TestHTTP2Server(unittest.TestCase):
    def test_request(self):
        import time, socket
        def handler(m, p, h):
            return 200, b"hello h2"
        srv = http2_server.Http2Server(port=0, handler=handler).start()
        time.sleep(0.5)
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        s.sendall(http2.build_settings({http2.SETTINGS_MAX_FRAME_SIZE: 16384}))
        s.sendall(http2.build_window_update(0, 65535))
        hdrs = [(":method", "GET"), (":path", "/"), (":scheme", "http"), (":authority", "localhost")]
        s.sendall(http2.build_frame(http2.HEADERS, 0x4, 1, http2.hpack_encode(hdrs)))
        s.sendall(http2.build_window_update(1, 65535))
        buf = b""; s.settimeout(2)
        try:
            while True:
                c = s.recv(4096)
                if not c: break
                buf += c
        except socket.timeout:
            pass
        s.close(); srv.stop()
        self.assertIn(b"hello h2", buf)

class TestRangeExt(unittest.TestCase):
    def test_partial_body(self):
        data = b"0123456789"
        r = http_semantics.parse_range("bytes=0-4", 10)
        self.assertEqual(r, [(0, 4)])
        kind, body = http_semantics.partial_body(data, r)
        self.assertEqual(kind, "single")
        self.assertEqual(body, b"01234")

class TestMethodProps(unittest.TestCase):
    def test_safe(self):
        self.assertTrue(http_semantics.method_props("GET")["safe"])
        self.assertTrue(http_semantics.method_props("PUT")["idempotent"])
        self.assertFalse(http_semantics.method_props("POST")["idempotent"])

class TestCacheControl(unittest.TestCase):
    def test_parse(self):
        cc = http_semantics.parse_cache_control("max-age=3600, no-cache")
        self.assertEqual(cc["max-age"], "3600")
        self.assertTrue(cc["no-cache"])

class TestNegotiateExt(unittest.TestCase):
    def test_neg(self):
        h = "permessage-deflate; client_max_window_bits=15"
        n = websocket.negotiate_extensions(h)
        self.assertEqual(n[0][0], "permessage-deflate")

class TestHTTP2Client(unittest.TestCase):
    def test_request(self):
        def handler(m, p, h):
            return 200, b"hello client"
        srv = http2_server.Http2Server(port=0, handler=handler).start()
        import time; time.sleep(0.5)
        status, hdrs, body = http2_client.request("127.0.0.1", srv.port, "GET", "/")
        srv.stop()
        self.assertEqual(status, 200)
        self.assertEqual(body, b"hello client")

class TestValidateCache(unittest.TestCase):
    def test_none_match(self):
        self.assertTrue(http_semantics.validate_cache({"if-none-match": '"abc"'}, {"etag": '"abc"'}, 200))
        self.assertFalse(http_semantics.validate_cache({"if-none-match": '"xyz"'}, {"etag": '"abc"'}, 200))

class TestWSContextTakeover(unittest.TestCase):
    def test_compressor(self):
        from rfc import ws_compress
        c = ws_compress.Compressor()
        d = ws_compress.Decompressor()
        m1 = "hello world " * 5
        enc1 = c.compress(m1)
        dec1 = d.decompress(enc1)
        self.assertEqual(dec1, m1.encode())
        m2 = "second message"
        enc2 = c.compress(m2)  # context takeover (no reset)
        dec2 = d.decompress(enc2)
        self.assertEqual(dec2, m2.encode())

if __name__ == "__main__":
    unittest.main()