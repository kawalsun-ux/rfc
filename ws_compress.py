"""RFC 7692 WebSocket per-message deflate (stdlib zlib)."""
import zlib

class Compressor:
    """Stateful compressor supporting context takeover."""
    def __init__(self, wbits=-15, level=9):
        self.wbits = wbits
        self.level = level
        self._co = zlib.compressobj(level=level, method=zlib.DEFLATED, wbits=wbits)
        self._first = True

    def compress(self, payload, reset=False):
        if reset or self._first:
            self._co = zlib.compressobj(level=self.level, method=zlib.DEFLATED, wbits=self.wbits)
            self._first = False
        data = payload.encode() if isinstance(payload, str) else payload
        out = self._co.compress(data) + self._co.flush(zlib.Z_SYNC_FLUSH)
        # strip trailing 0x00 0x00 0xff 0xff if present (deflate trailer)
        if out.endswith(b"\x00\x00\xff\xff"):
            out = out[:-4]
        return out

    def reset(self):
        self._co = zlib.compressobj(level=self.level, method=zlib.DEFLATED, wbits=self.wbits)
        self._first = True

class Decompressor:
    def __init__(self, wbits=-15):
        self.wbits = wbits
        self._do = zlib.decompressobj(wbits=wbits)
        self._first = True

    def decompress(self, data, reset=False):
        if reset or self._first:
            self._do = zlib.decompressobj(wbits=self.wbits)
            self._first = False
        # re-add trailer
        d = data + b"\x00\x00\xff\xff"
        return self._do.decompress(d)

    def reset(self):
        self._do = zlib.decompressobj(wbits=self.wbits)
        self._first = True

def compress(payload, wbits=-15):
    co = zlib.compressobj(level=9, method=zlib.DEFLATED, wbits=wbits)
    out = co.compress(payload if not isinstance(payload, str) else payload.encode()) + co.flush(zlib.Z_SYNC_FLUSH)
    if out.endswith(b"\x00\x00\xff\xff"):
        out = out[:-4]
    return out

def decompress(data, wbits=-15):
    do = zlib.decompressobj(wbits=wbits)
    return do.decompress(data + b"\x00\x00\xff\xff")

def negotiate(extensions_header):
    if not extensions_header:
        return False
    return "permessage-deflate" in extensions_header.lower()