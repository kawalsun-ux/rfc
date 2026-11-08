"""RFC 3986 URI parser (stdlib only)."""
import re

# RFC 3986 ABNF (simplified)
_URI_RE = re.compile(
    r"^(?:(?P<scheme>[A-Za-z][A-Za-z0-9+.\-]*)://)?"
    r"(?:(?P<userinfo>[^@/?#]*)@)?"
    r"(?P<host>[^/?#:]*)"
    r"(?::(?P<port>\d+))?"
    r"(?P<path>/[^?#]*)?"
    r"(?:\?(?P<query>[^#]*))?"
    r"(?:#(?P<fragment>.*))?$"
)

def parse(uri):
    m = _URI_RE.match(uri)
    if not m:
        return None
    d = m.groupdict()
    # percent-decode helper
    def pctdec(s):
        if s is None:
            return None
        return _pct_decode(s)
    return {
        "scheme": d["scheme"],
        "userinfo": pctdec(d["userinfo"]) if d["userinfo"] else None,
        "host": d["host"] or None,
        "port": int(d["port"]) if d["port"] else None,
        "path": pctdec(d["path"]) if d["path"] else ("" if d["host"] is not None else d["path"]),
        "query": d["query"],
        "fragment": pctdec(d["fragment"]) if d["fragment"] else None,
        "raw": uri,
    }

def _pct_decode(s):
    def repl(m):
        return chr(int(m.group(1), 16))
    # handle %XX
    out = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)
    return out

def build(parts):
    out = ""
    if parts.get("scheme"):
        out += parts["scheme"] + "://"
    if parts.get("userinfo"):
        out += _pct_encode(parts["userinfo"]) + "@"
    if parts.get("host"):
        out += parts["host"]
    if parts.get("port"):
        out += ":" + str(parts["port"])
    if parts.get("path"):
        out += parts["path"]
    if parts.get("query") is not None:
        out += "?" + parts["query"]
    if parts.get("fragment") is not None:
        out += "#" + parts["fragment"]
    return out

_PCT_UNRESERVED = re.compile(r"[A-Za-z0-9\-_.~]")

def _pct_encode(s):
    out = []
    for ch in s:
        if _PCT_UNRESERVED.match(ch):
            out.append(ch)
        else:
            for b in ch.encode("utf-8"):
                out.append(f"%{b:02X}")
    return "".join(out)