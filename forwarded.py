"""RFC 7239 Forwarded header (stdlib only)."""
import re

def parse(header):
    # returns list of dicts with by/for/host/proto (lowercased keys)
    out = []
    # split by comma for multiple forwarded entries
    for entry in header.split(","):
        entry = entry.strip()
        if not entry:
            continue
        d = {}
        for part in entry.split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                k = k.strip().lower()
                v = v.strip().strip('"')
                d[k] = v
        out.append(d)
    return out

def build(entries):
    parts = []
    for e in entries:
        segs = []
        for k in ("by", "for", "host", "proto"):
            if k in e and e[k] is not None:
                v = e[k]
                if " " in v or ";" in v or "," in v:
                    v = '"' + v + '"'
                segs.append(f"{k}={v}")
        parts.append("; ".join(segs))
    return ", ".join(parts)