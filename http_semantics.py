"""RFC 9110 HTTP Semantics (helpers, stdlib only)."""
# Status codes (RFC 9110 section 15)
STATUS = {
    100: "Continue", 101: "Switching Protocols", 200: "OK", 201: "Created",
    202: "Accepted", 204: "No Content", 206: "Partial Content",
    301: "Moved Permanently", 302: "Found", 303: "See Other", 304: "Not Modified",
    307: "Temporary Redirect", 308: "Permanent Redirect",
    400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
    405: "Method Not Allowed", 408: "Request Timeout", 409: "Conflict",
    410: "Gone", 413: "Content Too Large", 414: "URI Too Long",
    415: "Unsupported Media Type", 429: "Too Many Requests",
    500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}

METHODS = {"GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"}

SAFE_METHODS = {"GET", "HEAD", "OPTIONS", "TRACE"}
IDEMPOTENT_METHODS = {"GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"}

def reason_phrase(code):
    return STATUS.get(code, "Unknown")

def is_safe(method):
    return method.upper() in SAFE_METHODS

def is_idempotent(method):
    return method.upper() in IDEMPOTENT_METHODS

def eval_conditional(headers, last_modified=None, etag=None):
    # returns True if request should proceed (304 not applicable / condition met)
    # If-None-Match
    inm = headers.get("if-none-match")
    if inm and etag and inm.strip() == etag:
        return False  # 304 Not Modified
    if inm and inm.strip() == "*":
        return False
    # If-Match
    im = headers.get("if-match")
    if im and etag and im.strip() not in ("*", etag):
        return False  # 412 Precondition Failed
    # If-Modified-Since
    ims = headers.get("if-modified-since")
    if ims and last_modified:
        # simple string compare fallback
        if ims.strip() == last_modified.strip():
            return False
    # If-Unmodified-Since
    ius = headers.get("if-unmodified-since")
    if ius and last_modified and ius.strip() != last_modified.strip():
        return False
    return True

def parse_range(header, size):
    # returns list of (start, end) inclusive or None
    if not header or not header.lower().startswith("bytes="):
        return None
    spec = header[6:].strip()
    if spec == "*":
        return None
    out = []
    for part in spec.split(","):
        part = part.strip()
        if "-" not in part:
            return None
        a, b = part.split("-", 1)
        if a == "":
            # suffix range
            if not b:
                return None
            suffix = int(b)
            start = max(0, size - suffix)
            end = size - 1
        else:
            start = int(a)
            if b == "":
                end = size - 1
            else:
                end = int(b)
        if start < 0 or end >= size or start > end:
            return None
        out.append((start, end))
    return out

def content_range(start, end, size):
    return f"bytes {start}-{end}/{size}"

def partial_body(data, ranges):
    # data: bytes; ranges: list of (start,end); returns (content_type_suffix, body_bytes)
    if not ranges:
        return None
    if len(ranges) == 1:
        s, e = ranges[0]
        return "single", data[s:e+1]
    # multipart
    boundary = "BOUNDARY"
    parts = []
    for s, e in ranges:
        parts.append(f"--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-Range: bytes {s}-{e}/{len(data)}\r\n\r\n".encode() + data[s:e+1] + b"\r\n")
    body = b"".join(parts) + f"--{boundary}--\r\n".encode()
    return "multipart", body

# RFC 7231 method properties
METHOD_PROPS = {
    "GET":     {"safe": True,  "idempotent": True,  "cacheable": True},
    "HEAD":    {"safe": True,  "idempotent": True,  "cacheable": True},
    "POST":    {"safe": False, "idempotent": False, "cacheable": False},
    "PUT":     {"safe": False, "idempotent": True,  "cacheable": False},
    "DELETE":  {"safe": False, "idempotent": True,  "cacheable": False},
    "CONNECT": {"safe": False, "idempotent": False, "cacheable": False},
    "OPTIONS": {"safe": True,  "idempotent": True,  "cacheable": False},
    "TRACE":   {"safe": True,  "idempotent": True,  "cacheable": False},
    "PATCH":   {"safe": False, "idempotent": False, "cacheable": False},
}

def method_props(method):
    return METHOD_PROPS.get(method.upper(), {"safe": False, "idempotent": False, "cacheable": False})

def allowed_methods(allowed):
    return ", ".join(sorted(allowed)) + ", OPTIONS"

# RFC 7234 cache-control
def parse_cache_control(header):
    out = {}
    if not header:
        return out
    for part in header.split(","):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip().strip('"')
        elif part:
            out[part.lower()] = True
    return out

def is_cacheable(status, method, cache_control):
    cc = parse_cache_control(cache_control)
    if "no-store" in cc:
        return False
    if method.upper() not in ("GET", "HEAD"):
        return False
    if status in (200, 203, 204, 206, 300, 301, 404, 405, 410, 414, 501):
        return True
    return False

def validate_cache(request_headers, cached_headers, cached_status):
    # returns True if cached response can be used (304 conditions)
    # If-None-Match
    inm = request_headers.get("if-none-match")
    etag = cached_headers.get("etag")
    if inm and etag:
        if inm.strip() == "*" or inm.strip() == etag.strip():
            return True
    # If-Modified-Since
    ims = request_headers.get("if-modified-since")
    lm = cached_headers.get("last-modified")
    if ims and lm:
        if ims.strip() == lm.strip():
            return True
    # If no validators, conservative: revalidate
    if not inm and not ims:
        return False
    return False

def content_negotiate(accept, available):
    # accept: "text/html, application/json;q=0.9" ; available: list of media types
    # returns best match or None
    prefs = []
    for part in accept.split(","):
        part = part.strip()
        if not part:
            continue
        if ";" in part:
            mt, q = part.split(";", 1)
            mt = mt.strip()
            qm = q.strip()
            qval = 1.0
            if qm.startswith("q="):
                try:
                    qval = float(qm[2:])
                except ValueError:
                    qval = 1.0
        else:
            mt = part.strip()
            qval = 1.0
        prefs.append((mt, qval))
    prefs.sort(key=lambda x: -x[1])
    for mt, q in prefs:
        if mt == "*/*":
            return available[0] if available else None
        if mt in available:
            return mt
        # wildcard subtype
        if "/" in mt:
            major = mt.split("/")[0]
            for a in available:
                if a.startswith(major + "/"):
                    return a
    return None