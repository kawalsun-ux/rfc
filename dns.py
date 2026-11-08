"""RFC 1035 DNS (query via stdlib socket)."""
import socket, struct, random

def query(name, qtype="A", server="8.8.8.8", port=53, timeout=5):
    # Build query
    tid = random.randrange(0, 65536)
    flags = 0x0100  # standard query, recursion desired
    header = struct.pack("!HHHHHH", tid, flags, 1, 0, 0, 0)
    # encode name
    qname = b""
    for part in name.strip(".").split("."):
        qname += bytes([len(part)]) + part.encode()
    qname += b"\x00"
    qtype_map = {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "CNAME": 5, "NS": 2}
    qt = qtype_map.get(qtype.upper(), 1)
    question = qname + struct.pack("!HH", qt, 1)  # QTYPE, QCLASS IN
    packet = header + question
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    s.sendto(packet, (server, port))
    data, _ = s.recvfrom(512)
    s.close()
    return parse_response(data)

def parse_response(data):
    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    offset = 12
    # skip questions
    for _ in range(qd):
        offset = skip_name(data, offset)
        offset += 4  # qtype + qclass
    answers = []
    for _ in range(an):
        offset = skip_name(data, offset)
        rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlen]
        offset += rdlen
        if rtype == 1 and rdlen == 4:  # A
            answers.append(("A", ".".join(str(b) for b in rdata)))
        elif rtype == 28 and rdlen == 16:  # AAAA
            import ipaddress
            answers.append(("AAAA", str(ipaddress.IPv6Address(rdata))))
        elif rtype == 5:  # CNAME
            answers.append(("CNAME", read_name(data, offset - rdlen)))
        elif rtype == 15:  # MX
            pref = struct.unpack("!H", rdata[:2])[0]
            mx = read_name(data, offset - rdlen + 2)
            answers.append(("MX", (pref, mx)))
        elif rtype == 16:  # TXT
            txt = rdata[1:].decode("utf-8", errors="replace") if rdata else ""
            answers.append(("TXT", txt))
        else:
            answers.append((rtype, rdata.hex()))
    return {"id": tid, "flags": flags, "answers": answers}

def skip_name(data, offset):
    while True:
        l = data[offset]
        if l == 0:
            return offset + 1
        if (l & 0xC0) == 0xC0:
            return offset + 2
        offset += l + 1

def read_name(data, offset):
    parts = []
    jumped = False
    orig = offset
    while True:
        l = data[offset]
        if l == 0:
            offset += 1
            break
        if (l & 0xC0) == 0xC0:
            ptr = ((l & 0x3F) << 8) | data[offset+1]
            if not jumped:
                orig = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        parts.append(data[offset:offset+l].decode("utf-8", errors="replace"))
        offset += l
    return ".".join(parts)