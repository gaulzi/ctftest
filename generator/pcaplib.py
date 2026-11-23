"""Tiny dependency-free pcap writer (Ethernet / IPv4 / TCP / UDP).

Good enough to produce captures that Wireshark and tshark open cleanly,
with correct checksums and TCP sequence numbers so "Follow TCP Stream" works.
"""
import struct
import random


def _csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ip2b(ip: str) -> bytes:
    return bytes(int(x) for x in ip.split("."))


def mac_for(ip: str) -> bytes:
    # deterministic fake MAC per IP
    return b"\x00\x50\x56" + ip2b(ip)[1:]


class Pcap:
    def __init__(self, start_ts: float):
        self.ts = start_ts
        self.packets = []
        self.ip_id = random.randint(1000, 60000)

    def advance(self, seconds: float):
        self.ts += seconds

    def _eth_ip(self, src, dst, proto, payload, ttl=64):
        self.ip_id = (self.ip_id + 1) & 0xFFFF
        total = 20 + len(payload)
        hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, self.ip_id, 0x4000,
                          ttl, proto, 0, ip2b(src), ip2b(dst))
        hdr = hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:]
        eth = mac_for(dst) + mac_for(src) + b"\x08\x00"
        return eth + hdr + payload

    def add_raw(self, frame: bytes, dt=0.0005):
        self.ts += dt
        self.packets.append((self.ts, frame))

    def tcp(self, src, sport, dst, dport, seq, ack, flags, data=b"", dt=0.0005, win=64240):
        fl = 0
        for ch, bit in (("F", 1), ("S", 2), ("R", 4), ("P", 8), ("A", 16)):
            if ch in flags:
                fl |= bit
        hdr = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF,
                          5 << 4, fl, win, 0, 0)
        pseudo = ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(data))
        c = _csum(pseudo + hdr + data)
        hdr = hdr[:16] + struct.pack("!H", c) + hdr[18:]
        self.add_raw(self._eth_ip(src, dst, 6, hdr + data), dt)

    def udp(self, src, sport, dst, dport, data, dt=0.0005):
        hdr = struct.pack("!HHHH", sport, dport, 8 + len(data), 0)
        pseudo = ip2b(src) + ip2b(dst) + struct.pack("!BBH", 0, 17, 8 + len(data))
        c = _csum(pseudo + hdr + data) or 0xFFFF
        hdr = hdr[:6] + struct.pack("!H", c)
        self.add_raw(self._eth_ip(src, dst, 17, hdr + data), dt)

    def save(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            for ts, frame in self.packets:
                sec = int(ts)
                usec = int(round((ts - sec) * 1_000_000))
                if usec >= 1_000_000:
                    sec, usec = sec + 1, usec - 1_000_000
                f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
                f.write(frame)


class TcpSession:
    """A simple client/server TCP conversation."""

    def __init__(self, pcap: Pcap, cip, cport, sip, sport):
        self.p = pcap
        self.c = (cip, cport)
        self.s = (sip, sport)
        self.cseq = random.randint(1, 2**31)
        self.sseq = random.randint(1, 2**31)

    def handshake(self, rtt=0.02):
        (ci, cp), (si, sp) = self.c, self.s
        self.p.tcp(ci, cp, si, sp, self.cseq, 0, "S", dt=0.001)
        self.cseq += 1
        self.p.tcp(si, sp, ci, cp, self.sseq, self.cseq, "SA", dt=rtt / 2)
        self.sseq += 1
        self.p.tcp(ci, cp, si, sp, self.cseq, self.sseq, "A", dt=rtt / 2)
        return self

    def client(self, data: bytes, dt=0.05, mss=1400):
        (ci, cp), (si, sp) = self.c, self.s
        first = True
        for i in range(0, len(data), mss):
            chunk = data[i:i + mss]
            self.p.tcp(ci, cp, si, sp, self.cseq, self.sseq, "PA", chunk, dt=dt if first else 0.0003)
            first = False
            self.cseq += len(chunk)
        self.p.tcp(si, sp, ci, cp, self.sseq, self.cseq, "A", dt=0.01)
        return self

    def server(self, data: bytes, dt=0.03, mss=1400):
        (ci, cp), (si, sp) = self.c, self.s
        first = True
        for i in range(0, len(data), mss):
            chunk = data[i:i + mss]
            self.p.tcp(si, sp, ci, cp, self.sseq, self.cseq, "PA", chunk, dt=dt if first else 0.0003)
            first = False
            self.sseq += len(chunk)
        self.p.tcp(ci, cp, si, sp, self.cseq, self.sseq, "A", dt=0.01)
        return self

    def close(self):
        (ci, cp), (si, sp) = self.c, self.s
        self.p.tcp(ci, cp, si, sp, self.cseq, self.sseq, "FA", dt=0.05)
        self.cseq += 1
        self.p.tcp(si, sp, ci, cp, self.sseq, self.cseq, "FA", dt=0.01)
        self.sseq += 1
        self.p.tcp(ci, cp, si, sp, self.cseq, self.sseq, "A", dt=0.01)


def dns_query(qid: int, name: str, qtype=1) -> bytes:
    hdr = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    return hdr + q + struct.pack("!HH", qtype, 1)


def dns_response(qid: int, name: str, ip: str, qtype=1) -> bytes:
    hdr = struct.pack("!HHHHHH", qid, 0x8180, 1, 1, 0, 0)
    q = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    q += struct.pack("!HH", qtype, 1)
    if qtype == 16:
        txt = ip.encode()
        rdata = bytes([len(txt)]) + txt
    else:
        rdata = ip2b(ip)
    ans = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 300, len(rdata)) + rdata
    return hdr + q + ans
