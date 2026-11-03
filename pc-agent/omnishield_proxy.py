#!/usr/bin/env python3
"""
OmniShield X — PC DNS Protection Agent (Windows / macOS / Linux)
================================================================

A local DNS proxy that:
  1. Answers DNS queries on 127.0.0.1 (port 53 needs admin; use --port for testing),
  2. Applies the SAME rule ladder as the Android app and the website engine:
       custom allow (exact -> suffix) -> custom block -> filter-list block (suffix walk),
  3. Forwards everything else to an ENCRYPTED upstream (DNS-over-HTTPS) only.
     It never downgrades to plaintext DNS.

This COMPLEMENTS Microsoft Defender (it filters DNS, not files) — it does not
replace it. HONEST LIMITS: it protects every app that uses the system resolver
while you point your adapter at 127.0.0.1. Browsers with their own secure DNS
(Chrome "Secure DNS", Firefox DoH) bypass it — turn those off (see README), and
local Admin rights are needed only to bind port 53 and switch the adapter.

Usage:
  python omnishield_proxy.py --selftest          # offline self-test (no network)
  python omnishield_proxy.py --rules core_ads.txt --port 53
  python omnishield_proxy.py --rules core_ads.txt --port 53 --apply-windows-dns
"""

import argparse
import socket
import struct
import sys
import threading
import urllib.request

DOH_DEFAULT = "https://dns.adguard-dns.com/dns-query"  # ad-blocking resolver, TLS-encrypted


# ----------------------------------------------------------------------------
# Rule ladder (mirrors website/engine.js and the Android FilterRuleEngine)
# ----------------------------------------------------------------------------
class RuleLadder:
    def __init__(self):
        self.block = set()      # suffix rules: ||domain^
        self.allow = set()      # exception rules: @@||domain^

    @staticmethod
    def normalize(domain: str) -> str:
        d = domain.strip().lower().rstrip(".")
        if d.startswith("www."):
            d = d[4:]
        return d

    def load(self, text: str) -> int:
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith(("!", "#")):
                continue
            if "$" in line or line.startswith("/") or "*" in line:
                continue  # unsupported modifier/regex/wildcard: skipped, counted by caller
            if line.startswith("@@||") and line.endswith("^"):
                self.allow.add(line[4:-1])
            elif line.startswith("||") and line.endswith("^"):
                self.block.add(line[2:-1])
        return len(self.block) + len(self.allow)

    def _suffix_hit(self, rules, domain):
        d = self.normalize(domain)
        while True:
            if d in rules:
                return True
            if "." not in d:
                return False
            d = d.split(".", 1)[1]

    def decide(self, domain: str) -> str:
        """'allow' | 'block' — exceptions first, exactly like the Android ladder."""
        if self._suffix_hit(self.allow, domain):
            return "allow"
        if self._suffix_hit(self.block, domain):
            return "block"
        return "allow"


# ----------------------------------------------------------------------------
# Minimal DNS wire handling
# ----------------------------------------------------------------------------
def parse_question_name(payload: bytes) -> str:
    """Decodes the QNAME of the first question (no compression pointers in queries)."""
    if len(payload) < 13:
        raise ValueError("short packet")
    qdcount = struct.unpack("!H", payload[4:6])[0]
    if qdcount < 1:
        raise ValueError("no question")
    labels = []
    pos = 12
    while True:
        length = payload[pos]
        if length == 0:
            break
        labels.append(payload[pos + 1:pos + 1 + length].decode("idna"))
        pos += 1 + length
    return ".".join(labels)


def build_nxdomain(payload: bytes) -> bytes:
    """Copies the question and answers NXDOMAIN (RCODE=3), RA=1."""
    header = bytearray(payload[:12])
    header[2] = (header[2] | 0x80) & 0xFE | 0x00  # QR=1, keep opcode, AA=0
    header[3] = (header[3] | 0x80) | 0x03         # RA=1, RCODE=3
    qdcount = struct.unpack("!H", payload[4:6])[0]
    rest = payload[12:]
    # Keep only the question section (drop any OPT/answers the client added).
    pos = 12
    consumed = 0
    for _ in range(qdcount):
        while payload[pos] != 0:
            pos += 1 + payload[pos]
        pos += 5  # null + qtype + qclass
        consumed = pos - 12
    return bytes(header[:4]) + struct.pack("!HHHHH", qdcount, 0, 0, 0, 0) + rest[:consumed]


def doh_forward(payload: bytes, doh_url: str, timeout: float = 4.0) -> bytes:
    req = urllib.request.Request(
        doh_url, data=payload, method="POST",
        headers={"Content-Type": "application/dns-message",
                 "Accept": "application/dns-message"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def serve_udp(ladder: RuleLadder, port: int, doh_url: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", port))
    print(f"OmniShield X PC agent: filtering on 127.0.0.1:{port} -> DoH {doh_url}")
    print(f"Rules loaded: {len(ladder.block)} block / {len(ladder.allow)} allow")
    while True:
        payload, addr = sock.recvfrom(4096)
        try:
            name = parse_question_name(payload)
        except Exception:
            continue
        if ladder.decide(name) == "block":
            sock.sendto(build_nxdomain(payload), addr)
            continue
        try:
            sock.sendto(doh_forward(payload, doh_url), addr)
        except Exception:
            # Never silently cut connectivity: tell the client SERVFAIL rather than
            # dropping the packet into a timeout.
            sock.sendto(build_servfail(payload), addr)


def build_servfail(payload: bytes) -> bytes:
    resp = bytearray(build_nxdomain(payload))
    resp[3] = (resp[3] & 0xF0) | 0x02  # RCODE=2 SERVFAIL
    return bytes(resp)


# ----------------------------------------------------------------------------
# Offline self-test (no network needed)
# ----------------------------------------------------------------------------
def selftest() -> int:
    ladder = RuleLadder()
    n = ladder.load(
        "||doubleclick.net^\n"
        "||ads.example.co^\n"
        "@@||safe.doubleclick.net^\n"
        "! comment\n"
        "||tracker.*/x^$script\n"
    )
    assert ladder.decide("ad.doubleclick.net") == "block", "suffix block failed"
    assert ladder.decide("doubleclick.net") == "block", "apex block failed"
    assert ladder.decide("safe.doubleclick.net") == "allow", "exception must win"
    assert ladder.decide("example.com") == "allow", "unrelated must be allowed"
    assert ladder.decide("deep.sub.ads.example.co") == "block", "deep suffix failed"
    assert n == 3, f"expected 3 parsed rules, got {n}"

    query = b"\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
            b"\x03www\x06adidas\x03com\x00\x00\x01\x00\x01"
    assert parse_question_name(query) == "www.adidas.com"

    blocked_q = b"\x11\x22\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" \
                b"\x02ad\x0bdoubleclick\x03net\x00\x00\x01\x00\x01"
    nx = build_nxdomain(blocked_q)
    assert nx[3] & 0x0F == 3, "NXDOMAIN rcode"
    assert struct.unpack("!H", nx[2:4])[0] & 0x8000, "QR bit set"
    assert nx.endswith(blocked_q[12:]), "question copied verbatim"

    sf = build_servfail(blocked_q)
    assert sf[3] & 0x0F == 2, "SERVFAIL rcode"

    print("SELFTEST OK: ladder (block/allow/exceptions/suffix), QNAME parse, "
          "NXDOMAIN + SERVFAIL builders all pass.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="OmniShield X PC DNS agent")
    ap.add_argument("--rules", default=None, help="filter list path (||domain^ format)")
    ap.add_argument("--port", type=int, default=53)
    ap.add_argument("--doh", default=DOH_DEFAULT)
    ap.add_argument("--apply-windows-dns", action="store_true",
                    help="point the active adapter at 127.0.0.1 (admin)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    ladder = RuleLadder()
    if args.rules:
        with open(args.rules, "r", encoding="utf-8") as f:
            ladder.load(f.read())
    else:
        print("No --rules given: pure encrypted forwarder (no blocklist).")

    if args.apply_windows_dns and sys.platform == "win32":
        import subprocess
        guid = subprocess.check_output(
            ["powershell", "-c",
             "(Get-NetAdapter | Where-Object Status -eq 'Up')[0].InterfaceIndex"]
        ).decode().strip()
        subprocess.check_call(["netsh", "interface", "ip", "set", "dns",
                               f"{guid}", "static", "127.0.0.1"])
        print("Windows adapter DNS set to 127.0.0.1 (admin).")

    serve_udp(ladder, args.port, args.doh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
