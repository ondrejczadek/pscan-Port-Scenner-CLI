#!/usr/bin/env python3
"""
pscan.py - TCP + UDP scanner with protocol-aware UDP payloads (DNS, NTP)
Educational use only. Use on your own network or with permission.

Features:
- TCP connect scan
- UDP scan that sends protocol payloads for DNS and NTP
- DNS Transaction ID generation + response verification
- Threaded scanning via ThreadPoolExecutor
- Optional CSV export
"""

import socket
import sys
import time
import random
import struct
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

# --------------------------
# Helper: parse ports string
# --------------------------
def parse_ports(ports_str):
    """
    Convert string like '1-1024,80,443' into sorted list of ints.
    """
    parts = ports_str.split(',')
    ports = set()
    for p in parts:
        p = p.strip()
        if not p:
            continue
        if '-' in p:
            try:
                a, b = p.split('-', 1)
                a = int(a); b = int(b)
            except ValueError:
                raise ValueError(f"Invalid port range: {p}")
            if a > b:
                a, b = b, a
            ports.update(range(a, b+1))
        else:
            try:
                ports.add(int(p))
            except ValueError:
                raise ValueError(f"Invalid port number: {p}")
    return sorted([pt for pt in ports if 1 <= pt <= 65535])

# --------------------------
# UDP payload builders
# --------------------------
def build_dns_query(domain="example.com"):
    """
    Build a simple DNS query (A record) for `domain`.
    Returns tuple (tid, bytes_payload)
    DNS header: 2 bytes Transaction ID, 2 bytes Flags, 2 bytes QDCOUNT, 2 ANCOUNT, 2 NSCOUNT, 2 ARCOUNT
    We'll set Flags=0x0100 (standard recursive query).
    """
    tid = random.randint(0, 0xffff)
    # Header: tid (2), flags (2), qdcount (2), ancount (2), nscount (2), arcount (2)
    header = struct.pack(">H H H H H H", tid, 0x0100, 1, 0, 0, 0)
    # QNAME: sequence of labels: length + label, terminated by 0
    qname = b"".join((bytes([len(label)]) + label.encode('ascii') for label in domain.split('.'))) + b"\x00"
    # QTYPE A (1), QCLASS IN (1)
    qtail = struct.pack(">H H", 1, 1)
    payload = header + qname + qtail
    return tid, payload

# NTP simple request (48 bytes) - first byte 0x1B
def build_ntp_request():
    return bytes([0x1b]) + bytes(47)

# Map of well-known UDP ports to payload builders (callables returning (maybe tid, payload) or payload only)
UDP_PAYLOAD_MAP = {
    53: lambda: build_dns_query("example.com"),  # returns (tid, payload)
    123: lambda: (None, build_ntp_request()),    # returns (None, payload) - no transaction id
    # Add more mappings if desired (e.g., SNMP, etc.)
}

# --------------------------
# NetScanner OOP
# --------------------------
class NetScanner:
    def __init__(self, target, ports, timeout=1.0, threads=200):
        self.target = target
        self.ports = sorted(set(ports))
        self.timeout = timeout
        self.threads = threads
        self.ip = self._resolve_target(target)

        # results
        self.tcp_open = []
        self.udp_open = []           # list of (port, info)
        self.udp_open_verified = []  # for DNS verified by tid (strong)
        self.udp_open_unverified = []# for responses w/o tid (e.g., NTP)
        self.udp_open_filtered = []  # open|filtered (no reply)
        self.tcp_errors = []
        self.udp_errors = []

    def _resolve_target(self, host):
        try:
            ip = socket.gethostbyname(host)
            return ip
        except socket.gaierror as e:
            print(f"[!] Cannot resolve target {host}: {e}")
            sys.exit(1)

    # --------------------------
    # TCP scan (connect)
    # --------------------------
    def _scan_tcp_port(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect((self.ip, port))
            s.close()
            return (port, True, None)
        except (socket.timeout, ConnectionRefusedError) as e:
            return (port, False, str(e))
        except Exception as e:
            return (port, False, str(e))

    def scan_tcp(self):
        print(f"[TCP] Scanning {self.target} ({self.ip}) {len(self.ports)} ports with {self.threads} threads")
        start = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._scan_tcp_port, p): p for p in self.ports}
            for fut in as_completed(futures):
                try:
                    port, is_open, info = fut.result()
                except Exception as exc:
                    continue
                if is_open:
                    self.tcp_open.append(port)
                    print(f"[TCP OPEN] {port}")
        elapsed = time.time() - start
        print(f"[TCP] Done in {elapsed:.2f}s. Open ports: {self.tcp_open}")

    # --------------------------
    # UDP scan (protocol-aware)
    # --------------------------
    def _scan_udp_port(self, port):
        """
        Send protocol-appropriate UDP payload and wait for response.
        For DNS (port 53) we generate Transaction ID (tid) and verify response tid.
        Returns tuple (port, status, info)
        status: "open_verified" (DNS tid matched), "open_unverified" (got udp reply but no tid to verify),
                "open|filtered" (no reply), "error" (exception)
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        try:
            # prepare payload and optional tid
            entry = UDP_PAYLOAD_MAP.get(port)
            if callable(entry):
                res = entry()
                # entry might return (tid, payload) or (None, payload)
                if isinstance(res, tuple) and len(res) == 2:
                    tid, payload = res
                else:
                    tid = None
                    payload = res
            else:
                tid = None
                payload = b"\x00"

            # send
            try:
                sock.sendto(payload, (self.ip, port))
            except Exception as e:
                sock.close()
                return (port, "error", f"send error: {e}")

            # wait for reply
            try:
                data, addr = sock.recvfrom(4096)
                sock.close()
                # if DNS payload (we sent with tid), verify first two bytes match tid
                if tid is not None and len(data) >= 2:
                    # response tid: first 2 bytes
                    resp_tid = struct.unpack(">H", data[0:2])[0]
                    if resp_tid == tid:
                        return (port, "open_verified", f"DNS reply matched tid {tid} ({len(data)} bytes)")
                    else:
                        # mismatched tid - might be unrelated traffic; still consider we got a UDP reply
                        return (port, "open_unverified", f"DNS reply tid mismatch {resp_tid} != {tid}, {len(data)} bytes")
                else:
                    # no tid to verify (NTP etc.) -> treat as open_unverified
                    return (port, "open_unverified", f"UDP reply {len(data)} bytes from {addr[0]}:{addr[1]}")
            except socket.timeout:
                sock.close()
                return (port, "open|filtered", "no reply (timeout)")
            except Exception as e:
                sock.close()
                return (port, "error", f"recv error: {e}")

        except Exception as e:
            try:
                sock.close()
            except:
                pass
            return (port, "error", f"unexpected error: {e}")

    def scan_udp(self):
        print(f"[UDP] Scanning {self.target} ({self.ip}) {len(self.ports)} ports with {self.threads} threads (timeout {self.timeout}s)")
        start = time.time()
        with ThreadPoolExecutor(max_workers=self.threads) as ex:
            futures = {ex.submit(self._scan_udp_port, p): p for p in self.ports}
            for fut in as_completed(futures):
                try:
                    port, status, info = fut.result()
                except Exception:
                    continue
                if status == "open_verified":
                    self.udp_open_verified.append((port, info))
                    print(f"[UDP OPEN VERIFIED] {port} - {info}")
                elif status == "open_unverified":
                    self.udp_open_unverified.append((port, info))
                    print(f"[UDP OPEN (unverified)] {port} - {info}")
                elif status == "open|filtered":
                    self.udp_open_filtered.append((port, info))
                    # don't print every filtered port to avoid clutter; uncomment if you want details
                    # print(f"[UDP OPEN|FILTERED] {port} - {info}")
                elif status == "error":
                    self.udp_errors.append((port, info))
                    # optionally print errors
                    # print(f"[UDP ERROR] {port} - {info}")
        elapsed = time.time() - start
        print(f"[UDP] Done in {elapsed:.2f}s. Open verified: {len(self.udp_open_verified)}, open unverified: {len(self.udp_open_unverified)}, open|filtered: {len(self.udp_open_filtered)}")

    # --------------------------
    # CSV export
    # --------------------------
    def export_csv(self, path):
        rows = []
        for p in sorted(self.tcp_open):
            rows.append(("tcp", p, "open", ""))
        for p, info in sorted(self.udp_open_verified):
            rows.append(("udp", p, "open_verified", info))
        for p, info in sorted(self.udp_open_unverified):
            rows.append(("udp", p, "open_unverified", info))
        for p, info in sorted(self.udp_open_filtered):
            rows.append(("udp", p, "open|filtered", info))
        if self.udp_errors:
            for p, info in sorted(self.udp_errors):
                rows.append(("udp", p, "error", info))
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["protocol", "port", "status", "info"])
            w.writerows(rows)
        print(f"[+] CSV exported to {path}")

# --------------------------
# CLI
# --------------------------
def usage():
    print("Usage: pscan <target> <ports> [--tcp] [--udp] [--threads N] [--timeout S] [--csv out.csv]")
    print("Example: pscan 192.168.1.10 1-200 --tcp --udp --threads 200 --timeout 1.0 --csv out.csv")
    sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        usage()

    target = sys.argv[1]
    ports_arg = sys.argv[2]
    flags = sys.argv[3:]

    do_tcp = False
    do_udp = False
    threads = 200
    timeout = 1.0
    csv_out = None

    if "--tcp" in flags:
        do_tcp = True
    if "--udp" in flags:
        do_udp = True
    if "--threads" in flags:
        i = flags.index("--threads"); threads = int(flags[i+1])
    if "--timeout" in flags:
        i = flags.index("--timeout"); timeout = float(flags[i+1])
    if "--csv" in flags:
        i = flags.index("--csv"); csv_out = flags[i+1]

    # default: both if none specified
    if not do_tcp and not do_udp:
        do_tcp = True
        do_udp = True

    try:
        ports = parse_ports(ports_arg)
    except Exception as e:
        print(f"[!] Invalid ports argument: {e}")
        sys.exit(1)

    scanner = NetScanner(target, ports, timeout=timeout, threads=threads)

    if do_tcp:
        scanner.scan_tcp()
    if do_udp:
        scanner.scan_udp()

    if csv_out:
        scanner.export_csv(csv_out)