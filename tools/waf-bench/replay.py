#!/usr/bin/env python3
"""Replay blazehttp HTTP testcases against a running reverse proxy/WAF.

Reads raw HTTP request files (*.black = expected blocked, *.white = expected
passed), sends each one verbatim over a TCP socket, and classifies the
response:

  blocked         403 (block page) or 503 (challenge page) — a WAF verdict
  passed          2xx/3xx — reached the origin
  protocol_reject 400/413/414/431/501 — proxy protocol layer, not a WAF verdict
  rate_limited    429
  error           timeout / connection reset / unreadable response

Results are written as JSONL, one object per sample.
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BLOCK_STATUSES = {403, 503}
PROTOCOL_REJECT = {400, 413, 414, 431, 501}
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 5.0
MAX_RESPONSE = 256 * 1024

CATEGORY_PATTERNS = [
    ("log4shell", [rb"\$\{jndi"]),
    ("sqli", [
        rb"union[\s%2b(]{0,8}select", rb"union%20", rb"or[\s+]%?1%?=%?1",
        rb"'\s*or\s*", rb"'--", rb"%27--", rb"sleep\s*\(", rb"benchmark\s*\(",
        rb"waitfor[\s+]+delay", rb"information_schema", rb"select\s+.+\s+from",
        rb"1=1--", rb"admin'--",
    ]),
    ("xss", [
        b"<script", rb"onerror\s*=", rb"onload\s*=", rb"onfocus\s*=",
        rb"onmouseover\s*=", b"javascript:", rb"alert\s*\(", rb"document\.cookie",
        b"<svg", b"<iframe", b"<img", rb"<\w+\s+on\w+\s*=", rb"prompt\(",
        rb"eval\s*\(", rb"fromcharcode", rb"atob\(", rb"%5cx[0-9a-f]{2}",
        rb"\\x[0-9a-f]{2}",
    ]),
    ("xxe", [b"<!doctype", b"<!entity", rb'system\s*["\']file']),
    ("ssti", [rb"\$\{[^}]{0,80}\}", b"%24%7b"]),
    ("rce", [
        rb"[;&|]\s*(cat|ls|id|whoami|wget|curl|bash|sh|nc|ncat|python|perl|chmod|ping)\b",
        rb"\$\(", b"%24%28", rb"%0a\s*(cat|ls|id|whoami)\b", b"/bin/",
    ]),
    ("lfi", [
        rb"\.\./", rb"\.\.%5c", rb"\.\.\\", b"%2e%2e", b"%252e", b"/etc/passwd",
        b"/etc/shadow", rb"win\.ini", b"php://filter", b"php://input", b"file://",
    ]),
    ("ssrf", [
        rb"169\.254\.169\.254", rb"127\.0\.0\.1", rb"0177\.0\.0\.1", b"localhost",
        b"gopher://", b"dict://", b"0x7f000001", b"2130706433",
    ]),
    ("scanner", [
        b"nikto", b"sqlmap", b"nmap", b"acunetix", b"nessus", b"masscan",
        b"zgrab", b"gobuster", b"dirbuster", b"wpscan", b"hydra", b"xray",
        b"goby", b"dirsearch", b"wfuzz",
    ]),
    ("deser", [
        b"rmi://", b"commons-collections", b"ysoserial", b"java.lang.runtime",
    ]),
    ("crlf", [b"%0d%0a"]),
]

STATUS_LINE = re.compile(rb"^HTTP/1\.[01] (\d{3})")
REQUEST_LINE = re.compile(rb"^[A-Z]+ \S+ HTTP/1\.[01]$")


def classify(raw: bytes) -> str:
    if not REQUEST_LINE.match(raw.split(b"\n", 1)[0].rstrip(b"\r")):
        return "malformed"
    low = raw.lower()
    for category, patterns in CATEGORY_PATTERNS:
        for pattern in patterns:
            if re.search(pattern, low):
                return category
    return "other"


def prepare(raw: bytes, xff: str | None, host_rewrite: str | None) -> bytes:
    """Force Connection: close and optionally inject XFF / rewrite Host."""
    sep = raw.find(b"\r\n\r\n")
    seplen = 4
    if sep < 0:
        sep = raw.find(b"\n\n")
        seplen = 2
    if sep < 0:
        return raw  # headerless garbage — send verbatim
    head, rest = raw[:sep], raw[sep + seplen:]

    def replace_line(header_block: bytes, prefix: bytes, value: bytes) -> bytes:
        lines = header_block.split(b"\r\n")
        out, found = [], False
        for line in lines:
            if line.lower().startswith(prefix):
                out.append(value)
                found = True
            else:
                out.append(line)
        if not found:
            out.append(value)
        return b"\r\n".join(out)

    head = replace_line(head, b"connection:", b"Connection: close")
    if host_rewrite:
        head = replace_line(head, b"host:", b"Host: " + host_rewrite.encode())
    if xff:
        head = replace_line(head, b"x-forwarded-for:", b"X-Forwarded-For: " + xff.encode())
    return head + b"\r\n\r\n" + rest


def read_response(sock) -> tuple[int | None, str]:
    buf = b""
    try:
        while len(buf) < MAX_RESPONSE:
            chunk = sock.recv(65536)
            if not chunk:
                break
            buf += chunk
            end = buf.find(b"\r\n\r\n")
            if end >= 0:
                match = STATUS_LINE.match(buf)
                if not match:
                    return None, "unparsable"
                status = int(match.group(1))
                header_block = buf[:end].lower()
                if b"content-length:" in header_block:
                    length = int(
                        re.search(rb"content-length:\s*(\d+)", header_block).group(1)
                    )
                    if len(buf) - end - 4 >= length:
                        return status, "ok"
                else:
                    return status, "ok"  # no CL: rely on EOF (Connection: close)
        if not buf:
            return None, "empty"
        match = STATUS_LINE.match(buf)
        return (int(match.group(1)) if match else None), "truncated"
    except socket.timeout:
        match = STATUS_LINE.match(buf)
        if match:
            return int(match.group(1)), "read-timeout-with-status"
        return None, "timeout"
    except (ConnectionResetError, BrokenPipeError, OSError):
        match = STATUS_LINE.match(buf)
        if match:
            return int(match.group(1)), "reset-with-status"
        return None, "reset"


def verdict_of(status: int | None, detail: str) -> str:
    if status is None:
        return "error"
    if status in BLOCK_STATUSES:
        return "blocked"
    if status in PROTOCOL_REJECT:
        return "protocol_reject"
    if status == 429:
        return "rate_limited"
    if 200 <= status < 400:
        return "passed"
    if detail.endswith("reset") or detail.endswith("timeout"):
        return "error"
    return f"status_{status}"


class Replayer:
    def __init__(self, args):
        self.args = args
        self.root = Path(args.testcases)
        self.lock = threading.Lock()
        self.out = open(args.output, "w")
        self.counter = 0
        self.done = 0
        self.local = threading.local()

    def source_addr(self):
        # Note: unlike Linux, macOS only routes 127.0.0.1 to loopback, so
        # per-thread source addresses on 127.0.0.10+ cannot be bound there.
        return self.local

    def send_one(self, path: Path):
        local = self.source_addr()
        raw = path.read_bytes()
        expected = "black" if path.suffix == ".black" else "white"
        category = classify(raw)
        with self.lock:
            self.counter += 1
            n = self.counter
        xff = (str(ipaddress.ip_address(self.args.xff_base) + (n % self.args.xff_count))
               if self.args.xff else None)
        payload = prepare(raw, xff, self.args.host_rewrite)

        status, detail, latency_ms = None, "unsent", 0
        sock = None
        start = time.monotonic()
        try:
            sock = socket.create_connection(
                (self.args.host, self.args.port), timeout=CONNECT_TIMEOUT,
                **getattr(local, "sock_args", {}),
            )
            sock.settimeout(READ_TIMEOUT)
            sock.sendall(payload)
            status, detail = read_response(sock)
        except socket.timeout:
            detail = "connect-timeout"
        except (ConnectionResetError, BrokenPipeError, OSError):
            detail = "connect-error"
        finally:
            latency_ms = int((time.monotonic() - start) * 1000)
            if sock:
                try:
                    sock.close()
                except OSError:
                    pass

        record = {
            "file": str(path.relative_to(self.root)),
            "name": path.name,
            "expected": expected,
            "category": category,
            "status": status,
            "detail": detail,
            "verdict": verdict_of(status, detail),
            "latency_ms": latency_ms,
            "group": self.args.group,
        }
        with self.lock:
            self.out.write(json.dumps(record) + "\n")
            self.done += 1
            if self.done % 1000 == 0:
                print(f"[{self.args.group}] {self.done} done", file=sys.stderr)

    def run(self, samples: list[Path]):
        with ThreadPoolExecutor(max_workers=self.args.concurrency) as pool:
            futures = []
            for sample in samples:
                futures.append(pool.submit(self.send_one, sample))
                time.sleep(self.args.delay_ms / 1000.0)
            for future in futures:
                future.result()
        self.out.close()


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("testcases", help="blazehttp testcases root directory")
    parser.add_argument("-t", "--target", default="127.0.0.1:6188")
    parser.add_argument("-g", "--group", default="g1")
    parser.add_argument("-o", "--output", required=True)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--delay-ms", type=float, default=10.0)
    parser.add_argument("--xff", action="store_true",
                       help="rotate X-Forwarded-For per sample")
    parser.add_argument("--xff-base", default="203.0.113.1",
                       help="first XFF address in the rotation range")
    parser.add_argument("--xff-count", type=int, default=254,
                       help="size of the XFF rotation range; keep it well above "
                            "sample count / expected auto-block windows, or "
                            "collateral denials of reused IPs pollute FP stats")
    parser.add_argument("--host-rewrite", default=None,
                       help="rewrite the Host header of every sample")
    parser.add_argument("--limit", type=int, default=None,
                       help="only replay the first N samples (smoke test)")
    args = parser.parse_args()

    host, _, port = args.target.rpartition(":")
    args.host, args.port = host, int(port)

    root = Path(args.testcases)
    samples = sorted(
        p for p in root.rglob("*") if p.is_file() and p.suffix in (".black", ".white")
    )
    if args.limit:
        samples = samples[: args.limit]
    blacks = sum(1 for p in samples if p.suffix == ".black")
    print(
        f"[{args.group}] {len(samples)} samples ({blacks} black, "
        f"{len(samples) - blacks} white) -> {args.output}",
        file=sys.stderr,
    )
    Replayer(args).run(samples)


if __name__ == "__main__":
    main()
