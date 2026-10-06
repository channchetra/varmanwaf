#!/usr/bin/env python3
"""Mock origin server for WAF benchmarking.

Returns 200 for every request regardless of method/path, so that any
non-200/503 response observed by the replayer can only come from the WAF
or the proxy protocol layer.
"""

import argparse
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _drain(self):
        # BaseHTTPRequestHandler keeps the connection alive; without draining,
        # leftover body bytes get parsed as the next request line and answered
        # with 501/400, which pingap's upstream pool then serves to unrelated
        # follow-up requests (observed as ~11% status pollution under load).
        # Attack samples routinely declare Content-Length larger than the body
        # actually sent, so every read below must be timeout-guarded — a bare
        # blocking read hangs the handler thread forever.
        self.connection.settimeout(3)
        try:
            self._drain_inner()
        except OSError:
            pass
        finally:
            self.connection.settimeout(None)

    def _drain_inner(self):
        remaining_budget = 16 * 1024 * 1024
        te = self.headers.get("Transfer-Encoding", "").lower()
        if "chunked" in te:
            while remaining_budget > 0:
                line = self.rfile.readline(65536)
                if not line:
                    return
                try:
                    size = int(line.strip().split(b";")[0], 16)
                except ValueError:
                    return
                if size == 0:
                    while True:
                        trailer = self.rfile.readline(65536)
                        if trailer in (b"\r\n", b"\n", b""):
                            return
                    return
                remaining_budget -= size
                while size > 0:
                    chunk = self.rfile.read(min(size, 65536))
                    if not chunk:
                        return
                    size -= len(chunk)
                self.rfile.readline(65536)
            return
        cl = self.headers.get("Content-Length")
        if cl:
            try:
                remaining = min(int(cl), remaining_budget)
            except ValueError:
                return
            while remaining > 0:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    return
                remaining -= len(chunk)

    def _respond(self):
        self._drain()
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = _respond
    do_POST = _respond
    do_PUT = _respond
    do_DELETE = _respond
    do_PATCH = _respond
    do_HEAD = _respond
    do_OPTIONS = _respond
    do_TRACE = _respond
    do_TRACK = _respond

    def log_message(self, fmt, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=6199)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"mock origin listening on {args.host}:{args.port}", file=sys.stderr)
    server.serve_forever()


if __name__ == "__main__":
    main()
