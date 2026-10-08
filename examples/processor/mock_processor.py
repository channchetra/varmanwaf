#!/usr/bin/env python3
"""Example VarmanWAF external processor (Phase 9).

Speaks the newline-delimited JSON contract on TCP (default :9100) or a Unix
domain socket (`--unix /run/varman/proc.sock`):

* request  -> `ProcessorRequest` + "\\n"
* response <- `ProcessorResponse` + "\\n"

The mock flags requests whose path starts with `/fraud` with a `block`
finding and answers everything else with an empty finding list. Use it as a
template for real processors (fraud checks, tenant logic, external feeds):
the WAF bounds your contribution, merges it monotonically, and resolves
timeouts/failures through its configured failure policy.

Run it:

    python3 examples/processor/mock_processor.py --port 9100
    python3 examples/processor/mock_processor.py --unix /run/varman/proc.sock
"""

import argparse
import json
import os
import socketserver
import sys


def handle_request(payload):
    """Return the `ProcessorResponse` for one request summary."""
    findings = []
    path = payload.get("path", "")
    if path.startswith("/fraud"):
        findings.append(
            {
                "rule_id": "fraud_path",
                "category": "api_abuse",
                "score": 35,
                "action_hint": "block",
                "detail": "path matches the processor's fraud rule",
            }
        )
    return {
        # Capability negotiation: the WAF namespaces findings with this name
        # and clamps its limits to the declared ones.
        "processor": {"name": "varman-mock", "version": "1.0", "max_findings": 8},
        "findings": findings,
    }


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline(65536)
        if not line:
            return
        try:
            payload = json.loads(line.decode("utf-8", "replace"))
            response = handle_request(payload)
        except Exception as error:  # noqa: BLE001 - a bad client must not kill the mock
            print(f"mock processor: bad request: {error}", file=sys.stderr)
            response = {"findings": []}
        self.wfile.write((json.dumps(response) + "\n").encode())


class ThreadingUnixStreamServer(socketserver.ThreadingUnixStreamServer):
    pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=9100)
    parser.add_argument("--unix", help="listen on a Unix domain socket instead")
    args = parser.parse_args()

    if args.unix:
        if os.path.exists(args.unix):
            os.unlink(args.unix)
        server = ThreadingUnixStreamServer(args.unix, Handler)
    else:
        server = socketserver.ThreadingTCPServer(
            (args.host, args.port), Handler
        )
        server.allow_reuse_address = True
    print(
        f"mock processor listening on {args.unix or f'{args.host}:{args.port}'}",
        file=sys.stderr,
    )
    server.serve_forever()


if __name__ == "__main__":
    main()
