#!/usr/bin/env python3
"""WebSocket client for the frame-inspection end-to-end test.

Usage:

    python3 ws_client.py <host> <port> [payload]

Performs the RFC 6455 handshake, sends one masked text frame with `payload`
(default: a benign message), then waits for the echo. Prints `echo` when the
server echoed the exact payload, `closed` when the WAF aborted the tunnel, or
`timeout`. The Host header defaults to the connect host and can be overridden
with a fourth argument (site routing).
"""

import base64
import os
import socket
import struct
import sys


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
    payload = (
        sys.argv[3] if len(sys.argv) > 3 else "hello from the ws client"
    ).encode("utf-8")
    host_header = sys.argv[4] if len(sys.argv) > 4 else host

    conn = socket.create_connection((host, port), timeout=8)
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    handshake = (
        "GET /ws HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        f"Origin: https://{host_header}\r\n\r\n"
    )
    conn.sendall(handshake.encode("ascii"))
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = conn.recv(4096)
        if not chunk:
            print("closed-during-handshake")
            return
        response += chunk
    if b" 101 " not in response.split(b"\r\n", 1)[0]:
        print("handshake-failed:", response.split(b"\r\n", 1)[0].decode())
        return

    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    conn.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)

    try:
        header = conn.recv(2)
        if not header:
            print("closed")
            return
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack("!H", conn.recv(2))[0]
        received = b""
        while len(received) < length:
            chunk = conn.recv(length - len(received))
            if not chunk:
                print("closed")
                return
            received += chunk
        print("echo" if received == payload else f"other:{received[:60]!r}")
    except (ConnectionResetError, BrokenPipeError):
        # The WAF aborted the tunnel: no echo, connection torn down.
        print("closed")
    except (socket.timeout, OSError):
        print("timeout")


if __name__ == "__main__":
    main()
