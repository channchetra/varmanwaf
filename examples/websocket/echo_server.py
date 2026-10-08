#!/usr/bin/env python3
"""Minimal WebSocket echo server for testing frame inspection.

Standard library only; completes the RFC 6455 handshake, then echoes data
frames back to the client (control frames are handled and never echoed). Used
by the frame-inspection end-to-end test:

    docker run -d --name varman-ws-echo --network varmanwaf_varman-net \
        -v "$PWD/examples/websocket:/ws:ro" python:3-alpine python3 /ws/echo_server.py
"""

import base64
import hashlib
import socket
import struct
import threading

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def handshake(conn):
    request = b""
    while b"\r\n\r\n" not in request:
        chunk = conn.recv(4096)
        if not chunk:
            return False
        request += chunk
    headers = {}
    for line in request.decode("latin-1").split("\r\n")[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
    key = headers.get("sec-websocket-key")
    if not key:
        return False
    accept = base64.b64encode(
        hashlib.sha1((key + GUID).encode("ascii")).digest()
    ).decode("ascii")
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )
    conn.sendall(response.encode("ascii"))
    return True


def read_exact(conn, length):
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def read_frame(conn):
    header = read_exact(conn, 2)
    fin = header[0] & 0x80
    opcode = header[0] & 0x0F
    masked = header[1] & 0x80
    length = header[1] & 0x7F
    if length == 126:
        length = struct.unpack("!H", read_exact(conn, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", read_exact(conn, 8))[0]
    mask = read_exact(conn, 4) if masked else b"\x00\x00\x00\x00"
    payload = read_exact(conn, length)
    payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    return fin, opcode, payload


def write_frame(conn, opcode, payload):
    out = bytes([0x80 | opcode])
    length = len(payload)
    if length < 126:
        out += bytes([length])
    elif length <= 0xFFFF:
        out += bytes([126]) + struct.pack("!H", length)
    else:
        out += bytes([127]) + struct.pack("!Q", length)
    conn.sendall(out + payload)


def serve(conn):
    try:
        if not handshake(conn):
            return
        while True:
            fin, opcode, payload = read_frame(conn)
            if opcode == 0x8:  # close
                write_frame(conn, 0x8, b"")
                return
            if opcode == 0x9:  # ping
                write_frame(conn, 0xA, payload)
                continue
            if opcode in (0x1, 0x2) and fin:
                write_frame(conn, opcode, payload)
    except (ConnectionError, OSError):
        pass
    finally:
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("0.0.0.0", 8080))
    server.listen(16)
    while True:
        conn, _ = server.accept()
        threading.Thread(target=serve, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
