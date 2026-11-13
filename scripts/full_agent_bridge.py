#!/usr/bin/env python3
"""Solver-side loopback bridge. Only the mounted Unix socket reaches the host.

This file contains no evaluator, model credential, policy, seed or lab source.
The whole process runs in a network namespace with no host network access.
"""
from __future__ import annotations

import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socket
import subprocess
import sys
import threading

MAX_BODY = 16 * 1024 * 1024


class UnixConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect("/bridge/host.sock")


def main():
    if len(sys.argv) < 2:
        return 2

    class Handler(BaseHTTPRequestHandler):
        # Native fetch clients reuse connections during MCP initialization.
        # Every response is length-framed, including the empty 202 reply.
        protocol_version = "HTTP/1.1"

        def log_message(self, *_):
            pass

        def do_GET(self):
            # Streamable HTTP may try an optional server event stream. This
            # stateless broker replies to POST only; 405 is the MCP signal.
            # Keep the reply empty and length-framed. Native fetch cancels
            # unsupported event streams; an HTML error body plus connection
            # close can disrupt concurrent initialization POSTs in its pool.
            self.send_response(405)
            self.send_header("Allow", "POST")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= MAX_BODY:
                    raise ValueError("invalid body size")
                conn = UnixConnection("host", timeout=1800)
                try:
                    conn.request("POST", self.path, self.rfile.read(size), {"Content-Type": "application/json"})
                    response = conn.getresponse()
                    body = response.read(MAX_BODY + 1)
                    if len(body) > MAX_BODY:
                        raise ValueError("response too large")
                    self.send_response(response.status)
                    self.send_header("Content-Type", response.getheader("Content-Type", "application/json"))
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                finally:
                    conn.close()
            except (OSError, ValueError, http.client.HTTPException) as exc:
                # No payloads, credentials or exception messages cross into
                # diagnostics; keep enough to distinguish a transport fault.
                sys.stderr.write(json.dumps({"native_bridge_error": type(exc).__name__,
                                             "errno": getattr(exc, "errno", None)}) + "\n")
                sys.stderr.flush()
                self.send_error(502, "host bridge unavailable")

    class Server(ThreadingHTTPServer):
        # Native MCP clients initialize concurrently and immediately follow
        # with initialized notifications and tools/list requests.
        request_queue_size = 64

    server = Server(("127.0.0.1", 17777), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # The host checks this nonce before accepting any provider or MCP calls.
        conn = UnixConnection("host", timeout=10)
        try:
            conn.request("POST", "/ready", json.dumps({"nonce": os.environ["CCO_NATIVE_NONCE"]}),
                         {"Content-Type": "application/json"})
            reply = conn.getresponse()
            reply.read()
        finally:
            conn.close()
        if reply.status != 200:
            return 2
        return subprocess.call(sys.argv[1:])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


if __name__ == "__main__":
    raise SystemExit(main())
