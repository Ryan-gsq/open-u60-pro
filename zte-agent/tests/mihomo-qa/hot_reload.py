#!/usr/bin/env python3
"""Loopback-only Mihomo v1.19.33 reload acceptance: python3 hot_reload.py CORE."""

import http.client
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while data := self.request.recv(4096):
            self.request.sendall(data)


def api(port, method, path, body=None):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        client.request(method, path, json.dumps(body) if body is not None else None,
                       {"Authorization": "Bearer test", "Content-Type": "application/json"})
        response = client.getresponse()
        return response.status, response.read()
    finally:
        client.close()


def fake_address(port):
    name = b"\x05probe\x07invalid\x00"
    query = struct.pack("!6H", 1, 0x100, 1, 0, 0, 0) + name + struct.pack("!2H", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        client.settimeout(3)
        client.sendto(query, ("127.0.0.1", port))
        answer = client.recv(4096)
    assert struct.unpack("!H", answer[6:8])[0] == 1
    offset = 12 + len(name) + 4
    if answer[offset] & 0xC0 == 0xC0:
        offset += 2
    else:
        while answer[offset]:
            offset += 1 + answer[offset]
        offset += 1
    record_type, _, _, length = struct.unpack("!HHIH", answer[offset:offset + 10])
    assert record_type == 1 and length == 4
    return answer[offset + 10:offset + 14]


def connect_proxy(port, destination):
    client = socket.create_connection(("127.0.0.1", port), timeout=3)
    client.sendall(f"CONNECT 127.0.0.1:{destination} HTTP/1.1\r\nHost: 127.0.0.1:{destination}\r\n\r\n".encode())
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = client.recv(4096)
        if not chunk:
            break
        response += chunk
    assert b"200" in response.split(b"\r\n")[0]
    return client


def main():
    core_path = str(Path(sys.argv[1]).resolve())
    controller, mixed, dns = free_port(), free_port(), free_port(socket.SOCK_DGRAM)
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory(prefix="mh-core-", dir="/tmp/u60-test/work") as directory:
            config = {
                "external-controller": f"127.0.0.1:{controller}", "secret": "test",
                "mixed-port": mixed, "log-level": "silent", "rules": ["MATCH,DIRECT"],
                "profile": {"store-selected": True, "store-fake-ip": True},
                "dns": {"enable": True, "listen": f"127.0.0.1:{dns}",
                        "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
                        "nameserver": ["127.0.0.1:9"]},
            }
            path = Path(directory) / "config.yaml"
            path.write_text(json.dumps(config))
            core = subprocess.Popen([core_path, "-d", directory, "-f", str(path)],
                                    env={**os.environ, "SKIP_SYSTEM_IPV6_CHECK": "true"},
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        assert api(controller, "GET", "/version")[0] == 200
                        break
                    except (OSError, AssertionError):
                        assert time.monotonic() < deadline and core.poll() is None
                        time.sleep(0.05)
                before = fake_address(dns)
                assert fake_address(dns) == before, "fake-IP persistence unavailable before reload"
                assert (Path(directory) / "cache.db").is_file(), "core cache was not created"
                client = connect_proxy(mixed, server.server_address[1])
                with client:
                    client.sendall(b"before")
                    assert client.recv(6) == b"before"
                    config["rules"] = ["MATCH,REJECT"]
                    assert api(controller, "PUT", "/configs?force=false", {"payload": json.dumps(config)})[0] == 204
                    client.sendall(b"after")
                    assert client.recv(5) == b"after", "existing TCP connection closed"
                    after = fake_address(dns)
                    replacement = connect_proxy(mixed, server.server_address[1])
                    with replacement:
                        replacement.sendall(b"blocked")
                        try:
                            assert replacement.recv(7) != b"blocked", "new rules were not applied"
                        except ConnectionResetError:
                            pass
                    assert core.poll() is None
                    assert api(controller, "PUT", "/configs?force=false", {"payload": json.dumps(config)})[0] == 204
                    assert fake_address(dns) == after, "subsequent reload lost the fake-IP mapping"
                print(json.dumps({"existing_tcp_survives": True, "subsequent_fake_ip_preserved": True,
                                  "first_reload_fake_ip_preserved": before == after,
                                  "listener_kept": True, "new_rules_applied": True}))
            finally:
                core.terminate()
                core.wait(timeout=5)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
