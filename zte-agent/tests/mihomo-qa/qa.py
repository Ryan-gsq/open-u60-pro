#!/usr/bin/env python3
"""Isolated acceptance for the agent's Mihomo tables and journal (v2).

Run only inside a disposable `--privileged --network none` container; see
README.md. Prints one JSON line per check and exits non-zero on a failure.
"""
import ctypes
import json
import os
import shutil
import socket
import subprocess
import sys
import threading
import time

DATA = "/qa-data"
TABLE = "u60_mihomo"
ROOT = "/data/zte-agent-mihomo"
FAILED = []
LIBC = ctypes.CDLL(None, use_errno=True)


def enter(ns):
    """This thread into network namespace `ns` (os.setns is Python 3.12+)."""
    fd = os.open(f"/run/netns/{ns}", os.O_RDONLY)
    try:
        if LIBC.setns(fd, 0x40000000) != 0:  # CLONE_NEWNET
            raise OSError(ctypes.get_errno(), "setns")
    finally:
        os.close(fd)


def sh(*args, ns=None, check=True):
    command = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    done = subprocess.run(command, capture_output=True, text=True)
    if check and done.returncode != 0:
        raise RuntimeError(f"{' '.join(command)}: {done.stderr.strip()}")
    return done


def report(name, ok, detail=""):
    print(json.dumps({"check": name, "ok": bool(ok), "detail": detail}), flush=True)
    if not ok:
        FAILED.append(name)


def in_ns(ns, target, *args):
    """Runs `target(*args)` in network namespace `ns` (a thread of its own)."""
    result = {}

    def run():
        enter(ns)
        try:
            result["value"] = target(*args)
        except Exception as e:  # noqa: BLE001 - reported as the result
            result["value"] = f"error: {e}"

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()
    return result.get("value")


def serve(ns, family, address, port, label, transparent=False):
    """A line server in `ns`: answers `<label>:<line>` to every line."""
    ready = threading.Event()
    stop = threading.Event()
    state = {}

    def run():
        enter(ns)
        server = socket.socket(family, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        if transparent:
            if family == socket.AF_INET6:
                server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                server.setsockopt(socket.IPPROTO_IPV6, 75, 1)  # IPV6_TRANSPARENT
            else:
                server.setsockopt(socket.SOL_IP, 19, 1)  # IP_TRANSPARENT
        server.bind((address, port))
        server.listen(16)
        server.settimeout(0.2)
        state["server"] = server
        ready.set()
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            threading.Thread(target=answer, args=(conn, label), daemon=True).start()
        server.close()

    def answer(conn, label):
        with conn:
            conn.settimeout(10)
            buffer = b""
            try:
                while True:
                    data = conn.recv(256)
                    if not data:
                        return
                    buffer += data
                    while b"\n" in buffer:
                        line, buffer = buffer.split(b"\n", 1)
                        conn.sendall(label.encode() + b":" + line + b"\n")
            except OSError:
                return

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    ready.wait(5)
    return stop


def ask(ns, address, port, line="hi", timeout=1.5):
    def run():
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        conn = socket.socket(family, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        try:
            conn.connect((address, port))
            conn.sendall(line.encode() + b"\n")
            return conn.recv(256).decode().strip()
        except socket.timeout:
            return "timeout"
        except ConnectionRefusedError:
            return "refused"
        except ConnectionResetError:
            return "reset"
        finally:
            conn.close()

    return in_ns(ns, run)


class Session:
    """A connection kept open in the client namespace."""

    def __init__(self, address, port):
        self.conn = in_ns("client", lambda: socket.create_connection((address, port), timeout=2))

    def say(self, line):
        try:
            self.conn.sendall(line.encode() + b"\n")
            return self.conn.recv(256).decode().strip()
        except OSError as e:
            return f"error: {e}"


def load(name):
    return sh("nft", "-f", f"{DATA}/{name}.nft", ns="router", check=False)


def marker():
    seen = set()
    for family in ("ip", "ip6"):
        listing = sh("nft", "-t", "list", "table", family, TABLE, ns="router", check=False).stdout
        start = listing.find('comment "zte-agent mihomo ')
        seen.add(listing[start + 9:listing.find('"', start + 9)] if start >= 0 else None)
    return seen.pop() if len(seen) == 1 else None


def expected(name):
    with open(f"{DATA}/{name}.marker") as f:
        return f.read().strip()


def topology():
    for ns in ("client", "router", "remote"):
        sh("ip", "netns", "add", ns)
        sh("ip", "link", "set", "lo", "up", ns=ns)
    sh("ip", "link", "add", "br-lan", "netns", "router", "type", "veth", "peer", "name", "c0", "netns", "client")
    sh("ip", "link", "add", "wan0", "netns", "router", "type", "veth", "peer", "name", "r0", "netns", "remote")
    for ns, link, v4, v6 in (("client", "c0", "192.168.0.23/24", "fd00:1::23/64"), ("router", "br-lan", "192.168.0.1/24", "fd00:1::1/64"), ("router", "wan0", "203.0.113.1/24", "2001:db8::1/64"), ("remote", "r0", "203.0.113.10/24", "2001:db8::10/64")):
        sh("ip", "addr", "add", v4, "dev", link, ns=ns)
        sh("ip", "-6", "addr", "add", v6, "dev", link, "nodad", ns=ns)
        sh("ip", "link", "set", link, "up", ns=ns)
    sh("ip", "addr", "add", "198.51.100.10/32", "dev", "lo", ns="remote")
    for ns, v4, v6 in (("client", "192.168.0.1", "fd00:1::1"), ("remote", "203.0.113.1", "2001:db8::1"), ("router", "203.0.113.10", "2001:db8::10")):
        sh("ip", "route", "add", "default", "via", v4, ns=ns)
        sh("ip", "-6", "route", "add", "default", "via", v6, ns=ns)
    sh("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1", ns="router")
    for family, everything in (("-4", "default"), ("-6", "::/0")):
        sh("ip", family, "route", "add", "local", everything, "dev", "lo", "table", "60625", ns="router")
        sh("ip", family, "rule", "add", "pref", "18620", "fwmark", "0x700/0xff00", "lookup", "60625", ns="router")
    for ns, gateway, link in (("client", "fd00:1::1", "c0"), ("router", "2001:db8::10", "wan0")):
        def solicit():
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as probe:
                probe.sendto(b"ready", (gateway, 9))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            in_ns(ns, solicit)
            neighbor = sh("ip", "-6", "neigh", "show", "to", gateway, "dev", link, ns=ns).stdout
            if "lladdr" in neighbor:
                break
            time.sleep(0.05)
        else:
            raise RuntimeError("IPv6 fixture gateway did not resolve")


def tables_and_data_plane():
    remote = [serve("remote", socket.AF_INET, "0.0.0.0", 80, "remote"), serve("remote", socket.AF_INET, "0.0.0.0", 17894, "remote17894"), serve("remote", socket.AF_INET6, "::", 80, "remote6")]
    for name in ("guard", "hold", "full", "full-both", "reject"):
        done = load(name)
        report(f"{name} loads and reads back", done.returncode == 0 and marker() == expected(name), done.stderr.strip())
    before = marker()
    done = load("broken")
    report("an invalid IPv6 half changes neither family", done.returncode != 0 and marker() == before, f"marker {marker()}")

    load("hold")
    core = [serve("router", socket.AF_INET, "0.0.0.0", 17894, "core", True), serve("router", socket.AF_INET6, "::", 17894, "core6", True)]
    report("hold: IPv4 goes to the core", ask("client", "198.51.100.10", 80) == "core:hi")
    report("hold: a would-be DIRECT range goes to the core", ask("client", "203.0.113.10", 80) == "core:hi")
    answer = ask("client", "2001:db8::10", 80)
    report("hold: IPv6 goes to the core", answer == "core6:hi", answer)
    for stop in core:
        stop.set()
    time.sleep(0.5)
    for address in ("198.51.100.10", "2001:db8::10"):
        got = ask("client", address, 80)
        report(f"no listener: {address} is dropped, never direct", got == "timeout", got)

    core = [serve("router", socket.AF_INET, "0.0.0.0", 17894, "core", True), serve("router", socket.AF_INET6, "::", 17894, "core6", True)]
    load("full")
    report("full: the DIRECT range goes direct", ask("client", "203.0.113.10", 80) == "remote:hi")
    report("full: the rest goes to the core", ask("client", "198.51.100.10", 80) == "core:hi")
    got = ask("client", "198.51.100.10", 17894)
    report("full: a new SYN to a proxied port 17894 is intercepted", got == "core:hi", got)
    held = Session("198.51.100.10", 80)
    first = held.say("one")
    load("full-both")
    second = held.say("two")
    report("a connection the core holds keeps reaching it after its range turns DIRECT", (first, second) == ("core:one", "core:two"), f"{first} / {second}")
    report("new connections to the new DIRECT range go direct", ask("client", "198.51.100.10", 80) == "remote:hi")
    got = ask("client", "198.51.100.10", 17894)
    report("a new SYN to remote port 17894 in a DIRECT range is not taken by the wildcard listener", got == "remote17894:hi", got)

    load("reject")
    started = time.monotonic()
    got = ask("client", "198.18.0.5", 80)
    report("D3: fake-ip TCP is reset at once", got in ("refused", "reset") and time.monotonic() - started < 1.0, got)

    def udp():
        conn = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        conn.settimeout(1.0)
        conn.connect(("198.18.0.5", 5353))
        conn.send(b"x")
        try:
            conn.recv(16)
            return "answered"
        except ConnectionRefusedError:
            return "refused"
        except socket.timeout:
            return "timeout"

    got = in_ns("client", udp)
    report("D3: fake-ip UDP is refused at once", got == "refused", got)
    report("D3: everything else goes direct", ask("client", "198.51.100.10", 80) == "remote:hi")
    for stop in core + remote:
        stop.set()


def boot_id():
    with open("/proc/sys/kernel/random/boot_id") as f:
        return f.read().strip()


def sysctl(key):
    with open(f"/proc/sys/net/ipv4/{key}") as f:
        return f.read().strip()


def engage(boot):
    """The kernel state a running Mihomo leaves, and its journal."""
    sh("ip", "netns", "exec", "router", "sh", "-c", ":")
    for family, everything in (("-4", "default"), ("-6", "::/0")):
        sh("ip", family, "route", "replace", "local", everything, "dev", "lo", "table", "60625", ns="router")
        if "18620:" not in sh("ip", family, "rule", "show", ns="router").stdout:
            sh("ip", family, "rule", "add", "pref", "18620", "fwmark", "0x700/0xff00", "lookup", "60625", ns="router")
    load("full")
    original = in_ns("router", lambda: {key: sysctl(key) for key in ("tcp_pacing_ss_ratio", "tcp_pacing_ca_ratio")})
    in_ns("router", lambda: [open(f"/proc/sys/net/ipv4/{key}", "w").write("1000") for key in original])
    with open(f"{DATA}/journal.json") as f:
        journal = json.load(f)
    expected = [
        {"program": "@u60-sysctl", "args": [key, "{" + key + "}"]}
        for key in ("tcp_pacing_ss_ratio", "tcp_pacing_ca_ratio", "bridge-nf-call-iptables", "bridge-nf-call-ip6tables")
    ]
    for family, destination in (("-4", "default"), ("-6", "::/0")):
        expected.extend([
            {"program": "ip", "args": [family, "route", "del", "local", destination, "dev", "lo", "table", "60625"]},
            {"program": "ip", "args": [family, "rule", "del", "pref", "18620", "fwmark", "0x700/0xff00", "lookup", "60625"]},
        ])
    expected.append({"program": "@u60-mihomo-nft", "args": ["remove"]})
    if journal["undo"] != expected:
        raise RuntimeError("EffectSet start journal differs from ef58bd4")
    undo = []
    for cmd in journal["undo"]:
        if cmd["program"] == "@u60-sysctl":
            key = cmd["args"][0]
            if key not in original:
                continue
            cmd = {"program": cmd["program"], "args": [key, original[key]]}
        undo.append(cmd)
    os.makedirs(ROOT, exist_ok=True)
    with open(f"{ROOT}/network.json", "w") as f:
        json.dump({"boot": boot, "undo": undo}, f)
    return original


def clean_state(original):
    rules = [sh("ip", family, "rule", "show", ns="router").stdout for family in ("-4", "-6")]
    routes = [sh("ip", family, "route", "show", "table", "all", ns="router").stdout for family in ("-4", "-6")]
    tables = [sh("nft", "-t", "list", "table", family, TABLE, ns="router", check=False).returncode for family in ("ip", "ip6")]
    values = in_ns("router", lambda: {key: sysctl(key) for key in original})
    return (not any("18620:" in r for r in rules), not any("table 60625" in r for r in routes), all(code != 0 for code in tables), values == original, not os.path.exists(f"{ROOT}/network.json"))


def rollback(agent, label):
    original = engage(boot_id())
    done = sh(agent, "network-recover", ns="router", check=False)
    state = clean_state(original)
    report(f"{label} rolls this version's journal back completely", done.returncode == 0 and all(state), f"exit {done.returncode} {done.stderr.strip()[:200]} rules,routes,tables,sysctls,journal={state}")


def main():
    topology()
    tables_and_data_plane()
    for agent, label in (("/old-agent", "the previous agent"), ("/new-agent", "this agent")):
        if os.path.exists(agent):
            rollback(agent, label)
        else:
            report(f"{label} binary present", False, agent)
    # Another boot's journal is dropped, never replayed.
    original = engage("00000000-0000-0000-0000-000000000000")
    done = sh("/new-agent", "network-recover", ns="router", check=False)
    rules = sh("ip", "-4", "rule", "show", ns="router").stdout
    report("another boot's journal is dropped, not replayed", done.returncode == 0 and "18620:" in rules and not os.path.exists(f"{ROOT}/network.json"), rules)
    del original
    shutil.rmtree(ROOT, ignore_errors=True)
    print(json.dumps({"failed": FAILED}), flush=True)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
