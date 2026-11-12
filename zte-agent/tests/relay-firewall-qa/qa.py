#!/usr/bin/env python3
"""Isolated acceptance for the relay's firewall layout (v5).

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
TABLE = "u60_relay"
JOURNAL = "/data/zte-agent-relay"
FAILED = []
LIBC = ctypes.CDLL(None, use_errno=True)
LEGACY = ["iptables", "ip6tables", "iptables-restore", "ip6tables-restore", "iptables-save", "ip6tables-save"]


def enter(ns):
    fd = os.open(f"/run/netns/{ns}", os.O_RDONLY)
    try:
        if LIBC.setns(fd, 0x40000000) != 0:  # CLONE_NEWNET
            raise OSError(ctypes.get_errno(), "setns")
    finally:
        os.close(fd)


def sh(*args, ns=None, check=True, stdin=None):
    command = (["ip", "netns", "exec", ns] if ns else []) + list(args)
    done = subprocess.run(command, capture_output=True, text=True, input=stdin)
    if check and done.returncode != 0:
        raise RuntimeError(f"{' '.join(command)}: {done.stderr.strip()}")
    return done


def report(name, ok, detail=""):
    print(json.dumps({"check": name, "ok": bool(ok), "detail": str(detail)[:300]}), flush=True)
    if not ok:
        FAILED.append(name)


def in_ns(ns, target, *args):
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


def serve(ns, family, address, port, label):
    """A TCP line server in `ns`: answers `<label>:<peer>:<line>`."""
    ready = threading.Event()
    stop = threading.Event()

    def run():
        enter(ns)
        server = socket.socket(family, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            server.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        server.bind((address, port))
        server.listen(16)
        server.settimeout(0.2)
        ready.set()
        while not stop.is_set():
            try:
                conn, peer = server.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(3)
                try:
                    line = conn.recv(256).decode().strip()
                    conn.sendall(f"{label}:{peer[0]}:{line}\n".encode())
                except OSError:
                    pass
        server.close()

    threading.Thread(target=run, daemon=True).start()
    ready.wait(5)
    return stop


def udp_listen(ns, family, address, port):
    """A UDP socket in `ns` that records the first datagram's source port."""
    got = {}
    ready = threading.Event()
    stop = threading.Event()

    def run():
        enter(ns)
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((address, port))
        sock.settimeout(0.2)
        ready.set()
        while not stop.is_set():
            try:
                _, peer = sock.recvfrom(64)
                got.setdefault("ports", []).append(peer[1])
            except socket.timeout:
                continue
        sock.close()

    threading.Thread(target=run, daemon=True).start()
    ready.wait(5)
    return got, stop


def send_udp(ns, family, source_port, address, port):
    def run():
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("::" if family == socket.AF_INET6 else "0.0.0.0", source_port))
        sock.sendto(b"x", (address, port))
        sock.close()

    in_ns(ns, run)


def ask(ns, address, port, source=None, timeout=1.5):
    """`<answer>`, `timeout`, `refused`/`reset`/`error: …` and how long it took."""
    def run():
        family = socket.AF_INET6 if ":" in address else socket.AF_INET
        conn = socket.socket(family, socket.SOCK_STREAM)
        conn.settimeout(timeout)
        if source:
            conn.bind((source, 0))
        started = time.monotonic()
        try:
            conn.connect((address, port))
            conn.sendall(b"hi\n")
            return conn.recv(256).decode().strip(), time.monotonic() - started
        except socket.timeout:
            return "timeout", time.monotonic() - started
        except ConnectionRefusedError:
            return "refused", time.monotonic() - started
        except ConnectionResetError:
            return "reset", time.monotonic() - started
        except OSError as e:
            return f"error: {e.strerror}", time.monotonic() - started
        finally:
            conn.close()

    return in_ns(ns, run)


def rejected(answer):
    """An ICMP error came back (not a silent drop, not a connection). The
    first error of a fresh namespace may be rate limited: the SYN sent again
    after 1 s gets it, inside the 1.5 s an unanswered try waits."""
    got, took = answer
    return got in ("refused", "reset") or got.startswith("error: "), took < 1.5


def twice(ns, address, port, source=None):
    return [ask(ns, address, port, source=source) for _ in range(2)]


def legacy_tools():
    """B31 runs iptables-legacy: the agents' `iptables*` resolve to it here."""
    os.makedirs("/usr/local/sbin", exist_ok=True)
    for name in LEGACY:
        link = f"/usr/local/sbin/{name}"
        if not os.path.exists(link):
            os.symlink("/usr/sbin/xtables-legacy-multi", link)


def topology():
    for ns in ("client", "router", "upstream", "cell"):
        sh("ip", "netns", "add", ns)
        sh("ip", "link", "set", "lo", "up", ns=ns)
    for router_side, peer, peer_ns in (("br-lan", "c0", "client"), ("ath20", "u0", "upstream"), ("rmnet_data0", "m0", "cell")):
        sh("ip", "link", "add", router_side, "netns", "router", "type", "veth", "peer", "name", peer, "netns", peer_ns)
    addresses = (
        ("client", "c0", ["192.168.0.23/24", "fd12:3456:789a::23/64", "fd99::23/64"]),
        ("router", "br-lan", ["192.168.0.1/24", "fd12:3456:789a::1/64", "fd99::1/64"]),
        ("router", "ath20", ["10.20.0.7/24", "2001:db8:20::7/64"]),
        ("upstream", "u0", ["10.20.0.1/24", "2001:db8:20::1/64"]),
        ("router", "rmnet_data0", ["100.100.0.2/24", "2001:db8:c::2/64"]),
        ("cell", "m0", ["100.100.0.1/24", "2001:db8:c::1/64"]),
    )
    for ns, link, cidrs in addresses:
        for cidr in cidrs:
            sh("ip", "addr", "add", cidr, "dev", link, *(["nodad"] if ":" in cidr else []), ns=ns)
        sh("ip", "link", "set", link, "up", ns=ns)
    sh("ip", "addr", "add", "2001:db8:99::1/128", "dev", "lo", ns="cell")
    routes = (
        ("client", ["default", "via", "192.168.0.1"]),
        ("client", ["-6", "default", "via", "fd12:3456:789a::1"]),
        ("router", ["default", "via", "10.20.0.1", "dev", "ath20"]),
        ("router", ["-6", "default", "via", "2001:db8:20::1", "dev", "ath20"]),
        ("router", ["-6", "2001:db8:99::/64", "via", "2001:db8:c::1", "dev", "rmnet_data0"]),
        ("upstream", ["192.168.0.0/24", "via", "10.20.0.7"]),
        ("upstream", ["-6", "fd12:3456:789a::/64", "via", "2001:db8:20::7"]),
        ("cell", ["default", "via", "100.100.0.2"]),
        ("cell", ["-6", "default", "via", "2001:db8:c::2"]),
    )
    for ns, route in routes:
        family = [route.pop(0)] if route[0] == "-6" else []
        sh("ip", *family, "route", "add", *route, ns=ns)
    sh("sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1", ns="router")


def load(name):
    return sh("nft", "-f", f"{DATA}/{name}.nft", ns="router", check=False)


def marker():
    seen = set()
    for family in ("ip", "ip6"):
        listing = sh("nft", "-t", "list", "table", family, TABLE, ns="router", check=False).stdout
        start = listing.find('comment "zte-agent relay ')
        seen.add(listing[start + 9:listing.find('"', start + 9)] if start >= 0 else None)
    return seen.pop() if len(seen) == 1 else None


def expected(name):
    with open(f"{DATA}/{name}.marker") as f:
        return f.read().strip()


def tables_load():
    for name in ("guard", "discovery", "relay", "full", "full-nodns"):
        checked = sh("nft", "-c", "-f", f"{DATA}/{name}.nft", ns="router", check=False)
        done = load(name)
        report(f"{name}: nft -c passes, the two-family batch loads and its marker reads back", checked.returncode == 0 and done.returncode == 0 and marker() == expected(name), checked.stderr.strip() or done.stderr.strip())
    before = marker()
    done = load("broken")
    report("an invalid IPv6 half changes neither family", done.returncode != 0 and marker() == before, marker())


def restore_inputs():
    with open(f"{DATA}/restore.json") as f:
        inputs = json.load(f)
    results = [sh(r["program"], "--noflush", "--wait", "2", ns="router", check=False, stdin=r["input"]) for r in inputs]
    report("legacy restore transactions apply to the owned chains", all(r.returncode == 0 for r in results), [r.stderr.strip() for r in results if r.returncode])
    owned = {}
    for tool in ("iptables", "ip6tables"):
        for table in ("filter", "nat"):
            for line in sh(tool, "-w", "2", "-t", table, "-S", ns="router").stdout.splitlines():
                if line.startswith("-A U60_"):
                    owned.setdefault(f"{tool} {line.split()[1]}", []).append(line)
    targets = {line.split(" -j ")[-1] for lines in owned.values() for line in lines}
    report("owned legacy chains hold accepts only", targets <= {"ACCEPT", "U60_R6_IN"} and len(owned) == 5, json.dumps(owned))
    network = next(r for r in inputs if r["plan"] == "network")
    again = sh(network["program"], "--noflush", "--wait", "2", ns="router", check=False, stdin=network["input"])
    rules = [l for l in sh("iptables", "-w", "2", "-S", "U60_RELAY_FWD", ns="router").stdout.splitlines() if l.startswith("-A ")]
    report("an existing chain of that name is neither taken over nor flushed", again.returncode != 0 and len(rules) == 2, again.stderr.strip())


def data_plane():
    servers = [
        serve("upstream", socket.AF_INET, "0.0.0.0", 80, "up"),
        serve("upstream", socket.AF_INET6, "::", 80, "up6"),
        serve("upstream", socket.AF_INET, "0.0.0.0", 53, "hoteldns"),
        serve("upstream", socket.AF_INET6, "::", 53, "hoteldns6"),
        serve("router", socket.AF_INET, "0.0.0.0", 9090, "agent"),
        serve("router", socket.AF_INET6, "::", 9090, "agent6"),
        serve("router", socket.AF_INET, "0.0.0.0", 53, "routerdns"),
        serve("router", socket.AF_INET6, "::", 53, "routerdns6"),
        serve("client", socket.AF_INET, "0.0.0.0", 80, "client"),
        serve("client", socket.AF_INET6, "::", 80, "client6"),
        serve("cell", socket.AF_INET6, "::", 80, "cell6"),
    ]
    dhcp, stop_dhcp = udp_listen("router", socket.AF_INET, "0.0.0.0", 68)
    dhcp6, stop_dhcp6 = udp_listen("router", socket.AF_INET6, "::", 546)

    load("guard")
    for address in ("10.20.0.7", "2001:db8:20::7"):
        got = ask("upstream", address, 9090)
        report(f"guard: the upstream cannot reach the router's 9090 over {address}", got[0] == "timeout", got)
    send_udp("upstream", socket.AF_INET, 1234, "10.20.0.7", 68)
    send_udp("upstream", socket.AF_INET, 67, "10.20.0.7", 68)
    time.sleep(0.5)
    report("guard: DHCP offers (67 -> 68) pass, other UDP does not", dhcp.get("ports") == [67], dhcp)
    got = ask("client", "10.20.0.1", 80)
    report("guard: nothing is forwarded to the upstream before routes", got[0] == "timeout", got)
    send_udp("upstream", socket.AF_INET6, 547, "2001:db8:20::7", 546)
    time.sleep(0.5)
    report("guard: upstream IPv6 stays closed before discovery (DHCPv6 too)", not dhcp6.get("ports"), dhcp6)

    load("relay")
    got = ask("client", "10.20.0.1", 80)
    report("relay: LAN IPv4 reaches the upstream, masqueraded (legacy)", got[0] == "up:10.20.0.7:hi", got)
    got = ask("upstream", "192.168.0.23", 80)
    report("relay: a new connection from the upstream to the LAN is dropped", got[0] == "timeout", got)
    got = ask("upstream", "10.20.0.7", 9090)
    report("relay: the upstream still cannot reach the router's 9090", got[0] == "timeout", got)
    got = twice("client", "2001:db8:99::1", 80, source="fd12:3456:789a::23")
    report("relay: LAN IPv6 to cellular is rejected (before any exception)", all(all(rejected(g)) for g in got), got)
    got = twice("router", "2001:db8:99::1", 80)
    report("relay: the router's own IPv6 to cellular is rejected (one OUTPUT rule)", all(all(rejected(g)) for g in got), got)
    got = ask("client", "2001:db8:20::1", 80, source="fd12:3456:789a::23")
    report("relay: LAN IPv6 does not leave through the upstream without NAT66", got[0] == "timeout", got)
    got = ask("client", "8.8.8.8", 53)
    report("relay: LAN DNS goes to the Wi-Fi resolver", got[0] == "hoteldns:192.168.0.23:hi" or got[0].startswith("hoteldns:"), got)
    got = ask("client", "192.168.0.1", 53)
    report("relay: DNS to the router stays local", got[0].startswith("routerdns:"), got)
    got = ask("router", "8.8.8.8", 53)
    report("relay: the router's own DNS goes to the Wi-Fi resolver", got[0].startswith("hoteldns:"), got)

    load("full")
    got = ask("client", "2001:db8:20::1", 80, source="fd12:3456:789a::23")
    report("NAT66: an approved LAN source reaches the upstream as the relay address", got[0] == "up6:2001:db8:20::7:hi", got)
    got = ask("client", "2001:db8:20::1", 80, source="fd99::23")
    report("NAT66: another LAN source does not leave", got[0] == "timeout", got)
    got = ask("upstream", "fd12:3456:789a::23", 80)
    report("NAT66: a new connection from the upstream to the LAN is dropped", got[0] == "timeout", got)
    got = ask("client", "2001:db8:99::1", 80, source="fd12:3456:789a::23")
    report("NAT66: cellular is still rejected first", all(rejected(got)), got)
    send_udp("upstream", socket.AF_INET6, 547, "2001:db8:20::7", 546)
    time.sleep(0.5)
    report("discovery: DHCPv6 replies (547 -> 546) pass", dhcp6.get("ports") == [547], dhcp6)
    got = ask("upstream", "2001:db8:20::7", 9090)
    report("discovery: the upstream still cannot reach the router's 9090 over IPv6", got[0] == "timeout", got)
    got = ask("client", "2001:db8:5::53", 53, source="fd12:3456:789a::23")
    report("NAT66: LAN IPv6 DNS is answered by the router", got[0].startswith("routerdns6:"), got)
    got = ask("router", "2001:db8:5::53", 53)
    report("NAT66: the router's IPv6 DNS goes to the Wi-Fi resolver", got[0].startswith("hoteldns6:"), got)
    load("full-nodns")
    got = twice("router", "2001:db8:5::53", 53)
    report("NAT66 without a resolver: the router's IPv6 DNS is rejected", all(all(rejected(g)) for g in got), got)

    for stop in servers + [stop_dhcp, stop_dhcp6]:
        stop.set()


def chain_lines(tool, chain):
    return [l for l in sh(tool, "-w", "2", "-t", "nat", "-S", chain, ns="router").stdout.splitlines() if l.startswith("-A ")]


def portal():
    with open(f"{DATA}/portal.json") as f:
        moves = json.load(f)
    ours = "-A redirect_chain -i br-lan -m comment --comment zte-agent-wifi-relay -j RETURN"
    dnat = "-A redirect_chain -i br-lan -p tcp -m tcp --dport 80 -j DNAT --to-destination 192.168.0.1:8080"
    sh("iptables", "-w", "2", "-t", "nat", "-N", "redirect_chain", ns="router")
    sh("iptables", "-w", "2", "-t", "nat", "-A", "PREROUTING", "-j", "redirect_chain", ns="router")
    sh("iptables", "-w", "2", "-t", "nat", *dnat.split(), ns="router")
    sh("iptables", "-w", "2", "-t", "nat", *ours.split(), ns="router")
    time.sleep(0.5)  # the data plane's listeners close within 0.2 s
    up = serve("upstream", socket.AF_INET, "0.0.0.0", 80, "up")
    load("relay")
    before = ask("client", "10.20.0.1", 80)
    done = sh("iptables-restore", "--noflush", "--wait", "2", ns="router", check=False, stdin=moves["late"])
    lines = chain_lines("iptables", "redirect_chain")
    after = ask("client", "10.20.0.1", 80)
    report("portal: a RETURN behind the vendor DNAT is moved first in one transaction", done.returncode == 0 and lines == [ours, dnat] and before[0] == "refused" and after[0].startswith("up:"), f"{lines} {before} {after}")
    sh("iptables", "-w", "2", "-t", "nat", "-D", *ours.split()[1:], ns="router")
    done = sh("iptables-restore", "--noflush", "--wait", "2", ns="router", check=False, stdin=moves["absent"])
    report("portal: a missing RETURN is inserted first", done.returncode == 0 and chain_lines("iptables", "redirect_chain") == [ours, dnat], chain_lines("iptables", "redirect_chain"))
    up.set()


def boot_id():
    with open("/proc/sys/kernel/random/boot_id") as f:
        return f.read().strip()


def engage():
    """Everything this version applies for a relay with NAT66, and its journals."""
    for ns, link, cidr in (("router", "ath20", "10.20.0.7/24"), ("router", "br-lan", "fd12:3456:789a::1/64")):
        sh("ip", "addr", "replace", cidr, "dev", link, ns=ns)
    load("full")
    with open(f"{DATA}/restore.json") as f:
        for r in json.load(f):
            sh(r["program"], "--noflush", "--wait", "2", ns="router", check=False, stdin=r["input"])
    for tool in ("iptables", "ip6tables"):
        if sh(tool, "-w", "2", "-t", "nat", "-S", "redirect_chain", ns="router", check=False).returncode != 0:
            sh(tool, "-w", "2", "-t", "nat", "-N", "redirect_chain", ns="router")
        rule = ["redirect_chain", "-i", "br-lan", "-m", "comment", "--comment", "zte-agent-wifi-relay", "-j", "RETURN"]
        if sh(tool, "-w", "2", "-t", "nat", "-C", *rule, ns="router", check=False).returncode != 0:
            sh(tool, "-w", "2", "-t", "nat", "-I", rule[0], "1", *rule[1:], ns="router")
    os.makedirs(JOURNAL, exist_ok=True)
    for name in ("wireless", "network", "dns", "ipv6-setup", "ipv6-network"):
        with open(f"{DATA}/{name}.json") as f:
            journal = json.load(f)
        journal["boot"] = boot_id()
        with open(f"{JOURNAL}/{name}.json", "w") as f:
            json.dump(journal, f)


def clean():
    tables = all(sh("nft", "-t", "list", "table", family, TABLE, ns="router", check=False).returncode != 0 for family in ("ip", "ip6"))
    legacy = "".join(sh(tool, "-w", "2", "-t", table, "-S", ns="router").stdout for tool in ("iptables", "ip6tables") for table in ("filter", "nat"))
    chains = "U60_" not in legacy
    portal_gone = "zte-agent-wifi-relay" not in legacy
    masquerade = "-o ath20 -m comment --comment zte-agent-wifi-relay -j MASQUERADE" not in legacy
    journals = not any(os.path.exists(f"{JOURNAL}/{name}.json") for name in ("wireless", "network", "dns", "ipv6-setup", "ipv6-network"))
    return tables, chains, portal_gone, masquerade, journals


def rollback(agent, label):
    engage()
    done = sh(agent, "network-recover", ns="router", check=False)
    state = clean()
    report(f"{label} undoes this version's relay journals completely", done.returncode == 0 and all(state), f"exit {done.returncode} {done.stderr.strip()[-300:]} tables,chains,portal,masquerade,journals={state}")


def main():
    legacy_tools()
    topology()
    tables_load()
    restore_inputs()
    data_plane()
    portal()
    for agent, label in (("/old-agent", "the previous agent"), ("/new-agent", "this agent")):
        if os.path.exists(agent):
            rollback(agent, label)
        else:
            report(f"{label} binary present", False, agent)
    shutil.rmtree(JOURNAL, ignore_errors=True)
    print(json.dumps({"failed": FAILED}), flush=True)
    return 1 if FAILED else 0


if __name__ == "__main__":
    sys.exit(main())
