# Agent documentation

## Current network references

| Topic | Reference |
| --- | --- |
| Operating Wi-Fi Relay, Mihomo and Tailscale | [Network extensions](network-extensions.md) and [API routes](network-extensions.md#routes) |
| Architecture and recovery | [Relay and Mihomo architecture](relay-mihomo-architecture.md) and [relay lifecycle](relay-lifecycle.md) |
| Product defaults and limits | [Mihomo and relay behavior](mihomo-relay-prd.md) |
| IPA hardware forwarding | [Relay hardware offload](relay-hw-offload.md) |
| USB networking | [USB network and ADB](usb-network.md) |
| Console, live data and authentication | [Responsive console](responsive-console.md), [event protocol](events.md) and [security policy](../../SECURITY.md) |
| Installation and online updates | [First-time setup](../../README.md#first-time-setup) and [OTA recovery](../../docs/ota-updates.md#failure-behavior) |

## Network source locations

- [`common.rs`](../src/common.rs) owns `hex_lower` and `panic_message`. [`netfx/netlink.rs`](../src/netfx/netlink.rs) opens the Linux routing socket used by neighbour and Mihomo egress queries.
- Tailscale version discovery and updates are in [`tailscale/update.rs`](../src/tailscale/update.rs), with [update tests](../src/tailscale/update/tests.rs). [`tailscale/localapi.rs`](../src/tailscale/localapi.rs) reads daemon status, and [`tailscale/supervisor.rs`](../src/tailscale/supervisor.rs) owns daemon supervision and uplink watching.
- Relay scan records are parsed in [`wifi_relay/bss.rs`](../src/wifi_relay/bss.rs). IPv4 lease parsing and its client callback live in [`wifi_relay/dhcp.rs`](../src/wifi_relay/dhcp.rs). [`wifi_relay/ipv6/lease.rs`](../src/wifi_relay/ipv6/lease.rs) handles IPv6 lease parsing, expiry and callbacks.
- Test directory helpers live alongside the [relay](../src/wifi_relay/test_dir.rs) and [Mihomo](../src/mihomo/test_dir.rs) tests.

## ADB debugging

Set `ANDROID_SERIAL` to the intended device from `adb devices -l` and keep
it set throughout the session. The management page is
`http://192.168.0.1:9090/console/`. To read the log, identify the executable and
inspect kernel messages, run the following on the development host. On B31,
`logread` reports “Failed to find log object”.

```sh
adb shell 'tail -n 100 /tmp/zte-agent.log'
adb shell 'p=$(cat /tmp/zte-agent-run/pid); readlink "/proc/$p/exe"'
adb shell 'dmesg | tail -n 100'
```

Use `adb shell 'tail -f /tmp/zte-agent.log'` to follow the log and Ctrl-C to
end it. To read API status using the per-start loopback token, use a subshell
with tracing disabled and let ADB assign the local port. The trap removes the
forward when the subshell exits.

```sh
(
  set +x
  port=$(adb forward tcp:0 tcp:9090) || exit 1
  trap 'adb forward --remove "tcp:$port" >/dev/null' EXIT
  token=$(adb shell cat /tmp/zte-agent-run/admin-token | tr -d '\r\n')
  test -n "$token" || exit 1
  curl --noproxy '*' -sS -H "Authorization: Bearer $token" \
    "http://127.0.0.1:$port/api/wifi-relay/status"
)
```

On the router, `/usr/bin/mtdev2tuio.sh` loads `sitronix-ts.ko` for the
Sitronix touch controller at I2C `1-0055` and starts the bridge. See the
[daemon sync checks and recovery commands](../../CLAUDE.md#critical-zte-daemon-sync-barrier)
when the boot logo persists.

## Tests and QA

Run these from the repository root on the development host. The [pull request workflow](../../.github/workflows/test.yml) runs the host and browser jobs.

| Check | Entry point | Where it runs |
| --- | --- | --- |
| Rust unit and integration tests | `cargo test --locked -p zte-agent --no-fail-fast`. To run only the factory-password startup integration test, use `cargo test --locked -p zte-agent --test auth-startup`. | CI host job and local host |
| Pure console fixtures | `node scripts/test-agent.cjs pure` or a suite name such as `dns-model`. | CI host job and local host |
| Zashboard browser bootstrap | `node --test zte-agent/tests/mihomo-dashboard.cjs` or runner entry `mihomo-dashboard`. | CI host job and local host |
| Installer tests | `python3 -m unittest scripts/test_install_agent.py` or runner entry `install-agent`. | CI host job and local host |
| Console browser fixtures | `NODE_PATH=/absolute/path/to/node_modules node scripts/test-agent.cjs browser` or a suite name such as `relay`. | CI browser job and local host with Playwright and Chrome. `navigation` also needs WebKit. |
| Screenshots | Use the runner entry `screenshots` for the full gallery, or use the [gallery capture commands](../ui/screenshots/README.md) to select captures. Set `U60_NUMBER_SCREENSHOT` to an output file to save a frame from the `numbers` suite. | Local, opt-in artifacts |

Install Playwright in a local directory and set `NODE_PATH` to its `node_modules`
when it is outside the repository. The [browser helper](../ui/tests/browser.cjs)
checks that the required browsers launch. Set `PLAYWRIGHT_WEBKIT_EXECUTABLE`
to the executable in an installed WebKit bundle to override the default.
Running `node scripts/test-agent.cjs` without an entry prints all suite names.
The Rust TLS bridge and DoH listener fixtures use OS-assigned ports. Conntrack
batching tests use isolated state.

| Manual QA | Environment and scope |
| --- | --- |
| [Relay firewall and Mihomo coexistence](../tests/relay-firewall-qa/README.md) | Privileged, network-isolated Docker on ARM64 Linux. Uses the relay and Mihomo exports with real nftables and legacy iptables. |
| [Mihomo table and journal checks](../tests/mihomo-qa/README.md) | Privileged, network-isolated Docker on ARM64 Linux for tables and rollback. The separate hot-reload check uses a real host-native Mihomo core on loopback without Docker. |
| [IPv6 relay and DHCP reservations](../tests/relay-ipv6/README.md) | Privileged, network-isolated Docker on ARM64 Linux. Lifecycle and runtime RA use an OpenWrt chroot. Reservations need an ARM64 OpenWrt container with UCI, dnsmasq and udhcpc. The outer Debian image alone lacks those tools. B31 RA and the real port-9090 panel are separate device checks. |
| [Admission probe](../../scripts/probe-admission.sh) | Authorized B31 over USB with `ANDROID_SERIAL` set. Uses a temporary ADB-assigned forward and the per-start token without printing it. Invalid PUT bodies reach the admission checks and stop before a configuration write. |
| [Relay Internet probe](../../scripts/check-relay-internet.sh) | Authorized B31 over USB with an active relay. Generates external traffic. HTTP and ICMP bind to `ath20`; DNS targets the relay gateway. See the [hotel checks](network-extensions.md#hotel-authentication). |

## Device acceptance

Results apply to the stated build, firmware and topology. The harness READMEs
contain the reproducible commands and their isolation boundaries.

| Area | Recorded evidence and checks still needed |
| --- | --- |
| Relay and firewall | [B31 batch 5](archive/2026-11-12-relay-mihomo-implementation.md#batch-5) records relay controller and namespace checks. Owner Connect during boot join and the full physical failure matrix still need coverage on that build. Check both hotspot bands, DHCP renewal, portal authorization, full-cycle upstream isolation, uplink loss and suspend/restart. See the [isolated firewall harness](../tests/relay-firewall-qa/README.md). |
| Wi-Fi relay and IPA | [B31 batch 3](archive/2026-11-12-relay-mihomo-implementation.md#batch-3) measured 2.4 and 5 GHz upstreams through the Mac's USB network. Repeat with real hotspot clients and on the final batch 5 build. The namespace HTTP 200 in [batch 5](archive/2026-11-12-relay-mihomo-implementation.md#batch-5) establishes connectivity in that topology. |
| Mihomo and Zashboard | [B31 batch 4](archive/2026-11-12-relay-mihomo-implementation.md#batch-4) records a successful subscription hot reload. B31 failure fallback, real LAN node traffic over IPv4/IPv6 TCP and UDP, provider writes and dashboard access across login, logout and expiry need scoped runs. See the [Mihomo harness](../tests/mihomo-qa/README.md) for local-core and isolated checks. |
| Relay IPv6 | The [October runtime RA record](archive/2026-10-27-relay-ipv6-validation.md#2026-10-27-runtime-ra-update) covers the controlled AP and B31 build used there. Retest with a dual-stack controlled AP and physical clients on both hotspot bands. Include TCP/UDP, small MTU and PMTU, pre-existing and changing external RA state, lease loss/renewal and withdrawal, and preserved IPv4 with cellular IPv6 blocked. Test hotel IPv6 authorization separately. See the [IPv6 harness](../tests/relay-ipv6/README.md). |
| USB | The [USB validation record](usb-network.md#验证记录) identifies the single- and dual-configuration builds. Physical unplug/replug and cold boot on both platforms, Windows release networking and fresh Windows ADB driver binding remain open. |

Additional B31 checks still needed include long idle, sustained throughput and thermal
tests, standby/resume, a cold start with an unavailable upstream, and repetition
on a second device. The [historical acceptance matrix](archive/2026-10-network-extension-validation.md#acceptance-still-required-on-the-u60)
captures the original scenarios.

## Historical records

- [October 2026 network extension validation and retired bandwidth experiments](archive/2026-10-network-extension-validation.md)
- [2026-10-25 IPv6/NAT66 feasibility assessment](archive/2026-10-25-relay-ipv6-nat-assessment.md)
- [2026-10-26–27 IPv6 validation](archive/2026-10-27-relay-ipv6-validation.md)
- [2026-10-27 relay and cellular recovery proposal](archive/2026-10-27-relay-cellular-recovery-plan.md)
- [2026-10-26–28 network integration review](archive/2026-10-28-network-integration-review.md)
- [2026-10-29 bandwidth tuning acceptance](archive/2026-10-29-width-v2-acceptance.md)
- [2026-11-03 DFS acceptance](archive/2026-11-03-dfs-acceptance.md)
- [2026-11-10 refactor plan](archive/2026-11-10-relay-mihomo-refactor-plan.md)
- [2026-11 relay hardware forwarding benchmarks](archive/2026-11-relay-offload-benchmarks.md)
- [2026-11-12 B31 fw3 integration experiments](archive/2026-11-12-fw3-integration-experiments.md)
- [Through 2026-11-12, implementation and B31 acceptance by batch](archive/2026-11-12-relay-mihomo-implementation.md)
- Research notes on [Wi-Fi throughput](../../docs/research/2026-11-03-wifi-throughput-diagnosis.md) and [Mihomo TPROXY](../../docs/research/2026-11-08-mihomo-tproxy-single-flow.md)
- [Retired server-rendered UI design](web-ui.md)
