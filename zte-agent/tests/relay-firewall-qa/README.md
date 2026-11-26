# Relay firewall layout: isolated Linux acceptance (v5)

Disposable checks for [v5 of the refactor plan](../../docs/archive/2026-11-10-relay-mihomo-refactor-plan.md#v5) that need a real
Linux kernel, real `nft` and legacy `iptables` (as on B31), but no router:
the exact batches the agent loads, exported from the production generators
(`uplink::tables` through the set's `NftTables` batch, the restore inputs
and journals actually written by `EffectSet`, whole-chain/hook repairs and
portal RETURN moves), on four network namespaces (`client` on `br-lan`,
`upstream` on `ath20`, `cell` on `rmnet_data0`, `router` between them).
**Never run this on the U60, a host or a shared container**: it creates
namespaces, replaces the container's `iptables*` with the legacy build and
writes `/data/zte-agent-relay`. Use a disposable ARM64 Linux Docker VM.
The command below mounts both agent binaries, both fixture exports and the
shared namespace helper read-only.

```sh
QA="$(mktemp -d)"
U60_RELAY_QA="$QA" cargo test --locked -p zte-agent export_relay_firewall_for_isolated_linux_acceptance -- --ignored
MIHOMO_QA="$(mktemp -d)"
U60_MIHOMO_QA="$MIHOMO_QA" cargo test --locked -p zte-agent export_for_isolated_linux_acceptance -- --ignored
cargo build --locked --release --target aarch64-unknown-linux-musl -p zte-agent
# $OLD_AGENT: the previous agent (the one an update may roll back to), built
# the same way from `git archive <commit>` into its own target directory.
docker build -t u60-relay-ipv6-qa:local zte-agent/tests/relay-ipv6
docker run --rm --privileged --network none \
  -e PYTHONPATH=/qa-common -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$PWD/zte-agent/tests/qa_netns.py:/qa-common/qa_netns.py:ro" \
  -v "$PWD/zte-agent/tests/relay-firewall-qa:/qa:ro" -v "$QA:/qa-data:ro" \
  -e U60_MIHOMO_QA_DATA=/mihomo-data -v "$MIHOMO_QA:/mihomo-data:ro" \
  -v "$PWD/target/aarch64-unknown-linux-musl/release/zte-agent:/new-agent:ro" \
  -v "$OLD_AGENT:/old-agent:ro" \
  u60-relay-ipv6-qa:local python3 /qa/qa.py
```

The [final batch 5 run](../../docs/archive/2026-11-12-relay-mihomo-implementation.md#batch-5) passed 39/39 checks in
isolated Linux using `ef58bd4` as the previous agent for that run. That count
belongs to the batch 5 build. The current harness covers the following cases.

- Each layout (guard, IPv6 discovery, routes, NAT66 with and without an
  upstream resolver) passes `nft -c`, loads as one two-family batch and its
  marker reads back from both families; a batch with an invalid IPv6 half
  changes neither family.
- The legacy restore transactions apply with `iptables-restore --noflush
  --wait 2` to the owned chains, which hold accepts only; applying one again
  fails without taking over or flushing the existing chain.
- A damaged owned chain is replaced whole, restoring its content and order.
  A doubled FORWARD hook becomes one copy. A foreign `U60_*` chain is
  refused with its contents intact.
- Guard: the upstream cannot reach TCP 9090 over either family. DHCP offers
  (67 → 68) reach the client socket, unrelated UDP on that socket is dropped,
  the forwarding probe is blocked and IPv6 DHCP stays closed until discovery.
- Routes: LAN IPv4 reaches the upstream (nft masquerade); the upstream
  cannot open connections to the LAN or the router; LAN and router IPv6 to
  `rmnet*` is rejected at once; LAN IPv6 does not leave without NAT66; LAN
  and router DNS go to the Wi-Fi resolver, DNS to the router stays local.
  The dual-stack core socket mark preserves its original DNS destination. The
  vendor portal mark 8880 alone selects the Wi-Fi resolver in both families.
- NAT66: an approved LAN source leaves as the relay address and gets its
  reply; another source and new upstream connections do not; DHCPv6
  replies pass and upstream TCP 9090 stays closed. LAN IPv6 DNS is answered locally,
  the router's goes upstream or is rejected without a resolver.
- With `U60_MIHOMO_QA_DATA` set, the relay's full layout and accept-only
  legacy chains run with legacy FORWARD policies set to DROP. Fresh dual-stack
  LAN UDP/TCP DNS connections reach the fixture core in Mihomo Full and Hold.
  In FakeReject and after the core tables are withdrawn they use relay DNS
  (the upstream resolver for IPv4 and the router for IPv6). Marked OUTPUT DNS
  keeps its original destination in all four states, and LAN and router
  traffic to `rmnet*` over IPv6 is refused. The listeners stand in for the core.
- The portal check loads Mihomo Full when the export is mounted. One restore
  transaction moves a late RETURN ahead of the vendor DNAT so LAN web traffic
  skips the redirect. A missing RETURN is also inserted first.
- Rollback: the previous agent's and this agent's `network-recover` undo
  this version's relay journals completely (both nft tables, owned legacy
  chains, the portal RETURN and journals). The harness also checks for residual
  legacy MASQUERADE rules after recovery. The active IPv4 masquerade is in `nat4`.

Device acceptance still covers actual ZTE firewall rewrites and rejects, real
DHCP/RA, IPA, sysctl sampling timing and relay coexistence with the real core.
