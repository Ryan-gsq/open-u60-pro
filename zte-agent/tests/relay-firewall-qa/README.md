# Relay firewall layout: isolated Linux acceptance (v5)

Disposable checks for `relay-mihomo-refactor-plan.md` v5 that need a real
Linux kernel, real `nft` and legacy `iptables` (as on B31), but no router:
the exact batches the agent loads, exported from the production generators
(`uplink::tables` through the set's `NftTables` batch, the restore inputs
and journals actually written by `EffectSet`, whole-chain/hook repairs and
portal RETURN moves), on four network namespaces (`client` on `br-lan`,
`upstream` on `ath20`, `cell` on `rmnet_data0`, `router` between them).
**Never run this on the U60, a host or a shared container**: it creates
namespaces, replaces the container's `iptables*` with the legacy build and
writes `/data/zte-agent-relay`. Use a disposable Docker VM.

```sh
QA="$(mktemp -d)"
U60_RELAY_QA="$QA" cargo test -p zte-agent export_relay_firewall_for_isolated_linux_acceptance -- --ignored
cargo build --locked --release --target aarch64-unknown-linux-musl -p zte-agent
# $OLD_AGENT: the previous agent (the one an update may roll back to), built
# the same way from `git archive <commit>` into its own target directory.
docker build -t u60-relay-ipv6-qa:local zte-agent/tests/relay-ipv6
docker run --rm --privileged --network none \
  -v "$PWD/zte-agent/tests/relay-firewall-qa:/qa:ro" -v "$QA:/qa-data:ro" \
  -v "$PWD/target/aarch64-unknown-linux-musl/release/zte-agent:/new-agent:ro" \
  -v "$OLD_AGENT:/old-agent:ro" \
  u60-relay-ipv6-qa:local python3 /qa/qa.py
```

The final batch 5 run passed 39/39 checks in isolated Linux, using the
`ef58bd4` build as the previous agent (`measurements/b5-final/summary.txt`
beside the handoff). The checks cover the following cases.

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
- Guard: the upstream reaches no router port (IPv4, IPv6) except DHCP
  67 -> 68; nothing is forwarded through the upstream; IPv6 stays closed
  until discovery.
- Routes: LAN IPv4 reaches the upstream (legacy MASQUERADE); the upstream
  cannot open connections to the LAN or the router; LAN and router IPv6 to
  `rmnet*` is rejected at once; LAN IPv6 does not leave without NAT66; LAN
  and router DNS go to the Wi-Fi resolver, DNS to the router stays local.
- NAT66: an approved LAN source leaves as the relay address and gets its
  reply; another source and new upstream connections do not; DHCPv6
  replies pass, router ports stay closed; LAN IPv6 DNS is answered locally,
  the router's goes upstream or is rejected without a resolver.
- Portal: a RETURN behind a vendor DNAT is moved first in one restore
  transaction, and LAN web traffic then skips the DNAT; a missing one is
  inserted first.
- Rollback: the previous agent's and this agent's `network-recover` undo
  this version's relay journals completely (tables, owned chains, portal
  RETURN, MASQUERADE, journals).

Not covered here: ZTE's own firewall (its rejects, fw3 reloads, flushes and
inserts ahead of the hooks), real DHCP/RA, IPA, the sysctl sampler's timing
and Mihomo together with the relay; those stay device acceptance.
