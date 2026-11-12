# Mihomo tables and journal: isolated Linux acceptance (v2)

Disposable checks for `relay-mihomo-refactor-plan.md` v2 that need a real
Linux kernel and real `nft`/`ip`, but no router and no Mihomo core: the
exact table batches the agent loads (exported from the production
generators), a transparent listener standing in for the core, and the
agent binaries' `network-recover`. **Never run this on the U60, a host or a
shared container**: it creates network namespaces and changes their
routing. Use a disposable Docker VM (`--privileged --network none`).

```sh
QA="$(mktemp -d)"
U60_MIHOMO_QA="$QA" cargo test -p zte-agent export_for_isolated_linux_acceptance -- --ignored
cargo build --locked --release --target aarch64-unknown-linux-musl -p zte-agent
# The previous agent (the one an update may roll back to), built the same way
# from `git archive <commit>` into its own target directory: $OLD_AGENT.
docker build -t u60-relay-ipv6-qa:local zte-agent/tests/relay-ipv6
docker run --rm --privileged --network none \
  -v "$PWD/zte-agent/tests/mihomo-qa:/qa:ro" -v "$QA:/qa-data:ro" \
  -v "$PWD/target/aarch64-unknown-linux-musl/release/zte-agent:/new-agent:ro" \
  -v "$OLD_AGENT:/old-agent:ro" \
  u60-relay-ipv6-qa:local python3 /qa/qa.py
```

What it checks:

- Every exported batch loads with the real `nft` and its generation marker
  reads back from both families with `nft -t`; a batch whose IPv6 half is
  invalid changes neither family.
- With the hold table and a listener on 17894, LAN TCP over IPv4 and IPv6
  reaches the listener; without a listener it is dropped (TPROXY's
  `NFT_BREAK` skips only its own rule) and never reaches the remote host.
- With a DIRECT range, new connections to it go to the remote host and the
  rest to the listener; a connection the listener already holds keeps
  reaching it after its destination becomes DIRECT; a new SYN to a remote
  port 17894 inside a DIRECT range goes to the remote host, not to the
  listener's wildcard socket.
- D3: fake-ip TCP is reset and UDP refused at once, everything else goes
  direct.
- Rollback: a journal this version writes (kernel settings, policy routes,
  tables) is undone completely by the previous agent's and by this agent's
  `network-recover`; a journal from another boot is dropped, not replayed.

The `qa.py` checks above do not cover the real core (DNS, fake-ip, provider
refreshes), IPA or ZTE's firewall rewrites. The local real-core check below
has a separate, narrower scope; it does not replace device acceptance.

## Real-core hot reload (2026-11-12)

`hot_reload.py` needs Python 3 with its standard library, an executable Mihomo
v1.19.33 built for the development host, free loopback TCP/UDP ports and the
existing writable directory `/tmp/u60-test/work`. It requires no router, Docker,
root privileges, paid node or Internet service. From the repository root:

```sh
mkdir -p /tmp/u60-test/work
python3 zte-agent/tests/mihomo-qa/hot_reload.py /absolute/path/to/mihomo
```

The script creates a private temporary core directory under that fixed test
folder, a loopback echo server, a controller, an HTTP proxy and a fake-ip DNS
listener. It enables persistent selected/fake-ip state and checks that the core
creates `cache.db`. An HTTP CONNECT TCP connection echoes before and after
`PUT /configs?force=false` changes `MATCH,DIRECT` to `MATCH,REJECT`; a new
connection through the retained listener must obey REJECT. The same core stays
alive. A second reload must preserve the fake-ip mapping established after the
first reload. The core is terminated and the temporary directory removed on exit.

The JSON result includes `existing_tcp_survives`, `listener_kept`,
`new_rules_applied`, `subsequent_fake_ip_preserved` and
`first_reload_fake_ip_preserved`. The first four are checked by assertions;
the last is reported, not required to be true: Mihomo v1.19.33 can clear its
fake-ip pool on the first reload with a brand-new persistent cache
(`component/fakeip/pool.go::restoreState`). That limitation was reproduced
locally and is not worked around. This script does not test the agent's
controller/fallback, nft TPROXY, UDP/QUIC continuity, provider failures, long-run
memory or the router's IPA. Router refresh evidence, unit-test coverage and
remaining gaps are in [implementation batch 4](../../docs/relay-mihomo-implementation.md#batch-4).
