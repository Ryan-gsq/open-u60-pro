# Optional Rust network extensions (experimental)

This reference covers the optional on-router extensions at `08274c3`. See
[product behavior](mihomo-relay-prd.md) for defaults and scope, and
[device acceptance](README.md#device-acceptance) for B31 evidence and
remaining checks.

## Console pages

- **Network → Mihomo** has a start/stop switch and installs the optional
  core/dashboard. **Open Zashboard** is shown only while the agent owns a running
  core. Off also refuses dashboard/API URLs, removes interception and stops the
  owned child.
- The same page manages a private library of up to 16 complete Mihomo YAML
  profiles: HTTPS subscription download, manual or scheduled refresh, file import
  and paste. Supply your own nodes or proxy-providers; no account is included.
- **Network → Mihomo proxies** sets the routing mode, picks the node of each
  selector group and tests delay without leaving the console; **Open Zashboard**
  there gives the full dashboard.
- **Network → Wi-Fi Relay**: scan, select an upstream, enter a password,
  explicitly acknowledge hotspot interruption/cellular charges, connect and
  disconnect. A connected relay keeps a short unverified-network notice; there is
  no separate hotel-login card or external login shortcut.
- The console preselects **Remember this network** for protected networks.
  API callers must send `remember: true` to save the password after a successful
  connection. Scan again and select a saved SSID with an empty
  password to reuse it; Forget removes the credential without disconnecting.
  The last successfully connected remembered/open network is eligible to resume
  after restart; the saved-network list is not an auto-connect list.
- The [DHCP reservation API](#remembered-wi-fi-and-dhcp-reservations) binds a
  downstream DHCPv4 address to a client MAC with either cellular or Wi-Fi Relay.
  The upstream router manages the relay station's own lease.
- Restart restoration follows persisted owner intent: Mihomo's enabled marker
  and Relay's last eligible connection. Off/Disconnect clears the respective
  choice; a dropped relay link is not automatically reconnected at runtime.
  Older upgrades without these records cannot invent intent from stored profiles
  or Wi-Fi credentials. See [After a restart](#after-a-restart) for bounds.

## Profile library and extensions

`/data/zte-agent-mihomo/profiles.json` is the private library index. It stores
metadata, the selected ID, subscription URLs and intervals, global extensions,
and references to immutable original and compiled YAML bodies in
`profile-bodies/<sha256>`. The agent saves new bodies before atomically replacing
the index. It also reads old inline libraries. Before an OTA slot change the
agent exports inline YAML, and while the slot change is pending it writes the
inline format so the previous slot can read the library.

Lists and status expose metadata and sanitized errors. The authenticated
profile editor shows the selected profile's subscription URL, name, source type
and interval. The global extensions editor can read the saved Merge and Script.
Saved YAML stays on the router. The console reads an imported YAML file locally
and submits its contents as JSON. An empty local editor keeps the previous
source during an edit. The console displays errors with the draft still available.

Deleting a selected profile requires Mihomo to be off; it clears the selection,
not silently selecting or starting another profile. Edit keeps the same ID;
editing an unchanged remote URL reuses its source (use Update now to refetch).

Pipeline: source -> global Merge -> global Script -> managed U60 fields -> actual
`mihomo -t` validation. Changing extensions validates every saved profile before
committing anything. Scripts fail closed at configuration time: failure retains
the previous config rather than silently dropping rules. This does not turn the
network into a kill switch; normal core-off/relay fallback policy is unchanged.

Merge uses replacement arrays, a one-level DNS overlay, hosts replacement and
recursive merging of other mappings. `prepend-rules` / `append-rules` (also
`proxies` and `proxy-groups`) are explicit U60 convenience keys. Script entry is
synchronous `main(config, profileName)` returning an object. Modern JS including
Set, spread and Object.fromEntries is supported. No Node.js, fetch, filesystem,
commands or module loader are provided. Console output and exceptions are not
echoed, to prevent credentials in scripts/configs reaching logs or flash messages.
The QuickJS child has 32 MiB JS heap, 512 KiB stack, 2 s execution interrupt,
5 s parent deadline, CPU cap and Linux address-space cap; no VM is kept idle.
Each extension is at most 128 KiB; input/processed config is at most 512 KiB.
Merge and Script may both be enabled, in that order. These are configuration
transforms, not a new rule engine. Rule strings still use Mihomo syntax and
first-match ordering (append after MATCH will normally never be reached).
The basic merge behavior follows Clash Verge Rev's merge implementation, but
this is not full desktop parity: the U60 managed network fields win last.

U60 enforces controller/authentication, ports, TPROXY, DNS listen/fake-ip (with a
rule-mode filter generated from the rules; the subscription's own filter becomes
a real-address prefix) and IPv6 after extensions.
PROCESS-NAME cannot identify programs on hotspot clients; use domain/IP rules.
Local 127.0.0.1 hosts entries refer to the resolving client, not a shared Mac.

Subscriptions must be HTTPS UTF-8 complete YAML, not Base64 node lists; redirects
cannot downgrade HTTPS. Downloads are capped in size, duration and redirect count;
TLS verification stays enabled. No third-party converter receives the URL.
Subscriptions, official geodata and pinned assets share one downloader. When
Mihomo is running it explicitly uses an authenticated HTTP CONNECT inbound on
127.0.0.1:17893; the randomly generated core credential stays server-side and
is also stripped from dashboard config responses. Readiness checks require a
407 rejection without credentials. No LAN listener is opened. This follows
Mihomo's current mode/rules, so DIRECT remains possible by configuration; it is
not an instruction to force every download through a remote node. A proxy error
is reported without a silent direct retry. With Mihomo off, it uses the current
uplink. Neither path enables cellular data. Intervals are manual-only
(default), 1/6/12/24/72/168 hours. Schedules persist and resume even with Mihomo off;
failed attempts retry after an hour, without discarding the last valid config.
No timer runs while no subscription has a schedule. This is not a cron calendar.
On B31, cellular-off can leave system resolv.conf empty. During relay, direct
downloads explicitly resolve through the live session's DHCP DNS (gateway if
none), using bounded BusyBox nslookup and reqwest address overrides; the HTTPS
hostname/SNI and certificate verification are retained. System DNS files are not
changed, and relay disconnect clears the per-download resolver override.

Selecting while off does not start Mihomo. Selecting another profile, editing the
active configuration or changing active extensions still uses a planned restart
when the compiled selection changes. Refreshing the selected subscription, manually
or on its timer, instead hot-reloads the core. A byte-identical source updates only
refresh metadata: no compilation or validation. A changed selected source is
validated once by the controller as `candidate.yaml`, leaving the serving
`config.yaml` intact, before it holds traffic, writes the configuration, reloads,
reads back, resets only lost DIRECT ranges and loads the new plan. Classic
listener/LAN access settings, external controller/authentication/TLS/UI settings,
QUIC GSO/ECN, inbound TFO/MPTCP and removal of `geodata-mode: true` require a
restart (`mihomo/reload.rs::needs_restart`). Rejected or unconfirmed reloads use
the already validated candidate for a planned restart; a failed new core falls
back to the last applied `Run.prepared`. The controller waits for the
`mihomo-validate` worker while still handling Guard and Exited messages. Saves
and changed refreshes of nonselected profiles validate on the caller's thread. Zashboard remains the pinned,
separate runtime dashboard, not a forked subscription manager.

[B31 batch 4](archive/2026-11-12-relay-mihomo-implementation.md#batch-4) records a successful subscription hot reload
and its test scope. B31 failure fallback, UDP/QUIC continuity and first-reload
fake-ip behavior remain separate checks.

The managed configuration preserves `geodata-mode`. When bypass is on but the
core uses `geoip.metadb`, status `notice` explains why GEOIP rules cannot bypass
the core in the kernel; forcing `GeoIP.dat` could break an offline start when the
file is absent. Every plan uses the running generation's `Prepared.bypass`, not
the `direct-bypass` intent file. If `keep-alive-idle`, `keep-alive-interval` and
`disable-keep-alive` are all absent, managed defaults are 120 s idle and 30 s
between probes. See [B31 batch 4](archive/2026-11-12-relay-mihomo-implementation.md#batch-4) for the observed
router-wide keep-alive counters and the compared builds.

## Remembered Wi-Fi and DHCP reservations

Remembered SSID/security/password tuples live only in
`/data/zte-agent-relay/saved-wifi.json` (0600, parent 0700). WPA2 credentials are
never reused for an open SSID. Disconnect removes disposable supplicant secrets,
not explicitly remembered credentials. Forget removes the saved tuple; root/ADB
can still read credentials at rest (this is not hardware-backed encryption).

DHCP reservations use B31 dnsmasq's existing `read-ethers`, a scoped block in
`/etc/ethers`, and SIGHUP to the supervisor. No second DHCP server, UCI commit,
RA edit, dnsmasq restart or upstream network change is required. Other file bytes
and permissions/ownership are preserved; current leases and UCI/official ethers
entries are checked for conflicts. Only agent-managed entries can be removed
here. Reservations survive reboot and apply in cellular and relay modes. Clients
renew/reconnect to acquire the address; private/randomized client MAC must stay
fixed for that SSID. IPv6 still uses SLAAC/NAT66, not fixed DHCPv6 leases. LAN
subnet changes require updating reservations; the agent does not rewrite them.
`GET /api/router/reservations` returns full MAC addresses and opaque IDs so
owners can verify bindings. Delete requests identify entries by their opaque ID.

The console makes JSON requests with `Authorization: Bearer <token>`. The
server checks the browser Host and Origin before processing the body. The legacy
`PUT /api/mihomo/config` replaces the selected configuration only while Mihomo
is off. The Zashboard bridge uses a dedicated pass cookie. See the
[security policy](../../SECURITY.md) and [console transport](responsive-console.md#authentication-and-transport).

## Mihomo

Rust owns installation, process lifecycle, configuration validation, firewall
and rollback. Mihomo remains a separate official executable; it is not a Rust
rewrite of its protocols. No enhanced project code is linked or copied.

Pinned upstream downloads:

| Asset | Version | SHA-256 |
| --- | --- | --- |
| `mihomo-linux-arm64-v1.19.33.gz` | 1.19.33 | `ba408b317080ee265c46cb923a50018c1b82cbd708551cdd46a1e3e307396187` |
| Zashboard `dist-no-fonts.zip` | 3.29.1 | `21371cd111b6b3d87774f3ea3ddeacdcb0f6aff8690a16d652daa3ea6e3b0145` |

Sources: [Mihomo release](https://github.com/MetaCubeX/mihomo/releases/tag/v1.19.33),
[Zashboard release](https://github.com/Zephyruso/zashboard/releases/tag/v3.29.1).
Both are the latest stable releases returned by GitHub on 2026-10-25; installation
is intentionally pinned, not an unverified automatic update to "latest".
About 22 MB downloads plus decompression space are needed; the install question
warns that cellular data may be used. Downloads are bounded and verified before
use. ZIP paths/symlinks and extracted size are checked. Licenses and upstream
source locations are installed alongside the binaries in `/data/zte-agent-mihomo`.
Mihomo installation holds its local `profile_operation` and `operation` locks.
The relay and Mihomo each serialize their own work on a controller thread. The
relay controller continues its own checks during a Mihomo install.

First configuration save prepares required official MetaCubeX GeoSite/GeoIP/ASN
data during validation, with per-file time/size bounds and the
official SHA-256 sidecar. Unlike executable/UI releases, rule databases use the
current official release; the installed URL and digest are saved privately.
The official release endpoint falls back to the same repository's official
`release` raw branch, with a separate SHA-256 check for that source. Provenance
records the actual checked endpoint; unchecked legacy cached files are not trusted.
Cached bytes are hash-checked and reused offline; damaged data is repaired before
the short core validation command. Download failure preserves the old YAML and
reports the missing database rather than claiming valid YAML is malformed.
Rule providers can still require Internet access during validation. No rule
database or subscription is embedded in the Rust binary.

### Interception scope

- LAN bridge `br-lan` only, TCP/UDP and IPv4/IPv6, by TPROXY to the core's
  `tproxy-port` 17894 (2026-11-08; it replaced the owned `u60mh0` TUN, which
  ran 125-132 Mbit/s single flow at about 90% core CPU against 190-238 at
  31-44% now). The rules live in the agent's own nftables tables `ip
  u60_mihomo` and `ip6 u60_mihomo` (ZTE rewrites only iptables-legacy): a
  prerouting chain at `mangle - 1` returns non-`br-lan` input, DNS and local
  destinations (`fib daddr type local`, so router addresses need no per-address
  exemption), sends the fake-ip range `198.18.0.0/16` to the core, returns
  private/multicast ranges and then what the core's mode and rules send DIRECT
  by address (the DIRECT bypass, below); the rest goes to the `to_core` chain,
  which marks established transparent sockets and TPROXYs the rest with mark
  `0x700/0xff00`. Rule pref `5100` (retiring legacy `18620` on same-boot
  adoption) sends that mark to table `60625` (`local default dev lo`, both
  families). A `dns` chain at `dstnat - 2` redirects LAN (`br-lan` only)
  TCP/UDP 53 to 1053, and an `input` chain drops 1053/17894 from anything but
  `br-lan`/`lo` (plus transparently-marked `tailscale0` TPROXY sockets when
  Tailscale Exit Node routing via Mihomo is active). The kernel has no
  `NFT_FIB_INET`, so the tables are per family, not `inet`.
- TPROXY needs `bridge-nf-call-iptables=0` and `bridge-nf-call-ip6tables=0`:
  with the bridge-netfilter path on, B31 loses the early socket association
  (rule counters rose while TCP stalled and UDP got no answer; a veth only named
  `br-lan` missed this). While the core runs these are 0 and restored to their
  old values on stop; LAN-to-LAN filtering such as guest isolation pauses
  meanwhile. `tcp_pacing_ss_ratio`/`tcp_pacing_ca_ratio` (1000 while active,
  restored on stop), `netdev_max_backlog >= 5000`, and Wi-Fi RPS (`wlan0` and
  `wlan2`, plus `ath20` only while Wi-Fi Relay is active; `ecm0` is left
  untouched, preserving its existing mask) are managed by the shared
  `netfx::perf` coordinator across Relay, Mihomo and Tailscale (Tailscale
  activates it only after kernel-TUN activation succeeds; owner lock and
  journaled restoration retire legacy per-feature pacing undo entries on
  adoption).
  ZTE resets brnf after relay connects and on `fw3 reload`, and `net_guard`
  sets it back (read every 0.5 s for 3 s after each ZTE trigger; see the
  relay's firewall layout). See
  `docs/research/2026-11-08-mihomo-tproxy-single-flow.md`.
- **Tailscale Strategy B Exit Node (`exit_via_mihomo`)**: when enabled and
  approved by the Tailscale control plane for a family, Mihomo enables
  `sniffer` (`override-destination: false`, read back via `configs["sniffing"]`)
  and adds `ts_pre` in `u60_mihomo` for `tailscale0`: fake-IP destinations
  (`198.18.0.0/16`) are rejected in `forward`, `:53` redirection remains
  strictly `br-lan`-only, approved LAN subnet prefixes (`skip_v4`/`skip_v6`)
  return unconditionally, and `routing::compile_tailscale()` emits single-hop
  IPv4 DIRECT rules while cutting before the first non-DIRECT domain rule so
  blacklist/GFWList subscriptions never bypass sniffing. Stopping Mihomo or
  entering Backoff withdraws `tailscale0` TPROXY so Exit traffic falls back
  seamlessly to kernel forwarding (`u60_tail`) and direct DoH.
- Port 17894 (17893 is the private download proxy), table, priority and the
  absence of both nft tables are checked before use; a taken port fails the
  start instead of failing silently in the core. Main default routes are not
  replaced. The start is verified with `ip route get ... mark 0x700` (must be
  `local`) in both families.
- Core TUN, auto-route/auto-redirect and interface detection are disabled.
- Core validation/start skips its heuristic "existing global IPv6 address"
  check. B31 can have only link-local addresses with cellular off and no Relay;
  the core must still listen on IPv6 in that state. No WAN route or modem switch
  is created to make the check pass.
- LAN DNS TCP/UDP 53 redirects to port 1053; managed DNS is always `fake-ip`
  (owner decision 64), retaining submitted upstream nameservers/policies: pool
  `198.18.0.1/16`, no IPv6 pool (it would fall in the ULA range the chain returns;
  such domains answer AAAA empty), TTL 1 s, `profile.store-fake-ip`. The
  rule-mode `fake-ip-filter` is generated from the configuration alone
  (`Routes::dns`; group choices and the mode never change it, owner choices
  Q2/Q3 of 2026-11-10): local names and Windows' connectivity check keep real
  addresses. With the DIRECT bypass off, so does the subscription's own
  blacklist and every other name is fake. With it on, top-down up to the last
  rule that could ever let traffic skip the core (an address rule whose target
  is DIRECT or a `select` group that can reach DIRECT, a `MATCH` like it, or
  the end): a domain rule sent to `DIRECT` itself from a fixed list keeps real
  addresses; every other domain rule fakes them (a group can be switched away
  from DIRECT later, and a client holding a real address would keep reaching it
  directly); a rule set that is refreshed or reloaded fakes its current names,
  and one sent anywhere but DIRECT may gain any name, so everything after it is
  fake; `NOT`/`SUB-RULE` and logical rules naming such sets likewise end the real
  addresses. The subscription's own blacklist follows the rules, then
  `MATCH,real-ip` (or `MATCH,fake-ip` after such a set). A switch therefore needs
  no DNS change; the bypass switch does: a hot reload of the same configuration
  (`PUT /configs?force=false` with the whole managed configuration, same secret,
  mode, log level, egress interface and ports), tightened first. A 204 is not
  proof: the mode, egress interface and every group's choice must read back as
  before (no group fallen back to `COMPATIBLE`), every rule set and listener must
  be there, and a name whose answer must change (`routing::reload_probe`: the
  never-resolving `u60-reload-probe.invalid` when the default changed, else a
  fixed DIRECT name) must answer as the new filter says on 1053 (fake or not). A
  timeout for the same source is an unknown result decided by the same read-back;
  a changed subscription's unknown reload result instead requires a restart.
  A rejected or unproven reload falls back behind the interception using the
  already validated candidate, without a second validation. Mihomo v1.19.33 keeps
  existing connections across `ApplyConfig`, but can lose UDP/QUIC uplink packets
  while new connections are suspended. With a brand-new persistent cache its first
  reload can clear the fake-ip pool once; subsequent reloads preserve mappings.
  The local real-core `tests/mihomo-qa/hot_reload.py` reproduces this limitation;
  it is not worked around or verified on the router. Status `state` is
  `reloading` meanwhile; Zashboard's writes get 503. The log line
  `[mihomo] reload answered=… verified=… elapsed_ms=…` records each reload. The current
  HTTPS management name (`u60.home.arpa` by default) is forced to the actual
  `br-lan` IPv4 address with host overrides enabled, so DNS interception does not
  lose local management. Hardcoded DoH is not universally blocked. Other
  local/private/tailnet traffic bypasses proxy.
- No blanket `OUTPUT` proxying: this avoids core self-proxy loops. The router's
  own applications do not automatically use the LAN transparent proxy.
- UDP and IPv6 destination reachability still require capable nodes/services.
  Dual-stack interception is an implementation target, not a tested no-leak
  guarantee. Unsupported TPROXY/nftables fails startup and triggers rollback.
- Bypass Mihomo for DIRECT rules (`direct-bypass`, reading the legacy `cn-direct`
  flag file as fallback; owner choice): IPv4 the core would send DIRECT by address skips it in the
  kernel (kernel NAT, so on the relay IPA can carry it). Rule mode: the rules are
  compiled top-down, in the core's order, after the private ranges return
  (`Routes::compile`): a rule matching by address, port or network (`IP-CIDR`,
  any `GEOIP` code from the core's GeoIP.dat, `DST-PORT`, `SRC-PORT`,
  `SRC-IP-CIDR`, `NETWORK`, compilable `AND`/`OR`, text/YAML `ipcidr`/`classical`
  rule sets) returns when its target reaches DIRECT through `select` groups and
  goes to the core otherwise; domain rules are left to fake-ip, process rules
  never match (process lookup is off). A DIRECT rule the kernel cannot check is
  skipped; a non-DIRECT one (`IP-ASN`, `NOT`, `SRC-GEOIP`, binary `mrs` address
  sets, a rule set not downloaded yet, a `file` rule set the core reloads whenever
  the file changes, a code GeoIP.dat lacks, any `GEOIP` without `geodata-mode: true`) ends
  the chain there, keeping earlier returns. `MATCH,DIRECT` or no `MATCH` (the
  core's default) returns the rest. Plain ranges of adjacent rules with one
  verdict share an `ip_<n>` set, each `GEOIP` code has a `geo_<code>` set. Status
  `kernel`: `bypass` `rules` with `returns` (DIRECT rules in the chain) and
  `reason` (where it ends early), or `none` with the reason. Direct mode: all
  IPv4. Global mode or the switch off: nothing. IPv6 always goes through the core.
  Clients that bypass the core's DNS (DoH, hard-coded IPs) are routed by address
  only.
- Rule sets never change behind the kernel (owner choice Q2): the managed
  configuration drops `interval` from `http` rule providers, so the core never
  refreshes one by itself; the controller refreshes each at the subscription's
  interval (`PUT /providers/rules/<name>`, retry after the shorter of the configured interval and 10 minutes if it fails)
  with the same order as any routing write: that set counts as unknown first
  (skipped where it sends DIRECT, the chain ends where it does not), then the
  content is read back and the new plan loaded. A manual refresh in Zashboard
  goes the same way. A `domain` rule set never enters the kernel chain (its
  names are fake-ip whatever it holds), so its refresh goes straight to the
  core, with no tightening and no table load.
- Routing writes are ordered (`relay-mihomo-architecture.md` section 5.4): a
  mode or group change from the console, and `PATCH /configs`,
  `PUT /proxies/*` and `PUT /providers/rules/*` from Zashboard, go through the
  controller: while anything is bypassed, the kernel first stops bypassing
  (the hold table, confirmed by its generation marker; if it cannot be
  confirmed the write is refused and nothing changes; a table declared earlier
  that did not confirm counts too, since a reconcile may load it later), then the core changes,
  its mode and choices are read back, LAN IPv4 connections to what lost DIRECT
  are reset (only those ranges when both chains are plain destinations, every
  LAN IPv4 connection otherwise or beyond 64 ranges; nothing when nothing lost
  it), and the new plan is loaded. During a restart Zashboard's writes get 503
  and console changes wait. Every 60 s the controller reads the core's mode and
  choices back and follows any difference the same way.
- Controller (`mihomo/controller.rs`): one thread for owner commands, routing
  writes, egress changes, core exits, retries, `net_guard` repairs and rule-set
  refreshes; it never takes the relay's network lock, so an association or a
  5 GHz CAC never delays an exit or a repair. A panic on it is logged and
  aborts the agent, so the guard below starts it again and the new agent
  adopts the tables (left running, the core would die with the thread while
  the tables kept LAN DNS on it). It tracks the table the kernel was last read
  to hold and every table declared since that did not confirm; a table a
  reconcile loads later becomes the published bypass. Pages read its published snapshot:
  `state` (`off`, `starting`, `running`, `restarting`, `backoff`,
  `cleanup_pending`), `generation`, `tables` (target and confirmed generation),
  `direct_fallback`, `failures`, `retry_in_s`. Each core process has one reaper
  (`waitid` without reaping first, so a stop never signals a reused process id);
  an exit of an older generation is ignored.
- Starting: the input guard, kernel settings and policy routes go in before the
  core; interception (the hold table: nothing skips the core) once it listens;
  the plan only from the mode and choices the ready core reports. `to_core` ends
  with a TCP/UDP drop in every interception table: TPROXY without a listening
  core skips only its own rule (`NFT_BREAK`), and the packet would otherwise be
  forwarded directly. A connection the core already holds keeps reaching it
  before any DIRECT return (`socket transparent 1 socket wildcard 0`), so a
  switch to DIRECT does not cut it; a new SYN to a remote port 17894 is not taken
  for one.
- Planned restart (egress change, profile change, a reload that was not proven): the new
  configuration is prepared and validated while the old core still serves (at
  background priority for a profile change), then the hold table goes in, the
  old core stops and the new one starts behind the interception; nothing goes
  direct meanwhile (`[mihomo] the restart held traffic for N ms`, 2.26 s for an
  egress change on B31, 2026-11-12). A new profile that does not validate
  leaves the old core serving; one that validates but does not start falls
  back to the configuration that ran before. An IPv4 egress change the relay
  announces restarts the core at once; an IPv6-only change must hold for 5 s and
  such restarts are at least 60 s apart; outside the relay the 15 s audit
  restarts only for an egress that strands connections.
- D3: a core exit the agent sees, or a planned restart that finally fails,
  withdraws interception, the kernel settings and the policy routes; LAN traffic
  goes direct while fake-ip addresses fail fast (TCP reset, UDP port
  unreachable). Retries follow D2: 5, 15, 30, 60 s, then every 5 min; three
  failures within 60 s go to 5 min at once; 5 min running clears the count. The
  owner turning it off cancels any retry. The boot restore, or a new IPv4
  egress (the relay came up), retries at once. A withdrawal that fails leaves
  the state `cleanup_pending` (the old tables may still send LAN DNS to the
  dead core) and is tried again on the same timers before the start. A retry
  with no effects held (a start that failed before it claimed any, or a failed
  adoption, which first rolls the previous agent's tables back) claims them
  afresh. A start from D3 keeps the fake-ip
  reject (and the input guard) until the full table takes over, then resets LAN
  IPv4 and IPv6 connections that went direct. A start the owner asked for that
  fails releases what it took and stays off; a boot restore keeps retrying.
- The agent itself dying (owner choice Q1): the resident drop keeps LAN traffic
  from going direct, and a guard process the agent started (`zte-agent guard`,
  `src/guard.rs`) runs the boot launcher again. The new agent adopts this boot's
  tables and journal while the owner wants Mihomo on (the hold table, the
  original kernel values kept from the journal), starts a new core and loads the
  plan; nothing passes direct and DNS comes back with the core. The guard never
  starts a second agent (the launcher's lock and identity check), leaves an OTA
  trial to the update helper (`pending` marker) and an operator's stop to the
  operator (`/tmp/zte-agent-run/stopped`), and after three failed attempts rolls
  the network changes back (`network-recover`, direct) while it keeps trying
  every 5 min. The ended agent's log is kept as `/tmp/zte-agent.previous.log`.
- Firmware rewrites (firewall reloads, ZTE scripts, sysctl resets) are repaired
  by `net_guard` (`relay-hw-offload.md`, section 5); the tables are compared with
  their generation marker and rule counts and reloaded whole.

The owner's `EffectSet` holds `netfx::effect::NftTables`, replacing both families in
one `nft -f` batch (stale sets go with them) carrying a generation marker, a rule
comment in the unhooked chain `state`. The marker read back with `nft -t` (no set
elements, so a large GeoIP set never meets an output limit) decides whether the
kernel holds a batch: a tool that failed or timed out may still have committed,
and a batch that cannot be read back stays the target and is loaded again; the
previous table or a table name that exists is never taken for the new one. A table
name without the agent's marker is never taken over; a previous agent's table
(marker present) is adopted or cleaned up. The journal keeps the format of
earlier versions (`{boot, undo}`) and only undo commands the deployed previous
agent runs (`@u60-sysctl`, `ip ... del`, `@u60-mihomo-nft remove`, tables last
in, first out); `tests/mihomo-qa` checks that the previous agent's
`network-recover` undoes it completely.

`EffectSet::declare` journals every undo with one durable write before applying
the batch. Consecutive legacy resources of one tool use `iptables-restore` or
`ip6tables-restore --noflush --wait 2`, with route and radio ordering barriers.
First acquisition uses exclusive `-N` and refuses an existing foreign chain.
An already owned chain is replaced whole using `:NAME - [0:0]` and its ordered
rules in one restore transaction. A later table/family failure may leave earlier
COMMITs applied: the same individual undo records recover that partial state.
A failed restore is never retried blindly as individual commands. Because an
interrupted plan also runs the undo of steps that never ran, no such undo may
match another writer's identical rule: a rule in a chain the agent does not own
jumps to an owned `U60_*` chain or carries a `zte-agent*` comment
(the relay's denials, the cellular IPv6 rejects among them, are rules
in its own nftables tables, not in legacy chains; a unit test checks every
prejournaled plan). File fsync is
retained; this is not a claim that runtime network journals survive power loss
as an atomic rename transaction. Previous-boot runtime journals are discarded.

### Configuration and dashboard security

The uploaded YAML is parsed, then the agent overrides controller, ports, DNS
binding and IPv6. It disables subscription-provided listeners, TUN, iptables,
NTP service, alternate controllers and server listeners; a subscription's
`sniffer` section is kept as written (it cannot bind an interface or open a
port) unless Tailscale Strategy B (`exit_via_mihomo`) is active, in which case
the agent enables `sniffer` (with TLS/HTTP/QUIC defaults) and forces
`override-destination: false`. Configuration checks
run `mihomo -t`; rejected YAML does not replace the selected profile. A start whose
generated configuration, referenced geodata contents and installed core identity
match one of the last four that passed and started this boot (with the
per-start secret masked and the top-level `interface-name` left out, so a
relay/cellular switch alone reuses it) skips the repeated check (logged as
`validation reused`; kept in `/data/zte-agent-mihomo/validated`). Databases referenced
by rules, sub-rules, rule providers, DNS and the sniffer's `geosite:`/`geoip:`
entries count; missing or unreadable dependencies disable reuse, and a
dependency change during the check or startup prevents caching that result.
Database digests are reused while a file keeps its inode, size, modification and
change times. This does not claim that `mihomo -t` validates every provider's
downloaded contents.
A check beside a live core uses one Go execution slot (`GOMAXPROCS=1`), a soft
128 MiB Go memory target and a lower priority. Neither is an OS-thread count or
RSS hard cap. Validation logs only its elapsed time, background flag and result. Credentials in
source/runtime YAML are private (`0600`, parent `0700`) and never rendered back.
Only import configurations from sources you trust: nodes/providers can of
course cause outbound requests and choose proxy destinations.
The subscription's TUN object is replaced by a disabled one. Node/provider
interface and mark overrides are removed; DNS URL fragments may select declared
proxies/groups but not an arbitrary interface. Router addresses are matched live
by `fib daddr type local`, so an address change alone (Tailscale, LAN or another
non-egress interface) does not restart the core or drop connections; the relay's
DNS tables match them the same way. The interception is
re-checked by `net_guard` (once a ZTE script or firmware event has been quiet
2 s, 5 s again after a repair, else once a minute); a missing piece is
re-applied as journaled, never by flushing or taking
over another writer's rules. The relay announces changes of
its own path, and such an uplink change restarts the core. For any other egress
(cellular) the watchdog compares the effective egress with the core's reference
egress whenever addresses change and at each 15 s audit (the route over
rtnetlink and the addresses from `getifaddrs`; no `ip` or `iw` process), and restarts only when
existing connections are stranded: a readable family moved to another interface
(name or index) or lost a source address it had. Added addresses, gateway or
preferred-source changes and a family that became available (IPv6, or IPv4
after an offline start) only update the reference in place. An unreadable or
lost family is no evidence and keeps its last reference, so its return on
another address still strands. A stranding observation must stay identical for
5 s before the restart, so a flapping uplink restarts nothing until it settles,
and the watchdog restarts the core at most once per 60 s; relay notifications
and owner operations are not limited.
Duplicate notifications with the same effective routes and source-address sets
on both egress interfaces keep a live core running. Non-egress address changes
and lifetime countdowns do not change that identity; withdrawal of a secondary
egress address does. Unknown/offline observations do not authorize skipping recovery. A long switch
may still need an intermediate fallback core followed by the new Wi-Fi core.

The core API binds `127.0.0.1:19090` with a fresh random secret each start.
Zashboard is served locally at `/ui/mihomo/dashboard/`; its `secondaryPath`
points to `/ui/mihomo/api`. The console's **Open Zashboard** button opens a new
tab: the console first calls `POST /api/mihomo/dashboard` with its bearer token
and receives a `zte_ui_zashboard` pass cookie (HttpOnly, SameSite=Strict, path
`/ui/mihomo/`, twelve hours, one per console session, at most eight; over HTTPS
it becomes a Secure `__Host-` cookie with `Path=/`). The pass opens only the dashboard and its bridge,
never the JSON API, and stops working when its console session ends. Lock console
calls `POST /api/auth/logout` to revoke that session and clear the pass cookie.
Existing WebSocket streams also end on pass expiry, replacement or eviction.
If logout cannot be confirmed over the network, the locked console reports it. Without a
valid pass, dashboard pages go back to the console and bridge calls get 401. The
dashboard opens at `#/proxies` directly, including on a first visit or with
browser storage disabled. Before the pinned dashboard
initializes its connection, a small Rust serving adapter selects its managed
U60 backend using the browser's current protocol, hostname and port (including
HTTPS/default ports and bracketed IPv6). A stale selected backend or URL query
cannot override those defaults. The managed entry is refreshed without clearing
other saved backends or dashboard preferences; blocked storage uses a module-local
in-memory fallback. If Setup is opened, its form and probe both use these same
settings, an empty password and the `U60 Pro` label, rather than localhost defaults.

The adapter checks the upstream index/main-module SHA-256 and exact, unique
replacement anchors before serving the pinned main module; a version mismatch
is refused with a reinstall message instead of silently applying a partial patch.
Upstream files on disk remain unchanged. When upgrading Zashboard, update the
bundle/archive hashes and anchors together and rerun the distribution/browser QA.
An authenticated browser session and exact same
origin are required by the bridge; the secret never appears in a link, HTML,
browser storage or a browser-supplied header. HTTP/WebSocket requests are
bounded, and the bridge disallows core upgrades/restarts and arbitrary config
replacement. Node selection, latency, provider refresh, mode, connections,
traffic and logs are bridged. Unsupported advanced Zashboard controls can show
an explicit denied operation; manage lifecycle and YAML in the console's Mihomo page instead.
Upgraded WebSocket connections retain the shared total/per-peer listener slots
until they end; HTTPS Reset also closes live WSS immediately. Stale browser
`token` query values are removed before the server injects its private credential.
There is no default `127.0.0.1:9090` setup probe. The stock panel's optional
GitHub update check remains blocked by same-origin CSP; its console `Failed to
fetch` warning does not mean the authenticated bridge failed.

Only the pinned third-party dashboard has its own CSP; the agent's nonced CSP
is unchanged elsewhere. Dashboard service-worker caching is disabled. Do not
forward management ports to a WAN. Plain HTTP still lacks transport encryption;
use the existing LAN HTTPS feature where appropriate.

## Wi-Fi relay

This is a fresh Rust implementation based on public device interfaces and the
earlier B31 association observations, not a translation of enhanced's GPL code.

- Creates only its own station `ath20` (named `u60sta0` before 2026-11-12;
  what a build from before that date left is not recognised: disconnect the
  relay before updating from one, or reboot); PHY is discovered from `wlan2/phy80211`. B31's
  stock IPACM configuration lists `ath20`, which is why the station has that
  name (section Hardware forwarding); a `wlan*` name would stall the vendor's
  Wi-Fi off, which waits for every such interface to disappear.
- Requires 5 GHz main AP enabled and Guest WiFi disabled. The matching upstream
  band's main AP must also be enabled. Open/WPA2-Personal only, on 2.4 GHz
  and 5 GHz channels enabled by the PHY, including DFS. Scans and connects
  honor the driver's current country/channel restrictions; disabled channels
  remain unavailable even if present in the BSS cache. Hidden, enterprise and
  WPA3-only networks are not supported. DFS radar checks may delay hotspot
  availability; see the device acceptance record for tested channels. The
  [relay lifecycle](relay-lifecycle.md) describes switching and recovery.
- Uses the existing `wpa_supplicant`, `wpa_cli`, `hostapd_cli`, `iw`, `ip`,
  `iptables`, `ip6tables`, `udhcpc` and `uci`; optional IPv6 also uses `odhcp6c`
  and the existing `odhcpd`. It does not disable vendor daemons.
- The radio allows two channels (`iw phy` combinations), one per band, so the
  STA shares its channel with the same-band AP. For a 2.4 GHz upstream the
  agent moves `wlan0` to the upstream channel at 20 MHz before associating
  (runtime `hostapd_cli` disable/set/enable, snapshotted and restored, no UCI
  commit; client reconnection is expected). Every 5 GHz upstream uses a temporary non-DFS 20 MHz staging channel
  on `wlan2`, then lets the driver follow the STA. The older disable/set/enable
  reconfiguration of this radio is unreliable on B31. Measured
  2026-10-27 without a connected STA: ch 44 at 20 MHz was refused by
  `enable`; ch 36/44 at 40 and 80 MHz reached `HT_SCAN`, then `DISABLED`
  without any `START AP` reaching the driver; ch 36/44 at 160 MHz started (DFS
  CAC). With a connected STA even 160 MHz failed. The old 5 GHz path (20 MHz) therefore always failed with "Hotspot
  channel change was not confirmed", and each rollback to 160 MHz cost a 60 s
  CAC. The driver's own policy (`gWlanMccToSccSwitchMode=3`, force SCC
  without SAP restart) is left to move the AP to the STA's channel by CSA.
- That CSA needs the driver's DFS channel switch. B31 turns it off for the
  first 10 minutes of every 160 MHz 5 GHz start on an auto channel
  (`/sbin/zte_wifi_dfs_hdlr.sh`: `iwpriv wlan2 disableDfsCS 1`, `sleep 599`,
  then `0`; the ini also loads `gDisableDFSChSwitch=1`). `disableDfsCS` sets
  one driver-wide flag that the driver reads at the end of every channel
  switch; while it is set, the switch restarts beaconing on the old channel.
  Any 160 MHz AP here spans DFS (44/160 covers
  52-64), and a STA connect makes the driver CSA it to 44/80. In the window
  the driver ends that CSA without the channel change: the connect waits 10 s
  and fails, and every later connect gets `Channel switch in progress` until
  the hotspot restarts. This is why the relay did not come back after a reboot
  with the upstream present. Owner decision 62 (`wifi_relay/dfs_switch.rs`):
  before each association the agent makes sure the vendor's own
  `wireless.zte_mbb.dfs_channel_switch_disable=1` is set (a persistent
  setting, owner approval 2026-11-12). With it the script leaves
  `disableDfsCS` alone, and from the next driver load the Wi-Fi scripts load
  `gDisableDFSChSwitch=0` (`qcacld32.sh`, `check_ini`). The agent commits the
  key only when no other `wireless` change is pending (`uci commit wireless`
  would make those permanent too); otherwise it sets it uncommitted, which
  `uci get` already reads, and logs that the next join commits it. It then
  still runs `iwpriv wlan2 disableDfsCS 0`, for a driver loaded before the key
  was committed. A script that started before the key was set has already
  read it and may still turn the flag off within its first second, after a
  join turned it on. A reboot with the key committed (2026-11-12): the relay
  was restored on the first attempt 70.9 s after boot, inside the vendor's
  10-minute window. See [B31 batch 1](archive/2026-11-12-relay-mihomo-implementation.md#batch-1).
  The AP ends at 44/80 after the connect; a later hotspot restart brings it
  back to the configured 160 on the STA's channel, whatever the STA's width.
  Validated 2026-10-29 with the switch turned off by hand before an agent
  restart, on the earlier build that waited for the script instead of setting
  the key. See [2026-10-29 acceptance](archive/2026-10-29-width-v2-acceptance.md).
- All 5 GHz upstreams share the same preparation (`wifi_relay/hotspot.rs`).
  A join to 5260 MHz while SAP runs 36/160 repeatedly failed before authentication:
  `hdd_validate_channel_and_bandwidth: BW 3 not possible in 2.4GHz band`,
  `Set channel with CSA IE failed, can't allow STA`. Before any 5 GHz join, snapshot
  SAP's actual primary/width/center, journal its restoration, and use runtime
  `chan_switch` to an enabled non-DFS 5 GHz channel at 20 MHz. Then associate;
  the driver follows the DFS STA (tested 52/160). Disconnect detaches STA first,
  restores the original SAP channel, and waits for CAC (about 60 s for 36/160).
  No radar detection is disabled; the only persistent wireless setting the
  relay writes is the DFS switch key above. In B31's `wlan_hdd_cm_connect`,
  the driver itself moves an AP spanning DFS before the STA joins. For a DFS
  upstream it picks a 2.4 GHz target while keeping 160 MHz, which fails as above.
  The non-DFS 20 MHz staging avoids that driver branch. See
  [2026-11-03 DFS acceptance](archive/2026-11-03-dfs-acceptance.md) for test coverage.
- Scans go over an attached wpa_supplicant control socket: all enabled 2.4 GHz
  channels in one request, then each enabled 5 GHz channel alone, each waiting
  for its completion event (about 3 s in all, instead of a fixed 6 s sleep).
  Reason, from the B31 `wlan.ko` (qcacld 5.2.1.110D): `scm_scan_start_req`
  removes from multi-channel STA scans the 5 GHz channels sharing a MAC with an
  AP that `policy_mgr_is_any_dfs_beaconing_session_present` reports, and any
  5 GHz AP at 160 MHz counts. With the main hotspot on channel 36 at 160 MHz,
  channels 36-64 vanished from every full scan and a 36-48-only request was
  refused (`Reject 0 channel Scan`, `INTERNAL_FAILURE`); 149-165 survive on the
  other MAC. One-channel requests skip that code. INI `ch_list_trim_conc` and
  `skip_6g_and_indoor_freq_scan` are 0 and not involved. wpa_supplicant still
  reports a refused scan as finished, refilled from the kernel's cached BSS
  table, so only entries whose `age` fits inside the scan are listed. The BSS
  table is read with `BSS RANGE=` pages, not the 4 KB `SCAN_RESULTS` reply.
- WPA2 passphrases become derived hex PSKs, never shell arguments. Credentials
  live only in the private runtime directory and are removed on disconnect.
  Scanned BSSIDs are kept internal; page selection uses opaque IDs.
- DHCP calls the Rust agent executable as its callback, not a shell script.
  Every IPv4 connection uses a fresh random lease-file nonce; delayed callbacks
  from an old udhcpc cannot overwrite or delete a newer connection's lease.
  Leases are checked for host/gateway validity and LAN/tailnet/link-local
  conflicts before routes/NAT are applied. The long-lived udhcpc renews leases.
- IPv4 policy table `60631`, priority `5120` (retiring legacy `18640` on
  same-boot adoption); NAT and guarded forwarding
  exist before the final route rule is installed (firewall layout below).
  Existing cellular main defaults remain untouched. Own LAN, tailnet and
  link-local management routes fall through; other private subnets may belong
  to the hotel's portal/resolvers and use Wi-Fi instead of cellular.
- Nonlocal LAN DNS is forwarded to the lease's upstream resolver before vendor
  DNS interception. DNS addressed to the router/own LAN/tailnet/link-local stays
  local, preserving dnsmasq's management-name answers. The router's ordinary
  TCP/UDP DNS queries also use the hotel resolver. The `nat4` chain's
  `oifname "ath20" masquerade` also covers a socket still bound to a SIM source.
  The rules live in
  the agent's nftables table `ip u60_relay` (IPv6: `ip6 u60_relay`,
  `wifi_relay/uplink.rs`): a LAN chain at prerouting `dstnat - 1` and a router
  chain at output `-101` (the output hook takes no `dstnat` keyword), both just
  ahead of legacy NAT. `fib daddr type local` matches the router's own
  addresses live, so no per-address exemption is kept or audited. Mihomo's
  redirect sits at `dstnat - 2` and takes precedence while it runs,
  irrespective of enable order. Invalid or conflicting DHCP DNS addresses are
  rejected before network changes.
- B31's offline DNS/HTTP portal follows its cellular-only WAN status. While
  relay is connected, Rust temporarily sets `zwrt_redirect.redirect.switch=0`
  without committing UCI and restarts dnsmasq once (SIGHUP does not reload this
  vendor option). The existing DHCP service and management names remain in use.
  Owned, LAN-scoped `RETURN` rules bypass only the vendor `redirect_chain` in
  IPv4/IPv6 NAT; other NAT/filter rules are not skipped. The switch delta and
  both RETURNs are journaled in the session's `dns` set (`dns.json`,
  `portal::web_bypasses`), so a handover between 5 GHz upstreams releases only
  the resolver line and passes the suppression to the next session as it is
  (`successor`, the new session declares it through `EffectSet`, an adoption after
  an agent restart takes the RETURNs into `dns`). Below iptables, the vendor
  kernel module `zte_http_redirect` answers a
  browser's (by User-Agent) port-80 request with a 302 to the offline page
  while `/sys/zte_genl/httpredirect_cmd` reads 4 or 0x13 (`zte_topsw_redirect`
  sets it only at its start and on a WAN event); a session that finds either
  value holds 1 as a kernel setting in the same `dns` set and writes the
  original back at disconnect (`portal::web_redirect`,
  `relay-hw-offload.md` section 5). A build before 2026-11-12
  kept the RETURNs in `network.json` and released the switch during a
  handover; a fw3 reload in that gap let the vendor's port-80 DNAT in until
  the next reload. [B31 portal handover measurements](archive/2026-11-relay-offload-benchmarks.md#2026-11-12-门户交接)
  record the tested builds and rule timing. The guard check
  repairs these rules after a reload replaces the chain, and keeps each
  ahead of every vendor rule in it: a RETURN found behind one (a DNAT inserted
  first) is deleted and inserted first in one `iptables-restore` transaction,
  so it is never missing; `-C` alone proves nothing about the order. Mihomo on/off
  does not own this behavior. Disconnect/crash cleanup reverts only our exact
  uncommitted switch delta and restarts dnsmasq; a vendor/user commit or new
  value is preserved rather than overwritten with an old snapshot. After a
  device reboot, the volatile delta/rules vanish and the old journal is dropped.
  Cached private DNS answers on a phone can require Wi-Fi reconnect after the
  first repair. B31's shipped web menu/RPC bundle has no exposed toggle for this
  switch; `https_redirect=0` alone does not disable the DNS portal.
- The web connection form defaults **Remember this network**, **Use upstream
  IPv6 / LAN NAT66**, and the hotspot/fallback acknowledgement on, as requested
  by the owner. Each remains user-toggleable; unchecked acknowledgement still
  prevents connection, and unchecked remember/IPv6 are submitted as false.
  With IPv6 off, absent usable upstream IPv6, or unsupported target
  capabilities, relay remains IPv4-only. It still requires IPv4 DHCP: IPv6-only
  upstreams and NAT64/464XLAT are not supported by this iteration.
- `odhcp6c` receives RA/SLAAC and optional IA_NA, but calls the Rust executable,
  never the vendor netifd script. Kernel RA/autoconf on the owned STA stay off;
  validated addresses/default-router lifetimes become owned /128 addresses and
  routes in IPv6 table `60631`, priority `5120` (retiring legacy `18640` on
  same-boot adoption). DAD completes before source
  route installation. Explicit RA on-link routes retain their lifetimes and
  advertised MTU; an address-generation prefix alone never creates an on-link
  route. No learned default is added to the cellular main table. Each discovery
  session has a random private lease path, so delayed callbacks from a prior
  connection cannot overwrite or remove the new connection's lease.
- IPv6 mode adds guarded NAT66 through `ath20`, including the LAN's existing
  IPv6 prefixes so clients retaining a cellular address do not bypass NAT or
  lose the selected Wi-Fi exit. Router/core connections also use Wi-Fi and
  masquerade an old selected source if needed. The masquerade is an nft rule
  (`ip6 u60_relay`, postrouting `srcnat - 1`, only `oifname ath20`; B31 has
  `CONFIG_NFT_MASQ=y`). Mihomo's marked rule (pref
  `5100`, retiring legacy `18620`) precedes Relay's table, so LAN TCP/UDP interception still wins.
  LAN address/prefix changes are reconciled even when the upstream lease is
  unchanged. Owned br-lan routes retain previously observed client prefixes
  only for their observed valid lifetime, capped at two hours; they never
  restore old vendor interface addresses or survive a reboot.

- The existing LAN `odhcpd` remains the only RA service. Rust applies typed
  runtime RA/SLAAC options through `network.interface.lan.set_data`, not UCI
  edits or a saved vendor baseline. It advertises a stable random RFC4193 ULA
  /64 and filters advertised prefixes to that ULA. Runtime DNS appends to UCI
  DNS in odhcpd, so RDNSS is suppressed during Relay: dual-stack clients use
  existing DHCPv4 DNS for both A and AAAA. IPv6-only clients are unsupported.
  Tagged current Wi-Fi DNS lines in volatile `/tmp/resolv.conf` keep the router
  and dnsmasq working even when disconnected cellular supplies no resolvers.
  Cleanup removes only those lines, never restores historical SIM DNS.
  Existing LAN global addresses
  remain local/management-reachable. DHCPv6/NDP relay is temporarily disabled.
  RA router lifetime is 90 s, intervals 10-30 s. Advertised MTU is the smaller
  of the validated upstream RA MTU and the current `br-lan` link MTU, not a
  fixed 1280. Missing/invalid upstream MTU retains the conservative 1280
  fallback; a LAN MTU below IPv6's minimum refuses IPv6 relay. The supervisor
  rebuilds RA state when either bound changes. Status exposes `upstream_mtu`
  and `lan_mtu` (the effective advertised value). A hardcoded 1280 broke
  macOS Hysteria2: its observed 1280-byte UDP handshake needs 1328 bytes with
  headers and was rejected locally with `EMSGSIZE` when fragmentation was
  disabled. The LAN ULA address
  lifetime is refreshed while the upstream lease remains live. Clients may
  continue preferring IPv4 with ULA; this is not a forced IPv6 preference.
- Upstream INPUT permits established return traffic, scoped RA/NDP, essential
  ICMPv6 errors and DHCPv6 replies, not management services. External LAN IPv6
  DNS is redirected locally, after Mihomo if enabled; public router IPv6 DNS
  follows a usable non-link-local upstream RDNSS, or fails fast if none exists
  so IPv4 DNS can be used. Private/local DNS is preserved. Link-local-only
  upstream DNS is not used as a router DNS destination in this iteration.
  RDNSS matching the router, assigned upstream addresses, LAN or Tailnet is
  filtered to prevent resolver loops or management redirection. Unknown upstream
  ULA destinations use Wi-Fi, not a blanket fallthrough to cellular routes.
- Cellular IPv6 bypass remains blocked for forwarded and core/router traffic.
  Loss/expiry withdraws owned IPv6 forwarding; missing IPv6 does not stop an
  otherwise working IPv4 relay. Lifetime-only renewals update owned addresses
  and the route without tearing down NAT/RA. Changed addressing rebuilds the
  owned IPv6 network set. The owned addresses, routes, policy rules and the
  runtime RA overlay of an unchanged path are checked on the tick after a
  settled `net_guard` trigger, on the next tick after a failed read, before a
  lifetime refresh, and otherwise every 15 s (`ipv6::CHECK_EVERY`): an object
  removed by something that fires no vendor trigger is noticed within 15 s
  (owner accepted, 2026-11-12, the controller runs the read-only checks through
  its device port). Missing owned effects are repaired
  without changing the upstream revision, including a route table emptied by
  another writer (it then no longer exists). A failed inspection read keeps the
  path and retries on the next two ticks. The third consecutive failed read
  withdraws IPv6. A confirmed conflict withdraws it immediately. Source,
  gateway and availability changes advance the upstream revision. Lifetime
  renewal, local exclusions and same-path repair leave it unchanged. Redundant lifetime writes are spaced
  15 s apart (every tick while an upstream lifetime is under 45 s), and a new
  renewal is checked before using that throttle. Local DNS exclusions update
  in place and are audited at 15 s intervals. Status says **configured / internet not verified**:
  RA/DHCP is not proof of hotel authorization or Internet reachability.
- RA release withdraws the temporary default, then nulls only still-owned
  runtime keys. JSON null is ignored by odhcpd's typed parser, leaving its
  CURRENT vendor UCI configuration in effect. Null tombstones persist only
  until netifd clears its runtime data; `{}` is not a clear operation. The
  journal records owned effects, no old DNS/address baseline. Vendor DHCP
  commits/reloads cannot persist the runtime overlay. Existing non-null runtime
  overrides are refused; newer external runtime values are preserved. Reboot
  discards the overlay and its old-boot journal without comparing stale DNS.
  The old UCI snapshot code remains migration-only for installations made by
  earlier versions. It is never created by new sessions. Actual OpenWrt and
  isolated B31 firmware packet tests cover release to newer vendor DNS/MTU.
  An ordinary RA/lease error releases IPv6 without taking down working IPv4;
  genuine unsafe cleanup failure still retains evidence and reports an error.
  The longer-term state/ownership design and release gates are documented in
  [relay-cellular-recovery-plan.md](archive/2026-10-27-relay-cellular-recovery-plan.md); those
  coordinator/dependency-group changes are a plan, not already deployed code.
- The `relay` controller schedules a check every 3 seconds while a session has
  a selected network. Queued work and device commands add to the observed interval.
  Settled guard triggers queue a check, coalesced during long operations. An incomplete association
  gets a 12-second CLOCK_BOOTTIME grace period from its first failed observation,
  provided both helpers and the original lease remain valid and the hotspot is
  still on. Recovery clears the timer; an expired grace period, lost helper or
  changed address/mask/gateway/first resolver removes relay and restores AP
  settings. A renewal changing only later resolvers is adopted in place after
  the usual lease checks. During association recovery, the tick skips maintenance
  and does not extend any lease. When the association completes again, udhcpc
  is asked to renew (at most every 30 s, as a second signal while a BusyBox
  renewal is pending can deconfigure the lease). A roam onto another network with the
  same SSID then loses its lease and tears the relay down instead of keeping a
  stale address. Status exposes the association state and elapsed
  recovery time, with logs recording the reason and query time;
  **cellular fallback may consume SIM data**. There is no internet-down probe
  and no reconnect after a dropped link while the agent runs; after an agent
  restart or a reboot it attempts only the saved eligible connection (see
  [After a restart](#after-a-restart)).
- B31 blocks the optional disruptive connectivity-watchdog ladder because
  the firmware reports the same disabled state for an owner turning data off
  and for the watchdog's own PDN pause. Check `status.safety_block` and the
  enable response for the reason. Manual modem controls and fallback to an
  already-enabled modem remain available. The existing cellular connectivity
  watchdog does not count Relay/portal probe failures against SIM. It clears escalation state while Relay owns the
  upstream or cellular is disabled/unreadable. Agent data-off/airplane requests
  cancel an automatic PDN restore already waiting between down/up; independent
  vendor writes are not serialized by this agent lock.
- Agent Wi-Fi/guest/LAN/USB and vendor-firewall setters refuse conflicting changes while relay is
  active and serialize their immediate effects with extension changes.
  Asynchronous vendor reloads, external vendor-page changes and suspend races remain device
  acceptance risks; do not reconfigure the radios concurrently.

### Relay clock and DNS

At startup the agent restores a UTC lower bound from its build or the last
verified time. Elapsed time while powered off remains unknown. A new relay
connection checks time over `ath20`. Certificate-verified HTTPS `Date`
responses from Apple and Microsoft must agree. The requests bind to the Wi-Fi
station, use no proxy and follow no redirects. A failure leaves IPv4 relay up
and publishes `clock_error` while connected.

**Recheck time** (`POST /api/wifi-relay/clock`) queues a fresh check on the relay
controller through the Slow lane and keeps the current Wi-Fi and Mihomo
sessions. Status uses the latest shared clock result. A successful later check
clears the warning. Mihomo starts `mihomo-clock` when preparing a new core on
the relay, with at most one such worker and no wait on the core startup path.
Its check can reuse verified UTC for five minutes. Failure invalidates that
cache. Checks run on demand.

Each owned resolver uses a separate `# zte-agent-wifi-relay nameserver <address>`
line immediately before its `nameserver` line. On B31, BusyBox `nslookup`
interprets an inline comment as part of the server address. Cleanup also
recognizes the old inline marker.

### Firewall layout

`wifi_relay/uplink.rs` builds both families of the relay's own nftables
tables, `ip`/`ip6 u60_relay`, in one place (`relay-mihomo-architecture.md`
section 4.3); `ipv6` only adds its parts while it has them. Every change
replaces both families in one `nft -f` batch whose generation marker is read
back (the wireless `EffectSet` holds `NftTables`); a table of that name without the agent's
marker is never taken over. The filter chains run at `filter - 1`, just ahead
of ZTE's legacy rules, so a drop there is final whatever ZTE inserts first;
a return only leaves these chains, and ZTE's rules still apply after them.

| Part | When | Rules |
| --- | --- | --- |
| Guard | From before `ath20` is raised (a scan too) until the station is deleted | Upstream INPUT: established/related and DHCP 67→68 return, the rest dropped; IPv6 dropped. All forwarding from or to `ath20` dropped. |
| IPv6 discovery | IPv6 requested, before `odhcp6c` starts | Upstream IPv6 INPUT: established/related, RA (link-local source, hop limit 255), NS/NA (hop limit 255), ICMPv6 errors 1–4, DHCPv6 547→546; the rest dropped. |
| Routes | From before the policy rule until the routes are released (the tables shrink back to the guard first) | IPv4 FORWARD: reject egress to `rmnet*`, then return `br-lan → ath20`, `tailscale0 → ath20`, and established/related replies from `ath20` to `br-lan` and `tailscale0` before the `ath20` drops. IPv6 FORWARD from `br-lan` and `tailscale0`: `rmnet*` rejected first (all interfaces in strict zero-cellular mode), then `br-lan` local exceptions `fc00::/7`, `fe80::/10`, `ff00::/8` return and remaining `br-lan` egress is rejected. One IPv6 OUTPUT reject to `rmnet*`, covering IPv6 off, a lost lease and a withdrawn NAT66. IPv4 masquerade in `ip u60_relay/nat4` (`oifname "ath20"`) and IPv4 DNS chains. |
| NAT66 | A valid IPv6 lease, from before its policy rule | Approved LAN sources to `ath20`, `tailscale0` sources in `fd7a:115c:a1e0::/48` to `ath20`, and established/related replies from `ath20` to `br-lan` and `tailscale0` return (ahead of the upstream drops); the masquerade; IPv6 DNS chains. |

Legacy iptables keeps the accepts needed to pass ZTE's DROP/REJECT. IPv4 has
`U60_RELAY_IN` for established replies and DHCP offers, and `U60_RELAY_FWD`
for LAN to upstream and established/related replies. IPv6 has `U60_R6_IN`
hooked directly from INPUT with `-i ath20`, and `U60_R6_FWD`. The portal
`RETURN` stays in legacy. `EffectSet` repairs owned chains whole and reduces
hooks to one copy. INPUT/FORWARD hooks are inserted first when added or repaired,
then leave later vendor filters ahead of them (D8). Only portal RETURNs
continually enforce their position before vendor rules. An upgraded live
session retains the former IPv6 `U60_RELAY_IN` until teardown.
The former `U60_RELAY_V6`, `U60_RELAY_OUT`,
`U60_R6_OUT` and `U60_R6_NAT` are gone; the previous agent's journals still
name them and remain undoable. This version's tables are journaled once, in
the wireless plan, as `@u60-relay-nft remove ip|ip6`, which the previous
agent runs too (`tests/relay-firewall-qa`).

An owned legacy rule is identified by its chain or target (`U60_*`) or by a
`zte-agent*` comment, which every rule in a vendor chain without a jump to one
carries (the current portal RETURN or the old IPv4 MASQUERADE), checked by
`netfx::effect::legacy::owned_rule`. The
station's name is no identity, since the vendor's IPACM file lists `ath20`
too. Two MASQUERADE rules that match the station must never exist together:
on B31 the first does not end the chain for every packet, and the second
then drops the new connection with a kernel warning (`nf_nat_setup_info`;
measured 2026-11-12: 9 warnings in 12 s with a second rule, none without).

On same-boot takeover, `installed_lease` converts a legacy `Lease` to
`NftLease` before migration. `retire_legacy_hook` then removes the exact old
tagged MASQUERADE. `uplink.adopt()` checks the ownership marker and stages
the IPv4 layout in memory. `take_over_ipv6` can confirm the combined layout
through `uplink.update()`. `uplink.finish_adopt()` reuses a confirmed layout
or loads both families in one batch when needed.

Mihomo sets `routing-mark` to `ids::CORE_OUT_MARK` (`0x01000000`). The
relay's local OUTPUT `dns_out` chains in both families return on this bit,
so the core's own plain DNS retains its destination. This exception is for
locally generated traffic. B31's portal can rewrite marks on transit DNS.
ZTE's scripts use `0x3f00` and `0x40000000`, TPROXY `0xff00`, Tailscale
`0xff0000`.

`net_guard` decides when owners check (`relay-mihomo-architecture.md`
section 4.4): after a ZTE script opens or a firmware event, a check once it
has been quiet 2 s (owners are woken for it, not left to their next tick),
and again 5 s after a check that had to restore something; once a minute
otherwise. For 3 s after each trigger it reads the kernel settings an owner
holds (`@u60-sysctl`, such as Mihomo's `bridge-nf-call-ip(6)tables=0`) every
0.5 s and writes back one ZTE changed, only while that owner still holds it:
an owner's release unregisters the setting before its undo runs. The watched
scripts and events are `net_guard::WATCHED` and `EVENTS`.

A check reads each legacy tool/table once (`-S`) and routes, rules and addresses
once per family, shared by the relay's sets through `net_tools::Pass`.
Repairs invalidate the listings. Owned chains are compared and replaced whole.
A hook missing from its predicted listed form gets its own `-C`, and a hook
found only that way is kept and logged once. Definite absence permits re-adding
it, for example when `-C` (or `-D` during undo) exits 1 with one of the two
wordings B31's iptables 1.8.8 (legacy, both families) uses for a missing
rule (`netfx::effect::legacy::no_rule`), "Bad rule (does a matching rule exist in that
chain?)" when the rule's target is ACCEPT or RETURN or its chain is missing,
"No chain/target/match by that name." when it jumps to a user chain that
exists (every hook into a `U60_*` chain), or when undoing an old legacy
MASQUERADE. A missing target chain exits 2 and proves nothing. The first batch-1 build knew only the first wording: after a reboot
the vendor's firewall start had flushed the IPv6 INPUT hook, its undo read as
"not checked", and every relay restore failed with "Network cleanup paused"
until the fixed build was installed (2026-11-12, about 15 minutes without an
uplink).
A listing or tool failure is reported as "not checked" and left to the next
check. Confirmed duplicate hooks are reduced to one. Undo removes every copy
of an owned rule and empties an owned `U60_*` chain once external jumps are gone,
before deleting it. Repair logs name commands or resources such as
`iptables -t nat hook redirect_chain …`.

The firewall reload that follows a relay connect is the agent's own: IPv6's
`ubus call network.interface.lan set_data` (`wifi_relay/ipv6/ra.rs`) makes
netifd run the `iface` hotplug with `ACTION=ifupdate IFUPDATE_DATA=1`, and
`/etc/hotplug.d/iface/20-firewall` runs `fw3 -q reload` (process chain
captured 2026-11-12; two reloads 3.2 s apart when IPv6 was withdrawn). Every
reload runs the vendor's `firewall_init.sh`, which sets
`bridge-nf-call-ip(6)tables` to 1 (no vendor setting turns that off; it read
1 for about 0.2-0.5 s per reload before the sampler set it back) and flushes
`redirect_chain` (`relay-hw-offload.md`, section 5).

### Hotel authentication

Connect the phone to the **U60** hotspot. Turn Mihomo off, connect Relay, and
open an ordinary HTTP page from the phone to trigger the upstream hotel's web
login. Complete authentication only on the expected hotel page; never ignore
TLS certificate errors. Once the U60's upstream session works, enable Mihomo.
An association/DHCP lease is displayed as **internet not verified**, not as a
successful internet or captive-portal acceptance test.

### Relay together with Mihomo

LAN clients still enter `br-lan`, so Mihomo interception applies regardless of
whether the upstream is cellular or the Wi-Fi relay. With both enabled, the
intended path is `LAN client -> Mihomo rule/node or DIRECT -> Wi-Fi upstream`.
Direct/private management exemptions still apply; `DIRECT` does not mean a
proxy-node exit. Router-originated applications are not all transparently proxied.
When optional upstream IPv6 is configured, Mihomo DIRECT connections and
IPv6-only node connections can use native Wi-Fi IPv6; with Mihomo off, LAN
clients can use the same upstream through NAT66. A capable node can separately
reach IPv6 destinations over its IPv4 transport. The combined path passed the
controlled B31 tests; hotel authorization, both radio bands and long-run behavior
remain separate acceptance gates. The earlier design/benefit assessment is in
[relay-ipv6-nat-assessment.md](archive/2026-10-25-relay-ipv6-nat-assessment.md).

### Admission of conflicting changes

`netfx::admission` briefly holds its gate to check conflicts and register work.
The registration covers the operation across ubus calls, Wi-Fi reloads, config
writes and CAC. See the [controller architecture](relay-mihomo-architecture.md#46-准入-admission). A relay operation the owner
starts (scan, connect, its settings) registers itself and is refused while a
router setting change is being applied; a disconnect always registers. The relay
serializes its own operations and its 3 s checks on the `relay` controller thread. Hotspot,
guest Wi-Fi, LAN, USB and vendor firewall changes wait at most 3 s for a relay
operation in progress (then 409 "in progress"), refuse at once while the relay
or Mihomo owns the network (409 with the reason), and otherwise hold their own
registration while they write. A hotspot or guest change also starts the
vendor's asynchronous Wi-Fi reload, which stays registered until the 5 GHz
hotspot reads `ENABLED` twice 2 s apart (at most 120 s): the relay does not scan
or connect meanwhile. Fixed DHCP reservations only serialize their own writes.
`POST /api/wifi-relay/disconnect` runs in the general lane, so it can cancel a
connect or restore even while long operations fill both slow permits.
`scripts/probe-admission.sh` counts "in progress"
and conflict refusals separately on a device.

### Hardware forwarding (IPA)

Relayed IPv4 NAT is carried by the Qualcomm IPA: B31's stock
`/etc/data/ipa/IPACM_cfg.xml` lists `ath20` as a Wi-Fi interface (Category
UNKNOWN, WlanMode full), and IPACM reads it once at boot. The agent only reads
that file (`offload.config`: `listed`, `not_listed` or `unavailable`); it
never writes it, and there is no install step or restart. Builds before
2026-11-12 inserted a `u60sta0` entry instead (removed from the owner's router
with that build's own remove action on 2026-11-12). The owner's switch
(`/data/zte-agent-relay/ipacm/off`) applies to a connected relay at once
(owner decision 64): releasing the path deletes the
`main` default (IPACM loses its relay WAN), then resets LAN IPv4 connections.
While connected and switched on the relay adds a `main` default (metric
60631, with unreachable guards for the ranges its table throws). The agent
never reads or switches IPACM's hardware/software mode (owner decision,
2026-11-12): the router's working mode decides it. Balanced (`Nomal_mode`,
极速模式) turns acceleration on; the other working modes, a vendor speed
limit, power saver and `ipa_disable` turn it off, and `Ai_mode` (the factory
default) and `Game_mode` switch it with traffic. The Relay page therefore
says "Hardware (IPA) in the Balanced (极速模式) working mode; CPU in any
other" while the route is in place, and confirms nothing. RPS and a 5000 backlog help the
traffic that stays on the CPU. With Mihomo on, the optional DIRECT bypass lets
IPv4 the core's mode and rules send DIRECT skip the core in the kernel, so it
can be offloaded too. Offloaded connections skip iptables, tc and parental
control. Design, measurements and open items:
[relay-hw-offload.md](relay-hw-offload.md).

### Upstream Wi-Fi power save

The driver turns 802.11 power save on for every new station (`iw dev
ath20 get power_save`); it is unrelated to ZTE's power saver mode. With it
off, short single-connection tests through the relay went from 166-218 to
244-250 Mbit/s (2026-11-08). By default each relay connection turns it off
(owner decision 65, `wifi_relay/power_save.rs`): an `@u60-relay-power-save
off` step in the session's network plan, so `net_guard` re-checks it with
the rest and turns it off again after the driver or a script turns it back
on. The Relay page switch (`POST /api/wifi-relay/power-save`) is saved as
`/data/zte-agent-relay/keep-power-save` when the owner keeps the driver's
default, and applies to a connected relay at once. Restoring it at teardown
is best effort and never pauses a cleanup, because the interface is deleted
next.

## Recovery

Modules serialize their network changes and journal undo commands before each
effect. Journals contain only owned changes and a boot ID. Same-boot restart
attempts rollback; old-boot kernel/wireless journals are discarded because the
changes were runtime-only. Runtime RA data also vanishes after reboot; no
old address, DNS or RA snapshot is replayed. Legacy UCI snapshots are migrated
once by repairing only proven committed relay values. No global firewall/table flushes or
main-default replacement.
Startup/disable refuse to hide a failed recovery. On Linux children have a
parent-death signal and are spawned by one permanent thread (not a retiring
blocking worker). This stops orphans, **not** kernel rules on an agent crash:
service restart/recovery is still necessary, and uninterrupted forwarding
during an agent crash is not promised. The kernel clears that signal when an
exec changes the SELinux domain, which B31 does for `wpa_supplicant`
(`wpad.subj`) and `odhcp6c` (`odhcp6c.subj`) even in permissive mode, so
those two survive the agent (seen on every update). Relay recovery therefore
first stops any `wpa_supplicant`, `odhcp6c` or `udhcpc` on `ath20` with the
relay's private paths that is not its own child (SIGTERM, then SIGKILL after
1 s); otherwise the old supplicant keeps the control socket, the new one
exits, and every reconnect fails at association.

Relay journals the roam-mode undo before changing the driver and an association
undo before reconfiguring a credentialed supplicant. Reverse recovery first
requires positive driver confirmation that STA is disconnected, then restores
the same-radio AP geometry and roam mode. Uncertain link state stops recovery
and retains its journal, rather than forcing AP changes while still associated.
An unresponsive owned supplicant is killed/reaped before normal rollback; after
a crash, restoring roam mode may use a temporary credential-free supplicant.

### Power-off charging boot

After a low-battery power-off (`reboot_module_name='lowbatt power off'`),
restored power may boot B31 into `mode_power_off_charger`
(`zwrt_zte_mc_tmp.mode.mode_main_state`). Linux, `adbd` and the agent run while
`iw dev` shows no Wi-Fi interfaces. In this mode `wifi_onoff` is 0 even when
`wifi_onoff_by_user` remains 1. Relay restore uses the owner switch through
`hotspot::off_by_owner` and preserves the saved intent. To resume normal boot
from this charging state, use `ubus call system reboot '{}'`.

### After a restart

After an update, crash or reboot, the agent attempts to resume only persisted owner choices. Restoration
is bounded, not a guarantee of connection or Internet access. The records are
Mihomo's
`/data/zte-agent-mihomo/enabled` marker (written by a successful switch on,
removed by switching off or by a switch on that failed), and the relay's
`/data/zte-agent-relay/resume.json` with the network's SSID, security, BSS and
the IPv6 choice (written by a successful connect whose password is
remembered, or an open network; removed by Disconnect or by a new owner connect
request before its replacement succeeds). Neither holds a password; a dropped
link or a failed restore keeps the records. A stored WPA2 password must still
match the chosen network to restore it. An older agent writes neither record,
so the first update from one cannot infer intent from saved profiles or Wi-Fi
credentials. Once connected again or explicitly switched on successfully, the
new agent can persist that choice.

On an agent restart within the same boot, the controllers can adopt live
network effects. On startup, `net-restore` waits for vendor boot sync (up to
3 minutes), then calls relay `recover_idle`, Mihomo `restore` once, and relay
`restore`, in that order. Relay `recover_idle` handles leftover state before
Mihomo chooses an uplink. After an unsuccessful start with enable intent
still set, the Mihomo controller manages its own retries (5, 15, 30 and 60 s,
then every 5 min). In backoff or while failure cleanup awaits retry, observing
an effective new IPv4 egress through `egress_while_direct` triggers an immediate
retry. A relay that installs routes notifies Mihomo to check its egress.

Relay restoration has a separate schedule of up to 10 attempts (about 17 min
in retry waits, plus scan and connection work). It scans for the saved BSS or
the strongest BSS with the same SSID and security, using the saved credential
if required. The relay page shows **Reconnecting** and a Stop button during
restoration. **After a restart** shows whether a connected relay is eligible
to resume. Mihomo setup also reports the real saved start choice independently of
whether the core is running. If it is off with that choice still enabled,
**Stop automatic start & keep off** clears it. A disconnected Relay with a saved
choice offers **Disconnect & clear restart choice**, even after restoration has
stopped. When cleanup is needed, the existing cleanup button performs both jobs
rather than showing duplicate stop controls.

Owner Connect validates the published scan selection, cancels pending restoration,
then takes admission and queues the request to `relay` within the same 3 s budget.
Validation takes only the snapshot lock. A request abandoned before starting is
skipped by the controller. Disconnect marks cancellation immediately, returning
acceptance during work. The controller tears down before processing the next
message or publishing the cancelled result. An idle caller waits for the
controller to finish teardown, including the hotspot's return. Restore retries
use controller timers so other requests can run between attempts. Switching
Mihomo off cancels its pending restoration.
Relay restoration runs only at startup. The running agent cleans up a dropped
relay when its recovery window ends. Mihomo Off clears its automatic start choice.

See the [2026-10-28 reboot record](archive/2026-10-network-extension-validation.md#2026-10-28-reboot-and-installer-validation) for the earlier 2.4 GHz and Mihomo build.

Keep USB ADB available for initial testing. Stop the agent before emergency
manual recovery, then run the agent binary's `network-recover` command over
USB/SSH. Do not run recovery against a live extension. It does not delete
subscriptions or touch factory daemon registrations. If a recovery reports a
failure, retain the journal for diagnosis; do not blindly delete it.

## Routes

Send a bearer token with the JSON requests below. Slow operations run through
the blocking gate. Submit passwords and subscription credentials in request
bodies. A console login can obtain the dedicated Zashboard bridge pass cookie.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/router/reservations` | List downstream DHCPv4 reservations |
| POST | `/api/router/reservations` | Add or remove an agent-owned DHCPv4 reservation |
| GET | `/api/mihomo/status` | Installed/configured/running state; no config secrets |
| POST | `/api/mihomo/install` | Install the pinned core and dashboard |
| PUT | `/api/mihomo/config` | Validate and save `{"yaml":"..."}` |
| POST | `/api/mihomo/switch` | Start/stop with `{"enabled":true/false}` |
| POST | `/api/mihomo/direct-bypass` | `{"enabled":true/false}`: the DIRECT bypass, IPv4 the core's mode and rules send DIRECT skips it in the kernel; a running core stays running. Tightening clears software conntrack for connections that lose DIRECT, falling back to all LAN IPv4 when the scope cannot be expressed precisely. IPA hardware eviction is unconfirmed. See [connection reset scope](relay-mihomo-architecture.md#45-conntrack删除范围代次结果). Status `direct_bypass`, `direct_bypass_active`, and `kernel` (`bypass`, `returns`, `reason`) |
| GET | `/api/wifi-relay/status` | Memory-only state and last scan; `phase` as listed below, `connected`, `recovery_required`, `autostart`, saved networks, offload/power-save state and `connection_resets`; no BSSID/password |
| POST | `/api/wifi-relay/scan` | Explicit scan, no background scanning; bounded admission/operation wait, busy 409 with `phase` |
| POST | `/api/wifi-relay/connect` | `{"network":"opaque scan id","password":"...","confirmed":true,"ipv6":true,"remember":true}`. Omitted `ipv6` defaults to `true` and omitted `remember` to `false`. The agent validates the selection, cancels pending restore, and applies the 3 s admission and start limit (409) |
| POST | `/api/wifi-relay/disconnect` | Cancel immediately; 200 with `disconnecting` means accepted during another operation, not finished. Otherwise restore runtime hotspot/routes synchronously, including CAC |
| POST | `/api/wifi-relay/clock` | Explicit fresh HTTPS time check; requires an active relay, never reconnects it; bounded admission/operation wait (409) |
| POST | `/api/wifi-relay/offload` | `{"enabled":true/false}`: the hardware forwarding switch; a connected relay follows at once; status `offload.config` (`listed`/`not_listed`/`unavailable`, read from IPACM's file), `offload.enabled`, `offload.state`, `offload.route` |
| POST | `/api/wifi-relay/power-save` | `{"auto_off":true/false}`: turn the upstream Wi-Fi power save off at each connection (default) or keep the driver's; a connected relay follows at once; status `power_save.auto_off`, `power_save.off`, `power_save.error` |
| POST | `/api/wifi-relay/strict-zero-cellular` | `{"enabled":true/false}`: pause cellular data calls and evict surviving cellular flows while the relay is connected, restoring the saved pre-pause cellular state on disconnect or recovery without enabling a previously disabled modem |
| GET | `/api/mihomo/profiles` | Profile library status, no URLs or YAML |
| GET | `/api/mihomo/profiles/{id}` | Explicit private editor read (metadata and URL, never saved YAML) for one profile |
| POST | `/api/mihomo/profiles` | Add, edit, select, refresh and delete profiles; set Merge and Script. Selected-subscription refresh hot-reloads when possible; identical source skips compile/validation |
| GET | `/api/mihomo/extensions` | Explicit private editor read of the global Merge and Script |
| GET | `/api/mihomo/proxies` | Proxy groups, members, current choice, last delay and routing mode; 409 when Mihomo is off |
| POST | `/api/mihomo/proxies/select` | `{"group":"...","name":"..."}`; slow lane |
| POST | `/api/mihomo/proxies/delay` | `{"name":"..."}`; tests against a fixed URL, `0` means failed, `null` never tested; slow lane |
| POST | `/api/mihomo/mode` | `{"mode":"rule\|global\|direct"}`; slow lane |
| POST | `/api/wifi-relay/forget` | Forget a saved network (its remembered password); the bandwidth choice and `/api/wifi-relay/tuning` were retired in v6 |
| POST | `/api/mihomo/dashboard` | Console login only; issues the Zashboard pass cookie and returns `{"url":"/ui/mihomo/dashboard/#/proxies"}`; 409 when Mihomo is off |
| GET | `/ui/mihomo/dashboard/*` | Running-only local third-party panel, pass cookie required |
| restricted | `/ui/mihomo/api/*` | Same-origin pass-cookie HTTP/WebSocket bridge |

See [Tailscale routes](#tailscale-routes) for the remote-management and Tailscale Services endpoints.

Relay `phase` is `idle`, `scanning`, `connecting`, `active`, `recovering`,
`disconnecting` or `recovery_pending`. `recovering` covers association recovery
and restore after agent start; actual scan/join steps show their own phases.
`recovery_required` is true only with journals left, `idle`/`recovery_pending`,
and no pending disconnect. The constant top-level `experimental`,
`cellular_fallback` and `internet` fields are removed; `ipv6.internet` remains.
Restart choice, journals, offload configuration/switch, power-save intent and
saved networks are computed at publish time. GET reads the published snapshot
and reset history under short locks while controller/device work continues.

All six owner actions (scan, connect, power-save, offload, forget and clock)
wait at most `admission::WAIT` (3 s) for admission and the controller to start
them. Once started they wait for the result. Requests that time out before
starting are abandoned and return HTTP 409 with
`{"ok":false,"error":"A network operation is in progress (<phase>); retry after it finishes","phase":…}`.
Vendor-write/reload conflicts also return 409 with their own reason; other relay
operation errors remain 503. The offload, power-save and forget rows above use
this same wait rule. See [B31 batch 4](archive/2026-11-12-relay-mihomo-implementation.md#batch-4) for responses during
teardown and [batch 5](archive/2026-11-12-relay-mihomo-implementation.md#batch-5) for the coverage of Connect during
boot restoration.

### Tailscale routes

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/tailscale/status` | Read saved settings and live TUN, sync, route and Exit Node status |
| GET | `/api/tailscale/versions` | Discover versions using the release cache |
| POST | `/api/tailscale/versions/refresh` | Refresh version discovery |
| POST | `/api/tailscale/setup` | Set up Tailscale |
| POST | `/api/tailscale/login-url` | Request an interactive sign-in link |
| POST | `/api/tailscale/enable` | Enable Tailscale |
| POST | `/api/tailscale/disable` | Disable Tailscale |
| PUT | `/api/tailscale/config` | Apply a partial update to managed settings and return refreshed status |
| POST | `/api/tailscale/logout` | Log out of Tailscale |
| POST | `/api/tailscale/update` | Update to the selected version with SHA-256 verification |
| GET | `/api/tailscale/services` | Aggregate `ServeConfig`, `Prefs.AdvertiseServices`, `Self.CapMap`, and `Self.PrimaryRoutes` for `svc:*` services |
| PUT | `/api/tailscale/services/:name` | Atomically create or update one `svc:<name>` service via `If-Match`-guarded `POST /localapi/v0/serve-config` |
| POST | `/api/tailscale/services/:name/drain` | Stop accepting new connections for `svc:<name>` while retaining saved handlers |
| POST | `/api/tailscale/services/:name/advertise` | Resume advertising `svc:<name>` to the tailnet, or re-advertise (`drain` then `advertise`) if already advertised |
| DELETE | `/api/tailscale/services/:name` | Clear all handlers and advertisement for `svc:<name>` |

Send the managed fields you want to change with `PUT /api/tailscale/config`.
Omitted fields keep their saved values. The managed fields are `hostname`,
`tailscale_ssh`, `hold_wakelock`, `advertise_routes`, `advertise_exit_node`
and `exit_via_mihomo`. A supplied `advertise_routes` array replaces the whole
subnet list. Send `[]` to clear it. The agent normalizes and deduplicates CIDRs
and accepts up to 16 distinct subnet routes. `advertise_exit_node` controls
advertising both default routes. `exit_via_mihomo` stores the routing preference
for Exit Node traffic and keeps that preference when advertising is turned off.

The `routing` block includes the reported `tun` mode and netfilter mode,
`lan_subnets` for quick-add, and `routes` with each saved prefix's live approval
state. `routing.exit` shows `advertised`, `via_mihomo`, and approval states in
`state`, `state_v4` and `state_v6`. `routing.sync` is `applied` when daemon
preferences match, `pending_daemon` when saved changes are waiting to apply,
`drift` when the running daemon differs, or `unknown` when the comparison is
unavailable.

Tailscale Services (`svc:*`) use `tailscaled`'s own `ServeConfig` in
`/data/tailscale/tailscaled.state` as the sole source of truth. Reads are
fork-free over `/localapi/v0/serve-config`, `/localapi/v0/prefs`, and
`/localapi/v0/status?peers=false`. Single-service writes validate syntax, port
conflicts, and HTTPS path uniqueness, preserve all other services and node-level
Serve entries verbatim, pass the `ETag` via `If-Match` (returning HTTP 409 on
concurrent edits), refuse to silently overwrite CLI-only advanced handlers
(`Text`, plaintext `HTTP`, `TerminateTLS`, `ProxyProtocol`, `AcceptAppCaps`,
`--tun`), distinguish undefined services (`defined_in_tailnet: false`) from defined-but-unapproved services, and automatically advertise newly created services while preserving an existing service's drained state on edit. Calling `POST /api/tailscale/services/:name/advertise` on an already-advertised service cycles `drain` then `advertise` so a service defined in Tailscale Admin after initial configuration registers immediately. All Tailscale Services endpoints
run on the Slow lane and require authentication, CSRF/Origin checks, and
serialization through `prefs_lock`.

### Tailscale kernel-TUN and Clean DNS

When `/dev/net/tun` is available, `tailscale::supervisor` applies
`netfilter-mode=off` through `tailscale set` during preflight and spawns
`tailscaled` with `--tun=tailscale0` behind an `EffectSet` data plane
(`tailscale::netplane`, journal `/data/tailscale/network.json`):

- **Firewall & policy routing**: dual-family `ip`/`ip6 u60_tail` owns anti-spoof
  `input` protection for management ports, `0x02000000` conntrack origin marking
  in `prerouting`, bidirectional `rt mtu` SYN MSS clamping and control-plane
  approved `forward` allowlists (approved LAN subnet traffic exits through
  `br-lan` in both IPv4 and IPv6, while Exit Node internet traffic is bound
  strictly to the active physical uplink `ath20` or `rmnet*`), and conditional
  `postrouting` masquerade (for `rmnet*` Exit Node traffic when cellular is
  active and `br-lan` approved subnets, never duplicating the Wi-Fi relay's
  `ath20` masquerade). Legacy
  `U60_TS_IN` and `U60_TS_FWD` provide accept-only passes through vendor
  filters. RPDB priorities `5110` (verified Tailnet destinations -> table `52`),
  `5130` (CGNAT -> `main`), and `5131` (CGNAT `unreachable` guard) cooperate
  with Mihomo (`5100`), Wi-Fi relay (`5120`), and `tailscaled` (`5210–5270`).
  Management privilege checks use `IP_PKTINFO` / `IPV6_RECVPKTINFO` so only true
  local loopback or verified `tailscale0` peers reach Tailnet/local routes.
- **Clean DNS isolation**: both kernel-TUN and userspace daemons spawn inside a
  private mount namespace (`CLONE_NEWNS` + `MS_REC|MS_SLAVE`) with a read-only
  bind mount over `/tmp/resolv.conf.d` pointing solely at `127.0.0.54`, backed
  by a dual-protocol UDP/TCP DoH resolver (`tailscale::clean_dns`) bound to
  `127.0.0.54:53`. In kernel-TUN mode only, port-53 contention falls back to
  `:1054` with an exact-verified `chain dns_out` DNAT rule in `ip u60_tail` and
  a loopback conntrack flush; userspace mode requires direct `127.0.0.54:53` and
  backs off if it cannot bind there. Clean DNS queries through Mihomo's private
  proxy (`127.0.0.1:17893`) only when `exit_via_mihomo` is enabled, Mihomo is
  running, and Mihomo is not in `Direct` mode; when Mihomo is stopped, in
  Backoff, in `Direct` mode, or `exit_via_mihomo` is off, it uses direct
  IP-literal DoH with no bootstrap DNS deadlock. Userspace fallback runs a
  two-pass `CLONE_NEWNET` cold-load scrub to ensure persisted exit routes are
  cleared on disk.
- **OTA rollback guard**: before any OTA slot change or fallback,
  `tailscale::netplane` persists a same-boot `clean-dns-dnat-flush-pending`
  marker before removing the journal, and both `tailscale::supervisor` and
  `zte-agent-supervisor.sh` verify that no same-boot Tailscale journal or flush
  marker remains active (completing any pending same-boot Clean DNS DNAT
  conntrack flush first) before handing off to an older slot.
