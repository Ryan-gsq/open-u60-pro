# October 2026 network extension validation

> Historical record · 2026-10-26 to 2026-10-29. The builds, topology and original
> evidence locations below belong to the recorded runs. Private paths refer to
> external development-machine or device records. See the [current extension reference](../network-extensions.md).

## Historical validation snapshot (2026-10-26)

These counts, sizes and browser/device results describe the 2026-10-26 checkout,
not the current tree. The actual-core acceptance at that point used all-gVisor
TUN; the current TPROXY interception and its measurements are described under
[Interception scope](../network-extensions.md#interception-scope). Rerun current artifacts for a new
acceptance claim; source changes alone do not extend these results.

- `cargo test -p zte-agent`: 1030 passed, 0 failed, 2 existing ignored tests on
  macOS. The new Linux-only mutating lifecycle test is separately ignored and
  explicitly run inside a disposable OpenWrt chroot: 1 passed.
- `node --test zte-agent/tests/mihomo-dashboard.cjs`: 4 passed; tests current
  origin/default ports/IPv6, query isolation, stale backends and blocked storage.
- `cargo clippy -p zte-agent --tests -- -W clippy::all`: succeeds; 23 existing
  repository warnings remain, none reported in the new networking modules.
- `cargo fmt --all -- --check` does not pass the existing repository formatting
  baseline (including untouched `euicc/src/der.rs` and many existing modules).
  No unrelated mass-formatting was applied; this is not a clean-format claim.
- ARM64 musl release builds as a stripped static ELF. Final size is recorded in
  `network-integration-review.md`. Cross-built on macOS with Zig's
  musl compiler via temporary external wrappers; repository build config unchanged.
- `app.css`: 49,026 bytes, within the 48 KiB budget.
- Real Rust-rendered HTML and assets were checked in headless Chrome at
  320/375/390/1440 px: 28 page/viewport combinations, no horizontal overflow;
  only the current tab's label expands on phones. Light/dark screenshots and
  selected/unsupported network cards were inspected. No router services ran.
- The pinned Zashboard loads against a same-origin mock and opens its four
  expected WebSocket streams. These browser cases do not use a real Mihomo core
  or router. Separate native loopback tests exercise the actual Rust HTTP/TLS
  listeners and bridge against a credential-checking mock core: session/origin
  checks, config redaction/write restrictions, WebSocket query sanitation,
  shared listener caps and immediate WSS close on HTTPS Reset.
  Thirteen additional browser cases cover first entry, direct bookmarks, stale
  and corrupt storage, blocked storage, HTTP/HTTPS/IPv6, hostile old query values
  and prefilled Setup while the backend is unavailable. First entry and refresh
  do not render Setup; no default-localhost probe occurs. Only the optional
  external update check is blocked as described above.
- Real Linux network namespaces pass TCP/UDP NAT66 from both downstream ULA
  and retained global sources, native router IPv6 including upstream ULA,
  finite-lifetime updates, Mihomo marked-route priority and full rule rollback.
- Official OpenWrt 23.05.5 `odhcp6c` runs the actual Rust callback. The full Rust
  IPv6 start/tick/stop test covers no-upstream detection, configuration, renewal,
  lost-route rebuild, reconnect, stale callbacks, lease withdrawal and exact
  restoration of persistent DHCP configuration/main routes. A separate actual
  odhcpd RA capture confirms only the relay ULA is advertised with router
  lifetime 90, and recovery preserves conflicting external changes.
- The OpenWrt lifecycle tests use the VM's kernel, not B31's kernel/driver. The
  OpenWrt chroot has no procd; odhcpd reload signals the real daemon directly,
  and the lifecycle test stubs dnsmasq restart only. Separate actual-core tests
  ran on a real Linux bridge and in B31 namespaces, followed by physical
  Relay/Hysteria2 TCP/UDP dual-stack testing (those runners and the
  namespace rule-plan runner above were removed on 2026-11-12). See
  [relay-ipv6-validation.md](2026-10-27-relay-ipv6-validation.md) for evidence and the
  [instructions](../../tests/relay-ipv6/README.md) for the lifecycle and RA runners.
- `git diff --check` passes; no iOS, Android or public-site changes.
- Standards and Spec reviews, fixes and the remaining acceptance gap are
  recorded in [network-integration-review.md](2026-10-28-network-integration-review.md).

At that 2026-10-26 acceptance snapshot, only bounded test agents and a manually
launched full port-9090 panel had been used; both extensions were left off.
Later `setup.sh` update/reboot testing is recorded under
[After a restart](../network-extensions.md#after-a-restart). The current installer supports a persistent
agent boot entry and extension restoration from saved owner intent. The list
below includes repeat/remaining gates, not a claim that no hardware testing or
installation has occurred.

## Acceptance still required on the U60

This is the October checklist. See the [device acceptance index](../README.md#device-acceptance) for subsequent coverage and remaining cases.

1. Deploy a test agent over USB without replacing the only working recovery
   path; first load Router/Relay while both features are off.
2. Install core/dashboard, save a private config, start Clash, confirm IPv4
   TCP/UDP and IPv6 TCP/UDP exit addresses/actual node hits from LAN. Stop and
   check process, owned chains, policy rules, DNS and ordinary direct traffic.
3. Test Zashboard selection, provider refresh, traffic/log WebSockets, logout,
   expiry, HTTPS and off-state access refusal from desktop and mobile browsers.
4. Relay into a controlled AP: both own hotspot bands, DHCP renew, NAT,
   upstream-side INPUT isolation, policy-routing selection and DNS. Then hotel
   authentication, not just a returned HTTP 200.
5. Repeat relay + Mihomo together, enable/disable order, upstream loss/lease
   changes, credential failure, occupied chains/tables, core exit, vendor Wi-Fi
   reload, suspend/resume and agent crash/restart. Verify no stale rules and
   that intended fallback uses SIM only when accepted.
6. On a controlled dual-stack AP, check native router IPv6, actual IPv6-only
   Mihomo node transport and DIRECT TCP/UDP, phone SLAAC/NAT66 from both hotspot
   bands, local/public DNS, low-MTU/PMTU and unsolicited upstream isolation.
   Repeat with IPv6 unchecked, absent, expired and changed: IPv4 must remain
   working and no IPv6 traffic may leave rmnet. Check lease refresh, zero-lifetime
   RA withdrawal, same-boot crash/restart, reboot and original UCI restoration.
   Test hotel IPv6 authorization separately from its IPv4 portal login.
7. Throughput, UDP games/QUIC, power/temperature, long idle, a cold boot with
   a 5 GHz upstream and a second B31 device remain unverified (cold boot with
   a 2.4 GHz upstream and Mihomo: see "After a restart"). Do not present this as production ready.


### B31 reboot clock and recovery guard

See the [current clock and DNS reference](../network-extensions.md#relay-clock-and-dns).

The agent restores a local UTC lower bound at startup (build time or its last
verified UTC). This is not an RTC and cannot determine elapsed offline time.
On Relay connection/core start, certificate-verified HTTPS Date responses from
Apple and Microsoft must agree before the system clock is synchronized. These
small requests bind to the selected Wi-Fi STA, never enable or use cellular, do
not follow redirects and do not disable certificate checks. A captive portal or
failed verification leaves IPv4 Relay active and exposes `clock_error`.
Relay status reads the latest shared clock result, not the connect-time copy:
a later successful core-start check clears an earlier warning on the next page
refresh. While a warning is present, **Recheck time** performs a fresh check
with success/error feedback, without reconnecting Wi-Fi or restarting Clash.
The Slow-lane request queues Clock to the `relay` controller and waits for its
result. Status reads the snapshot meanwhile. Each new relay connection also checks afresh.
A Mihomo core start on the relay starts that check on a thread of its own
(`mihomo-clock`, one at a time) and does not wait for it: a failing check took
4-16 s inside a planned restart's or an adoption's blackout. A passed check is
reused for five minutes; a failed check invalidates that cache. No periodic background clock probes are added, and a
restored local UTC floor alone never clears a failed-verification warning.

Clock warning regression validation (2026-10-27): `cargo test -p zte-agent`
passes 1090 unit tests plus 1 startup integration test, with 3 ignored tests.
Coverage includes failure/success replacement across callers, fresh retries,
nonblocking status, disconnected/busy guards and session/origin/CSRF/single-use
form checks. Browser fixtures verify the warning, round progress indicator and
successful return on desktop and narrow layouts without touching the live relay.
The ARM64 musl release has section Total 8,465,560 bytes and gzip size
4,330,994 bytes. This records source/build validation, not live deployment.

5 GHz relay scan validation (2026-10-27, one boot, relay on 2.4 GHz, main
5 GHz hotspot on 36 at 160 MHz with one client, existing association kept
`COMPLETED` throughout): requests `5180,5220` were refused (`Reject 0 channel
Scan`) 3/3; `2412,5220` finished with no fresh 5 GHz entry 3/3; `5220` alone
found the 5220 MHz upstream at age 0 s 3/3. The old full scan with a 6 s sleep
missed it 2/2. The new sequence (14 requests, run through a one-off
on-router diagnostic, since removed in favor of the scan API) found it
fresh 3/3 in 3.04-3.07 s. ARM64 musl release: section Total 8,486,448 bytes,
gzip -9 4,331,301 bytes, +16,720 and +7,371 bytes over the same tree without
this change (both measured with the same tool).

The dated records below (2026-10-27/28) name the station `u60sta0`, its name until 2026-11-12.

Live 5 GHz relay acceptance (2026-10-27, agent `35743a58`, Mihomo off): the
web scan listed the 5220 MHz upstream; connecting left `wlan2` alone and the
driver moved it by CSA from 36/160 MHz to 44/80 MHz within 3 s (no restart, no
CAC). The STA associated at 160 MHz, RX 1297-1921 Mbit/s (HE-MCS 6-9, 2 SS);
the owner measured 140 Mbit/s through the relay. The same router's 2.4 GHz
network (seen by the U60 only on 2412 MHz) stays at about 6 Mbit/s through the
relay, unchanged with the U60's 2.4 GHz AP disabled; under load the router
gateway RTT rose from 3 ms to 21-33 ms average (peaks 65-195 ms), so that
limit is on the router's 2.4 GHz side, not in the relay. A Mac reported as
"directly on W" was associated on 44 at 160 MHz (104 Mbit/s), i.e. 5 GHz.

Association scans (2026-10-27, agent `4f9163de`): the network block has both
`freq_list` and `scan_freq` set to the upstream frequency. `freq_list` alone
only restricts selection; the supplicant's own connect scans were full scans
(1.7 s each), lost 5 GHz while the hotspot ran 160 MHz, and "Wi-Fi association
failed" followed after 30 s. The first 5 GHz connect had worked only because
the kernel still cached the page scan. With `scan_freq` the connect scan took
75 ms and the 5220 MHz upstream associated in about 1 s.

Throughput layers on the 5 GHz upstream (same day, Mihomo off, 6 parallel
HTTP range downloads from two CN mirrors, 12 s): the U60 itself 249 Mbit/s, a
Mac directly on that upstream 250 Mbit/s, the Mac behind the relay (hotspot
44/80 MHz) 213, 219, 241 and 246 Mbit/s. During forwarding CPU0 ran 71-88%
softirq while CPUs 2-3 stayed about 87% idle. RPS (`rps_cpus=f` on
`u60sta0`, `wlan2`, `br-lan`) gave 234, 251 and 254 but collapsed to 71 and 51
Mbit/s in two of five runs with idle CPUs, so it is not used. The kernel has no
flow offload (`CONFIG_NF_FLOW_TABLE` unset).

2.4 GHz upstream, LAN only (U60 to a host on the same router, no WAN): 5-35
Mbit/s down, 11-26 up. The router sent to the U60 mostly at HE-MCS 1, 1 SS,
20 MHz at -34 dBm. Unchanged with STA power save off, with the U60's 2.4 GHz
AP disabled, and with the 5 GHz AP disabled (DBS off). Cellular coex reported
no active scheme; Bluetooth is soft-blocked. `pm_cinfo` showed DBS with the
STA in SCC on MAC 0, no MCC.

Cause (2026-10-28): the driver associated the STA at 40 MHz (ch 1 + 5),
while a Mac on the same AP used 20 MHz. Same test, same AP: the Mac 82-91
Mbit/s, the U60 32-36. `iwpriv u60sta0 chwidth 0` (20 MHz, no reassociation)
gave 92-117; back to 40 MHz 34 and 34; 20 MHz again 104 and 104, with the
AP's rate to the STA rising from HE-MCS 1 to HE-MCS 9-11, 2 SS.

### 上游带宽自适应 V2（2026-10-28，阶段 A）

> **已删除（v6，2026-11-10）。** 下面是自动调优的历史设计与实测记录。当时代码只保留每次关联后的一次宽度复位和热点需要的信道解析（`wifi_relay/width.rs`）；2026-11-12 起宽度复位也已删除，`width.rs` 不再存在，信道解析移到 `wifi_relay/hotspot.rs`，agent 中没有任何地方再运行 `iwpriv … chwidth`；`width_watch.rs`、`llstats.rs`、`widths.json` 的读写、`/api/wifi-relay/tuning` 和页面选项都已删除，已保存的 `auto` 读作保持协商带宽。设备上旧的 `/data/zte-agent-relay/widths.json` 不再读写，回退到旧版 agent 时仍可用。

已按 `width-v2-final-handoff` 实施；阶段 A 最初只做代码和本地验证，随后已获授权部署。
阶段 B 与方案 A 的后续状态见本节末尾及真机验收记录，不能把阶段 A 快照当作当前设备状态。
实现为 `wifi_relay/width.rs` 的纯状态机与 `wifi_relay/width_watch.rs` 的 watcher
适配层，替换旧版逐档搜索、PHY fallback 和从最宽档重测规则。

- 2026-11-03 起，网页按每个 Wi-Fi（SSID＋加密方式）保存 `off`（默认，保持协商带宽）
  或 `auto`（实验性自动调优）。新连接默认沿用保存选择，当前连接修改时共用重连流程；
  `ZTE_AGENT_WIDTH` 不再覆盖网页设置。内部 Observe 状态机只用于测试，不提供第三套用户路径。
  Off 不启用或读取 LL stats；两种模式新关联时都执行下述遗留宽度复位。
  持续调优 I/O 仅由已有 `relay-watch` 执行；空闲时只在保持窄档时约每 60 s 读回、重设并
  ping 网关一次。
- 锚点持续滚动测量；只有一个新鲜锚点窗口刚完成的 tick 能发起单候选挑战。挑战期间
  锚点固定，只有 Win 才替换。候选为本次协商上限内的 160/80/40/20 MHz，2.4 GHz
  最多 40 MHz；较窄的读回不降低协商上限。初次历史/扫描起点也必须读回确认。
- 常规挑战间隔 15 分钟；锚点 E 降到上窗一半以下（需求下降造成的不算）可提前挑战，但仍遵守每 15 分钟
  最多 2 次的预算。先选未测候选，再按档位距离、较宽优先、结果较旧优先确定排序，
  不假设分数随宽度单调，也不一次扫满四档。Lose 独立退避 15/30/60/120/240 分钟，
  Unknown 独立退避 5/10/20/40/60 分钟；操作失败至少冷却 15 分钟。
- 命令仍为 `iwpriv u60sta0 chwidth`（0/1/2/3 对应 20/40/80/160 MHz），只以
  `iw dev u60sta0 info` 读回确认。6 秒重试、最多 3 次、18 秒确认限时；从申请候选
  开始的 45 秒总期限不续期。确认后跳过 2 个有业务的 tick，再测候选。
- Lose、Unknown 都回滚锚点；回滚不受预算限制，也须读回确认。回滚失败进入
  `Cannot confirm`，不写缓存、不再挑战，直到后续真实读回合法宽度后重建锚点。
  外部宽度变化作废窗口；主信道、radio、协商上限变化及重新关联清空候选历史。
  所有事件/动作绑定关联代次，旧代次事件直接丢弃。
- 所有者于 2026-10-29 选择方案 A：Auto 保持低于协商上限的稳定锚点时，有业务且距
  上次施加约 60 s 就执行“协商上限 → 等 1 s → 锚点”，尝试避免 B31 静默丢弃窄档。
  当天晚些时候改为空闲也按时刷新（收不到数据的链路看起来和空闲一样）；挑战、回滚及暂停中不插入刷新。
  切换会丢弃测量端点和未完成窗口，并跳过下一合格样本；刷新不算候选挑战、不写历史。
  两条命令持有现有 network/session 锁。命令失败只记日志，若停在中间档，下一次读回
  按外部宽度处理；`iw` 读回本身不能证明上游逐帧发送宽度持续生效。
- 每次关联成功后、DHCP 与 `LinkWidth` 初始化前，先切到比协商宽度窄一档，等 1 s，
  再切回协商宽度并读回。适用于 Auto/Observe/Off，20 MHz 无更窄合法档时不操作；
  失败记日志但不阻止连接。这是清理跨连接遗留设置，不是清空评分历史或重跑最宽档搜索。

测量每约 3 秒取 `/sys/class/net/u60sta0/statistics/rx_bytes`、STA TX 字节、
同频热点 RX 字节、station signal 和 `ll_stats`。`iw station dump` 的 RX 字节在此
固件恒为零，不使用。LL stats 首次有业务时通过 QCA vendor 14 `LL_STATS_SET`
启用（nested nl80211）；按本 tick 主信道 `on_time` 增量选择 radio，不按历史累计
最大值选择。计数倒退、radio/宽度/主信道变化均不能跨界拼接。归属不明时无结论，
不每 tick 查询 `pm_cinfo`。读取失败只报告证据不足，不使用 `rx bitrate` 决策；
PHY 速率仅随状态日志附带。

窗口要求同 epoch、累计至少 12 秒合格时间、100 ms 接收空口和 R ≥ 1 Mbit/s，最长
30 秒，6 秒没有合格 tick 就作废。使用原始计数求和，不平均逐 tick 比值：

```text
E = 8 × ΣΔSTA_rx_bytes / ΣΔradio_rx_s   共享接收空口效率代理
R = 8 × ΣΔSTA_rx_bytes / 窗口墙钟秒数   本接口交付速率，仅检查需求可比性
```

E **不是网速或上游容量**，共享 radio 的热点上传可能反转排序。相邻 A/B 窗口有任一
情况即 Unknown：B 的 R < A 的 80% 而 E 却升高；热点 RX 速率相差超过 2 倍且差值
>5 Mbit/s；平均信号差 >6 dB；发生过本机扫描；两窗 R/E（本 STA 接收空口占比）都 <0.25
且 R 相差超过 2 倍（需求变了，E 随需求升降）。其余情况 E_B ≥ 1.15 × E_A 才 Win，
否则一律 Lose，包括平局。Settling 后连续两个有业务合格 tick 均低于锚点 E 的一半、
且这两个 tick 总空口 ≥100 ms，可提前认输；仍先检查可疑上下文。没有数据只能
Unknown，不能制造零分。TX 字节仅做上下文记录；G3 之前不使用 AC/per-rate TX 决策。

**两个频段的热点保护始终保留。** 同频热点为 `wlan0`/`wlan2`；挑战前、读回确认后、
比较结束、回滚确认后最多四个节点读取 hostapd 状态、HE/VHT 宽度/中心频率、iw 信道/
宽度。热点非 ENABLED、CAC/CSA 进行中或状态无法读取时不开始，不花预算/升级退避。
挑战中受保护字段变化则回滚，并在本次关联显示 `Paused: hotspot changed`，不写缓存；
回滚后热点未恢复只记录字段名并保留提示，**不重启、不改热点配置**。客户端数量变化
只记数量，不作为回滚依据。代码只写 STA 不证明对共享 SME/并发配置没有副作用。

`widths.json` 保留不透明网络 id、最新 32 条、0600；新记录为
`{id,width,source:"airtime",signal_dbm,saved_utc?}`，UTC 只来自本次启动已验证的网络
时钟。条目缺少 `source:"airtime"` 或信号即无效，重写时丢弃；信号差 >10 dB 或可信时钟证明年龄 >30 天时，仅作排序
参考，起点改用已有扫描预测。缓存不替代本次测量，只在 Win 或首次合格锚点窗口后写，
未确认、Paused、Observe 都不写。页面只增加文字状态，不新增 CSS/JS、不承诺最快。
日志仅包含匿名 id、代次、模式、宽度、E/R、证据量、信号、PHY、字段名与客户端数量，
不输出 SSID/BSSID、客户端身份或凭据。

**真机验收现状（2026-10-29）：** G1 经所有者判定通过；阶段 B 已在两个频段做了受控
负载（见下文“阶段 B 校准结果”），发现 `chwidth` 保持失效。所有者随后选择方案 A，
已实现并部署 60 s 刷新及连接复位。连接复位前后对照通过，**2.4 GHz 持续 Auto 下载
验收仍未通过**，当时设备回到原 5 GHz 上游和 Observe；当晚加入健康探测等保护后改为 Auto
运行在 `W`（见下文“健康探测与数据路径确认”）。本地 iperf 已证明维护刷新能维持
11 分钟长期吞吐，但短窗门槛、候选试探停顿与回滚后数据路径恢复仍有风险，完整阶段 C 未通过。
当前设备状态和结果以 [真机验收记录](2026-10-29-width-v2-acceptance.md) 为准。
历史 2.4 GHz 的 92–117 Mbit/s 和 5 GHz 的 249–251 Mbit/s 不是 V2 验收结果。
用户观察到的 150/280 Mbit/s 差异也可能来自同频共享空口、上游负载或路径瓶颈，
不能预先归因于带宽。5 GHz SAP–STA DFS 恢复已有连接前开关修复并通过模拟厂商窗口验证，
真实整机重启的最终验收仍未做。

#### 真机验收进展（2026-10-29）

用户授权后已部署 Observe，并完成 G1 手动 STA 160→80→160：热点保持 44/80，
两个客户端无掉线/重关联迹象，配置未变。但随后单次重启 5 GHz 热点，起来变为
44/160，与原运行宽度不同，**当时完整 G1 未通过**。持久配置重启前本来就是自动信道/160，
且前后哈希不变，当时尚不能归因于 STA setter，故先停在 Observe。
部署前还修复了固件 `cac_time_left_seconds=N/A` 被误判为 CAC 的问题。
最终设备状态、证据、备份和修复后产物见
[2026-10-29 真机验收记录](2026-10-29-width-v2-acceptance.md)。

之后：E3、P0（DFS 切换窗口）修复与 E2 见同一记录；E2 表明热点重启的宽度取配置，
与 STA 当时宽度无关。所有者据此判定 G1 通过。

#### 阶段 B 校准结果（2026-10-29）

条件：所有者的 Mac 连上游 `W_Game`（5 GHz 44/160）作 iperf3 服务端；U60 本机经
`u60sta0` 作客户端（4 流、45 s，不经过 Mihomo）；Observe，宽度用 `iwpriv` 固定。
5 GHz 时 Mac 与 STA 同在 44 信道，结果是同信道两跳吞吐，不能直接对照单跳或用户的
150/280 Mbit/s。热点客户端经中继的负载**未做**（没有第二台受控客户端），热点 RX 全程
≈0，热点相关可疑规则未被检验。原始数据与分析在私密备份 `20261029-width-v2/stageb-*`。

只列宽度确认有效的轮次（Mbit/s；E 为窗口中位数）：

| 频段/宽度 | 下载 A/B | E | 上传 A/B | 低速 20M 的 E |
|---|---|---|---|---|
| 5 GHz 160 | 549.9 / 548.1 | 1672 / 1681 | 295.2 / 429.2 | 739 |
| 5 GHz 80 | 425.2 / 436.7 | 892 / 917 | 316.9 / 361.5 | 802 |
| 5 GHz 40 | 277.6 / — | 448 | 213.3 / 235.0 | 354 |
| 2.4 GHz 40 | 28.5 / 28.2 | 41 / 40 | 117.6 / 115.5 | 39 |
| 2.4 GHz 20 | 103.9 / 107.2 | 166 / 169 | 120.9 / 121.5 | 105 |

- **G2（排序）：** 所有有效下载对里 E 的排序与吞吐一致；按 5.4 节初始值回放没有反转
  （5 GHz 判宽档胜，2.4 GHz 判 20 MHz 胜）。E 夸大幅度：5 GHz 80→160 E ×1.9、吞吐
  +25–29%；2.4 GHz 40→20 E ×4.1、吞吐 +265–280%。需求很低时吞吐相同而 E 相差 2 倍以上，
  规则会只凭 E 切换（不伤吞吐）。信号稳定在 −32…−45 dBm，各初始阈值没有数据要求修改。
- **上传：** 上传为主时窗口几乎凑不满（5 GHz 80/40、2.4 GHz 全部为 0 个），E 看不到上传；
  上传本身波动大（5 GHz 160：295 与 429），宽度排序不稳定。双向时上行多被压到 3–5 Mbit/s。
- **G3：** 窗口 `tx_R` 为 iperf3 上传的 1.02–1.09 倍（5 GHz，4 个窗口），STA TX 计数反映本机上传；
  `R` 为下载的 1.04 倍（中位数，0.82–1.24）。
- **开销：** U60 在 550 Mbit/s 下载时 4 核合计约 45%。`ll_stats` 读取空闲与满载都 ≤10 ms
  （`time` 分辨率）；刚重连后的一段时间内读取会失败。

**阶段 B 发现的执行问题（随后按方案 A 尝试缓解）：** `iwpriv u60sta0 chwidth` 不重启射频，驱动不打印日志。
- 设的窄宽度会**静默失效**：5 GHz 80 MHz 在持续下载第 186 s、40 MHz 约第 264 s 后，下行回到
  宽档（40 MHz 时 537 Mbit/s、E 1541，超过 40 MHz 物理上限）；同日晚另一次 5 GHz 80 MHz 则在
  第 190 s 从约 310 塌到 42–51 Mbit/s。上行仍按设定；`iw` 读回、
  station dump 的速率和 agent 的外部宽度检测都还显示窄档。2.4 GHz 20 MHz 约第 100 s 后下行
  **塌到约 3 Mbit/s** 并持续数分钟（窗口接收空口 64%，E 174→5），读回仍为 20。
- 重发相同值无效；先设别的宽度再设回，1 s 内恢复（5 GHz 160→80、2.4 GHz 40→20）。
- 设置**跨重连、接口重建和换频段保留**：在 2.4 GHz 留下 40 MHz 后重连 5 GHz，`iw` 读回 160，
  AP 却按 40 MHz 发（rx 516 Mbit/s 40MHz），下载 272–287；单独 `chwidth 3` 无效，80→160 后为 538。
- 因此仅保持窄档、只用 `iw` 读回确认的阶段 A 实现在 B31 上不成立：保持窄档需要在失效前
  （2.4 GHz 约 90 s 内）用“先切走再切回”重新施加，且没有读路径能发现失效；连接时也应先把
  宽度复位到协商上限，否则遗留设置会压低新连接。用户的 150/280 Mbit/s 可能来自这种遗留窄档
  或 Mihomo（10-27 实测减半），均未验证。

#### 方案 A 验证结果（2026-10-29）

所有者选择的 60 s 维护刷新及每次连接复位均已实现，52 个宽度相关测试通过。
连接复位前后对照：旧版重连后读回 160、实际上游仍按 40 MHz 发送；新版复位后 RX
恢复显示 160MHz，续接最终从 2.4 GHz 返回 5 GHz 也验证成功。

2.4 GHz Auto 的持续下载门槛**未通过**：原会话没有留下完成的负载输出；续接普通
DNS 轮次出现超时及解析失败。绕过 DNS、固定同一 HTTPS 服务器地址后，前 9 个
30 MB 文件为 1.938–2.100 MB/s，第 10 个在 45 s 超时，平均 0.246 MB/s。
`iw` 采样确认维护刷新相隔 60.50 s、各经 40 MHz 约 1 s 后回 20，并非计时器没执行；
热点保持 1/20、ENABLED。公共服务器/WAN/TCP 与驱动效果尚未隔离，不改评分阈值。

之后已完成上游 LAN 内的受控 iperf 对照（同日 14:00–14:36）：Mac 在上游 5 GHz，
U60 在 2.4 GHz，单流 reverse 20 Mbit/s，无公网、DNS 或 Mihomo 转发。

- Observe 固定 20、不刷新：前约 210 s 维持 20 Mbit/s，之后降到约 4，读回仍是 20。
- 正常 Auto 挑战 40 导致两次明显停顿，40 档分别停留约 26.8 / 46.2 s，之后 Lost / Unknown
  回滚。第一次回滚读回已确认但新 TCP、网关 ping 都失败，手动 40→等 1 s→20 后恢复；
  第二次自行恢复。不能再仅把原失败归于公网路径，也不能宣称每次回滚必然失联。
- 已恢复且处于正常候选冷却的 Auto 锚点完整运行 660 s，11 次刷新相隔 60.06–60.58 s；
  完整秒窗口均值 19.98 Mbit/s，没有持续塌陷。但最差 10 s 为 13.63，未达事先 ≥15 门槛。
- 同路径短时不限速 20→40→20 为约 57 / 0.84 / 95 Mbit/s；当前环境的 40 档很差，
  不能将它视作稳定 20M 的健康基线。两次 20 差异也提醒不能把结果解释成固定倍率。
- 恢复风险：watcher 的 demand 只看 RX，无 RX 且不在挑战中就走 idle，因此已关联但
  收不到数据可能无法触发维护刷新。后续应研究有上限的回滚后健康确认/恢复与严重退化
  候选的及时退出，而不是只改评分阈值。本轮未改 Rust 实现。

设备保留新程序但 launcher 恢复 Observe、中继恢复原 5 GHz 44/160，Mihomo 正常，无压测
或转发遗留。**不要把这次局部维持结果当作阶段 C 通过或默认 Auto 的稳定性依据**；
完整时间线、证据与限制见真机验收记录文末。

#### 健康探测与数据路径确认（2026-10-29 晚，已部署）

所有者保留 E 方案，要求坏宽度的试探尽快退出、回滚后确认数据路径。E 仍负责比较快慢，
下列机制只判断“这个宽度坏没坏”和“链路通不通”，都只走到网关这一跳，不耗蜂窝流量：

- **洪泛探测（`ping -q -f -l 8 -s 1400 -w 2`）：** 普通挑战前在锚点测一次作参照（发 ≥50
  且丢包 <5% 才可用，截止时在途的 8 个不算丢）；候选读回确认后立刻再测，丢包 ≥10% 或回包率
  不到参照 30% 判 Lost，退避 1/2/4/8/24 h。历史/扫描起点只会变窄，不做参照。小包 ping 和
  低速 ping 序列在真机上发现不了坏的 2.4 GHz 40 MHz，洪泛 4/4 发现；但也见过洪泛通过、真实 TCP
  仍停的情况，所以它只是一道关，下一条是兜底。
- **试探中撤退：** 候选上连续两个样本交付 <1 Mbit/s（基线 ≥2 Mbit/s），或信号 ≥ −55 dBm、
  有业务却接收 MCS ≤1，就再探测一次（每次挑战最多两次）；探测不可用时交付塌陷直接 Unknown。
  探测占用的墙钟和清空的计数端点不算“流量停止”。
- **跨重连避开：** 探测判坏的宽度在 agent 进程内按网络 id 记住（最多 32 条，信号差 >10 dB
  不沿用，进程重启即清空）；新关联不再挑战它，起点宽度正在退避时从更窄一档开始。
- **数据路径确认：** 按历史收窄、每次刷新、每次回滚读回后，立即 ping 网关一个回包
  （`ping -c 1 -i 0.2 -w 2`）。真机两次见过读回正确而网关不通、经协商上限绕一次即恢复，且那时
  `arping` 照常有回应，所以不能用 ARP。本关联回过 ICMP 的网关不通时绕一次，最多两次，仍不通
  显示 `Data path unconfirmed` 并停止本关联的挑战；从没回过的网关先绕一次，仍不回就视为拦
  ICMP，本关联不再检查，也不阻止挑战。部署后又在一次例行刷新之后真实出现网关不通，绕一次即
  `data path recovered`，该 60 s 下载平均仍为 20.0 Mbit/s。
- **刷新绕法：** 仍经协商上限。Mac 连 5 GHz 的满载对照中，压到 80 不刷新第 190 s 塌到约 45
  Mbit/s，每 60 s 刷新则 7 分钟保持约 310；改为经更窄一档未经验证，已撤回。

开销：洪泛与回滚后的确认持有 network/session 锁，正常时洪泛约 2 s、单包 ping 约 10 ms。
候选探测失败会在同一次 dispatch 内串行执行 Confirmed 热点检查、洪泛、End 热点检查、回滚；
仅这些命令的名义限时合计约 11 s（3 + 4 + 3 + 1），不含该 tick 的普通读数等耗时。状态 API
读取独立 snapshot，不等待 session 的 inner 锁；HTTP gate 的 7 s 只约束等待执行槽位，
不限制已开始的工作。真实持锁尾延迟仍需设备验证。
日志新增 `probe reference/passed/failed`、`avoid width=… for … h`、
`gateway silent …`、`data path recovered …`，只含宽度与包数。真机结果、修正过的问题和
仍未验证的部分见[验收记录](2026-10-29-width-v2-acceptance.md)末节。

##### 审查修正（2026-10-29，已随 `49c2dc21…` 部署）

- 恢复绕回只成功第一条命令、设备停在 `via` 时，接受合法读回仍保留 Verifying 的已用次数，
  继续检查网关；不重置恢复预算，确认结束后仍遵守本关联的热点暂停，不再挑战或写历史。
- Verifying 的 ICMP 检查不依赖 `iw` 读回；一次或连续读回失败均不能直接宣告恢复。
  仍按 ping 结果结束或重试，已知会回 ICMP 的网关最多绕两次后阻止挑战；没有网关或 ping
  时仍按原 `Alive(None)` 规则结束确认，不引入无限重试。
- 新增 4 个状态机/watcher 回归，覆盖绕回部分失败、无宽度读回，以及网关恢复、持续不通、
  无法检查三种结果；修复前 4 个均失败，修复后中继相关 161 个测试通过。
- 4 线程全量测试合计 **1224 通过、3 忽略**（含启动集成测试）；all-targets clippy 完成，
  改动文件无警告，其它模块的警告保留。ARM64 musl Release 构建通过：`llvm-size -A`
  Total **8,597,348 B**（相对 `22aa4b46…` +8 B），`gzip -n -9` **4,394,487 B**（-105 B）。
  本地产物 SHA-256：`0420626a4680a9eafc47b54f9c7652a5b13451611122bc54f78dda0e85b26166`，当时未部署；
  之后与下节的平稳门槛一起构建为 `49c2dc21…` 并部署。

##### 平稳门槛与驱动限制调查（2026-10-29 晚，已部署）

- **平稳门槛：** 窗口记录逐 tick R 的变异系数（`spread`，标准差/均值）。锚点窗口 >0.5 时本轮
  不挑战（日志 `challenge deferred: traffic not steady`），不占预算和 15 分钟间隔；候选窗口或
  基线不平稳时不能判 Won，只能 Unknown（判负不受限，坏宽度本身就会让交付起伏）。测速时约
  0.1–0.4。真机：每 6 s 交替 200/5 Mbit/s 得 0.74，72 s 内只推迟、不挑战；每 3 s 交替只有
  0.33，短于两个 tick 的起伏会被 3 s 采样平均掉，本来也不影响比较；有空闲的突发凑不满窗口。
- **LL stats 读不出 AP 实际发送宽度：** debugfs `ll_stats` 的按速率统计只有发送有数（含宽度、
  MCS、重传），接收全为 0；射频按（宽度, 中心频点）记的信道时间反映射频调谐的信道。5 GHz 压到 80
  不刷新时约 180–190 s 吞吐从约 330 塌到约 50 Mbit/s：信道记录始终是 80，本机接收空口每 10 s
  从 5.8 s 降到 2.05 s，信道忙碌却保持约 8.5 s，接收 MCS 6→3。即 AP 按宽档发、射频按窄档收
  而解不出（“读回正确但不通”是它的极端情况）。这一特征可被动发现失效，但 60 s 刷新已防住失效且
  有把邻居干扰误判为失效的风险，暂不实现；发送统计可留作上传防退化依据。
- **在关联时谈窄不可行：** 自编静态 `wpa_supplicant` 2.11（HT/VHT/HE 覆盖，libnl-tiny）在设备上
  读到 `disable_ht40=1` 并在 connect 中下发清掉 HT40 位的 `htcaps`，qcacld 仍按 40 MHz 关联，
  即驱动忽略 nl80211 能力覆盖。上游 hostap 也没有厂商私有 `DRIVER` 命令，中继用的
  `SETROAMMODE` 会失败，换用它时 agent 的恢复卡住，直到停掉测试进程才在第 4 次恢复。
  所以仍只能关联后用 `iwpriv` 收窄。实验文件已从设备删除。

以下是部署前阶段 A 的历史验证快照，不代表上述真机阶段通过。

#### 阶段 A 本地验证（2026-10-29）

- 最终 `cargo test --locked -p zte-agent`：**1188 通过、3 忽略**，另有启动集成
  **1 通过**。中继相关覆盖包括纯状态机、注入 Driver 的 watcher 接入、B31 LL fixture、
  缓存新旧格式与页面状态；不依赖真机。
- 验证过程中默认高并发全量测试曾出现 QR/eSIM 图片解码失败（一次解码子进程超时，
  另一次预期 303 实际 400），未修改这些测试或解码代码；最终版本以 4 线程全量通过，
  随后默认并发全量也通过。这是观察到的间歇性失败，不将它隐去或宣称已修复。
- 本机 all-targets clippy 与 aarch64-musl clippy 均完成；本轮改动文件无新增警告，
  仓库其他模块的既有警告保留。
- 最终 aarch64-musl release 构建通过，产物为静态链接、stripped ARM64 ELF。
  本机没有 `aarch64-linux-musl-size`，使用 Command Line Tools 的 `llvm-size -A`
  等价统计：**Total 8,576,164 B**；`gzip -n -9`：**4,383,688 B**。
  对比当前部署基准 8,533,816 / 4,358,909 B，分别增加 **42,348 B（0.50%）** /
  **24,779 B（0.57%）**。原 `/tmp/u60-cross-tools` 已消失，本次使用已安装 Zig 0.15.2
  的新临时包装脚本构建；工具链包装差异也可能影响体积，不能全归因于选择器。
- Release SHA-256：`0bfbb413d11b3fecbcf6ca94f41ed443e24394487ead12dc0737375de543e285`。
- 边界复核新增两个回归：挑战中外部改 STA 宽度仍先检查原热点快照；候选窗口末尾
  零交付字节不能以共享 radio 空口凑成 Lose，必须 Unknown。未部署、未提交，G1/G2/G3
  及阶段 B/C 尚未验收。

Runtime `hostapd_cli` geometry changes on `wlan2` are unreliable on B31: with
the relay STA connected even the original 160 MHz configuration and ACS ended
`DISABLED`. `/etc/init.d/hostapd-daemon.init restart wlan2` (the vendor's own
per-interface restart) brought it back from its unchanged configuration file.

The optional disruptive connectivity-watchdog ladder is safety-blocked on B31:
its vendor API cannot distinguish an external user-off from its own PDN pause.
`status.safety_block` and enable responses explain why; manual modem controls
and route fallback to an already enabled modem remain unchanged.

Resolver ownership uses a separate comment line directly before its matching
`nameserver` entry. Inline comments are intentionally avoided because B31's
BusyBox nslookup treats them as part of the server address. Old tagged inline
entries are recognized during cleanup/migration.

## 2026-10-28 reboot and installer validation

Historical live acceptance (2026-10-28, before the immediate-cancel and post-relay
core retry changes; relay on W at 2.4 GHz with IPv6, Mihomo on). The first
update failed to restore at association, 6 attempts in a row: the replaced
agent's `wpa_supplicant` and `odhcp6c` were still running with parent 1 (see
Recovery for why) and the stale supplicant owned the control socket. With
stray helpers stopped at recovery, two further `setup.sh` updates with both
on each logged "stopping 2 helper(s)", restored Mihomo, then rejoined W on the
first attempt, at the remembered 20 MHz. A cold reboot (`reboot` over ADB):
agent running by 54 s of uptime with the boot barrier already released,
Mihomo on at about 60 s, W associated at 69 s, both reported `autostart: true`
and no error by 94 s; the router reached 223.5.5.5 and HTTP through
`u60sta0` (the station's name then). Not yet tried: a 5 GHz upstream, an upstream that is down at boot.
