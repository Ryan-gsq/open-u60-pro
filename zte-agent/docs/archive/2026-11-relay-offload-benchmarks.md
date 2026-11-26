# 中继 IPA 历史实测（2026-11-08 至 2026-11-12）

> 历史记录。各节分别记录当时的 B31 构建、配置和测试路径。`measurements/`
> 是开发机外部留档。现行行为见[硬件转发参考](../relay-hw-offload.md)，
> 覆盖范围见[设备验收索引](../README.md#device-acceptance)。

## 部署后复测（2026-11-08，agent 本次实现）

> 2026-11-12 注：这一节和后面各节（两个 2026-11-12 回归除外）是当时版本的记录：站点叫 `u60sta0`，IPACM 配置要安装、
> 装后重启，状态有 `loaded`。那时 agent 自己切 HW、每 15 秒审计并按 TCP 回程计数重新挂载
> （kick），状态里有 `hardware`/`offload_confirmed`，`U60_RELAY_FWD` 的回程放行分 TCP 和其余两条；这些都已删除
> （回程现在只有一条），现在的行为见[硬件转发现行参考](../relay-hw-offload.md)的第 1a、3 节。测得的数字仍然有效。

安装配置后重启整机：

- 约 37 秒时 ZTE 切到 SW（智能 QoS）；约 67 秒时中继自动恢复，agent 切回 HW；
- main 表里出现 metric 60631 的默认路由和三条 unreachable；
- 状态为 `loaded` / `hardware: true`。

测试条件：Mac 连 G（52/160），Mihomo 开启并打开国内直连（6522 段），从 tuna/nju
镜像做 HTTP 下载 12 秒。"回程内核包"是 `U60_RELAY_FWD` 回程规则的计数。

| 路径 | 单连接 | 4 连接 | 回程内核包 | CPU |
| --- | ---: | ---: | ---: | --- |
| Clash（国内直连关） | 126.3 | 112.3 | 0（全部进 TUN） | 各核约 50%，Mihomo 用户态 |
| HW | 177.1 / 198.2；复测 222.8 / 232.4 | 237.1 / 240.1 | +236 至 +2,420 | 各核约 10–15%，与空闲相同 |
| SW + RPS（临时设 `ipa_disable=1`） | 138.2 / 239.5 | 241.2 / 235.9 | 约 +15 万至 +25 万 | 软中断分散到 CPU1–3，单核峰值 100% |

结论：

- 在这组镜像上，HW 和 SW + RPS 都能跑到约 240 Mbit/s，这是服务器和空口的上限；
  区别在 CPU，HW 下几乎空闲。
- 设置 `ipa_disable=1` 后 agent 没有强切，页面显示了原因；撤销后 15 秒内自动切回 HW。

speedtest.cn（云测节点评估模式，单连接）：

- **IPv4 走 HW**：212.49 Mbit/s 和 204.04 Mbit/s，延迟 31–40 ms。测速期间回程内核包
  约 +1.7k，`AddEntry` +54。
- **Mac 双栈默认情况**：125–127 Mbit/s。Mac 从中继的 NAT66 拿到 ULA 地址，用 IPv6
  连 `node-edge.speedtest.cn`（2409:8c3c:…）。国内直连只覆盖 IPv4，所以这条连接仍然
  进入 Mihomo（GeoSite CN → DIRECT，由 Mihomo 用户态转发），速度和 Clash 路径相同。
  要让这种情况也走硬件，需要另外决定：关闭中继的 IPv6/NAT66，或者让国内目标优先走
  IPv4。也可以把国内 IPv6 段也在内核绕过，但它只能走 NAT66 的 CPU 路径，不会被卸载。

## Mihomo 改用 TPROXY 后的复测（2026-11-08）

Mac 连 G（52/160），上游 W_Game；curl 绑定 en0、用路由器 DNS 解析（Mac 上的 Clash
Verge TUN 开着，不绑定会先经过它）。tuna 镜像下载 15 秒；CPU 是 12 秒采样，
"总 CPU" 是 4 核平均，Mihomo 按单核计。

| 路径 | 单连接 Mbit/s | 4 连接 | 总 CPU | Mihomo | 回程内核包 |
| --- | ---: | ---: | ---: | ---: | ---: |
| IPv4 国内（国内直连，HW） | 220.6 / 237.2 | 230.3 | 10% | 0–3% | 18–83 |
| IPv6 国内（TPROXY → DIRECT） | 238.0 / 190.6 | 235.2 | 48–51% | 31–39% | 0 |
| IPv4 国内（临时关国内直连，TPROXY） | 238.6 / 238.1 | — | 48–51% | 41–44% | 0 |

- 之前的 TUN：IPv4/IPv6 单连接 125–132，Mihomo 约 90%。
- UDP：IPv4 NTP（国内直连关时经 TProxy → DIRECT）双向正常；IPv6 UDP（QUIC 和其他
  DIRECT 流量）在连接表里有 MB 级双向流量。走代理节点 `JP-hy2-gou-IPv6` 的 UDP 123/443/5353
  只有上行没有回包，这是节点那边的限制，不是拦截的问题。
- DNS：LAN 的 53（包括发往 8.8.8.8 的）被重定向到 1053，ZTE 的 legacy INPUT 不需要另外放行。
- 退出中继：Mihomo 保持运行，nft 表、sysctl、pref 18620 规则和 17894/1053 监听都在；
  agent 重启时中继还没连上，Mihomo 也能正常起来。重连后 kick 执行，HW 正常。
- 对齐器：手工把 brnf 改成 1、清空 `redirect_chain`（v4 和 v6）、删掉 main 默认路由，
  再只读打开一次 `/sbin/fw3` 触发 inotify，4–7 秒全部恢复；不触发时 60 秒兜底在
  42 秒恢复了 brnf。`ipacm_switch.sh off` 后 3 秒切回 HW，之后下载仍然走硬件。
- speedtest.cn 这次弹出拼图验证，没有跑。

## 跟随 Mihomo 模式/规则、fake-ip 和运行时开关的验证（2026-11-09，owner decision 64）

Mac 连 G（52/160），上游 W_Game，Mihomo 开（rule），国内直连开。下载是清华镜像 HTTP 10–12 秒，
"回程内核包"是 `U60_RELAY_FWD` TCP 回程计数，几百个说明走 IPA，十几万说明走 CPU。
release 二进制 `size -A` Total 8,889,712、gzip 4,372,886 字节（部署前的版本 8,808,148 / 4,330,576；
其中约 4.4 KB / 2.7 KB 是同时加入的 u60sta0 省电开关）。

- DNS：baidu、清华、bilibili（`哔哩哔哩` → `直连` → DIRECT）、`time.apple.com`、`www.msftconnecttest.com`、
  `u60.home.arpa` 给真实地址；google、claude.ai、github 给 198.18.0.x，AAAA 为空。google 经假地址 204。
- 模式（控制台 `/api/mihomo/mode`，约 4 秒内跟上，核心不重启）：global 时清华连接由 Mihomo 终结
  （conntrack 回程目标是 Mac），direct 和 rule 时走内核 NAT（回程目标 192.168.2.124）；状态里的 `kernel`
  依次是 none / all_ipv4 / china。rule 模式下清华 201–218 Mbit/s，回程内核包 159–481。
- 策略组：把 `直连` 切到 `选择代理`，核心重启一次，之后 baidu、bilibili、清华都拿假地址，`kernel.reason`
  为 "GEOIP,CN goes to 直连, not DIRECT"；切回 DIRECT 再重启一次，恢复绕过和硬件转发。`selected.json`
  跟着更新，没有出现重启循环。
- 硬件转发开关（中继连着）：关 → CPU（15.7 万–20.7 万），开 → 硬件（484–521）；移除 → CPU（20.4 万），
  同一次开机重新安装 → 立即 `loaded`、硬件（418）。移除先撤硬件路径的顺序是这次测出来后改的（见第 3 节）。
- 对齐器：手工清空 `to_core` 和 `prerouting` 两条链，再读一次 `/sbin/fw3`，4 秒后补回。
- IPv6 经 Mihomo：清华约 243 Mbit/s。

**改成按全部 DIRECT 地址规则编链之后的复测**（同一天，release `size -A` Total 8,902,580、gzip 4,379,969，
比上一版多 12,868 / 7,083 字节）：

- 订阅的 `fake-ip-filter` 和改动前逐行相同（61 条），最后一个放行点仍是 `GEOIP,CN`。
- 内核链：`@ip_0`（EHentai 1 段）进核心、`@ip_1`（GoogleFCM 26 个地址）放行、`@geo_netflix`（22 段）和
  `@geo_telegram`（7 段）进核心、`@geo_cn`（4,471 段，合并后）放行；`kernel.returns` 为 2。和改动前相比只多了
  GoogleFCM 放行，`mtalk.google.com` 拿真实地址 74.125.137.188，落在 `@ip_1` 里。`IP-CIDR,192.168.0.44/32,DIRECT`
  和 `MATCH` 前的 `DST-PORT,22` 没有进链。
- 清华镜像 197–240 Mbit/s，回程内核包 24–373（硬件）；google 拿 198.18.x，204。
- 模式：global 时清华连接由核心终结，direct、rule 时走内核 NAT。
- `直连` 切到 `选择代理`：核心重启一次，`bypass` 变 `none`（"No rule sends IPv4 DIRECT by address"），集合全部删掉；
  这时没有放行点，DNS 全给真实地址，全部进核心，由核心按 DNS 映射分流。切回 DIRECT 再重启一次，链和集合恢复，
  硬件转发 337 个回程内核包。

这两次部署后都遇到热点客户端一直走 CPU、靠 deauthenticate 才恢复的现象，原因和修复见第 9 节。

## 还能提速的地方（2026-11-08 测试）

省电关闭后，speedtest.cn 经中继 244–253 Mbps，直连 W_Game 291–295；用 tuna 镜像持续下载时，
中继和直连一样都在 230 左右（镜像那端的上限）。

| 尝试 | 结果 | 结论 |
| --- | --- | --- |
| `u60sta0` 省电关闭（当时手动 `iw`，中继重连后恢复默认） | 166–218 → 244–250 | 有效；11-09 起由中继页开关处理，默认每次连上都关掉（owner decision 65，`network-extensions.md` 的 Upstream Wi-Fi power save） |
| 禁用 CPU 深度休眠（C3/C4）+ performance 调频 | 250.5 / 253.1；U60→网关 ping 约少 0.5–1 ms | 在噪声范围内，增加耗电，已恢复 |
| 信道 52 繁忙度 | 4% | 没有外部争用 |
| 两段链路速率 | 上游 2161 Mbps、到 Mac 2402 Mbps（160 MHz HE 2×2） | 远高于 300，不是瓶颈 |

剩下约 15% 的差距只在短时测速里出现：同一块射频、同一条信道上跑两段 Wi-Fi，中继比直连多
约 3–4 ms 的最小 RTT（Mac→上游网关 5.3–6.5 ms，直连 2.1 ms），影响 TCP 起步。软件层面没有
找到明显的手段；能消掉这一跳的是有线上行。线路更快时，Mihomo 路径（单流约 238 Mbps，Mihomo
占单核 31–44%）会先于硬件路径成为瓶颈。

## 不开 Mihomo 的 IPv4/IPv6 × TCP/UDP 复测（2026-11-09）

条件：Mac 连 G（52/160，HE-MCS 11），中继连 W_Game 52/160，`u60sta0` 省电开着（默认），HW 模式，
RPS `c`；Mihomo 关闭（brnf 1，pacing 200/120）。Homebrew curl 8.23（ngtcp2）绑定 en0，每项 15 秒，
跑两轮。TCP 是 HTTP/1.1（tuna、nju 镜像）；UDP 是 QUIC/HTTP3（兰大 `mirror.lzu.edu.cn`，同一台服务器的
HTTPS/TCP 作对照）。"内核份额"是 conntrack 回程字节 ÷ Mac 收到的字节：约 1.05 表示全部经过内核，
约 0 表示已被卸载。CPU 是 4 核平均，以及最忙一核的软中断占比；空闲时分别约 10% 和 1%。

| 路径 | 单连接 Mbit/s | 多连接 | 总 CPU | 最忙核软中断 | 内核份额 |
| --- | ---: | ---: | ---: | ---: | ---: |
| IPv4 TCP（HW） | tuna 238 / 240，nju 54–237 | 4 连接 237–241 | 8–12% | ≤3% | ≤0.005 |
| IPv4 UDP QUIC（HW） | lzu 189 / 208 / 232 | 2 连接 213 / 218 | 8–14% | ≤3% | 0.000 |
| IPv6 TCP（NAT66） | tuna 234 / 235，nju 173 / 173 | 4 连接 233–239 | 31–56% | 62–76% | 1.05–1.07 |
| IPv6 UDP QUIC（NAT66） | lzu 178 / 43 | 2 连接 200 / 227 | 29–51% | 31–72% | 1.08 |

- **IPv4 UDP 会被 IPA 卸载。** 一条 311 MB / 12 秒（208 Mbit/s）的 QUIC 连接，conntrack 回程只记到 23 个包；
  `U60_RELAY_FWD` 的非 TCP 回程规则 12 秒内只涨 23–48 个包；IPA `ip4_nat` 表里有这条连接
  （`Proto=17`、`Enable=true`）。IPv4 的 TCP 和 UDP 都走硬件，CPU 和空闲时一样。
- **IPv6/NAT66 全部走 CPU**（内核份额约 1.06，`U60_R6_FWD` 回程 12 秒约 25 万包）。在这条约 240 Mbit/s
  的线路上，它还不是瓶颈：多连接 233–239，和 IPv4 硬件一样。代价是 CPU 30–56%，软中断集中在 RPS 的
  CPU2/3 上（最忙一核 62–76%）。车主随后在更快的线路上以 `ath20 rps_cpus=c` 实测 NAT66 为 451.1 / 553.3 Mbit/s。
- 约 240 是镜像、空口和上游的共同上限：路由器本机从 nju 下载是 210–223。CPU 转发对照（临时设
  `ipa_disable=1` 并执行 `ipacm_switch.sh off`）：IPv4 TCP nju 单连接 173.9，CPU3 软中断 90%。
- nju 单连接走 CPU 时（NAT66 两轮、IPv4 软件转发一次）都在 173 左右，走硬件时是 194–237；
  tuna 走 CPU 也能到 234。原因没有查。
- QUIC 测试源：国内镜像大多不支持 HTTP/3。nju、xjtu 的 QUIC 每条连接约 7 Mbit/s，切到 CPU 转发也一样，
  是服务器的上限。兰大超过 2 个并发会返回 429，所以 UDP 只测了 2 连接；它的单连接波动也大
  （IPv4 41–232，IPv6 39–197）。腾讯 `dldir1.qq.com` 的 GET 会被 302 调度到 HTTP 节点，用不了。

## 批次 1 回归（2026-11-12，站点接口仍是 `u60sta0`）

批次 1 的构建（模式交还厂商、核对读列表）在 B31 上的第一次回归。来源：开机一项是
`measurements/b1-reboot2/agent-boot.log`，其余是会话里看着命令输出记下的 `measurements/observations-2026-11-12.md`。

- 硬件转发：厂商处于硬件模式、agent 恢复中继之后，LAN 客户端经路由器的 USB 网络下载 205 MB，
  151/157/167/159 Mbit/s，内核转发路径 +155 个包，软中断 1.0%。
- 厂商切到软件（手工 `ipacm_switch.sh off`）：45 秒后 `close_ipa_acce` 仍是 1，agent 没有动 IPACM 的模式，
  main 默认路由保留；103 MB 139/87 Mbit/s，内核路径 +72,042 个包，软中断 18.6%。`ipacm_switch.sh on` 之后
  103 MB 168/153 Mbit/s，+72 个包，软中断 0.9%。
- 没有厂商触发时的守护：手工删掉 IPv6 的 INPUT 跳转和 IPv4 的 DHCP 放行，34 秒后各补回一份（60 秒兜底）；
  删掉 IPv6 的策略规则（pref 18640）后 2 秒补回。
- 开机（DFS 键已提交）：中继在开机后 70.9 秒第一次尝试就恢复。

## 最终版回归（2026-11-12，站点 `ath20`，没有安装步骤）

- 同一次开机里从用 `u60sta0` 的构建更新过来：日志 "previous connection not taken over (the relay interface is gone)"，
  停掉 2 个旧助手，第一次尝试就在 `ath20` 上恢复（`measurements/b2-final/agent.log`）。之后 iptables、ip6tables、
  nft、链路、进程和日志里都没有 `u60sta0`（工程师的检查记录，没有原始文件）。
- 硬件转发：新开机、原厂 IPACM 文件，205 MB，128/155/120/125 Mbit/s，内核转发路径 +135 个包（全走 CPU 约
  141,715 个），软中断 0.9%，`close_ipa_acce=0`（`measurements/b2-reboot3/hw-throughput.txt`）。
- 开机：`dmesg` 里没有厂商 DFS 脚本的 `disableDfsCS` 行，`dfs_channel_switch_disable=1`，驱动 ini
  `gDisableDFSChSwitch=0`，站点和热点都在 52/160，IPACM 文件里 `u60sta0` 0 条、`ath20` 1 条，main 默认路由经
  `ath20`，MASQUERADE 带注释（`measurements/b2-reboot3/observations.txt`）；中继开机后 72.9 秒第一次尝试就恢复
  （`agent-boot.log`），状态 `offload.config` 为 `listed`、`state` 为 `routed`（`relay-status.json`）。
- 车主断开再连接：中继的规则、表、策略路由和 main 默认路由都撤干净，热点回到 36/160，IPACM 文件的 sha 不变；
  重新连接 5 秒返回（`measurements/b2-final/disconnect-connect.log`）。
- agent 以 SIGABRT 结束：guard 重新拉起，992 ms 接管连接，Mihomo 在结束后约 6.5 秒运行
  （`measurements/b2-final/agent-abort.log`）。
- 已知注意：同一次开机里退回到改名之前的构建时，如果中继连着，旧版的清理会暂停（它的 RPS 撤销不认 `ath20`）；
  先断开中继或重启再退回（工程师记录；旧版 `steering.rs` 只认 `u60sta0`）。

换频段往返（同一天，构建 `acc6a3f6…`：在上面的构建上只多了 `join` 失败路径的重启选择修复；不重启部署，
新 agent 1037 ms 接管连接。`measurements/b3-final/band-switch.log`，速度都是开发机经 USB 下载）：

- 从 5 GHz 上游用错密码连 2.4 GHz 上游：100 秒后返回 "Wi-Fi association failed; check password and signal"
  （其中拆除原来的 5 GHz 会话约 65 秒）。之后 legacy 规则 0 条、没有中继的 nft 表、没有站点接口和助手进程、
  没有日志文件、策略规则 0 条，已保存的 3 个网络不变；重启选择按设计已清除（车主发起的连接成功后才写回）。
- 用已保存的密码连 2.4 GHz 上游：7 秒返回，再过 5 秒开发机能上网。站点 40 MHz，2.4 GHz 热点跟到同一信道
  20 MHz，IPv6 `configured`，Mihomo 因出口变化重启，断流 2.3 秒。
- 在 2.4 GHz 上游上保持约 4.5 分钟：开始 103 MB、47/47 Mbit/s，结束 103 MB、42/59 Mbit/s；内核转发路径
  +103 / +90 个包（全走 CPU 约 70,857 个），软中断约 1%。宽度一直读 40 MHz：没有宽度复位，速度也没有塌陷。
- 切回 5 GHz 上游：10 秒返回，再过 5 秒能上网，IPv6 约 30 秒内 `configured`。154 MB，160/160/185 Mbit/s，
  内核转发路径 +108 个包（全走 CPU 约 106,286 个），软中断 1.1%。IPACM 文件的 sha 全程不变。
- 隔离 Linux 验收（`tests/relay-firewall-qa`，这个构建加上 4155f03 构建的旧 agent）：36 项全部通过
  （`measurements/b3-final/docker-qa.log`）。它的日志不含 RPS 步骤，所以上面“已知注意”的情况不在它的范围内。

**关机充电模式下的重启选择（修复已合入，只有单元测试）**：低电量关机后进入关机充电模式时，厂商把
`wireless.zte_mbb.wifi_onoff` 设成 0，而车主的开关 `wifi_onoff_by_user` 仍是 1（`measurements/observations-2026-11-12.md`，
08:50；之前的版本因此清掉了 `resume.json`）。现在 `hotspot::off_by_owner` 读 `wifi_onoff_by_user`（没有这个键的固件
才看 `wifi_onoff`）以及射频和 SSID 的 `disabled`：tick 和连接失败的清理只在热点是车主自己关的时候清除
`resume.json`，开机恢复在 Wi-Fi 被固件关着时跳过这次尝试并保留选择。已验证的只有针对配置文本的单元测试；路由器上
没有复现，因为那需要再一次低电量关机。

## 2026-11-12 原厂配置与旧安装清理

依据（2026-11-12）：站点改名 `ath20` 后，IPACM 把中继登记成 WAN，为真实 LAN 客户端添加了硬件 NAT 表项，
205 MB 下载 141–183 Mbit/s，内核转发路径只有 168 个包（`measurements/exp2-ath20-*`）；最终版在新开机、
原厂文件上 205 MB 只有 135 个包走内核，软中断 0.9%（`measurements/b2-reboot3/hw-throughput.txt`）。

**以前的安装（2026-11-12 删除）**：之前的版本把 `u60sta0` 条目插进这个文件，需要重启整机才生效，并有备份、
标记文件和“本次开机是否已加载”的记账。车主的路由器上，这个条目已在 2026-11-12 用旧版自己的移除操作删掉，
文件又与原厂一致（`measurements/b2-final/disconnect-connect.log` 的 sha 前缀）。路由器上旧安装留下的备份
`/data/zte-agent-relay/ipacm/IPACM_cfg.xml.orig`（核对过与正在用的文件相同）已在同一天按车主的要求删除。
开发机上仓库旁边的 `../backups/ipacm/`（原厂文件、装过条目的文件和 `restore-stock.sh`）也在同一天按车主的要求删除。

## 2026-11-12 重连硬件路径

**已知未处理**：早先的版本观察到，中继重连后偶尔模式是 HW、连接却全部留在 CPU 上
（`U60_RELAY_FWD` 回程计数每秒十几万包），先切 SW 再切 HW 每次都能恢复（3/3），所以当时在加好
main 路由后做一次 SW→HW，并按回程计数每会话最多再做 3 次。这一步随模式切换一起删了；现在出现这种情况，
页面照样显示“极速模式下走硬件”，agent 不会发现。2026-11-12 没有任何重新挂载的几次下载都走了硬件：
agent 恢复中继后、厂商处于硬件模式时 205 MB 只有 155 个包走内核（全走 CPU 约 141,700 个）；厂商从软件切回
硬件后 103 MB 只有 72 个（约 70,900 个）（`measurements/observations-2026-11-12.md`）；最终版新开机后 205 MB
只有 135 个（`measurements/b2-reboot3/hw-throughput.txt`）。这几次都不是重连之后。

同一天下午在极速模式（`Nomal_mode`，`close_ipa_acce=0`）下专门测了重连之后（`measurements/b3-final/ipa-switch.log`，
开发机经 USB 下载）：重连同一个 5 GHz 上游、5 GHz 换到 2.4 GHz、2.4 GHz 换回 5 GHz、车主断开再连接，每次连上后
立刻测一次、60 秒后再测一次。8 次测量走内核的包数在 41–377 之间（全走 CPU 约 35,400–70,900 个），`dmesg` 里
厂商的 HW/SW 切换行一直只有开机时的那一条 `ipacm to HW`。加上当天早些时候的 5→2.4→5 往返，共 6 次重连都没有
出现。旧现象是偶发的，所以这只说明这 6 次没有出现，不能说明它不会再出现；要判断是否出现，下载时看
`iptables -L U60_RELAY_FWD -nvx` 的回程计数：每 100 MB 涨几百个包是硬件，涨约 7 万个包是 CPU。

## 2026-11-12 门户交接

为什么这样做：之前的版本把 RETURN 记在 `network.json`，交接时连同开关改动一起释放、几秒后随新租约再设。
2026-11-12 实测同一上游重连时，这几秒里正好有一次 fw3 重载（agent 自己的 IPv6 设置引起），厂商的 DNAT 写进去
并一直留到下一次重载（5 分钟以上）；agent 的 RETURN 缺了 6.3 秒，其中 3.1 秒 DNAT 在位
（`measurements/exp1-step1-ipv6-off.log`）。

现在的实测（2026-11-12，`measurements/b2-portal/handover-sampler.log`）：同一上游两次交接重连（IPv6 先关后开），
每次后面都有防火墙重载；开关始终读 0，`redirect_chain` 里从没出现厂商规则，dnsmasq 的两个主进程没有变；
每次清空后链里约 4 秒是空的，然后 RETURN 回到第一条。之后 `network.json` 不再提 `redirect_chain`，`dns.json`
里有两条撤销。RETURN 和“排在所有厂商规则之前”的维护仍保留：开关一旦读到 1，厂商的 DNAT 就会出现。
