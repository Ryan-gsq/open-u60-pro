# Wi-Fi 中继的 IPA 硬件转发（owner decision 63）

2026-11-08。中继的 IPv4 NAT 转发主要交给高通 IPA 硬件（IPACM + WDI3）完成；
CPU 转发路径保留，作为兜底，并加上 RPS/backlog 作辅助。代码：
`wifi_relay/offload.rs`（配置、HW 模式、main 路由、硬件自检）、`wifi_relay/steering.rs`
（RPS/backlog）、`mihomo/cn_set.rs`（国内直连分流）、`net_guard.rs`（统一对齐 ZTE
的改动），以及 `wifi_relay/hotspot.rs` 的同主信道 CSA 修复。

## 为什么要做

纯软件中继时，B31 的 Wi-Fi 数据通道中断只落在 CPU0/1，RPS 默认关闭，整条转发
路径（连接跟踪、NAT、约 265 条 iptables 规则、`bridge-nf-call-iptables=1`、
br-lan 上的 HTB + fq_codel）都压在一个 A55 核上。Speedtest.cn 的云测只开单个连接，
所以中继只能跑到约 140 Mbit/s，直连上游能到约 300。同一次开机内的对比（Mac 连 G，
从 tuna/nju 镜像做 HTTP 下载 12 秒）：

| 路径 | 单连接 | 4 连接 | 回程内核转发包数 | CPU1 软中断 |
| --- | ---: | ---: | ---: | --- |
| SW | 179.1 Mbit/s | 156.5 | +200,537 / +168,515 | 约 78–79%，峰值 100% |
| HW（三个条件都满足） | 189.3 Mbit/s | 209.4 | +1,227 / +979 | 约 3% |

速度没有翻倍：瓶颈已经转到镜像服务器或同频空口上（上游和热点都在 52/160）。

## 三个缺一不可的条件

1. **开机前 IPACM 配置里已经有 `u60sta0`。** 格式照 wlanX 的条目写（Category
   `UNKNOWN`、WlanMode `full`），插在 `wlan0` 条目之前。IPACM 只在启动时读一次接口表；
   运行中重启 ipacm 不仅无效还有害（新起来的进程收不到驱动之前发过的 AP/STA 事件），
   所以 agent 永远不会重启它。只改名成 `wlan1`（ZTE 留给访客热点/回程热点、
   169.254.31.1 的名字），或者只切 HW 模式，都已实测无效。
2. **main 表里有一条经过中继的默认路由。** IPACM 不看策略路由表：只放在 60631 表时，
   日志一直是 "Wan is not up, cache connections"；加上之后立刻 `TriggerWANUp()`，
   缓存的连接被写进硬件 NAT（AddPdn / AddEntry）。
3. **IPACM 处于 HW 模式**（`/sbin/ipacm_switch.sh on`，发 SIGUSR2；`off` 发 SIGUSR1，
   并设置 `zwrt_router.tmp_router.close_ipa_acce=1`）。

另外，流量不能被 Mihomo 的 nft 表 TPROXY 进核心（见"国内直连"）：核心终结的连接
不经过转发路径，IPA 无从卸载。
驱动层的 STA 卸载本来就是开着的（`gIPAConfig=0x46d`；dmesg 中有
`wlan_ipa_setup_iface mode:0` 和 offload enable=1），问题完全出在 IPACM 这一层。

## ZTE 为什么关掉加速

开机约 38 秒时，dmesg 先后出现 `ipacm_switch: ipacm to SW` 和
`sfe_switch: sfe to off`。调用链是：`zte_smart_manage` 按
`zwrt_smart_mng.smart_qos.mode='Ai_mode'` 执行
`/sbin/smart_set_qos_policy.sh Ai_mode`，它调用 `router_common.sh` 里的
`accelate_modem_proc off`（X75 平台上会同时关 IPA 和 SFE），然后在 br-lan 上建立
智能 QoS 的 HTB 1:10–1:40 和 fq_codel。也就是说，这是 ZTE 的默认智能 QoS 策略：
它需要每个包都经过 CPU。

`zte_router` 里另外两处调用 off 的路径，这台机器都不满足：

- `x75_platform_init` 要求 `dev_info == SDX75_switch` 并且 `opms_wan_mode == DHCP`，
  这台是 `PPP`；
- `ipa_disable == 1` 时也会调用 off，这台没有设置。

用户在设置里的显式选择同样会关加速：`speedlimit.sh` 的限速、省电模式，以及 ubus 上
"user set ipa disable"（`zwrt_router.other.ipa_disable`）。

## 实现

### 1. 配置安装（需要重启）

中继页"Hardware forwarding"面板，接口是 `POST /api/wifi-relay/offload`，
请求体 `{"install":true|false}`：

- 安装：把条目插到 `/etc/data/ipa/IPACM_cfg.xml` 的 `wlan0` 之前。`/etc` 是 overlay，
  改动能跨重启保留。文件就地改写，保留属主、权限和 SELinux 标签。原文件备份到
  `/data/zte-agent-relay/ipacm/IPACM_cfg.xml.orig`，`installed` 里记下安装时的
  boot id。在 B31 的出厂文件（`a0f361c5…`）上，生成结果和实测用过的文件
  （`4b90dd39…`）逐字节一致。
- 状态：`not_installed` / `reboot_required`（本次开机才装的）/ `loaded`（重启之后，
  或者手工加的条目比 ipacm 进程早）/ `overwritten` / `unavailable`。
  QCMAP 恢复出厂时会用 `factory_IPACM_cfg.xml` 覆盖这个文件，这时状态显示
  `overwritten`，提示重新安装。QCMAP 运行时也会改写这个文件（当前文件比出厂文件
  大），所以卸载时只删掉我们那一块，不整份恢复旧文件。
- 卸载：删掉条目和 `installed` 记录，**保留 `.orig` 备份**。新的中继连接立刻改走 CPU，
  下次重启后 IPACM 也会忘掉这个接口。OTA 切换 A/B 槽位后，overlay 的上层目录不同，
  需要重新安装。
- 手工备份：`/data/zte-agent-backup/ipacm/` 里有原厂文件 `IPACM_cfg.xml.orig`
  （`a0f361c5…`）、安装后的 `IPACM_cfg.xml`（`4b90dd39…`），以及 `restore-stock.sh`；
  开发机上的副本放在仓库旁边的 `../backups/ipacm/`。agent 不在时，可以用这个脚本恢复
  原厂文件，然后重启整机。不要只重启 ipacm。

### 2. main 表默认路由（中继连接时加，断开时删）

只有配置状态是 `loaded` 时才加，并纳入中继的 network Transaction：

```text
ip -4 route add unreachable 100.64.0.0/10  metric 60631 table main
ip -4 route add unreachable 169.254.0.0/16 metric 60631 table main
ip -4 route add unreachable 224.0.0.0/4    metric 60631 table main
ip -4 route add default via <网关> dev u60sta0 metric 60631 table main
```

- **中继优先、蜂窝备用**：所有流量都先查 pref 18640 → 60631 表（中继），这一点不变。
  main 表里这条路由只用来让 IPACM 看到 WAN。蜂窝默认路由由 netifd 以 metric 0 添加
  （`zte_wan` 没有配置 metric），并且使用 NLM_F_REPLACE。如果我们也用 metric 0，
  两条路由会互相替换；所以用 metric 60631，两条可以共存，谁也不会删掉谁。
  蜂窝在线时，只有那些查到 main 表的流量才会优先走 metric 更小的蜂窝。
- **被 throw 的地址段**：60631 表把 100.64/10、169.254/16、224/4 和 LAN 网段 throw 回
  main，让它们使用 main 里的具体路由。如果 main 里有经过中继的默认路由，这些地址段
  会跟着它从酒店网络出去，所以加了 unreachable 守卫。具体路由（LAN /24、各热点的
  169.254.x/24、上游自己的连接路由）前缀更长，仍然优先。如果上游网段就在守卫范围内，
  会跳过对应的那一条。对于绑定了出接口的套接字，内核在查表失败后会按"直接可达"处理，
  所以蜂窝绑定的流量不受影响。
- 回滚：路由删除时会按 `dev` 过滤；如果接口已经消失，就当作已经删除
  （`net_tools::Cmd::undo`）。

### 3. HW 模式

中继连接时（配置已加载、并且没有用户限制）执行 `@u60-relay-ipa hw`。顺序和实测一致：
先切 HW，再加 main 路由。之后每 15 秒检查一次：

- 如果 `close_ipa_acce` 又变回 1（智能 QoS 事件等），就再切回 HW 并记一条日志；
- 如果检测到 `ipa_disable=1`、省电模式，或者 `total_limit_switch` /
  `st_total_limit_switch` 开着，就不再强切，页面显示原因。

**硬件自检和重新挂载**（只看 TCP：`U60_RELAY_FWD` 里单独有一条 TCP 回程放行规则，自检读
它的计数；UDP 例如 QUIC 可能本来就走 CPU，不算硬件失效）：中继重连后，偶尔会出现模式显示 HW、但所有连接仍在 CPU 上
转发的情况（`U60_RELAY_FWD` 回程计数每秒十几万包）；先切 SW 再切 HW 每次都能恢复（3/3）。
所以：

- main 路由加好之后立刻做一次 SW→HW（`Runtime::kick`，日志
  `re-arming IPACM for the new uplink`）；
- 之后每次 15 秒检查时，如果模式是 HW，就比较回程计数的速率，≥1500 包/秒说明连接还在
  CPU 上，再做一次 SW→HW（每次会话最多 3 次，间隔至少 60 秒）；
- 页面的 `hardware` 只有在模式是 HW、并且没有发现这种情况时才是 true，`mode` 另外给出
  IPACM 的模式。

断开时的处理（这个开关是整机的，会连带影响蜂窝）：只有在本次会话把 SW 切成了 HW 时，
才恢复成 SW，也就是 ZTE 智能 QoS 原来的选择；如果连接时已经是 HW，就保持不动。
所以中继关闭时，蜂窝路径和原厂行为完全一样。中继连着时，备用蜂窝的流量也会走 HW，
不经过智能 QoS。

### 4. Mihomo 国内直连（`POST /api/mihomo/cn-direct`）

这是用户可选的开关，在 Mihomo 页面上，状态存成 `/data/zte-agent-mihomo/cn-direct`
文件。开启后，核心启动时从它自己的 `GeoIP.dat`（geodata 模式；protobuf 格式，
只读 `CN` 条目的 IPv4 段，至少 1000 段才算有效）生成 nft 集合 `china`（`ip
u60_mihomo` 表里，interval 类型），拦截链在 TPROXY 之前加一条
`ip daddr @china return`。集合和规则随拦截链一起装上、一起删掉。

GeoIP.dat 不可用时，这次启动就不启用绕过，Mihomo 照常启动并给出提示。只处理 IPv4，
因为 IPA 不卸载 NAT66；IPv6 仍然全部进 Mihomo（用户选择：不做国内 IPv6 绕过，
TPROXY 下 IPv6 已经能跑满线路）。

行为变化：**域名规则命中代理、但解析出来是国内 IP 的连接，也会直连。**
当前订阅里 `GEOIP,CN,直连` 排在最后一条 `MATCH` 之前；DNS 是 `redir-host`，所以内核
看到的是真实 IP，按集合分流可以生效。如果改成 fake-ip，地址都在 198.18.x，
这个开关就匹配不到任何流量。

**conntrack 重置**：在 Mihomo 开关、国内直连开关或国内 IP 列表的摘要发生变化时，
执行 `conntrack -D -f ipv4 -s <LAN 网段>`。返回码 ≤1 都按成功处理，没有条目可删时
返回 1。目的是让已建立的连接和已经被卸载的连接按新的路径重建；IPACM 收到 DESTROY
事件会删掉对应的硬件表项。上游变化导致的核心重启不改变拦截范围，因此不会重置连接。
`proxy_plan` 里没有任何 `-F` 或 `flush`（测试会检查）。

Mihomo 的拦截本身（TPROXY、nft 表、`tcp_pacing_*_ratio`、brnf）见
`docs/research/2026-11-08-mihomo-tproxy-single-flow.md` 和
`network-extensions.md` 的 Interception scope 一节。

### 5. 统一对齐 ZTE 的改动（`net_guard.rs`）

ZTE 会从很多地方改写 legacy iptables、sysctl 和路由：fw3 重载、Wi-Fi/QoS/限速/IPA
脚本、WAN 事件。以前每样东西各自有检查（例如 `redirect_chain` 每个 tick 查一次），
现在统一成一处：

- 中继（IPv4 的 network，加上 IPv6 的 setup/network 两个事务）和 Mihomo 都把自己的改动
  记在 `Transaction` 里。IPv6 只交给这里检查防火墙和 nft 规则（NAT66、转发、DNS）；地址、
  路由和策略规则仍由 IPv6 每个 tick 的 `check_owned` 修复，因为它还要检查冲突（前缀被改、
  DAD 失败、路由或优先级被别人占用会撤掉 IPv6）、等 DAD，并使用租约当前的生存时间
  （`Transaction::reconcile_only`）。`apply`/`apply_network` 会把
  能复查的步骤（iptables 的 `-N/-I/-A`、`ip route/rule/addr add`、`@u60-sysctl`、
  `@u60-mihomo-nft`、`@u60-relay-steer`）连同撤销一起记进内存里的期望状态，
  `remove`/`rollback` 时删掉。`Transaction::reconcile` 按原顺序逐条检查
  （`iptables -C`/`-S`、`ip ... show`、读 sysctl、`nft list`），缺了就原样重做。
- `net_guard` 只决定什么时候查：inotify 监视 20 个 ZTE 脚本的 `IN_OPEN`
  （`fw3`、`firewall_*.sh`、`module_firewall_*.sh`、`wifi_isolate_*`、`isolate_exclude.sh`、
  `speedlimit.sh`、`mwan_speedlimit.sh`、`qos_set.sh`、`smart_set_qos_policy.sh`、
  `ipacm_switch.sh`、`router_common.sh`、`15-mwan3` 等），订阅 ubus 事件
  `zwrt_wlan`、`zwrt_router.msg`、`zwrt_smart_mng.msg`、`network.interface`；
  触发后安静 2 秒再查；没有触发时每 60 秒兜底一次。没有任何 owner 时什么都不跑。
- 每次恢复都会记日志，写明重做了哪些命令：
  `[guard] relay: restored after another writer removed them: ...`。某一条查不了或重做失败时，
  其余的照常处理；失败写进日志（同样的失败只记一次）并显示在页面上。
- agent 的 nft 表（Mihomo 的 `u60_mihomo`、中继 DNS 的 `u60_relay`）都用 `net::nft_fill`
  生成：同一个 `nft -f` 事务里先声明表、集合和链（已存在则无操作），再清空，最后写入规则，
  所以重做不会让规则重复。检查时用 `nft -t list table`（不列出国内 IP 集合的几千个元素），
  每个协议族一次，并逐条链比对规则数（`net::nft_holds`），被清空或删掉一部分的链也会被补回。
- IPA 模式不在这里：它有自己的 15 秒检查（要考虑用户限制，见第 3 节）。

实测到的 ZTE 改写（2026-11-08）：中继每次连上之后，ZTE 都会把
`bridge-nf-call-ip(6)tables` 改回 1，并清空 nat 表的 `redirect_chain`（中继放在里面的
RETURN 会跟着消失）；`fw3 reload` 也会把 brnf 改回 1。三者都被自动恢复了。手工删掉
IPv6 的 `U60_R6_NAT`/`U60_R6_FWD` 跳转后 4 秒补回。

### 6. RPS 和 backlog（辅助）

中继连接时，`u60sta0` 和 `wlan2` 所有接收队列的 `rps_cpus` 设为"没有处理过 Wi-Fi
中断的 CPU"（从 `/proc/interrupts` 计算，B31 上是 `c`）；`netdev_max_backlog`
不到 5000 的提到 5000。断开时恢复。这只影响仍然走 CPU 的流量：Mihomo 代理的连接、
IPv6/NAT66、每条连接的头几个包，以及设备本机的流量。

之前单独开 RPS 的效果：单连接 141.7 → 196.8 Mbit/s，4 连接 184 → 238.5；在 backlog
为 1000 时看到过 softnet 丢包。RPS 和 HW 同时开的组合效果还没有实测。

### 7. 热点同主信道 CSA

热点已经在 36 信道、只是带宽不同时（例如 36/40），用一次 CSA 切到 36/20 会被驱动
拒绝（`CSA failed ... ret -22`），清理会一直卡在 "Hotspot refused the channel switch"。

修复后的处理：

- `switch_with` 发现主信道相同时，先切到另一个非 DFS 的 20 MHz 信道，等它
  ENABLED，再切到目标。暂存和回滚都走这条逻辑。
- `prepare` 发现热点已经停在暂存信道、只是带宽不同时，直接换一个暂存信道，
  省掉一次切换。

## 不受影响或需要注意的地方

- **被卸载的连接**会绕过 iptables（`U60_RELAY_FWD`、ZTE 的 FORWARD 链）、tc
  （智能 QoS、限速）和 ZTE 家长控制。每条连接的头几个包仍然走内核，所以 NAT、
  `U60_RELAY_FWD`，以及 IPACM 靠 conntrack 学到的 NAT 都必须保留。
- **按终端的流量统计**（`client_details.rs` 读 `iw station dump`）计的是空口字节数，
  理论上不受影响，但还没有验证。
- **继续保留的兼容项**：5G 非 DFS 20 MHz 暂存、`disableDfsCS`、2.4G 的
  disable/set/enable、portal、DNS、udhcpc 续租、resume 和残留进程清理、NAT66、
  60631 策略路由、带宽调优（width\*、llstats）。
- **不再需要做**：精简 iptables 链。卸载以后收益很小。
- **brnf**：Mihomo 运行时 `bridge-nf-call-ip(6)tables=0`（TPROXY 在 bridge-netfilter
  路径上拿不到套接字），停止时恢复原值。期间 br-lan 内部的二层流量不再经过 iptables，
  访客热点隔离之类按 LAN 内部过滤的规则会失效（用户已接受）。中继本身不需要改 brnf。

## 已验证 / 未验证

已验证：上表中的 SW/HW 对比；整机冷启动后 agent 能自动恢复中继（两次，约 55–75 秒）。
部署后的复测结果见末尾一节。

未验证：

- IPv6 能否卸载；
- 蜂窝在线时 main 表的实际表现，以及 IPACM 在两个 WAN 同时存在时选哪一个；
- HW 模式对蜂窝路径的影响；
- 长时间运行的稳定性；
- 2.4G 上游；
- RPS 加 HW 的组合效果。

## 部署后复测（2026-11-08，agent 本次实现）

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

## 还能提速的地方（2026-11-08 测试）

省电关闭后，speedtest.cn 经中继 244–253 Mbps，直连 W_Game 291–295；用 tuna 镜像持续下载时，
中继和直连一样都在 230 左右（镜像那端的上限）。

| 尝试 | 结果 | 结论 |
| --- | --- | --- |
| `u60sta0` 省电关闭（手动 `iw`，中继重连后恢复默认） | 166–218 → 244–250 | 有效，用户选择手动关、不集成 |
| 禁用 CPU 深度休眠（C3/C4）+ performance 调频 | 250.5 / 253.1；U60→网关 ping 约少 0.5–1 ms | 在噪声范围内，增加耗电，已恢复 |
| 信道 52 繁忙度 | 4% | 没有外部争用 |
| 两段链路速率 | 上游 2161 Mbps、到 Mac 2402 Mbps（160 MHz HE 2×2） | 远高于 300，不是瓶颈 |

剩下约 15% 的差距只在短时测速里出现：同一块射频、同一条信道上跑两段 Wi-Fi，中继比直连多
约 3–4 ms 的最小 RTT（Mac→上游网关 5.3–6.5 ms，直连 2.1 ms），影响 TCP 起步。软件层面没有
找到明显的手段；能消掉这一跳的是有线上行。线路更快时，Mihomo 路径（单流约 238 Mbps，Mihomo
占单核 31–44%）会先于硬件路径成为瓶颈。
