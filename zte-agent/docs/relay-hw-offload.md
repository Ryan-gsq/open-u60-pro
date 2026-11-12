# Wi-Fi 中继的 IPA 硬件转发（owner decision 63）

2026-11-08。中继的 IPv4 NAT 转发主要交给高通 IPA 硬件（IPACM + WDI3）完成；
CPU 转发路径保留，作为兜底，并加上 RPS/backlog 作辅助。2026-11-12 起 agent 不再读、切换、审计或核验
IPACM 的 HW/SW 模式，由路由器的工作模式决定（车主决定，见“谁决定 HW/SW 模式”）。代码：
`wifi_relay/offload.rs`（读 IPACM 配置、main 路由、固件指纹）、
`wifi_relay/offload/neighbours.rs`（删掉 IPACM 给上游其他设备的上行规则，第 8 节）、
`wifi_relay/offload/clients.rs`（热点客户端换频段后补回 IPACM 的 LAN 路由，第 9 节）、`wifi_relay/steering.rs`
（RPS/backlog）、`mihomo/routing.rs` 和 `mihomo/geoip.rs`（按 Mihomo 的模式和规则在内核绕过，
第 4 节）、`net_guard.rs`（统一对齐 ZTE 的改动），以及 `wifi_relay/hotspot.rs` 的同主信道 CSA 修复。
运行时开关见第 3 节（owner decision 64）。2026-11-12 起中继的站点接口叫 `ath20`：B31 的原厂 IPACM 配置本来就列着它，
agent 不再改写那个文件，也没有安装步骤和安装后的重启（第 1 节）。在那之前接口叫 `u60sta0`，本文带日期的记录里仍用旧名。

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

1. **IPACM 开机时读到的配置里列着站点接口。** 条目要是 Wi-Fi 的格式（Category `UNKNOWN`、
   WlanMode `full`）。IPACM 只在启动时读一次接口表；运行中重启 ipacm 不仅无效还有害（新起来的进程
   收不到驱动之前发过的 AP/STA 事件），所以 agent 永远不会重启它。B31 的原厂文件已经这样列着
   `ath20`，所以站点就叫 `ath20`。不用 `wlan*` 这类名字：厂商关 Wi-Fi 时会等所有名字含 `wlan` 的接口
   消失（`lib/wifi/zteqcawifi.sh`）。早先实测：只改名成 `wlan1`（ZTE 留给访客热点/回程热点、
   169.254.31.1 的名字），或者只切 HW 模式，都无效。
2. **main 表里有一条经过中继的默认路由。** IPACM 不看策略路由表：只放在 60631 表时，
   日志一直是 "Wan is not up, cache connections"；加上之后立刻 `TriggerWANUp()`，
   缓存的连接被写进硬件 NAT（AddPdn / AddEntry）。
3. **IPACM 处于 HW 模式**（`/sbin/ipacm_switch.sh on`，发 SIGUSR2；`off` 发 SIGUSR1，
   并设置 `zwrt_router.tmp_router.close_ipa_acce=1`）。
   这一条由厂商决定，agent 只负责前两条，见下一节。

另外，流量不能被 Mihomo 的 nft 表 TPROXY 进核心（见第 4 节）：核心终结的连接
不经过转发路径，IPA 无从卸载。
驱动层的 STA 卸载本来就是开着的（`gIPAConfig=0x46d`；dmesg 中有
`wlan_ipa_setup_iface mode:0` 和 offload enable=1），问题完全出在 IPACM 这一层。

## 谁决定 HW/SW 模式

agent 不读也不改 IPACM 的模式（车主决定，2026-11-12）：想要硬件转发时，车主自己把工作模式设成
极速模式（Balanced）。厂商通过 `router_common.sh` 的 `accelate_modem_proc on|off` 切换（X75 平台上
同时开关 IPA 和 SFE）：

- **工作模式**（`zwrt_smart_mng.smart_qos.mode`，`/sbin/smart_set_qos_policy.sh`）：官方 Web UI 共 6 个。
  `Nomal_mode`（原文拼写，页面上叫 Balanced / 极速模式）执行 `on`；`Ai_mode`（出厂默认）、`Live_mode`、
  `Game_mode`、`Video_mode`、`Chat_mode` 执行 `off`，并在 br-lan 上建立智能 QoS 的 HTB 1:10–1:40 和
  fq_codel，需要每个包都经过 CPU。
- **随流量切换**：`Ai_mode` 和 `Game_mode` 下，`zte_smart_manage` 的 `[ai_qos]` 循环检测到应用流量时下发
  当前模式（加速关），连续检测不到时下发 `stop`（加速开），所以 IPA 模式随流量反复变化；`Nomal_mode` 下
  这个循环什么都不做。`Ai_mode` 下开机约 38 秒时 dmesg 先后出现 `ipacm_switch: ipacm to SW` 和
  `sfe_switch: sfe to off`，就是这条路径。
- **其他设置**：`speedlimit.sh` 的限速和省电模式也会关加速（这两种情况下 `smart_set_qos_policy.sh` 提前返回，
  不按工作模式打开），ubus 上 "user set ipa disable"（`zwrt_router.other.ipa_disable`）同样调用 `off`。
- `zte_router` 里还有 `x75_platform_init` 会调用 `off`，它要求 `dev_info == SDX75_switch` 并且
  `opms_wan_mode == DHCP`，这台是 `PPP`，不满足。

2026-11-11 只读查询时本机已是 `Nomal_mode`（谁改的未查明）；本文早先写的 `Ai_mode` 是那之前的状态。

## 实现

### 1. IPACM 配置：只读

agent 只读 `/etc/data/ipa/IPACM_cfg.xml`，从不写它（`offload::config`）。状态接口的 `offload.config`：

- `listed`：有一个 `<Iface>` 条目名为 `ath20`、Category `UNKNOWN`、WlanMode `full`。B31 的原厂文件
  （sha256 `a0f361c5…`）就是这样；QCMAP 运行时改写这个文件、恢复出厂时用 `factory_IPACM_cfg.xml` 覆盖它，
  都不会去掉这个条目。
- `not_listed`：别的固件没有这个条目，IPACM 不理中继，中继走 CPU，页面写明原因。
- `unavailable`：读不到文件。

页面的 “IPA CONFIGURATION” 一行显示这个状态，没有安装或移除的控件；`POST /api/wifi-relay/offload` 只接受
`{"enabled":true|false}`（第 3 节）。

依据（2026-11-12）：站点改名 `ath20` 后，IPACM 把中继登记成 WAN，为真实 LAN 客户端添加了硬件 NAT 表项，
205 MB 下载 141–183 Mbit/s，内核转发路径只有 168 个包（`measurements/exp2-ath20-*`）；最终版在新开机、
原厂文件上 205 MB 只有 135 个包走内核，软中断 0.9%（`measurements/b2-reboot3/hw-throughput.txt`）。

**以前的安装（2026-11-12 删除）**：之前的版本把 `u60sta0` 条目插进这个文件，需要重启整机才生效，并有备份、
标记文件和“本次开机是否已加载”的记账。车主的路由器上，这个条目已在 2026-11-12 用旧版自己的移除操作删掉，
文件又与原厂一致（`measurements/b2-final/disconnect-connect.log` 的 sha 前缀）。路由器上旧安装留下的备份
`/data/zte-agent-relay/ipacm/IPACM_cfg.xml.orig`（核对过与正在用的文件相同）已在同一天按车主的要求删除。
开发机上仓库旁边的 `../backups/ipacm/`（原厂文件、装过条目的文件和 `restore-stock.sh`）也在同一天按车主的要求删除。

### 1a. 状态机和固件指纹（`offload::Runtime`）

每个中继会话的硬件转发路径是一个显式状态（状态接口 `offload.state`），设备读写都经 `IpacmPort`
（测试用假实现跑转换和失败矩阵）。agent 管的只有第 2 节的 main 路由和第 8、9 节的两个监视器：

| 状态 | 进入与离开 |
| --- | --- |
| `off` | 不需要或做不到：没有会话、IPACM 配置没有列出 `ath20`、开关关、固件指纹不符、加路由失败（已加的部分先撤掉）。`reason` 写明原因。 |
| `routed` | main 默认路由和 unreachable 守卫已加好，邻居和客户端监视器在运行。IPACM 是否真的卸载，取决于它当时的模式（上一节）。 |
| `releasing` | 停监视器，删 main 路由（IPACM 的中继 WAN 下线）。撤销失败就停在这里（不报 `off`），剩余撤销项保留，下次再试；还要路由时，等撤完再重新加。 |

状态接口 `offload` 的键：`state`、`route`（main 路由是否在位）、`reason`、`config`（第 1 节的配置状态）、
`enabled`（运行时开关）、`ipv4_through_mihomo`（`none` / `rules` / `all`：Mihomo 拦截的公网 IPv4 无论 IPA
怎样都走 CPU，规则绕过开着时只有内核放行的 DIRECT 部分例外）。

**固件指纹**：邻居退役（第 8 节）和客户端 STALE（第 9 节）是对 B31 IPACM 行为的修补，
只在 `zwrt_common_info.common_config.wa_inner_version` 为 `BD_CNMU5250V1.0.0B31` 且 `/usr/bin/ipacm` 的
SHA-256 为 `95385816…5c11c0`（4,129,835 字节，2026-11-10 只读查询）时启用；不符时不加 main 路由，页面写明原因，
中继走 CPU。

只有路径真的变了（开关打开或关上）才重置 LAN IPv4 连接。路由在位时，页面的 RELAY PATH 写
“极速模式（Balanced）下走硬件（IPA），其他工作模式走 CPU”：agent 不读模式，也不核验卸载是否真的发生。
要确认，看 `U60_RELAY_FWD` 的回程计数（几百个包是硬件，十几万是 CPU），或第 8、9 节的 debugfs。

### 2. main 表默认路由（中继连接时加，断开时删）

只有配置状态是 `listed`、运行时开关开着、固件指纹相符时才加，路由归中继会话的 `network` set（`EffectSet`）。

```text
ip -4 route add unreachable 100.64.0.0/10  metric 60631 table main
ip -4 route add unreachable 169.254.0.0/16 metric 60631 table main
ip -4 route add unreachable 224.0.0.0/4    metric 60631 table main
ip -4 route add default via <网关> dev ath20 metric 60631 table main
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

### 3. 运行时开关（owner decision 64）

中继连接时（配置列着 `ath20`、开关开、指纹相符）加第 2 节的路由，再启动第 8、9 节的监视器。
IPACM 的模式整机共用、归厂商（见“谁决定 HW/SW 模式”），中继连接、断开和这个开关都不碰它，
所以中继开着时蜂窝备用路径也照工作模式走。

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

中继页"Hardware forwarding"标题旁的开关，接口是
`POST /api/wifi-relay/offload` 加 `{"enabled":true|false}`，关掉时存成
`/data/zte-agent-relay/ipacm/off`（重启和重连后仍然有效），状态里是 `offload.enabled`。
关掉时当前连接立刻改走 CPU，打开时立刻恢复硬件转发，不需要重启路由器，也不重连中继：

- 关（`Runtime::release`）：停止邻居和客户端监听，然后用 `EffectSet::withdraw` 撤掉这部分资源，
  按添加的反序删 main 默认路由和 unreachable 守卫（IPACM 失去中继 WAN）。其余中继步骤和日志都保留。
- 开（`Runtime::sync`）：和连接时一样，加 main 路由、启动监听。
- 路径变了之后执行 `conntrack -D -f ipv4 -s <LAN 网段>`，让已建立和已卸载的连接按新路径重建，
  所以每次切换都会重置一次现有的 LAN IPv4 连接。页面按实际结果提示（删了几条、没有可删的、
  已被同一次变化之后开始的删除覆盖，或失败待重试），不再一律说“已重置”；见下面的 conntrack 重置。
- 关掉时页面的原因是 "Hardware forwarding is turned off"。
- 设备事实（11-09，当时还有安装/移除）：IPACM 监视 `IPACM_cfg.xml`，文件一变就重读配置，重读之后不再理会中继
  WAN 的下线：先改文件、再删 main 路由，WAN 规则和 PDN 都还在，新连接照样被卸载（回程内核包 221–416）。
  只关开关（不改文件）则立即回到 CPU（约 20 万）。所以不要在中继连着时改这个文件。

### 4. Mihomo 的 DIRECT 规则在内核绕过（`POST /api/mihomo/cn-direct`）

这是用户可选的开关，Mihomo 页面上叫 "Bypass Mihomo for DIRECT rules"（接口和状态文件
`/data/zte-agent-mihomo/cn-direct` 沿用最初"国内直连"时的名字）。owner decision 64：哪些 IPv4
在内核里绕过核心，按 Mihomo 当前的模式、规则和策略组选择决定（`mihomo/routing.rs`），DNS 固定用
fake-ip：

| 模式 | 内核绕过的 IPv4 | 其余 |
| --- | --- | --- |
| rule | 订阅规则从上到下编成内核链（见下）：按地址判 DIRECT 的规则命中就放行 | 进 Mihomo |
| direct | 全部（fake-ip 地址除外） | fake-ip 地址进 Mihomo，由它直连 |
| global | 无 | 全部进 Mihomo |

开关关掉时任何模式都不绕过。IPv6 始终全部进 Mihomo（用户选择）。

**rule 模式的内核链**（`Routes::compile` 编译、`Compiled::render` 填入 GeoIP 范围），在私网段 return
之后，顺序和 Mihomo 一致：

| 规则 | 内核里 |
| --- | --- |
| 按地址、端口、协议匹配（`IP-CIDR`、任何国家的 `GEOIP`、`DST-PORT`、`SRC-PORT`、`SRC-IP-CIDR`、`NETWORK`、能编译的 `AND`/`OR`、`ipcidr`/`classical` 规则集里的这类条目），目标沿 select 组的当前选择落到 DIRECT | 命中就 `return`（内核 NAT，中继上走 IPA） |
| 同上，目标不是 DIRECT | 命中就 `goto to_core` |
| 域名规则 | 跳过，交给 fake-ip |
| 进程规则 | 跳过（核心的进程查找是关的，局域网连接也没有本机进程） |
| 内核判断不了、目标是 DIRECT（如 `IP-ASN,x,DIRECT`） | 跳过：这类流量落到后面的规则，最多进 Mihomo，再由它直连 |
| 内核判断不了、目标不是 DIRECT（`IP-ASN`、`NOT`、`SRC-GEOIP`、带 `src` 的 `GEOIP`、`mrs` 地址集、没下载的规则集、`GeoIP.dat` 里没有的国家代码等） | 链到此为止，后面全部进 Mihomo；前面已经编好的放行照常生效，原因显示为 "Chain ends at" |
| `MATCH,DIRECT` / 没有 `MATCH`（核心的默认就是 DIRECT） / `MATCH,其他` | 剩下的全部放行 / 全部放行 / 全部进 Mihomo |

- 只在 IPv6 上匹配的条件（`IP-CIDR6`、IPv6 段）、落在私网段里的目标地址段和 `GEOIP,PRIVATE`/`LAN`
  不进内核链（私网段在链前已经 return）。结尾进 Mihomo 时，紧挨在它前面的那些进 Mihomo 的规则也省掉
  （例如 `MATCH,选择代理` 前的 `DST-PORT,22`）。`AND` 里有一项永远匹配不到 IPv4 或是域名条件，整条在内核里就不会匹配，直接跳过。
- 集合：相邻、同一结果（放行或进核心）的规则之间顺序无关，所以其中的单独地址段合进一个 `ip_<n>` 集合；
  每个 `GEOIP` 国家代码一个 `geo_<代码>` 集合，按需从核心自己的 `GeoIP.dat` 读取（`mihomo/geoip.rs`，
  只读需要的代码，按文件和代码缓存；某个代码只有 IPv6 段时永远匹配不到）。不是 geodata 模式时核心用
  `geoip.metadb`，内核读不了，`GEOIP` 规则按"判断不了"处理。重新生成后，旧链用到、新链不用的集合会被删掉。
- 状态里 `kernel.bypass` 是 `rules`，`kernel.returns` 是放行的规则条数，`kernel.reason` 是截断原因；
  一条放行都没有时 `bypass` 是 `none`，`reason` 说明原因。

**fake-ip 和过滤表**（`config_with_lan_host` 固定写入，订阅改不了）：地址池 `198.18.0.1/16`，
不配 IPv6 地址池（订阅里的 `fake-ip-range6` 会被删掉：它落在内核提前放行的 ULA 段里；没有 IPv6
池时，这些域名的 AAAA 查询返回空，客户端改用 IPv4 假地址），TTL 1 秒，`profile.store-fake-ip`。
拦截链里 `ip daddr 198.18.0.0/16` 排在所有放行规则之前，在任何模式下都送进核心。
`fake-ip-filter-mode: rule` 的过滤表（`Routes::dns`）**只由配置和这个开关决定**，模式和组选择都不改它
（车主 2026-11-10 选择 Q2=A、Q3=A）。开关关时：本地名字和订阅自己的黑名单给真实地址，其余全部假地址。
开关开时从上到下：

1. 本地名字（`.lan`、`.local`、`.localdomain`、`.home.arpa`）和 Windows 联网检测
   （`msftconnecttest.com`、`msftncsi.com`）给真实地址；
2. 到最后一个**可能**放行点为止的域名类规则：目标直接写 `DIRECT`、来自固定列表（规则本身或 inline
   规则集）的给真实地址；目标是任何策略组（即使现在选的是 DIRECT）的给假地址——组以后可能切走，
   缓存了真实地址的客户端就会继续按 DIRECT 前缀走硬件；会刷新的规则集（http/file）里的名字给假地址，
   目标不是 DIRECT 的这类规则集还可能收进任何名字，所以从它开始其余全部给假地址；`NOT`、`SUB-RULE`
   和引用这类规则集的 `AND`/`OR` 同样到此为止；
3. 订阅自己的 `fake-ip-filter` 黑名单（换成规则语法）给真实地址——排在规则之后，所以被策略组或会刷新的
   规则集管着的名字不会因为黑名单拿到真实地址；
4. 最后 `MATCH,real-ip`，或在第 2 步提前结束时 `MATCH,fake-ip`。

最后一个可能放行点是最后一条能按地址匹配、且目标是 DIRECT 或"能选到 DIRECT 的 select 组"的规则；
`MATCH` 同理，没有 `MATCH` 时是规则末尾（`Routes::last_return`）。它只看配置，不看当前选择，所以切组
不会挪动它。这样切组只改内核链，不改 DNS、不重启核心；拿到真实地址的名字，切组前后的走法都一样。
代价：放在策略组或会刷新的规则集后面的域名都走核心（CPU），硬件只承担固定 DIRECT 名字和按地址判断的流量。

**策略组**：目标是 `select` 组时，沿当前选择一路找下去，最后到 DIRECT 才算 DIRECT；
`url-test`、`fallback` 等自动组一律不算。内核链用的选择只来自本代核心就绪后实际读到的值
（`GET /configs`、`GET /proxies`），不再读 `selected.json`。

**跟随变化**（`mihomo/controller.rs`）：控制台或 Zashboard 改模式（`PATCH /configs`）、改组选择
（`PUT /proxies/…`）、更新规则集（`PUT /providers/rules/…`）都经控制器排队：先装"保持"表（不绕过任何
地址，由代次标记确认；确认不了就拒绝这次修改，核心不动），再改核心、读回模式和选择、只重置失去 DIRECT
的 LAN IPv4 连接，最后装新链。`http` 规则集的定时刷新也由控制器做（托管配置删掉了它们的 `interval`），
刷新期间只把这个规则集当作未知；`domain` 行为的规则集（内核链从不读它）刷新时直接交给核心，不收紧也不换表。
上次声明而没有确认的表也算在内：收紧与否、要重置哪些连接，都按内核可能持有的所有表算。每 60 秒控制器还会读一次核心的模式和选择，有差异按同样顺序跟随。
这个开关会改 DNS 过滤表：先收紧，再对同一份配置热重载（`PUT /configs?force=false`），读回模式、出口接口、
各组选择（没有退到 `COMPATIBLE`）、规则集和监听，并在 1053 上查一个答案必须改变的名字；确认后才放开新链，
确认不了就改用保留拦截的计划内重启。

当前订阅（2026-11-09，47 条，11 个每日刷新的 http 规则集）：放行的是 `GoogleFCM` 规则集（直连）的
IPv4 段和 `GEOIP,CN,直连`；进核心的是 `EHentai` 规则集的 1 段 IPv4、`GEOIP,NETFLIX`、`GEOIP,TELEGRAM`
和 `DST-PORT,22`，其余是域名或进程规则；`ADBlock.mrs` 是域名行为，不影响内核链。按 Q2/Q3 的过滤表，
第 5 条 `RULE-SET,ADBlock,广告拦截`（会刷新、目标是策略组）之后的名字全部给假地址，所以 `GEOSITE,CN`
的国内域名也进核心；硬件绕过只剩按地址命中的流量（写死 IP、绕开路由器 DNS 的客户端）和 `lihan.me`
这类固定 DIRECT 的名字。这是车主为"不误直连"接受的代价，设备上的吞吐和 CPU 对照待测。

限制：绕过了核心 DNS 的客户端（DoH、浏览器安全 DNS、写死 IP 的应用）拿到真实地址时，只按地址规则判断，
即使嗅探出的域名会让核心走代理；被绕过的连接不出现在 Mihomo 的连接列表和流量统计里；
fake-ip 改变了核心对 `no-resolve` IP 规则的判断（假地址的连接没有目标 IP，只按域名匹配），
这对排在域名规则之前、带 `no-resolve` 的 IP 规则有影响。

**conntrack 重置**：在 Mihomo 开关、模式、组选择、这个开关或规则集让拦截链发生变化时，
执行 `conntrack -D -f ipv4 -s <LAN 网段>`（只经 `netfx::conntrack`，直接传参，不经 shell）。
conntrack-tools 1.4.8 在“没有条目可删”和“操作失败”时都返回 1，只能看标准错误区分：
最后一行 `N flow entries have been deleted.`（N=0 且返回 1 是零匹配的证据，N>0 且返回 0
是删除了 N 条），`Operation failed: …` 或没有计数行都是失败。失败的请求保留下来，
由中继/Mihomo 的看护在下一拍重试，并与后来的请求合并；只有**在本次路径变化之后开始**、
成功且覆盖全部范围的一次删除才能抵掉之后的请求。最近 8 次结果在两个状态接口的
`connection_resets` 里（开机后秒数、原因、范围、结果）。目的是让已建立的连接和已经被卸载的
连接按新的路径重建；IPACM 收到 DESTROY 事件会删掉对应的硬件表项。切换只重置失去 DIRECT 的范围
（`routing::lost_from`，D10；“旧”是上次重置以来内核可能持有过的每一张表）：新旧两张链直到最后一个放行点都只按目的地址判断时，用"旧放行减新放行"按首个
命中计算（例如在原 DIRECT 段前加了代理规则，被它截走的那半段）；任一张链含端口、来源或协议条件
（例如前面加了 `DST-PORT,443,代理`，原 DIRECT 段里的 443 硬件流也必须退出）时，旧链不纯就重置整个
LAN IPv4，新链不纯就重置旧链放行的全部范围；超过 64 段也重置整个 LAN IPv4；没有失去放行的就什么都不删
（反方向切到 DIRECT，核心里的连接靠 `socket transparent` 规则继续走核心）。首次启动重置 LAN IPv4，
从 D3 恢复后 IPv4 和 IPv6 都重置。`proxy_plan` 里没有任何 `-F` 或 `flush`（测试会检查）。

Mihomo 的拦截本身（TPROXY、nft 表、`tcp_pacing_*_ratio`、brnf）见
`docs/research/2026-11-08-mihomo-tproxy-single-flow.md` 和
`network-extensions.md` 的 Interception scope 一节。

### 5. 统一对齐 ZTE 的改动（`net_guard.rs`）

ZTE 会从很多地方改写 legacy iptables、sysctl 和路由：fw3 重载、防火墙/QoS/限速/访客隔离
脚本、WAN 事件。以前每样东西各自有检查（例如 `redirect_chain` 每个 tick 查一次），
现在统一成一处：

- 中继的 wireless、network、dns、IPv6 setup/network 及 Mihomo 的 network 各对应一个
  `EffectSet`。IPv6 只交给这里检查防火墙，nft 表归 wireless（含 NAT66、转发、DNS）；地址、
  路由、策略规则和 RA 由 IPv6 自己的 `check_owned` 修复，因为它还要检查冲突（前缀被改、
  DAD 失败、路由或优先级被别人占用会撤掉 IPv6）、等 DAD，并使用租约当前的生存时间
  （`EffectSet::reconcile_only`）。`check_owned` 在中继控制器的 tick 里运行，检查时机包括
  `net_guard` 的触发已安静（与下面的检查同一拍）、上次读取失败后的重试、续写生存时间之前，
  以及距上次检查满 15 秒（`ipv6::CHECK_EVERY`）。所以不发厂商触发的删除最晚约 15 秒才发现（车主 2026-11-12 接受）。
  `declare` 从分类型资源生成期望状态及 undo，整批撤销先持久写盘再应用。
  `withdraw` 按键撤资源，`release` 释放整份日志，遇错保留剩余项。
- 一次检查（`EffectSet::reconcile`）先读列表、再逐项对照，每个工具/表只 `-S` 一次，路由、
  策略规则、地址每族各列一次（`net_tools::Listings`）；中继的 tick 用 `net_tools::Pass` 让同一次检查的
  各个 set 共用这些列表。自有链核对内容和顺序，缺失或不符时整链修复。工具仍以预测外形式列出时，
  记一次 `[net] listed in a form not predicted` 并保存修复后的读回供下次核对。
  钩子只由 `-C` 找到时保留并记一次日志，列表确认有重复时归一。确定缺失才补回，
  例如 `-C` 以退出码 1 报不在（`netfx::effect::legacy::no_rule`）。B31 的 iptables 1.8.8（legacy，两族）有两种措辞：
  目标是 ACCEPT、RETURN 或链不存在时是 "Bad rule (does a matching rule exist in that chain?)"，跳到一条存在的用户链
  （每个挂到 `U60_*` 链的钩子）或目标是 MASQUERADE 时是 "No chain/target/match by that name."；目标链不存在则退出 2（"Couldn't load
  target"），不算答案。批次 1 的第一版只认第一种：开机后厂商的防火墙启动清掉了 IPv6 INPUT 钩子，它的撤销读成
  “查不了”，之后每次中继恢复都以 "Network cleanup paused" 失败，直到装上修复版（2026-11-12，约 15 分钟没有上行）。
  列表或工具本身失败算“查不了”，报出来，留给下一次检查。重做之后，这个列表在本次检查里重新读。
- 撤销（`Cmd::undo` → `netfx::effect::legacy::undo`）删掉自有规则的每一份副本，自有 `U60_*` 链在无外部跳转后清空并删除；
  厂商链从不清空，别人的同样规则只删一次。只有确定的“不在”才算已撤销，工具或锁失败时保留日志。
- `net_guard` 只决定什么时候查：inotify 监视 6 个 ZTE 脚本和工具的 `IN_OPEN`（`net_guard::WATCHED`）：`fw3`
  （restart 或 flush 会清掉全部 legacy 规则，每次 reload 都运行后面几个脚本）、把 brnf 写成 1 的
  `firewall_sys_fw.sh`、`wifi_isolate_and_second_ssid_access_control.sh` 和 `mwan_speedlimit.sh`、清空
  `redirect_chain` 的 `firewall_redirect.sh` 和 `firewall_multi_wan_redirect.sh`。2026-11-12 之前监视 18 个；
  去掉的 12 个只动厂商自己的链，或者只是上面几个的调用者，监视它们只会多查。订阅 ubus 事件
  `zwrt_wlan`、`zwrt_router.msg`、`network.interface`；
  触发后安静 2 秒再查（到点直接唤醒中继和 Mihomo，不等它们下一个 tick）；某次检查真的补回了
  东西，5 秒后再查一次；没有触发时每 60 秒兜底一次。没有任何 owner 时什么都不跑。
  每次触发后的 3 秒内，每 0.5 秒只读一遍 owner 持有的 `@u60-sysctl`（如 Mihomo 的 brnf=0），
  被改了才写回，而且写之前在同一把锁里确认它仍被同一 owner、同一代次持有；owner 释放时先注销
  再执行撤销，所以释放后的迟到采样不会把运行值写回去（`net_guard::hold/release`）。
- 每次恢复都会记日志，列应用命令或资源描述，例如 `iptables -t nat hook redirect_chain …`，前缀为
  `[guard] relay: restored after another writer removed them: ...`。某一条查不了或重做失败时，
  其余的照常处理；失败写进日志（同样的失败只记一次）并显示在页面上。
- agent 的 nft 表（Mihomo 的 `u60_mihomo`、中继的 `u60_relay`）由各自 `EffectSet` 中的 `NftTables`
  维护，两族放进同一个 `nft -f` 批处理整表替换，并带代次标记，用 `nft -t list ruleset`
  （不列出集合元素）读回标记确认，逐条链比对规则数，被清空、删掉一部分或丢了标记的表会按
  目标重新载入。中继的表在 `wifi_relay/uplink.rs` 一处拼装（v5，见 `network-extensions.md`
  的 Firewall layout）：上游防护、转发、IPv6 基线、NAT66 和中继 DNS 的拒绝/改写都在 nft；
  legacy 只留必须穿过 ZTE 拒绝的放行（IPv4 的 `U60_RELAY_IN`、`U60_RELAY_FWD`，IPv6 的 `U60_R6_IN`、
  `U60_R6_FWD`）、门户 RETURN 和 IPv4 MASQUERADE。IPv6 INPUT 直接挂 `U60_R6_IN`。
  INPUT/FORWARD/MASQUERADE 钩子添加时插首位，之后保留厂商后来插到前面的过滤规则（D8）。

**fw3 重载做了什么、谁触发的**（2026-11-12 查明）：每次 fw3 start/restart/reload 都运行 include
`firewall_init.sh`，它调用的 `firewall_sys_fw.sh`（`:1104-1106`，无条件）和
`wifi_isolate_and_second_ssid_access_control.sh`（`:125-130`，本机条件恒真）把 brnf 写成 1，调用的
`firewall_redirect.sh` 清空两族的 `redirect_chain`。没有厂商设置能关掉 brnf 的写入。实测每次重载后
brnf 读到 1 约 0.2–0.5 秒，才被上面的采样写回 0。中继连上之后那次重载是 agent 自己引起的：IPv6 的
`ubus call network.interface.lan set_data`（`wifi_relay/ipv6/ra.rs`）让 netifd 以
`ACTION=ifupdate IFUPDATE_DATA=1` 跑 `iface` hotplug，`/etc/hotplug.d/iface/20-firewall` 随即
`fw3 -q reload`（进程链实测；撤 IPv6 时两次重载相隔 3.2 秒）。

**离线门户的抑制**（`wifi_relay/portal.rs`）：`firewall_redirect.sh` 只在 `zwrt_redirect.redirect.switch` 为 1 时
写端口 80 的 DNAT（本机去掉 agent 的改动后读到的是 1）。中继会话期间 agent 用一个易失的 uci 改动把它设成 0，
另在两族 `redirect_chain` 的最前面放一条 RETURN（`LegacyHook` 的 `BeforeVendor`，注释 `zte-agent-wifi-relay`），
核对时保证只有一份且排在厂商规则前。三项都记在会话的 `dns` set（`dns.json`）里，和解析器那一行放在一起。5 GHz 之间的交接只释放解析器那一行，
开关改动和两条 RETURN 原样交给新会话（`successor`），新会话用 `declare` 声明；guard 的核对在同一拍里查
`dns`；agent 重启接管时把两条 RETURN 接进 `dns`；断开时才全部撤掉。

为什么这样做：之前的版本把 RETURN 记在 `network.json`，交接时连同开关改动一起释放、几秒后随新租约再设。
2026-11-12 实测同一上游重连时，这几秒里正好有一次 fw3 重载（agent 自己的 IPv6 设置引起），厂商的 DNAT 写进去
并一直留到下一次重载（5 分钟以上）；agent 的 RETURN 缺了 6.3 秒，其中 3.1 秒 DNAT 在位
（`measurements/exp1-step1-ipv6-off.log`）。

现在的实测（2026-11-12，`measurements/b2-portal/handover-sampler.log`）：同一上游两次交接重连（IPv6 先关后开），
每次后面都有防火墙重载；开关始终读 0，`redirect_chain` 里从没出现厂商规则，dnsmasq 的两个主进程没有变；
每次清空后链里约 4 秒是空的，然后 RETURN 回到第一条。之后 `network.json` 不再提 `redirect_chain`，`dns.json`
里有两条撤销。RETURN 和“排在所有厂商规则之前”的维护仍保留：开关一旦读到 1，厂商的 DNAT 就会出现。

实测到的 ZTE 改写（2026-11-08）：中继每次连上之后，ZTE 都会把
`bridge-nf-call-ip(6)tables` 改回 1，并清空 nat 表的 `redirect_chain`（中继放在里面的
RETURN 会跟着消失）；`fw3 reload` 也会把 brnf 改回 1。三者都被自动恢复了。手工删掉
IPv6 的 `U60_R6_NAT`/`U60_R6_FWD` 跳转后 4 秒补回（当时的版本；v5 起 NAT66 在 nft 表里，
新的恢复时间待设备复测）。门户 RETURN 现在还要排在 `redirect_chain` 里所有厂商规则之前：
排在后面时用一个 restore 事务删掉再插到第一条，期间不会缺失。
（2026-11-12 注：这里的“中继连上之后”就是上面 IPv6 `set_data` 引起的那次 fw3 重载。）

### 6. RPS 和 backlog（辅助）

中继连接时，`ath20` 和 `wlan2` 所有接收队列的 `rps_cpus` 设为"没有处理过 Wi-Fi
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

### 8. 上游其他设备抢走硬件上行（IPACM STA 模式缺陷，2026-11-09）

现象：中继连着一段时间后，Mac 连 G 打不开国内直连的 IPv4 网站，直连 W_Game 正常。例如
`signin.volcengine.com` 的登录页每次停在 16–42 KB（共 118 KB），清华镜像 0 字节。小页面（baidu）
能打开；走 Mihomo 的 IPv6 和国外连接正常；路由器本机下载正常；手动 `ipacm_switch.sh off`
后立刻正常，agent 切回 HW 后又坏。

原因：IPACM 在 STA 模式下，把 `ath20` 上每个带 MAC 的 IPv4 邻居都登记成 wan client。
上游另一台设备 ARP 过 U60 一次就够了。IPACM 为它建一个 `32_IEEE802_3_STA_v4_<n>` 头，
并在 `WANRTBLv4` 最前面插一条按源地址匹配的规则：`src = 中继地址 → 这台设备的 MAC`。
NAT 之后的上行包都命中这条规则，所以连接被 IPA 接管后，客户端的 ACK 被发给了那台设备，
服务器收不到确认就停发，下行本身是通的。每条连接开头的包还走内核，所以握手和前几十 KB
正常。邻居条目删除、SW→HW 切换、删掉再加回 main 默认路由，都不会动这条规则。

修复（`wifi_relay/offload/neighbours.rs`）：实测发现，已登记设备的 MAC 以另一个 IPv4 地址
出现时，IPACM 会删掉它的规则，并且不再重建。中继会话在 main 路由加好之后，
起一个线程运行 `ip -4 monitor neigh dev ath20`，启动时先读一遍 `ip -4 neigh show dev ath20`。
每个不是网关的 MAC，每个会话处理一次：

```text
ip -4 neigh replace 192.0.2.1 lladdr <MAC> nud reachable dev ath20   # IPACM 删掉它的规则
ip -4 neigh del 192.0.2.1 dev ath20
ip -4 neigh replace <原地址> lladdr <MAC> nud stale dev ath20
ip -4 neigh replace <原地址> lladdr <MAC> nud reachable dev ath20
```

- `192.0.2.1` 是 RFC 5737 的文档地址：不会是上游的真实设备，也不在链路上，内核不会经这条
  临时条目发包。它也不是链路本地地址（IPACM 忽略 169.254/16）。
- 后两步把设备放回原地址，IPACM 仍把它当上游主机（发往它的连接不卸载），实测不会重建规则。
  条目已经是 REACHABLE 时，内核不会发事件，所以先设成 stale。
- 网关的 MAC 从不处理，它以别的地址出现时也一样（那样会让 IPACM 删掉网关自己的规则）。
  还不知道网关 MAC 时，先把设备记下，等网关条目出现再处理。
- 日志：`[relay] upstream host <地址> (MAC ..:<末两段>) retired from IPACM's uplink rules`。
- `cleanup` 第一步就停止监听。`ip` 运行在 SELinux 域 `ip.subj`，exec 时父进程死亡信号会被
  清掉，所以 agent 被杀时监听进程可能留下：它在下一次写管道时因 SIGPIPE 退出，下一个
  agent 的 `stop_strays` 也会停掉它。

调试：IPA 的表用 debugfs 读，但驱动把内容打印进内核日志，不写进文件。执行
`cat /sys/kernel/debug/ipa/hdr`（头，含 MAC）或 `ip4_rt`（`WANRTBLv4` 的规则、优先级和头偏移）
后看 `dmesg`。

限制：

- 只处理 agent 运行期间出现的设备。agent 不在时（例如重启的那几秒）建立的规则，在 agent
  重启后会残留：IPACM 不再追踪它，换地址删不掉，显式断开中继也删不掉，只有重启路由器能清掉。
  每个新会话里，网关的规则都会重新插到最前面，所以残留规则平时不生效；只有同一会话里网关的
  MAC 以别的地址出现、IPACM 删掉网关规则时，它才会重新起作用。
- agent 重启不会清空 IPACM 的 wan client；显式断开会清空它还在追踪的部分。连接仍有效时新
  agent 接管它（`ath20` 不重建，只换监听进程）；接管不成立时才断开重连。
- IPA 头表空间有限。登记的上游设备多了以后，新设备拿不到自己的头，IPACM 给它的规则挂上
  别的设备的头；按 MAC 修复同样能删掉这条规则。
- 不处理 IPv6：IPv6 走 NAT66 或 Mihomo，不经过 IPA。

验证（2026-11-09，Mac 连 G，上游 W_Game 52/160）：

- 修复前：上游设备 `e6:3e:…` 的规则排在网关前面，火山引擎登录页每次都停住。用假邻居
  （`ip neigh replace 192.168.2.250 lladdr 02:00:5e:00:00:99 nud reachable dev u60sta0`）
  每次都能复现；手动按上面的步骤处理后恢复，连接仍走硬件（31.7 MB 传输期间 conntrack
  一直停在 19 个下行包）。
- 部署后：注入假邻居（stale 和 reachable 两种状态），第一次读规则（约 100 ms）时已经修好；
  先暂停监听进程再注入，故障出现（火山引擎 31 KB / 0 字节），恢复后 1 秒内自动修好，
  火山引擎 3/3（0.25–0.27 秒）。显式断开后监听进程消失，重连后重新启动；agent 重启后，
  旧的监听进程被 `stop_strays` 停掉。

### 9. 热点客户端换频段后 IPACM 丢了它的 LAN 路由（2026-11-09）

现象：部署或 agent 重启后，热点客户端在 IPA 的 `COMRTBLLANv4` 里没有路由，连接一直走 CPU
（`U60_RELAY_FWD` 的 TCP 回程计数几万）。只有 deauthenticate 一次才恢复。和 Mihomo、硬件转发开关无关，
是 IPACM 自身的问题。

原因（已复现，侧边会话 11-09 23:09–23:12）：

1. 客户端离开某个热点接口时，网桥会删掉它的 FDB 条目（`bridge monitor fdb`：`Deleted <MAC> dev wlan2
   master br-lan`）。IPACM 收到这个 RTM_DELNEIGH 后，把邻居缓存里这台设备的记录整条清掉
   （`IPACM_Neighbor.cpp … Clean N-st Cached client-MAC`，然后 `update_client_info(): Cleared client mac …`）。
2. 客户端重新关联时（WLAN_CLIENT_CONNECT_EX → IPA_WLAN_CLIENT_ADD_EVENT_EX），IPACM 重建记录，但 IPv4 是
   0.0.0.0。它只会补发缓存里已有的 IPv4，是 0 就什么也不发。客户端的 IPv4 路由只能等之后 br-lan 上来一个
   IPv4 RTM_NEWNEIGH 才装得上（`Got Neighbor event with ipv4 address` → `handle_wlan_client_route_rule`）。
3. 一直在传数据的客户端，ARP 条目一直保持 REACHABLE，状态不变，内核就不发事件，路由一直装不上。
   空闲的客户端条目会过期变成 STALE，触发事件，所以能自己恢复。

部署时这几步会自然发生：中继恢复时 5 GHz 热点可能先经 CSA 切到暂存信道，客户端掉到 2.4G 的 `wlan0`，
之后再回 `wlan2`，每次换频段都会删 FDB、清缓存。这次复现里，最后一次回到 `wlan2` 后记录里的 IPv4 一直是 0。
是否换频段要看客户端：跟着 CSA 切信道的客户端不会重新关联（后来三次重启都没有出现）。

修复（`wifi_relay/offload/clients.rs`）：不断开客户端，把它的 ARP 条目设成 STALE 一次：

```text
ip -4 neigh change <IP> dev br-lan lladdr <MAC> nud stale
```

内核会报告这次变化，IPACM 收到 IPv4 邻居事件后补上路由（`found client … Adding client mac … ip4 0xC0A8007C,
iface wlan2` 和 `rt rule hdl=…`）；内核那边只是把条目从 STALE 走到 DELAY/PROBE 再确认一次。IPACM 已经登记过、
IP 也相同的客户端，这个事件会被直接跳过，没有副作用。

- 触发：`iw event -t` 里热点接口（`wlan*`）的 `new station`。等 5 秒，让 IPACM 先按驱动事件登记客户端，
  客户端也先做完 DHCP 和 ARP，再处理这个 MAC 在 `br-lan` 上的 IPv4 条目：只有 REACHABLE 才设成 STALE；
  STALE、DELAY、PROBE 时内核会自己发下一个事件，不用管；没有条目时不建（`change` 不会新建条目）。
- 监听启动时（中继会话里 main 路由加好之后）把 `br-lan` 上所有 REACHABLE 的客户端都处理一遍，
  因为中继连接的过程中它们可能已经换过频段。监听进程退出会重启。
- 生命周期和第 8 节的上游邻居监听相同：只在硬件转发路径生效时运行，关掉硬件转发或中继
  cleanup 时停止。两者共用 `offload/monitor.rs`。只处理 IPv4，没有轮询。
- `iw` 在 SELinux 域 `iw.subj` 里运行，exec 时父进程死亡信号会被清掉。agent 被杀时这个监听进程可能留下：
  它在下一次写管道时退出，下一个 agent 的 `stop_strays` 也会停掉它：只停记录里的那个进程
  （`/tmp/zte-agent-relay/relay-*.pid` 记 PID、`/proc/<pid>/stat` 的启动时间和 boot id，
  发信号前再核对一次），人工运行的同名 `iw event -t`、复用了这个 PID 的进程和别的开机记下的 PID 都不碰。
- 日志：`[relay] LAN client <IP> (MAC ..:<末两段>) announced to IPACM again`。
- 不做的事：deauthenticate、重启 ipacm、删邻居条目（删条目试过，没用）。

验证（B31，Mac 连 G 持续下载约 250 Mbit/s）：

- 侧边会话在卡住状态下手动执行上面的命令：Mac 没有断线，3 秒内 `.124` 出现在 `COMRTBLLANv4`，
  之后 10 秒内走 CPU 的 TCP 回程包是 0。
- 部署后：监听启动时 `.124` 和 `.89` 都被处理了一遍；手机自己 `wlan2 → wlan0 → wlan2` 后，5 秒内又处理一次。
  三次重启（两次 `setup.sh`、一次 SIGTERM 后执行启动脚本）期间，两台设备的路由一直都在，回程内核包每 10 秒
  0–99 个。不过 Mac 这三次都没有换频段，所以卡住的场景没有自然复现。
- 触发路径：Mac 下载时 deauthenticate 一次，重新关联后 agent 把 `.124` 设成 STALE，IPACM 日志出现
  `Got Neighbor event with ipv4 address: 0xc0a8007c`、`found client`、`Adding client mac … ip4 0xC0A8007C`，
  路由在，回程内核包 16 个/10 秒。
- 下载中手动设 STALE：每 0.5 秒采样的接收速率没有下降（设之后 277、349、264 Mbit/s），条目变成 DELAY 后再确认。
- 正常停止 agent 时，它的 `iw event` 随之退出。

调试：

- IPACM 日志：`/data/data_ipa/log_file.txt`，2 MB 循环写，没有时间戳，大约保留 5 分钟。`kill -46 <ipacm pid>`
  打开详细日志、`kill -47` 关闭（即 ZTE 的 `ipacm_switch.sh logon/logoff`），不需要重启 ipacm。`kill -43`/`-44`
  是 ZTE 的 Wi-Fi 调试开关，会在 `/tmp` 生成 `ipacm_wifi_debug_*` 文件，用完关掉并删除。IPACM 能捕获这些信号，
  不会被杀掉。
- 路由表：`echo <marker> > /dev/kmsg`，再 `cat /sys/kernel/debug/ipa/ip4_rt`，然后从 `dmesg` 里取 marker 之后的内容，
  看 `COMRTBLLANv4` 下的 `dst_addr`。不要用 `dmesg -c`。

## 不受影响或需要注意的地方

- **被卸载的连接**会绕过 iptables（`U60_RELAY_FWD`、ZTE 的 FORWARD 链）、tc
  （智能 QoS、限速）和 ZTE 家长控制。每条连接的头几个包仍然走内核，所以 NAT、
  `U60_RELAY_FWD`，以及 IPACM 靠 conntrack 学到的 NAT 都必须保留。走 CPU 的中继
  流量也在 ZTE 的家长控制、网址过滤之前被 `U60_RELAY_FWD` 放行，所以这两项对经中继
  的设备都不生效；中继页连着时直接说明这一点（D8，v6）。
- **按终端的流量统计**（`client_details.rs` 读 `iw station dump`）计的是空口字节数，
  理论上不受影响，但还没有验证。
- **继续保留的兼容项**：5G 非 DFS 20 MHz 暂存、`disableDfsCS`、2.4G 的
  disable/set/enable、portal、DNS、udhcpc 续租、resume 和残留进程清理、NAT66、
  60631 策略路由（带宽自动调优及 llstats 采样在 v6 删除，关联后的一次宽度复位在 2026-11-12 删除）。
- **不再需要做**：精简 iptables 链。卸载以后收益很小。
- **brnf**：Mihomo 运行时 `bridge-nf-call-ip(6)tables=0`（TPROXY 在 bridge-netfilter
  路径上拿不到套接字），停止时恢复原值。期间 br-lan 内部的二层流量不再经过 iptables，
  访客热点隔离之类按 LAN 内部过滤的规则会失效（用户已接受）。中继本身不需要改 brnf。

## 已验证 / 未验证

已验证：上表中的 SW/HW 对比；整机冷启动后 agent 能自动恢复中继（两次，约 55–75 秒）；
IPv4 UDP（QUIC）会被卸载、IPv6/NAT66 不会（2026-11-09，见末节）。
2.4 GHz 上游的硬件转发（2026-11-12，一次，开发机经 USB，见“最终版回归”）。部署后的复测结果见末尾一节。

未验证：

- 蜂窝在线时 main 表的实际表现，以及 IPACM 在两个 WAN 同时存在时选哪一个；
- HW 模式对蜂窝路径的影响；
- 长时间运行的稳定性；
- Wi-Fi 客户端（不是经 USB 的开发机）在 2.4 GHz 上游下的速度；
- RPS 加 HW 的组合效果。

## 部署后复测（2026-11-08，agent 本次实现）

> 2026-11-12 注：这一节和后面各节（两个 2026-11-12 回归除外）是当时版本的记录：站点叫 `u60sta0`，IPACM 配置要安装、
> 装后重启，状态有 `loaded`。那时 agent 自己切 HW、每 15 秒审计并按 TCP 回程计数重新挂载
> （kick），状态里有 `hardware`/`offload_confirmed`，`U60_RELAY_FWD` 的回程放行分 TCP 和其余两条；这些都已删除
> （回程现在只有一条），现在的行为见第 1a、3 节。测得的数字仍然有效。

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
  CPU2/3 上（最忙一核 62–76%）。按单流时最忙一核 70–75% 推算，线路更快时，NAT66 单流大约在
  300 Mbit/s 见顶（推算，没有实测）。
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
