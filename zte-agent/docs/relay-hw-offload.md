# Wi-Fi 中继的 IPA 硬件转发（owner decision 63）

2026-11-08。中继的 IPv4 NAT 转发主要交给高通 IPA 硬件（IPACM + WDI3）完成；
CPU 转发路径保留，作为兜底，并加上 RPS/backlog 作辅助。代码：
`wifi_relay/offload.rs`（配置、HW 模式、main 路由、硬件自检）、
`wifi_relay/offload/neighbours.rs`（删掉 IPACM 给上游其他设备的上行规则，第 8 节）、
`wifi_relay/offload/clients.rs`（热点客户端换频段后补回 IPACM 的 LAN 路由，第 9 节）、`wifi_relay/steering.rs`
（RPS/backlog）、`mihomo/routing.rs` 和 `mihomo/geoip.rs`（按 Mihomo 的模式和规则在内核绕过，
第 4 节）、`net_guard.rs`（统一对齐 ZTE 的改动），以及 `wifi_relay/hotspot.rs` 的同主信道 CSA 修复。
运行时开关和即时生效的安装/移除见第 3 节末（owner decision 64）。

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

另外，流量不能被 Mihomo 的 nft 表 TPROXY 进核心（见第 4 节）：核心终结的连接
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
  手工加的条目比 ipacm 进程早，或者本次开机 IPACM 已经加载过它）/ `overwritten` / `unavailable`。
  每次判定为 `loaded` 时，把 boot id 记到 `/tmp/zte-agent-relay/ipacm-loaded`：IPACM 把接口表
  留在内存里直到重启，所以同一次开机里移除后再安装，状态直接是 `loaded`，立即生效。
  QCMAP 恢复出厂时会用 `factory_IPACM_cfg.xml` 覆盖这个文件，这时状态显示
  `overwritten`，提示重新安装。QCMAP 运行时也会改写这个文件（当前文件比出厂文件
  大），所以卸载时只删掉我们那一块，不整份恢复旧文件。
- 卸载：删掉条目和 `installed` 记录，**保留 `.orig` 备份**。当前的中继连接立刻改走 CPU
  （见第 3 节末），下次重启后 IPACM 也会忘掉这个接口。OTA 切换 A/B 槽位后，overlay 的上层目录不同，
  需要重新安装。
- 手工备份：原厂文件 `IPACM_cfg.xml.orig`（`a0f361c5…`）、安装后的 `IPACM_cfg.xml`
  （`4b90dd39…`）和 `restore-stock.sh` 现在只在开发机上，放在仓库旁边的 `../backups/ipacm/`。
  设备上的 `/data/zte-agent-backup/ipacm/` 已于 2026-11-11 按车主要求删除；agent 状态目录里的
  `/data/zte-agent-relay/ipacm/IPACM_cfg.xml.orig` 与原厂文件相同。agent 不在时，把这个目录推到
  设备上运行脚本恢复原厂文件，然后重启整机。不要只重启 ipacm。
- **写入方式（H5，v1 记录风险，v4 修复）**：原先是 `O_TRUNC` 就地改写，截断与写完之间 agent
  被杀或掉电会留下半份或空的唯一生效配置。现在（`offload::rewrite`）先在同一文件系统写完整副本
  （父目录 `/etc/data` 与 `/etc/data/ipa` 同属一个文件系统时放在父目录，IPACM 监视的目录只看到一次
  rename；否则放在同目录），把原文件的属主、权限和 SELinux 标签（`security.selinux`）复制过去，fsync
  后核对内容和这三项，再 `rename` 覆盖并 fsync 目录。崩溃时只会留下完整的旧文件或完整的新文件
  （外加一个可删的副本）；任何一步失败都删掉副本、原文件不动。中断写入的故障试验已在本机副本上做过
  （目录不可写时原文件完整、副本删除）；设备上的属主、权限、标签和下次开机加载待维护窗口核对。

### 1a. 状态机、固件指纹和车主限制（v4，`offload::Runtime`）

每个中继会话的硬件路径是一个显式状态（状态接口 `offload.state`），设备读写都经 `IpacmPort`
（测试用假实现跑完整的转换和失败矩阵）：

| 状态 | 进入与离开 |
| --- | --- |
| `off` | 没有请求或没有会话；配置未加载、开关关、会话结束都回到这里。 |
| `engaging` | 先切 HW（记下原模式，日志里有撤销），再加 main 路由和 unreachable 守卫，然后 SW→HW 重新挂载、启动邻居和客户端监视器。任何一步失败都撤掉这次取得的部分（路由和模式），进 `software` 并写明原因，不会留下"软件"快照掩盖实际接管。 |
| `hardware` | 每 15 s 审计：ZTE 改回 SW 就再切 HW（模式归本会话，不再记新日志）；车主限制（`ipa_disable`、省电模式、限速）出现就释放进 `software`；回程计数在有负载时 ≥1,500 包/s 就重新挂载，每会话最多 3 次。有负载且回程只有少量包才显示"已确认卸载"（`offload_confirmed`），空闲不算。 |
| `software` | 车主限制、固件不符、路由或模式失败。限制解除且开关仍开时，审计会重新 `engaging`（重启以后不用重连中继）。 |
| `releasing` | 先删 main 路由（IPACM 的中继 WAN 下线），再恢复本次接管的模式。撤销失败就停在这里（不报 `off`），剩余撤销项保留，下次再试。释放后有负载时用回程计数确认回到 CPU（`cpu_path: confirmed`），否则 `unverified`。 |

**固件指纹**：邻居退役（第 8 节）、客户端 STALE（第 9 节）和 SW→HW 重新挂载都是对 B31 IPACM 行为的修补，
只在 `zwrt_common_info.common_config.wa_inner_version` 为 `BD_CNMU5250V1.0.0B31` 且 `/usr/bin/ipacm` 的
SHA-256 为 `95385816…5c11c0`（4,129,835 字节，2026-11-10 只读查询）时启用；不符时不进入硬件路径，页面写明原因，
中继走 CPU。

只有路径真的变了（开、关、移除、限制出现或解除）才重置 LAN IPv4 连接。页面区分"HW 模式但未确认""有负载下确认卸载"
和"公网 IPv4 由 Mihomo 处理"（Mihomo 拦截的公网 IPv4 无论 IPA 状态都走 CPU；规则绕过开着时只有 DIRECT 部分例外）。

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
它的计数；UDP 不参与自检，虽然 11-09 实测 IPv4 QUIC 也会被卸载，见末节）：中继重连后，偶尔会出现模式显示 HW、但所有连接仍在 CPU 上
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

**运行时开关（owner decision 64）**：中继页"Hardware forwarding"标题旁的开关，接口是
`POST /api/wifi-relay/offload` 加 `{"enabled":true|false}`，关掉时存成
`/data/zte-agent-relay/ipacm/off`（重启和重连后仍然有效），状态里是 `offload.enabled`。
关掉、移除配置时，当前连接立刻改走 CPU；打开、或者同一次开机里重新安装时，立刻恢复硬件转发。
不需要重启路由器，也不重连中继：

- 关（`Runtime::release`）：停止邻居监听，然后用 `Transaction::release` 只撤掉这部分步骤，
  按添加的反序：先删 main 默认路由和 unreachable 守卫（IPACM 失去中继 WAN），再恢复本次会话
  切换前的 IPACM 模式（原来是 SW 就切回 SW）。其余中继步骤和日志都保留。
- 开（`Runtime::sync`）：和连接时一样，先切 HW、加 main 路由，再 SW→HW 重新挂载、启动邻居监听。
- 路径变了之后执行 `conntrack -D -f ipv4 -s <LAN 网段>`，让已建立和已卸载的连接按新路径重建，
  所以每次切换都会重置一次现有的 LAN IPv4 连接。页面按实际结果提示（删了几条、没有可删的、
  已被同一次变化之后开始的删除覆盖，或失败待重试），不再一律说“已重置”；见下面的 conntrack 重置。
- 关掉时页面的原因是 "Hardware forwarding is turned off"。
- 移除时先撤掉硬件路径、等 1 秒，再改写 `IPACM_cfg.xml`。IPACM 监视这个文件，文件一变就重读配置；
  重读之后它不再理会中继 WAN 的下线：11-09 实测先改文件、再删 main 路由，WAN 规则和 PDN 都还在，
  新连接照样被卸载（回程内核包 221–416）。只关开关（不改文件）则立即回到 CPU（约 20 万）。

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
刷新期间只把这个规则集当作未知。每 60 秒控制器还会读一次核心的模式和选择，有差异按同样顺序跟随。
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
（`routing::lost`，D10）：新旧两张链直到最后一个放行点都只按目的地址判断时，用"旧放行减新放行"按首个
命中计算（例如在原 DIRECT 段前加了代理规则，被它截走的那半段）；任一张链含端口、来源或协议条件
（例如前面加了 `DST-PORT,443,代理`，原 DIRECT 段里的 443 硬件流也必须退出）时，旧链不纯就重置整个
LAN IPv4，新链不纯就重置旧链放行的全部范围；超过 64 段也重置整个 LAN IPv4；没有失去放行的就什么都不删
（反方向切到 DIRECT，核心里的连接靠 `socket transparent` 规则继续走核心）。首次启动重置 LAN IPv4，
从 D3 恢复后 IPv4 和 IPv6 都重置。`proxy_plan` 里没有任何 `-F` 或 `flush`（测试会检查）。

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
  触发后安静 2 秒再查（到点直接唤醒中继和 Mihomo，不等它们下一个 tick）；某次检查真的补回了
  东西，5 秒后再查一次；没有触发时每 60 秒兜底一次。没有任何 owner 时什么都不跑。
  每次触发后的 3 秒内，每 0.5 秒只读一遍 owner 持有的 `@u60-sysctl`（如 Mihomo 的 brnf=0），
  被改了才写回，而且写之前在同一把锁里确认它仍被同一 owner、同一代次持有；owner 释放时先注销
  再执行撤销，所以释放后的迟到采样不会把运行值写回去（`net_guard::hold/release`）。agent
  自己运行 `ipacm_switch.sh` 期间（及之后 1 秒）对它的打开只算一次触发，其他脚本和 ubus
  照常算。
- 每次恢复都会记日志，写明重做了哪些命令：
  `[guard] relay: restored after another writer removed them: ...`。某一条查不了或重做失败时，
  其余的照常处理；失败写进日志（同样的失败只记一次）并显示在页面上。
- agent 的 nft 表（Mihomo 的 `u60_mihomo`、中继的 `u60_relay`）都由 `netfx::effect::NftTables`
  维护：两族放进同一个 `nft -f` 批处理整表替换，并带代次标记；用 `nft -t list table`
  （不列出集合元素）读回标记确认，逐条链比对规则数，被清空、删掉一部分或丢了标记的表会按
  目标重新载入。中继的表在 `wifi_relay/uplink.rs` 一处拼装（v5，见 `network-extensions.md`
  的 Firewall layout）：上游防护、转发、IPv6 基线、NAT66 和中继 DNS 的拒绝/改写都在 nft；
  legacy 只留必须穿过 ZTE 拒绝的放行（`U60_RELAY_IN`、`U60_RELAY_FWD`、`U60_R6_IN`、
  `U60_R6_FWD`）、门户 RETURN 和 IPv4 MASQUERADE。
- IPA 模式不在这里：它有自己的 15 秒检查（要考虑用户限制，见第 3 节）。

实测到的 ZTE 改写（2026-11-08）：中继每次连上之后，ZTE 都会把
`bridge-nf-call-ip(6)tables` 改回 1，并清空 nat 表的 `redirect_chain`（中继放在里面的
RETURN 会跟着消失）；`fw3 reload` 也会把 brnf 改回 1。三者都被自动恢复了。手工删掉
IPv6 的 `U60_R6_NAT`/`U60_R6_FWD` 跳转后 4 秒补回（当时的版本；v5 起 NAT66 在 nft 表里，
新的恢复时间待设备复测）。门户 RETURN 现在还要排在 `redirect_chain` 里所有厂商规则之前：
排在后面时用一个 restore 事务删掉再插到第一条，期间不会缺失。

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

### 8. 上游其他设备抢走硬件上行（IPACM STA 模式缺陷，2026-11-09）

现象：中继连着一段时间后，Mac 连 G 打不开国内直连的 IPv4 网站，直连 W_Game 正常。例如
`signin.volcengine.com` 的登录页每次停在 16–42 KB（共 118 KB），清华镜像 0 字节。小页面（baidu）
能打开；走 Mihomo 的 IPv6 和国外连接正常；路由器本机下载正常；手动 `ipacm_switch.sh off`
后立刻正常，agent 切回 HW 后又坏。

原因：IPACM 在 STA 模式下，把 `u60sta0` 上每个带 MAC 的 IPv4 邻居都登记成 wan client。
上游另一台设备 ARP 过 U60 一次就够了。IPACM 为它建一个 `32_IEEE802_3_STA_v4_<n>` 头，
并在 `WANRTBLv4` 最前面插一条按源地址匹配的规则：`src = 中继地址 → 这台设备的 MAC`。
NAT 之后的上行包都命中这条规则，所以连接被 IPA 接管后，客户端的 ACK 被发给了那台设备，
服务器收不到确认就停发，下行本身是通的。每条连接开头的包还走内核，所以握手和前几十 KB
正常。邻居条目删除、SW→HW 切换、删掉再加回 main 默认路由，都不会动这条规则。

修复（`wifi_relay/offload/neighbours.rs`）：实测发现，已登记设备的 MAC 以另一个 IPv4 地址
出现时，IPACM 会删掉它的规则，并且不再重建。中继会话在 main 路由加好、`kick` 之后，
起一个线程运行 `ip -4 monitor neigh dev u60sta0`，启动时先读一遍 `ip -4 neigh show dev u60sta0`。
每个不是网关的 MAC，每个会话处理一次：

```text
ip -4 neigh replace 192.0.2.1 lladdr <MAC> nud reachable dev u60sta0   # IPACM 删掉它的规则
ip -4 neigh del 192.0.2.1 dev u60sta0
ip -4 neigh replace <原地址> lladdr <MAC> nud stale dev u60sta0
ip -4 neigh replace <原地址> lladdr <MAC> nud reachable dev u60sta0
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
  agent 接管它（`u60sta0` 不重建，IPACM 不重新挂载，只换监听进程）；接管不成立时才断开重连。
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
- 监听启动时（中继会话里 main 路由加好、kick 之后）把 `br-lan` 上所有 REACHABLE 的客户端都处理一遍，
  因为中继连接的过程中它们可能已经换过频段。监听进程退出会重启。
- 生命周期和第 8 节的上游邻居监听相同：只在硬件转发路径生效时运行，关掉硬件转发、移除配置或中继
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
  60631 策略路由、关联后的一次宽度复位（带宽自动调优及 llstats 采样在 v6 删除）。
- **不再需要做**：精简 iptables 链。卸载以后收益很小。
- **brnf**：Mihomo 运行时 `bridge-nf-call-ip(6)tables=0`（TPROXY 在 bridge-netfilter
  路径上拿不到套接字），停止时恢复原值。期间 br-lan 内部的二层流量不再经过 iptables，
  访客热点隔离之类按 LAN 内部过滤的规则会失效（用户已接受）。中继本身不需要改 brnf。

## 已验证 / 未验证

已验证：上表中的 SW/HW 对比；整机冷启动后 agent 能自动恢复中继（两次，约 55–75 秒）；
IPv4 UDP（QUIC）会被卸载、IPv6/NAT66 不会（2026-11-09，见末节）。
部署后的复测结果见末尾一节。

未验证：

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
