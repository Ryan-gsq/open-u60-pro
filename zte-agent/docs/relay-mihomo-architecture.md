# Wi-Fi 中继与 Mihomo：架构规范

定稿：2026-11-10。本文规定目标行为；[版本与验收](relay-mihomo-refactor-plan.md)是 v1–v6 唯一的交付顺序。[产品说明](mihomo-relay-prd.md)描述已发布行为；[设备约束](../../CLAUDE.md)适用于全部版本。车主已确定自动恢复、provider 自主刷新零误直连和旧真实地址保护；[验收条件](relay-mihomo-refactor-plan.md#owner-decisions)同样适用于 v2/v3。

## 1. 不变式

| 编号 | 实现与验收共同遵守的约束 |
| --- | --- |
| I1 | 中继和 Mihomo 的 nft、iptables-legacy、地址、路由、策略规则、sysctl、conntrack 写入只经 `netfx`；一项资源只有一个 owner。IPACM 由 `wifi_relay::offload` 写；核心进程、托管配置及影响路由的核心 API 写操作由 Mihomo 控制器排序。ZTE 是外部写入者；WireGuard 和 TTL 的 legacy 链不在本次迁移范围。 |
| I2 | 不持跨功能锁做设备 I/O。HTTP 读状态只取快照；在单线程 Tokio 上不得阻塞等待控制器、运行命令或调用阻塞 HTTP。中继的关联、CAC、撤销或核对不能挡住 Mihomo 的退出处理、重试或 brnf 修复。 |
| I3 | 对可撤销的自有效果，先持久记录本次开机的撤销依据，再生效；只能撤自己的东西。部分执行、执行前被杀、重复撤销都可恢复。conntrack 删除不可逆，按已生效的策略代次记录结果，不伪造 undo。 |
| I4 | 控制器主导的计划内重启、重载和规则切换，必须先收紧受影响的内核绕过，核心不可接包时阻断本应拦截的流量，核验后才扩大 DIRECT。provider 自主刷新也不允许误直连；用旧 DNS 真实 A 新建的连接必须遵守新策略，无法证明可直连的流量不得绕过。agent 仍在且确认核心意外退出，或计划内重启最终失败时，按 D3 撤常规拦截、显示正在直连并重试。单次 nft 写失败、PUT 超时或读回失败本身不授权直连。 |
| I5 | 在有 nft 支持的本机网络层，拒绝放在 agent 的 nft 表；穿过厂商 DROP/reject 的放行和门户 RETURN 留 legacy。nft 里的 return/accept 都不能替代 legacy 的放行。NAT 是地址转换，迁移有单独门槛。 |
| I6 | 决策输入包括意图、有效观测、先前状态和单调时间，输出为动作；设备读写在适配器。可用假时钟和假设备重放退出、重试、切换和撤销。 |
| I7 | 持久意图、实际观测、希望应用的计划与最近确认生效的计划分开。状态页不能因配置已保存、命令已发出或核心进程在运行就显示“已生效”。 |

## 2. 产品与设备边界

- 管理端拒绝来自 `rmnet*` 或中继上游 `u60sta*` 的对端（D1），沿用现有接口分类、本机/Tailnet 例外和失败策略。它只保护 agent 的 9090/9443，不能代替对所有设备监听端口的上游 INPUT 防护。
- 保留双栈，不做“IPv4 优先”（D4、M14）。透明代理处理从 `br-lan` 进入的 TCP/UDP；本机、私网等例外仍走原路径，不代理路由器的一般 OUTPUT。外网 IPv6 始终进核心，没有 IPv6 fake-ip 池。只有符合 DIRECT 的 IPv4 可绕过核心并有机会被 IPA 卸载。默认不开绕过。
- TPROXY 工作时必须将 `bridge-nf-call-iptables` 和 `bridge-nf-call-ip6tables` 设为 0；车主接受在此期间依赖 brnf 的访客隔离失效。固件会重写 legacy、路由与 sysctl；B31 没有 `NFT_FIB_INET` 和 nft bridge family。使用分开的 `ip` / `ip6` 表，链名避开 `fwd`、`post`、`c`。
- 中继 CPU 转发抢在 ZTE 的部分 FORWARD 过滤之前；IPA 卸载的流也不走这条 CPU 路径。开启相关家长控制或网址过滤时页面提示实际影响（D8）。不主动开启蜂窝、不重启 ipacm、不踢客户端。蜂窝协调不在本次范围。

## 3. 控制器、消息与状态

中继与 Mihomo 各用一个串行控制器线程，取代原来跨功能持有的全局网络操作锁。两个控制器之间只有一类运行时业务通知：中继出口的观测变了；中继不等待 Mihomo 重启。核心退出、HTTP 命令和重试定时器各自进入所属控制器，不属于两个控制器之间的消息。

| 执行者 | 责任 |
| --- | --- |
| `relay` | 串行处理扫描、连接、更换上游、断开、开机恢复和每 3 s 的活动会话检查；在本线程做无线/租约操作和 IPA 15 s 审计。关联约 60 s、恢复热点含 CAC 最长 80 s，均不占用跨功能的锁。 |
| `mihomo` | 串行处理车主命令、影响路由的桥接写、出口变化、子进程退出、重试和规则跟随。安装、订阅下载和可能很慢的校验由后台任务执行，返回带配置/意图代次的结果。 |
| `mihomo-core-wait` | 每个子进程只有一个回收者。停止路径给已确认属于该代的进程发信号；等待者负责 wait/reap，回送 `CoreExited { generation, status }`。控制器忽略旧代退出、已取消的定时器及迟到的后台结果。 |
| `net-guard` | 订阅 inotify/ubus、合并触发并调度各 set 核对。遇忙跳过并单独补查，不能因一个 set 等待其他 owner。`relay-neigh` / `relay-lan` 归当前 IPA 会话，退出后不能再操作下一次会话。 |
| HTTP、页面、Zashboard | 读取不可变快照；车主命令交给相应控制器。重启或热重载期间，普通控制命令排队，桥接写回 503。已放行的在途写必须与切换排序，不能凭请求开始时读到的 Running 快照跨代写入。保留桥接的现有认证、同源和端点限制。 |

中继的 `resume.json`、已保存网络、IPv6/省电和 IPA 开关表达车主意图。Mihomo 的 `enabled`、`cn-direct`、`profiles.json` 表达启用、绕过和配置选择。托管配置开启 `profile.store-selected` 和 `profile.store-fake-ip`；`selected.json` 只为启动前生成配置提供初值，第一张带 DIRECT 放行的运行表必须依据**本代就绪后**实际读到的模式和选组。页面读取快照不写 `ipacm-loaded`，也不更改恢复意图。

中继发布带代次的出口快照（v4/v6 的有效性、接口、网关/出口身份、租约 DNS；无 DNS 时用租约网关）。Mihomo 自行判定哪些变化需要重启；下载器可单独读取最新 DNS。核心关着或正在安装时不为出口消息报错或重启，但 DNS 变化和断开时清除旧解析器仍要传达。

## 4. 网络效果层 `netfx`

I1 的写入边界须有随 `cargo test` 运行的源码扫描测试：中继与 Mihomo 不能绕过 `netfx` 写 legacy、nft、地址、路由、策略规则、sysctl 或 conntrack。只读检查（如读取回程计数）不是写入；WireGuard 和 TTL 的既有 legacy 写入按 §4.7 列入白名单。

### 4.1 声明、撤销与资源归属

一个 `EffectSet` 对应一个 owner 和一份日志。`declare` 批量声明或替换本 owner 的资源；`withdraw` 撤指定项；`step` 记录带 undo 的命令式操作；`reconcile` 修复期望状态；`release` 反序撤销；`recover` 处理上个进程留下的日志。

首次声明要检查链名、表名、路由表、优先级、接口是否已被占用；**只有已经证明归本 owner 的同键对象才可替换**。发现同名外部资源或无法判断归属，拒绝接管并保留证据。一次批量声明的全部 undo 在首次生效前写盘；中途失败时按已记录的顺序恢复，未执行过的 undo 也不能触及厂商状态。撤销遇错保留剩余日志及 `owns_network`，允许重试。无线步骤在锁内登记、锁外执行；同一 set 的变更按代次排序，后台核对不能重放已撤销的声明。

### 4.2 资源、核验与日志兼容

| 资源 | 取得后如何维护 |
| --- | --- |
| `NftTable`（族、表名） | 一个表一个 owner。已持有的表用 `nft -f` 整表原子替换，过期集合随之消失；同次切换若跨 `ip`/`ip6`，把两族放入同一 nft 批处理。分别保留目标内容/代次和最后一次成功应用、读回的内容/代次。写 B 失败而 A 完好时，B 仍待重试；读回失败是“未确认”。`nft -t` 只能核对结构，不能证明集合元素相同；大表不得因通用 256 KiB 输出上限而被误判成功。常规结构核对与首次应用、集合变更或异常后的内容核验可分开；需要验证全量时用不受整段文本上限影响的方式。 |
| `LegacyChain`、`LegacyHook` | 确认归属后用 `iptables-restore` / `ip6tables-restore --noflush --wait 2` 整链替换。首次不能用会清空既有链的 `:链名` 声明抢占名字。核对自有链内容与顺序；厂商链上检查钩子存在、无重复，并检查必须先于哪条终局规则。清理先解钩再清除自有链。 |
| `Route`、`Rule`、`Addr`、`Sysctl` | 记录族、接口、表、优先级等足以区分所有者的身份；不以单独优先级宽泛删除。sysctl 首次记原值，释放时恢复；本期键按 owner 排他登记，不建无使用者的跨日志引用计数。IPv6 寿命、DAD 和冲突由会话根据活租约核验，不由通用 guard 复写旧值。 |
| `Internal` / `step` | 功能模块注册有名的 apply、可选 check 和 undo。无线、守护进程、RPS/backlog、省电、resolv 标记行、门户按实际可核对性处理；不可重放的射频操作不进通用核对。 |

中继保留 `wireless.json`、`network.json`、`dns.json`、`ipv6-setup.json`、`ipv6-network.json`；Mihomo 在自己的目录持有 `network.json`。`ra-runtime.json` 保留专用覆盖值、owner、boot id 和 `withdrawing`：外部设置的零寿命不能当作自己撤 RA 的零值清掉。不同 boot 不重放上一轮的临时地址、射频或 RA 快照；本次开机的孤儿和旧日志即使没有启用意图也要清理。

升级和自动回退使用同一恢复契约：新版本读 v1；只要旧 A/B 槽或救援 Stable 仍可能启动，新版写出的日志就必须可被它**解析且完整撤销**。可在 v1 的 `{boot, undo: Vec<Cmd>}` 外壳增加新字段，但 `undo` 必须是最老受支持版本确实执行得了的命令。做不到就延后激活该效果，或先交付不依赖候选 agent 的兼容恢复器。跳过未知 `@u60-*` 只用于尽力处理历史残留，不算回退验收。手动先关功能不是 OTA 自动回退的前提。

### 4.3 防火墙：先在 nft 排除合法流量，再由 legacy 放行

`wifi_relay::uplink` 统一拼装两族的 `u60_relay`，`ipv6` 只提供租约有效期间的片段。`iifname` 形式的上游 INPUT 防护在 `u60sta0` 拉起前建立，纯扫描也建立；取得租约后扩展表，释放路由时先缩回仅防护，确认 STA 断联/移除后才撤。以下顺序是规则规范；“返回”指退出**本 agent 的防护链**，之后仍受厂商规则约束。

| 方向 | nft 自有规则 | 必要的 legacy 例外 |
| --- | --- | --- |
| 上游 INPUT v4/v6，`filter - 1` | 只约束 `iifname u60sta0`。v4 允许 established/related 和 DHCP 67→68 后 drop。未请求 IPv6 或尚未启用发现时保持上游 v6 关闭；发现开始前才允许 established/related、RA（链路本地源、跳数 255）、NS/NA（跳数 255）、ICMPv6 错误 1–4、DHCPv6 547→546，拒绝其余。 | v6 需要 `U60_R6_IN` 在 ZTE reject 前放行。v4 在证明首租、单播续租、广播重绑定和已建立回程都能穿过厂商 INPUT 前保留相应放行；仅看到 ESTABLISHED 规则不够。 |
| IPv4 FORWARD，`filter - 1` | 先返回 `br-lan → u60sta0`，再返回 `u60sta0 → br-lan` 的 established/related；然后 drop 其余从/向 `u60sta0` 的流量。其他接口保持原路径。 | `U60_RELAY_FWD` 放行同样的合法流量；保留独立 TCP 回程计数规则供 IPA 核验。 |
| IPv6 FORWARD / OUTPUT | 从 `br-lan` 向 `rmnet*` **先 reject**，不让后面的本地/组播例外覆盖它。NAT66 有效时返回经认可 LAN 源到 `u60sta0` 的去程、从该接口到 LAN 的 established/related 回程，再拒绝其他涉及该上游的转发。基线对其余 LAN 转发保留 `fc00::/7`、`fe80::/10`、`ff00::/8` 的本地例外，拒绝其他外部 v6；与中继无关的转发不受影响。OUTPUT 只需一条向 `rmnet*` 的拒绝。 | 合法 NAT66 流仍经 `U60_R6_FWD` 穿过厂商过滤。OUTPUT 拒绝归**中继基线**，覆盖 IPv6 未开启、租约丢失、NAT66 撤销后仍有 IPv4 中继的时段。 |
| DNS、门户和地址转换 | `u60_mihomo` LAN DNS 优先于 `u60_relay`；中继区分 LAN DNS 与路由器 DNS，保留管理地址和必要的本地例外。核心出站采用经设备核对的独立掩码位后，中继 DNS OUTPUT 遇该位返回（M13）。NAT66 只匹配中继上游出口；IPv4 MASQUERADE 迁移须通过 D11。 | 门户 `redirect_chain` 的两族 RETURN 必须位于厂商 DNAT **之前**；`-C` 成功不能证明位置正确。IPv4 nft MASQUERADE 若不能继续卸载则保留 legacy MASQUERADE。 |

### 4.4 ZTE 改写后的核对

`net-guard` 以脚本 IN_OPEN、ubus 事件和 60 s 兜底调度。触发后约 2 s 静默再全量核对；确实补回资源后，5 s 再查一次。触发后的 3 s 内，每 0.5 s 只读已声明的 sysctl，发现被改才写；写前确认仍是同一所有者和代次。0.5 s 是采样目标，不是设备恢复上界。

自己的 `ipacm_switch.sh` 打开事件按路径合并，不屏蔽窗口内其他脚本或 ubus；不能判断来源时保留一次核对。忙 set 不阻塞其他 set，本轮失败或未完成的资源保留待办。核对不得靠来回删除正常规则恢复顺序；一次 fw3 reload、两次连续 reload、restart/flush 和只丢一个钩子是不同验收。IPA 模式单独按 15 s 审计；不再给中继每个 3 s tick 加一套防火墙检查。

### 4.5 conntrack：删除范围、代次、结果

只有 `netfx::conntrack` 删除条目，直接执行 `conntrack`，不经 shell。范围为 `Lan { v4, v6 }` 或 `Destinations(IPv4 前缀)`；后者也必须限定 LAN 来源，不能删路由器或其他接口的连接。每个请求带原因、范围及相应路径改变的代次/时刻。

- 同时考虑新旧计划的**首条命中结果**。只有两边直到最后一个放行点的有效判定都能以纯目的 IPv4 区间表达时，才用“旧 DIRECT 减新 DIRECT”。例如在原 DIRECT /24 前加 `DST-PORT,443,PROXY`，虽然 DIRECT 条文本身没变，已有 443 硬件流也必须退出。来源、端口、协议、复合条件或全域兜底无法可靠求差时，退回 LAN IPv4；超过 64 段同样退回（D10）。纯目的集合没有失去放行时，不为了重编同一张表清连接。UDP 不享受已有 TCP 的 socket 固定；需改路径时也纳入相应范围。
- 在 200 ms 内可合并尚未执行的请求。已完成的一次删除只有在**它开始于本次路径变化之后**、成功并覆盖全部请求范围时才可抵账。保留有界诊断，区分“成功删除、有证据的零匹配、操作失败”：conntrack-tools 1.4.8 的退出码 1 也可能是 netlink 错误，不能单凭返回码判断。部分失败记录待重试，不报告“已重置”。[conntrack-tools 1.4.8 源码包](https://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-1.4.8.tar.xz) 中的 `print_stats`（零匹配）和 `OTHER_PROBLEM`（操作失败）是两个不同分支。
- 删除 conntrack 不是给 TCP 发送 RST，也不是清理客户端 DNS 缓存。UI 按实际范围及结果显示。已卸载的流要以失去 DIRECT 的真实硬件流验证；路径没变的流在 B31 上能很快重新卸载。

### 4.6 准入 `Admission`

准入锁只登记/释放资源占用，不跨 ubus、Wi-Fi 重载、配置写盘或 CAC。扫描、连接、启动及恢复开始前先声明占用；清理失败时仍拥有残留资源。外部写入在同一临界区检查冲突并登记自己的操作，等待取得准入最多 3 s，超时回 409；自动连接看护不等。厂商异步 Wi-Fi reload 的冲突占用不能在 HTTP 返回时就释放，要跟到实际完成或可验证的稳定状态。3 s 不代表任何设备操作在 3 s 内完成。

厂商防火墙、LAN 修改与中继或 Mihomo 冲突；热点、访客、USB 修改按中继所有权判断。固定 DHCP 保留仍按自身写入/重载需要串行，不因任一功能运行就一律拒绝。长操作用 Slow lane；取消须能在两个 Slow 名额都被长操作占用时递增令牌、通知控制器，不在 Tokio 线程上等设备。

### 4.7 名字和编号 `netfx::ids`

| 范围 | 保留值与用途 |
| --- | --- |
| 策略路由 | Mihomo `pref 18620`、`fwmark 0x700/0xff00` → 表 60625 的本地路由；中继 `pref 18640` → 表 60631；IPA 的 main 默认路由和 unreachable 用 metric 60631。核心出站标志不能碰 TPROXY 或 ZTE 已用位。 |
| 表、接口、端口 | `ip`/`ip6 u60_relay` 归中继，`ip`/`ip6 u60_mihomo` 归代理。STA 为 `u60sta0`；旧日志可能仍含 `u60mh0`。1053：DNS；17894：TPROXY；127.0.0.1:17893：认证下载；127.0.0.1:19090：核心控制；9090/9443：agent。 |
| 地址、其他 owner | `198.18.0.0/16` 是 fake-ip。统一登记地址常量，但代理私网例外、中继 DNS 例外、策略表 throw 和 IPA main 防护分别取其所需子集；不能把所有酒店私网都 throw。WireGuard 和 TTL 自有链登记并列入写入检查白名单。 |

## 5. Mihomo

### 5.1 意图、核心与规则规划

`controller` 持有意图和已发布快照；`core` 独占进程、托管 `config.yaml` 和控制器写操作；`intercept` 生成网络资源；`routing` 编译订阅规则及 DNS 过滤表；`follow::plan / decide` 决定保持、换链、重载或重启，以及需清除的连接范围；`egress` 负责出口观测与去抖。后台任务不直接覆盖活动配置或选组，提交带代次，过期不生效。

### 5.2 状态与失败行为

| 状态 | 网络效果和退出条件 |
| --- | --- |
| Off | 不持有拦截；关闭意图取消后台重试。若实际还有未撤完的效果，报 CleanupPending，不能报 Off。 |
| Starting | 先装 1053/17894 的非 LAN、非本机 INPUT 防护并准备 brnf/pacing 和两族策略路由，再启动核心。在首次安装完整表前验证进程、控制端、认证下载代理、透明监听和双栈 DNS，读回实际模式/选组。Backoff 发起的启动还保留 fake-ip 拒绝，直到完整表接管。 |
| Running | 按已确认的计划拦截；出口变化进 Restarting，DNS 过滤变化进 Reloading。首次启动或从 fail-open 恢复后清除能沿旧直连路径继续的连接；后者核对 LAN v4/v6。 |
| Restarting / Reloading | 保留策略路由、sysctl 和拦截；切换开始前收紧绕过，给 `to_core` 加无 socket 时的 TCP/UDP 兜底 drop。就绪并完成核验后才发布 Running。热重载不关旧出口连接，出口变化必须重启。 |
| Backoff | agent 确认核心意外退出，或替代核心最终未能启动：撤常规拦截、sysctl 和策略路由，保留 LAN 到 fake-ip 的 TCP reset/UDP reject，页面显示“正在直连”、错误、次数和下次重试。快速失败不保证客户端立即重新查 DNS。 |
| CleanupPending | 停止/撤销失败：保留日志、所有权和具体错误，允许重试；不得把未知状态当作干净的 Off/Backoff 并覆盖外部资源。 |

启用意图仍在就自动重试：依次等 5、15、30、60 s，此后每 5 min；60 s 内退出连续 3 次，直接进入 5 min 档。稳定后清零；车主关闭使已排队的旧重试失效。开机先等厂商启动同步并回滚上个进程的中继日志，清理孤儿和残留路由；回滚失败且旧路由仍在时，不用该路由启动核心。随后按意图恢复 Mihomo，再重连最近一次符合条件的中继。若 agent 本身意外退出，须由进程外的恢复机制自动拉起，按持久意图恢复可用网络：处理失效的 1053 重定向、拦截、策略路由与 brnf，不等车主操作。恢复不得产生第二个网络 owner、对抗显式停止或与 OTA 试运行/回旧槽竞争。只有已确认的核心故障才走 D3，不能仅靠等待客户端重试消除黑洞。

### 5.3 拦截表

保持独立的 `ip`/`ip6` 表、同一 owner。prerouting 只处理来自 `br-lan` 的包：先让**已有核心透明 TCP 会话**继续本地交付（保留其他标志位，再设 `0x700`）；排除 DNS 和本机目的，v4 fake-ip 强制 `goto to_core`，之后才处理私网例外、编译的 IPv4 规则和最终 `goto to_core`。LAN 53 用优先于中继 DNS 的 nat prerouting 重定向到 1053。IPv6 没有内核 DIRECT 规则段。ICMP 不进 TPROXY。

在 `to_core` 中，TPROXY、打标与 accept 同属一条规则。内核找不到可用的透明连接或监听时返回 `NFT_BREAK`，**仅跳过本规则余下部分**；因此计划内切换必须另有末尾 TCP/UDP drop，不能靠保留表名来阻止直连。计划内停旧核心前必须先装好阻断；agent 死亡后由独立恢复机制接管，不能把残留 drop 或无人监听的 DNS 重定向留给车主手动处理。已有 TCP 的匹配要在 DIRECT return 前；它不适用于 UDP、核心已重启的旧连接，也不能把通配监听误当成已建立会话。需用新 SYN（含目的端口 17894）和既有 TCP 验证匹配条件。[Linux TPROXY](https://github.com/gregkh/linux/blob/v5.15.194/net/netfilter/nft_tproxy.c#L49-L80) · [nft 规则执行](https://github.com/gregkh/linux/blob/v5.15.194/net/netfilter/nf_tables_core.c#L244-L247)

### 5.4 规则切换与 DNS

rule 模式按订阅顺序编译，select 的实际选择最终到 DIRECT 才可绕过；无法在内核证明安全的非 DIRECT 条件截断后续放行。保留 `no-resolve` 及规则顺序；带 `no-resolve` 的 DIRECT 地址规则不得遮蔽仍应代理的域名，无法判定时发 fake-ip 或留在核心。global/关绕过不放行普通公网 IPv4；direct 也不能放过 fake-ip。新旧规则对连接的影响按 §4.5 计算。

一次切换分三个可核验的步骤：

1. 对车主可控的写操作，先在同一控制器内登记新代次，收紧旧 DIRECT（拿不准就暂时取消相关绕过），使已失去资格的硬件流退出旧路径；若旧路径尚未排除，不确认该次切换已完成。桥接的模式/选组/规则 provider 写操作遵守同一顺序。
2. 改核心状态，读回 `/configs`、`/proxies` 及实际 provider；DNS 过滤表变化才热重载。读取、应用或核对失败，保持保守表并重试。外部 provider 的内容、成员或选组可以自主改变。无法在更新前证明始终 DIRECT 的动态范围，从首次开放绕过前就留在核心，或让更新先经过控制器收紧放行；不得等看到文件变化才补救已误放的包。按内容而非 mtime 跟随替换，60 s 兜底只用于核对，不是允许直连的宽限。
3. 新 DNS/选组/规则确认一致后才扩大允许绕过的范围。客户端用路由器 DNS 先前发出的真实 A **新建连接**，也按新策略处理：对可能切换的域名稳定使用 fake-ip，并覆盖已发出、可能命中不变 DIRECT 前缀的旧地址。无法可靠区分时收起相关绕过；若核心也不能判明可直连，不能回落到 DIRECT。允许因此少用部分硬件加速。清 conntrack、只测新 DNS 回答或固定等几分钟，都不构成旧地址已受保护的证据。

### 5.5 热重载的成功条件

本期热重载用于**同一配置的 DNS 过滤表变化**。`PUT /configs?force=false` 的 JSON `payload` 是完整托管配置，保留实际 mode、log-level、`interface-name`、端口和 secret；秘密不入日志。v1.19.33 会暂停接入、更新代理/规则/DNS，继承 fake-ip 映射并按缓存恢复选组。暂停期间不仅新 TCP 受影响，既有 UDP/QUIC 的上行包也可能丢失。

204 只证明入口完成调用：provider 初始化错误可能只写日志，节点组为空时默认 `COMPATIBLE` 可直连。收到 204 后核对实际模式和接口、实际选组及必要 provider（不得意外退回 COMPATIBLE）、监听/下载代理状态，并向 1053 查询本次应该改变答案的测试域名或可验证等价项。**超时是结果未知**，读回能确认才提交，否则保持收紧并回退到校验后的保留拦截重启。切换订阅/配置继续保留上一份可用配置与选择；若以后也使用热重载，另验失败回滚、旧连接和内存。[配置入口](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/hub/route/configs.go#L405-L454) · [provider 加载](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/hub/executor/executor.go#L318-L338) · [UDP 检查](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/tunnel/tunnel.go#L420-L441)

### 5.6 出口变化

以**实际装过、撤过或改变的出口**为准：从未装路由的失败连接和扫描不触发重启；装过路由后才失败的会话及从已有会话切走的失败操作，仍要发布实际快照。相同出口不重复重启。v4 有效变化立即处理；v6 持续 5 s 才处理，相关重启至少间隔 60 s；蜂窝沿用 15 s 出口审计和旧连接是否搁浅的判断。仅接口名变化且核心及其他校验依赖未变时可复用上次校验；DNS 过滤表变化后走重启回退须重新 `mihomo -t`。

## 6. Wi-Fi 中继

### 6.1 会话与取消

`Idle → Scanning → Idle`；活动会话上的扫描保留其路由。`Idle → Connecting → Active`；活动会话掉关联进入 `Recovering`，12 s 内回来且旧租约及助手仍有效则续约回到 Active，否则进入 `Disconnecting`。车主断开、有效地址变更、热点关闭或连接取消走同一拆除路径；撤销成功才 Idle，失败为 `RecoveryPending`。运行中不后台重连；开机只恢复最近一次符合条件的成功连接，不轮询全部已保存网络。

先校验车主请求，再变更取消令牌和排队；各等待点和最终发布前都查同一代次，迟到的成功不能复活已断开的会话。仅在成功连接到开放网络或已有匹配凭据时写 `resume.json`；手动断开清除，掉线保留。开机恢复沿用有界重试（约 17 min），手动操作和车主关闭热点可取消。记住凭据与开机恢复是不同的意图。残留监视器核对本次 boot 的 PID、进程身份/私有参数，不因进程恰叫 `iw event` 而杀掉人工观测；已知会切 SELinux 域的无线及 DHCP 助手按私有路径清理。

连接顺序：先建受保护的 STA（§4.3），启动 supplicant，处理热点和 DFS 开关，关联并取得 DHCP。校验地址、网关和冲突后，先装地址、路由、NAT、转发防护和 DNS 数据面，策略规则最后；核实出口再接管可选的 IPA、resolv/门户和 IPv6，并发布会话。断开时停止 IPA 监视器，撤 RA/可选 IPv6、IPA main 路由、IPv4 选路和 DNS；实际出口改变即通知 Mihomo，不等后续最长 80 s 的 CAC。STA 确认断联才恢复热点，INPUT 防护最后撤。

### 6.2 运行检查和无线设置

每 3 s 只在活动会话观测 wpa 状态、带会话标识的租约、助手及热点开关。`watch::decide` 区分关联宽限、有效续约、只变 DNS 与真正掉线；DNS 变化由 uplink 一处更新 resolv 标记行和下载器快照。IPv6 根据剩余寿命、DAD、优先级归属与保留 LAN 前缀维护路由/地址；撤 RA 在撤 NAT66 前。普通 IPv6 租约失效只撤可选片段，不能拆掉仍工作的 IPv4 及基线防护。时钟复核在 relay 控制器执行，不跨功能持锁。

上游省电仍按车主的 `keep-power-save` 意图在关联时处理，与路由器自身省电模式分开。删除不可靠的带宽自动调优（D5），保留关联时一次性 `reset_width` 及热点仍使用的信道/带宽解析；取消 tuning API 和页面选项，已存 `auto` 迁为 `off`，保留其余网络参数。上下游共用射频、DFS 窗口、真实读回和恢复热点的固件要求继续遵守[设备指南](../../CLAUDE.md)。

## 7. IPA 硬件转发

IPA 状态机通过 `wifi_relay::offload` 的 `IpacmPort` 接口读写 IPACM：模式、配置、车主限制、回程计数以及上游邻居和 LAN 客户端维护都走这个接口。用假实现跑完整的状态转换和失败矩阵；相关的 main 路由和 conntrack 仍由 `netfx` 写。

只有本次 boot 已被 IPACM 加载的 STA 配置、正确的 `main` 默认路由和 HW 模式同时具备时，才可能卸载 IPv4。IPACM 在启动时读接口表，首次安装需要整机重启；本次开机原已加载、移除后重装是另一种情况。模式审计不得覆盖车主的限速、省电或 `ipa_disable`。B31 的邻居退役、客户端 ARP STALE、SW→HW 重新挂载，仅在 `wa_inner_version=BD_CNMU5250V1.0.0B31` 且 ipacm 二进制哈希匹配时启用；不匹配显示原因，回软件路径。详见[硬件转发说明](relay-hw-offload.md)。

| 状态 | 转换和所有权 |
| --- | --- |
| Off | 无请求或无会话。车主仍要求开启且已有可用会话时评估已加载、指纹、限制等前提，再进入 Engaging 或 Software。 |
| Engaging | 记清原模式与本次声明，按设备验证顺序准备 HW、安装 main 防护和默认路由，再重新挂载和启动监视器。路由或后续步骤失败，要撤销部分路由及这次取得的模式，不能留下“软件”快照掩盖实际接管。 |
| Hardware | 每 15 s 审计；无车主限制时允许纠正 ZTE 改回的 SW。用实际有负载时的 TCP 回程计数判断，≥1,500 包/s 可触发重新挂载，每次会话最多 3 次。空闲时少包不能证明正在卸载。 |
| Software | 记录受限/未核验/失败原因及车主意图。限制解除且意图仍开 → Engaging；关闭、移除、会话结束 → Releasing 或无资源时 Off。 |
| Releasing | 停监视器，先删 main 路由，再恢复本次接管的模式；失败保留恢复信息。因车主限制释放且仍要求开启 → Software，其余 → Off。有效路径变化才通知 conntrack 重置 LAN IPv4。 |

安装、移除须保留原备份、属主、权限和 SELinux 标签。不能把唯一生效配置截断一半留给下次开机；采用在目标文件系统写完整临时文件、核验元数据和内容后原子替换，或先证明等效的崩溃恢复机制能在 IPACM 下次读取前修复。不能用运行时重启 ipacm 补救。移除先 Releasing，按设备确认顺序等 1 s 后改配置；有足够流量时用回程计数核验回 CPU，否则标“未核验”。页面区分 HW 模式、已确认卸载以及“公网 IPv4 当前由 Mihomo 处理”。
