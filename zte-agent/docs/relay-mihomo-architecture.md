# Wi-Fi 中继与 Mihomo：架构

定稿：2026-11-10，原是目标规范；2026-11-12 起改为描述代码现状。规定了但没有实现的部分集中在[第 8 节](#8-规定了但未实现)，正文在相应位置写“未实现（§8）”。车主已决定暂不实现 `EffectSet` 层和中继控制器线程。[版本与验收](relay-mihomo-refactor-plan.md)是 v1–v6 的交付顺序。[产品说明](mihomo-relay-prd.md)描述已发布行为；[设备约束](../../CLAUDE.md)适用于全部版本。车主已确定自动恢复、provider 自主刷新零误直连和旧真实地址保护；[验收条件](relay-mihomo-refactor-plan.md#owner-decisions)同样适用于 v2/v3。

## 1. 不变式

| 编号 | 实现与验收共同遵守的约束 | 代码现状 |
| --- | --- | --- |
| I1 | 中继和 Mihomo 的 nft、iptables-legacy、地址、路由、策略规则、sysctl、conntrack 写入只经 `netfx` 和 `net_tools::Transaction`；一项资源只有一个 owner。agent 不写 IPACM 的配置文件（`wifi_relay::offload` 只读它）；核心进程、托管配置及影响路由的核心 API 写操作由 Mihomo 控制器排序。ZTE 是外部写入者；WireGuard 和 TTL 的 legacy 链不在本次迁移范围。 | 随 `cargo test` 的源码扫描（`netfx::boundary`）检查，白名单见 §4。agent 既不写 IPACM 的配置，也不写它的 HW/SW 模式（§7）。 |
| I2 | 不持跨功能锁做设备 I/O。HTTP 读状态只取快照；在单线程 Tokio 上不得阻塞等待控制器、运行命令或调用阻塞 HTTP。中继的关联、CAC、撤销或核对不能挡住 Mihomo 的退出处理、重试或 brnf 修复。 | 中继与 Mihomo 之间成立：Mihomo 从不拿中继的锁。中继内部不成立：tick 持 `inner` 做设备 I/O，`active()` 要等它；中继状态读取不是纯快照（§3）。 |
| I3 | 对可撤销的自有效果，先持久记录本次开机的撤销依据，再生效；只能撤自己的东西。部分执行、执行前被杀、重复撤销都可恢复。conntrack 删除不可逆，按已生效的策略代次记录结果，不伪造 undo。 | 由 `Transaction`（日志 `{boot, undo: Vec<Cmd>}`）实现。 |
| I4 | 控制器主导的计划内重启、重载和规则切换，必须先收紧受影响的内核绕过，核心不可接包时阻断本应拦截的流量，核验后才扩大 DIRECT。provider 自主刷新也不允许误直连；用旧 DNS 真实 A 新建的连接必须遵守新策略，无法证明可直连的流量不得绕过。agent 仍在且确认核心意外退出，或计划内重启最终失败时，按 D3 撤常规拦截、显示正在直连并重试。单次 nft 写失败、PUT 超时或读回失败本身不授权直连。 | 由 Mihomo 控制器按 §5.4 的顺序做。 |
| I5 | 在有 nft 支持的本机网络层，拒绝放在 agent 的 nft 表；穿过厂商 DROP/reject 的放行和门户 RETURN 留 legacy。nft 里的 return/accept 都不能替代 legacy 的放行。NAT 是地址转换，迁移有单独门槛。 | 相符：`wifi_relay::uplink` 一处拼装。 |
| I6 | 决策输入包括意图、有效观测、先前状态和单调时间，输出为动作；设备读写在适配器。可用假时钟和假设备重放退出、重试、切换和撤销。 | 部分：Mihomo 的 `Port`、IPA 的 `IpacmPort`、中继的 `decide`/`lease_change`/`Association` 可用假设备或纯函数重放；Mihomo 的决策和 `Port` 调用交错写在控制器里（没有 `follow::plan/decide`，§8），中继 tick 的观测与动作内联，IPv6 没有端口。 |
| I7 | 持久意图、实际观测、希望应用的计划与最近确认生效的计划分开。状态页不能因配置已保存、命令已发出或核心进程在运行就显示“已生效”。 | 部分：nft 表分开记目标和已确认代次；中继会话没有阶段（§6.1），`recovery_required` 在操作进行中也会成立。 |

## 2. 产品与设备边界

- 管理端拒绝来自 `rmnet*` 或中继上游 `ath20`（按确切名字）的对端（D1），沿用现有接口分类、本机/Tailnet 例外和失败策略。它只保护 agent 的 9090/9443，不能代替对所有设备监听端口的上游 INPUT 防护。
- 保留双栈，不做“IPv4 优先”（D4、M14）。透明代理处理从 `br-lan` 进入的 TCP/UDP；本机、私网等例外仍走原路径，不代理路由器的一般 OUTPUT。外网 IPv6 始终进核心，没有 IPv6 fake-ip 池。只有符合 DIRECT 的 IPv4 可绕过核心并有机会被 IPA 卸载。默认不开绕过。
- TPROXY 工作时必须将 `bridge-nf-call-iptables` 和 `bridge-nf-call-ip6tables` 设为 0；车主接受在此期间依赖 brnf 的访客隔离失效。固件会重写 legacy、路由与 sysctl；B31 没有 `NFT_FIB_INET` 和 nft bridge family。使用分开的 `ip` / `ip6` 表，链名避开 `fwd`、`post`、`c`。
- 中继 CPU 转发抢在 ZTE 的部分 FORWARD 过滤之前；IPA 卸载的流也不走这条 CPU 路径。开启相关家长控制或网址过滤时页面提示实际影响（D8）。不主动开启蜂窝、不重启 ipacm、不踢客户端。蜂窝协调不在本次范围。

## 3. 线程、锁、消息与状态

Mihomo 用一个串行控制器线程；中继没有控制器线程（未实现，§8），用自己的 `op` 互斥锁把操作和 3 s 看护串行。原来跨功能持有的全局网络操作锁已由 `netfx::admission` 取代（§4.6）。两者之间只有一类运行时业务通知：中继装过或撤过路由后发 `Message::Egress`；中继不等待 Mihomo 重启。核心退出、HTTP 命令和重试定时器各自进入 Mihomo 控制器。

| 执行者 | 代码现状 |
| --- | --- |
| 中继操作 | 扫描、连接、更换上游、断开和中继页的设置在发起它们的线程上直接执行：HTTP 阻塞池线程（`server::route`）、开机恢复的 `net-restore` 线程。先在准入登记（§4.6），再拿 `op`；`op` 没有等待上限（扫描、连接、省电和 IPA 开关在 Slow lane 上等，断开在 General lane 上等）。关联约 60 s、恢复热点含 CAC 最长 80 s 都在 `op` 下进行，不占跨功能的锁。 |
| `relay-watch` | 有会话时每 3 s 醒一次，`net_guard` 触发安静后立即醒。拿 `op` 后经 supplicant 控制套接字读 `wpa_state`（最多等 2 s，不起 `wpa_cli`），再持 `inner` 判断租约、助手和热点开关（`decide`），按 `net_guard::Cursor` 到期核对四个事务（共用一次列表，§4.4），然后跑 IPv6 的 tick。 |
| `mihomo` | 串行处理车主命令、影响路由的桥接写、出口变化、`net_guard` 唤醒、子进程退出、重试和规则集刷新。慢调用都在本线程同步做：启动前的 `mihomo -t`（最长 30 s）、规则集 PUT（30 s）、热重载 PUT（15 s）、`nft -f`（20 s）、最多 64 次 `conntrack -D`（各 8 s）；其间核心退出和车主命令排队，命令最多等 150 s（`COMMAND_WAIT`）。后台任务和带代次的后台结果未实现（§8）。换配置的计划内重启和热重载在旧核心还在服务时校验新配置，这时 `mihomo -t` 降低优先级（`GOMAXPROCS=1`、`GOMEMLIMIT=128MiB`、nice 10），但仍在本线程上；保存或刷新订阅时的校验在调用方线程上跑，核心在运行时同样降低优先级。经中继启动核心时的 HTTPS 时钟校验在自己的线程（`mihomo-clock`，同时只有一个）上跑，核心不等它。控制器线程 panic 时记一行日志并结束 agent（`Controller::supervised` → `abort`），由 `zte-agent guard` 重新拉起，新 agent 接管本次开机的表。 |
| `mihomo-core-wait` | 每个子进程只有一个回收者。停止路径给已确认属于该代的进程发信号；等待者负责 wait/reap，回送 `Exited { generation, how }`。控制器忽略旧代退出和已取消的定时器。 |
| `net-guard`、`net-guard-sample` | 订阅 inotify/ubus、合并触发，只负责唤醒：各 owner 在自己的循环里问 `Cursor::due()`，所以一个 owner 忙时不挡别的 owner。采样线程在触发后的 3 s 内维护已登记的 sysctl。`relay-neigh` / `relay-lan` 归当前 IPA 会话，退出后不能再操作下一次会话。 |
| HTTP、页面、Zashboard | Mihomo 页面读控制器发布的不可变快照；车主命令交给控制器。重启或热重载期间，普通控制命令排队，桥接写回 503。已放行的在途写必须与切换排序，不能凭请求开始时读到的 Running 快照跨代写入。保留桥接的现有认证、同源和端点限制。 |

中继的 `resume.json`、已保存网络、IPv6/省电和 IPA 开关表达车主意图。Mihomo 的 `enabled`、`cn-direct`、`profiles.json` 表达启用、绕过和配置选择。托管配置开启 `profile.store-selected` 和 `profile.store-fake-ip`；`selected.json` 只为启动前生成配置提供初值，第一张带 DIRECT 放行的运行表必须依据**本代就绪后**实际读到的模式和选组。

中继状态（`WifiRelay::status`）不是纯快照：在 `publish` 时存好的快照之外，每次读取还读 `resume.json`、`IPACM_cfg.xml`（只读）、`saved-wifi.json` 和省电设置，查日志文件是否存在；`connection_resets` 要拿 conntrack 的状态锁，而这把锁在整个删除期间被持着。读取不更改恢复意图。

出口：中继不发布出口快照（未实现，§8）。`Message::Egress` 不带内容，Mihomo 自己观测出口（`mihomo/egress.rs`），判定哪些变化需要重启；中继在 `publish` 时把租约 DNS（没有时用网关）交给下载器（`set_subscription_dns`），会话结束清空。核心关着或正在安装时不为出口消息报错或重启；在 Backoff 中，一个新的 IPv4 出口会让控制器立即重试（§5.2）。

## 4. 网络效果层（`net_tools::Transaction` 与 `netfx`）

I1 的写入边界有随 `cargo test` 运行的源码扫描测试（`netfx::boundary`）：中继与 Mihomo 不能绕过 `netfx` 或 `Transaction` 的步骤写 legacy、nft、地址、路由、策略规则、sysctl 或 conntrack。白名单是 `@u60-relay-steer` 步骤自身和 IPv6 会话对已登记地址/路由的寿命 `change`；只读检查不是写入；WireGuard 和 TTL 的既有 legacy 写入按 §4.7 不在范围内。`netfx` 提供有界命令（`exec`）、私有文件（`files`）、名字与编号（`ids`）、唯一的 conntrack 写入者（`conntrack`）、nft 整表（`effect::NftTables`）和准入（`admission`）。

### 4.1 日志、撤销与资源归属

一份日志对应一个 `net_tools::Transaction`。`apply` 先把一步的撤销写进日志再执行；`apply_network` 先把整份计划的撤销一次写盘，再按顺序执行，连续的 iptables/ip6tables 步骤合成 `iptables-restore`/`ip6tables-restore --noflush --wait 2` 事务（`firewall::Batch`，每张表的行一起提交）；另有 `ensure`、`adopt`（接管时只登记仍在的步骤）、`release`（反序撤指定的撤销）、`rollback`（反序撤全部）、`recover`（处理上个进程留下的日志）。能复查的步骤同时记进内存里的期望状态，供核对（§4.4）。nft 表由 `netfx::effect::NftTables` 管（`declare` 整表替换、`reconcile`、`remove`），它没有自己的日志：撤销登记在所属 `Transaction` 里（`@u60-relay-nft remove`、`@u60-mihomo-nft remove`）。规范里的 `EffectSet` 及其 `declare`/`withdraw`/`step` 接口未实现（§8）。

归属：nft 表名被没有本 owner 代次标记的表占用时拒绝接管；legacy 自有链用 `-N` 声明，同名链已存在时 restore 失败，不接管也不清空（`tests/relay-firewall-qa`）。中途失败时按日志反序撤回，包括没执行过的步骤，所以每个撤销都要对不存在的对象成功、且不能匹配别人的对象。撤销遇错保留剩余日志及 `owns_network`，允许重试。只有确定的“不在”才算已撤（列表里没有该链，或 `iptables` 退出 1 并报 B31 的两种措辞之一：目标是 ACCEPT/RETURN 或链不存在时 "Bad rule (does a matching rule exist in that chain?)"，跳到一条存在的用户链或目标是 MASQUERADE 时 "No chain/target/match by that name."；`firewall::no_rule`）；工具或锁失败时保留日志。自有规则的每一份副本都删，自有 `U60_*` 链先清空再删；厂商链从不清空，别人的同样规则只删一次（`firewall::undo`）。

### 4.2 资源、核验与日志兼容

| 资源 | 取得后如何维护 |
| --- | --- |
| nft 表（族、表名） | 一个表一个 owner。用 `nft -f` 整表原子替换，过期集合随之消失；两族放入同一 nft 批处理。分别保留目标代次和最后一次读回确认的代次。写失败时目标仍待重试；读回失败是“未确认”。内容与已确认目标相同、且读回仍在内核里时不再载入。核对用一次 `nft -t list ruleset` 读两族（ZTE 不写 nft，里面只有 agent 的表），比对代次标记和每条链的**规则条数**；集合元素被清空或规则被等量替换查不出来（内容核验未实现，§8；没有别的写入者碰 nft）。 |
| legacy 自有链与钩子 | 规则逐条作为步骤，用 restore 事务写入（§4.1），不是整链替换（未实现，§8）。核对对照每张表的 `-S` 列表逐条判断（§4.4），确定不在才在原位置重做；重复副本在撤销时全部删除。只有门户 RETURN 检查位置：它必须排在 `redirect_chain` 里所有厂商规则之前，排在后面时在同一个 restore 事务里删除再插到第一条（`@u60-relay-portal-return`）。 |
| 路由、策略规则、地址、sysctl | 记录族、接口、表、优先级等足以区分所有者的身份；不以单独优先级宽泛删除。sysctl 首次记原值，释放时恢复；本期键按 owner 排他登记，不建无使用者的跨日志引用计数。IPv6 寿命、DAD 和冲突由会话根据活租约核验，不由通用 guard 复写旧值（§6.2）。 |
| 内部步骤（`@u60-*`） | `Cmd::run`/`Cmd::undo` 按名字分发到功能模块：`@u60-sysctl`、`@u60-relay-steer`、`@u60-relay-power-save`、`@u60-relay-portal-return`、`@u60-relay-nft`、`@u60-mihomo-nft` 等；其中可复查的进入核对。无线、守护进程、resolv 标记行按实际可核对性处理；不可重放的射频操作不进通用核对。 |

中继保留 `wireless.json`、`network.json`、`dns.json`、`ipv6-setup.json`、`ipv6-network.json`；Mihomo 在自己的目录持有 `network.json`。`ra-runtime.json` 保留专用覆盖值、owner、boot id 和 `withdrawing`：外部设置的零寿命不能当作自己撤 RA 的零值清掉。不同 boot 不重放上一轮的临时地址、射频或 RA 快照；本次开机的孤儿和旧日志即使没有启用意图也要清理。

升级和自动回退使用同一恢复契约：新版本读 v1；只要旧 A/B 槽或救援 Stable 仍可能启动，新版写出的日志就必须可被它**解析且完整撤销**。可在 v1 的 `{boot, undo: Vec<Cmd>}` 外壳增加新字段，但 `undo` 必须是最老受支持版本确实执行得了的命令。做不到就延后激活该效果，或先交付不依赖候选 agent 的兼容恢复器。跳过未知 `@u60-*` 只用于尽力处理历史残留，不算回退验收。手动先关功能不是 OTA 自动回退的前提。

### 4.3 防火墙：先在 nft 排除合法流量，再由 legacy 放行

`wifi_relay::uplink` 统一拼装两族的 `u60_relay`，`ipv6` 只提供租约有效期间的片段。`iifname` 形式的上游 INPUT 防护在 `ath20` 拉起前建立，纯扫描也建立；取得租约后扩展表，释放路由时先缩回仅防护，确认 STA 断联/移除后才撤。以下顺序是规则规范；“返回”指退出**本 agent 的防护链**，之后仍受厂商规则约束。

| 方向 | nft 自有规则 | 必要的 legacy 例外 |
| --- | --- | --- |
| 上游 INPUT v4/v6，`filter - 1` | 只约束 `iifname ath20`。v4 允许 established/related 和 DHCP 67→68 后 drop。未请求 IPv6 或尚未启用发现时保持上游 v6 关闭；发现开始前才允许 established/related、RA（链路本地源、跳数 255）、NS/NA（跳数 255）、ICMPv6 错误 1–4、DHCPv6 547→546，拒绝其余。 | v6 需要 `U60_R6_IN` 在 ZTE reject 前放行。v4 在证明首租、单播续租、广播重绑定和已建立回程都能穿过厂商 INPUT 前保留相应放行；仅看到 ESTABLISHED 规则不够。 |
| IPv4 FORWARD，`filter - 1` | 先返回 `br-lan → ath20`，再返回 `ath20 → br-lan` 的 established/related；然后 drop 其余从/向 `ath20` 的流量。其他接口保持原路径。 | `U60_RELAY_FWD` 放行同样的合法流量，共两条（去程、已建立/相关的回程）。 |
| IPv6 FORWARD / OUTPUT | 从 `br-lan` 向 `rmnet*` **先 reject**，不让后面的本地/组播例外覆盖它。NAT66 有效时返回经认可 LAN 源到 `ath20` 的去程、从该接口到 LAN 的 established/related 回程，再拒绝其他涉及该上游的转发。基线对其余 LAN 转发保留 `fc00::/7`、`fe80::/10`、`ff00::/8` 的本地例外，拒绝其他外部 v6；与中继无关的转发不受影响。OUTPUT 只需一条向 `rmnet*` 的拒绝。 | 合法 NAT66 流仍经 `U60_R6_FWD` 穿过厂商过滤。OUTPUT 拒绝归**中继基线**，覆盖 IPv6 未开启、租约丢失、NAT66 撤销后仍有 IPv4 中继的时段。 |
| DNS、门户和地址转换 | `u60_mihomo` LAN DNS 优先于 `u60_relay`；中继区分 LAN DNS 与路由器 DNS，保留管理地址和必要的本地例外。核心出站采用经设备核对的独立掩码位后，中继 DNS OUTPUT 遇该位返回（M13；尚未启用，`ids::CORE_OUT_MARK` 为 `None`）。NAT66 只匹配中继上游出口；IPv4 MASQUERADE 迁移须通过 D11（未迁移）。 | 门户 `redirect_chain` 的两族 RETURN 必须位于厂商 DNAT **之前**；`-C` 成功不能证明位置正确。厂商只在 `zwrt_redirect.redirect.switch=1` 时写 DNAT；中继会话期间 agent 用易失 uci 改动把它设成 0。开关改动和两条 RETURN 都记在 `dns.json`，5 GHz 之间交接时原样交给新会话（之前的版本交接时释放开关几秒，期间的 fw3 重载写入过 DNAT）。RETURN 仍保留，以防开关读到 1。IPv4 MASQUERADE 留在 legacy，带注释 `zte-agent-wifi-relay`。 |
| 自有 legacy 规则的身份 | — | 在 `U60_*` 链里、跳到 `U60_*` 链，或带 `zte-agent*` 注释（`firewall::owned_rule`）。站点名不算身份：厂商的 IPACM 文件也列着 `ath20`；只有旧版创建过的名字（`ids::OLD_IFACES`：`u60sta0`、`u60mh0`）仍算，供它们的日志撤销。 |

### 4.4 ZTE 改写后的核对

`net-guard` 以脚本 IN_OPEN（`net_guard::WATCHED`）、ubus 事件（`EVENTS`）和 60 s 兜底调度，每个事件都算一次触发。触发后约 2 s 静默再全量核对（唤醒各 owner）；确实补回资源后，5 s 再查一次。触发后的 3 s 内，每 0.5 s 只读已声明的 sysctl，发现被改才写；写前确认仍是同一所有者和代次。0.5 s 是采样目标，不是设备恢复上界。

一次核对（`Transaction::reconcile`）每个 iptables 表只 `-S` 一次，路由、策略规则、地址每族各列一次，每一步对照列表判断；列表只在本次核对内有效（`net_tools::Pass`，中继 tick 让四个事务共用一次）。规则不在预测的列出形式里时才对它单独 `-C`。只有确定不在才重做；列表或工具失败记为“查不了”，留给下一次，从不因此重复添加。nft 表由 `NftTables::reconcile` 核对（§4.2）。忙的 owner 不挡其他 owner，本轮失败的资源保留待办。核对不靠来回删除正常规则恢复顺序；一次 fw3 reload、两次连续 reload、restart/flush 和只丢一个钩子是不同验收。中继 IPv6 的地址、路由、策略规则和 RA 由 IPv6 会话自己检查（§6.2），此外不给 3 s tick 另加检查。

中继连上后的那次 fw3 重载来自 agent 自己：IPv6 的 `ubus call network.interface.lan set_data` 让 netifd 跑 `iface` hotplug（`ifupdate`），`20-firewall` 随即 `fw3 -q reload`；重载运行厂商的 `firewall_init.sh`，把 brnf 写成 1 并清空 `redirect_chain`（2026-11-12 实测，[硬件转发](relay-hw-offload.md)第 5 节）。

### 4.5 conntrack：删除范围、代次、结果

只有 `netfx::conntrack` 删除条目，直接执行 `conntrack`，不经 shell。范围为 `Lan { v4, v6 }` 或 `Destinations(IPv4 前缀)`；后者也必须限定 LAN 来源，不能删路由器或其他接口的连接。每个请求带原因、范围及相应路径改变的代次/时刻。

- 同时考虑新旧计划的**首条命中结果**。只有两边直到最后一个放行点的有效判定都能以纯目的 IPv4 区间表达时，才用“旧 DIRECT 减新 DIRECT”。例如在原 DIRECT /24 前加 `DST-PORT,443,PROXY`，虽然 DIRECT 条文本身没变，已有 443 硬件流也必须退出。来源、端口、协议、复合条件或全域兜底无法可靠求差时，退回 LAN IPv4；超过 64 段同样退回（D10）。纯目的集合没有失去放行时，不为了重编同一张表清连接。UDP 不享受已有 TCP 的 socket 固定；需改路径时也纳入相应范围。
- 没有合并窗口（规范的“200 ms 内合并”未实现，§8）。合并只有两种：已完成的一次删除只有在**它开始于本次路径变化之后**、成功并覆盖全部请求范围时才可抵账；失败待重试的请求与下一个请求取并集，一次删除了结两者。删除在状态锁内依次进行。保留有界诊断，区分“成功删除、有证据的零匹配、操作失败”：conntrack-tools 1.4.8 的退出码 1 也可能是 netlink 错误，不能单凭返回码判断。部分失败记录待重试，不报告“已重置”。[conntrack-tools 1.4.8 源码包](https://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-1.4.8.tar.xz) 中的 `print_stats`（零匹配）和 `OTHER_PROBLEM`（操作失败）是两个不同分支。
- 删除 conntrack 不是给 TCP 发送 RST，也不是清理客户端 DNS 缓存。UI 按实际范围及结果显示。已卸载的流要以失去 DIRECT 的真实硬件流验证；路径没变的流在 B31 上能很快重新卸载。

### 4.6 准入 `Admission`

准入锁只登记/释放资源占用，不跨 ubus、Wi-Fi 重载、配置写盘或 CAC。扫描、连接、启动及恢复开始前先声明占用；清理失败时仍拥有残留资源。外部写入在同一临界区检查冲突并登记自己的操作，等待取得准入最多 3 s，超时回 409；自动连接看护不等。厂商异步 Wi-Fi reload 的冲突占用跟到 5 GHz 热点连续两次 `ENABLED`（相隔 2 s，最长 120 s）才释放。3 s 不代表任何设备操作在 3 s 内完成。中继自己的车主操作登记之后还要等中继的 `op` 锁，这一步没有上限（§3）。

厂商防火墙、LAN 修改与中继或 Mihomo 冲突；热点、访客、USB 修改按中继所有权判断。固定 DHCP 保留仍按自身写入/重载需要串行，不因任一功能运行就一律拒绝。长操作用 Slow lane；取消须能在两个 Slow 名额都被长操作占用时递增令牌、通知控制器，不在 Tokio 线程上等设备。

### 4.7 名字和编号 `netfx::ids`

| 范围 | 保留值与用途 |
| --- | --- |
| 策略路由 | Mihomo `pref 18620`、`fwmark 0x700/0xff00` → 表 60625 的本地路由；中继 `pref 18640` → 表 60631；IPA 的 main 默认路由和 unreachable 用 metric 60631。核心出站标志不能碰 TPROXY 或 ZTE 已用位。 |
| 表、接口、端口 | `ip`/`ip6 u60_relay` 归中继，`ip`/`ip6 u60_mihomo` 归代理。STA 为 `ath20`（B31 原厂 IPACM 配置列着它）；`ids::OLD_IFACES` 记着旧日志里可能出现的 `u60sta0`（2026-11-12 前的 STA 名）和 `u60mh0`。1053：DNS；17894：TPROXY；127.0.0.1:17893：认证下载；127.0.0.1:19090：核心控制；9090/9443：agent。 |
| 地址、其他 owner | `198.18.0.0/16` 是 fake-ip。统一登记地址常量，但代理私网例外、中继 DNS 例外、策略表 throw 和 IPA main 防护分别取其所需子集；不能把所有酒店私网都 throw。WireGuard 和 TTL 的自有链在这里登记，不在写入扫描范围内。 |

## 5. Mihomo

### 5.1 意图、核心与规则规划

`controller` 持有意图和已发布快照，记着内核可能持有的表（最后确认的一张，加上之后声明而未确认的各张：`reconcile` 以后可能把最后一张载入），收紧与否和“失去 DIRECT”的范围（`routing::lost_from`）都按这些表算，`reconcile` 载入的表也反映到发布的 bypass；它并决定保持、换链、重载或重启：这些决定写在 `Controller::follow`/`reload`/`restart` 里，和 `Port` 的设备调用交错（规范里纯函数的 `follow::plan / decide` 未实现，§8）；`core` 独占进程、托管 `config.yaml` 和控制器写操作；`intercept` 生成网络资源；`routing` 编译订阅规则及 DNS 过滤表，`routing::lost` 算出需清除的连接范围；`egress` 负责出口观测与去抖。慢操作在控制器线程上同步执行（§3），没有带代次的后台结果（§8）。

### 5.2 状态与失败行为

| 状态 | 网络效果和退出条件 |
| --- | --- |
| Off | 不持有拦截；关闭意图取消后台重试。若实际还有未撤完的效果，报 CleanupPending，不能报 Off。 |
| Starting | 先装 1053/17894 的非 LAN、非本机 INPUT 防护并准备 brnf/pacing 和两族策略路由，再启动核心。在首次安装完整表前验证进程、控制端、认证下载代理、透明监听和双栈 DNS，读回实际模式/选组。Backoff 发起的启动还保留 fake-ip 拒绝，直到完整表接管。 |
| Running | 按已确认的计划拦截；出口变化进 Restarting，DNS 过滤变化进 Reloading。首次启动或从 fail-open 恢复后清除能沿旧直连路径继续的连接；后者核对 LAN v4/v6。 |
| Restarting / Reloading | 保留策略路由、sysctl 和拦截。计划内重启先在旧核心还在服务时准备并校验新配置，再收紧（Hold 表）、停旧核心、起新核心，日志 `[mihomo] the restart held traffic for N ms`；新配置校验不过时旧核心继续服务，校验过了却起不来时退回之前的配置。`to_core` 有无 socket 时的 TCP/UDP 兜底 drop。就绪并完成核验后才发布 Running。热重载不关旧出口连接，出口变化必须重启。 |
| Backoff | agent 确认核心意外退出，或替代核心最终未能启动：撤常规拦截、sysctl 和策略路由，保留 LAN 到 fake-ip 的 TCP reset/UDP reject，页面显示“正在直连”、错误、次数和下次重试。快速失败不保证客户端立即重新查 DNS。 |
| CleanupPending | 停止/撤销失败：保留日志、所有权和具体错误，允许重试；不得把未知状态当作干净的 Off/Backoff 并覆盖外部资源。进入 D3 时的撤销失败也在这里：旧表可能仍把 LAN DNS 送到已经不在的核心，页面不说“正在直连”，按 D2 的定时器重试撤销，成功后转 Backoff 再启动。 |

启用意图仍在就自动重试：依次等 5、15、30、60 s，此后每 5 min；60 s 内退出连续 3 次，直接进入 5 min 档。稳定后清零；车主关闭使已排队的旧重试失效。开机先等厂商启动同步并回滚上个进程的中继日志，清理孤儿和残留路由；回滚失败且旧路由仍在时，不用该路由启动核心。随后按意图恢复 Mihomo，再重连最近一次符合条件的中继。若 agent 本身意外退出，须由进程外的恢复机制自动拉起，按持久意图恢复可用网络：处理失效的 1053 重定向、拦截、策略路由与 brnf，不等车主操作。恢复不得产生第二个网络 owner、对抗显式停止或与 OTA 试运行/回旧槽竞争。只有已确认的核心故障才走 D3，不能仅靠等待客户端重试消除黑洞。

开机顺序与上面一致：`Mihomo::start` 只发 `Boot`（同一次开机里接管旧表，否则回滚上个进程留下的）；全新启动等 `net-restore` 线程的 `restore`（`wait_for_boot` → 中继 `recover_idle` → `mihomo.restore` → 中继 `restore`，中继连上后再 `mihomo.restore` 一次）。在 Backoff（或撤销待重试的 CleanupPending）中，开机恢复的 `restore` 和一个新的 IPv4 出口都会立即重试，不等 D2 的下一档。重试时没有持有任何效果（启动在取得效果之前就失败了，或接管失败），就重新取得，而不是要求“从 Backoff 恢复”。接管失败时先回滚上一个 agent 的表（`Port::recover`）再进 Backoff；回滚也失败则 CleanupPending 并重试。

### 5.3 拦截表

保持独立的 `ip`/`ip6` 表、同一 owner。prerouting 只处理来自 `br-lan` 的包：先让**已有核心透明 TCP 会话**继续本地交付（保留其他标志位，再设 `0x700`）；排除 DNS 和本机目的，v4 fake-ip 强制 `goto to_core`，之后才处理私网例外、编译的 IPv4 规则和最终 `goto to_core`。LAN 53 用优先于中继 DNS 的 nat prerouting 重定向到 1053。IPv6 没有内核 DIRECT 规则段。ICMP 不进 TPROXY。

在 `to_core` 中，TPROXY、打标与 accept 同属一条规则。内核找不到可用的透明连接或监听时返回 `NFT_BREAK`，**仅跳过本规则余下部分**；因此计划内切换必须另有末尾 TCP/UDP drop，不能靠保留表名来阻止直连。计划内停旧核心前必须先装好阻断；agent 死亡后由独立恢复机制接管，不能把残留 drop 或无人监听的 DNS 重定向留给车主手动处理。已有 TCP 的匹配要在 DIRECT return 前；它不适用于 UDP、核心已重启的旧连接，也不能把通配监听误当成已建立会话。需用新 SYN（含目的端口 17894）和既有 TCP 验证匹配条件。[Linux TPROXY](https://github.com/gregkh/linux/blob/v5.15.194/net/netfilter/nft_tproxy.c#L49-L80) · [nft 规则执行](https://github.com/gregkh/linux/blob/v5.15.194/net/netfilter/nf_tables_core.c#L244-L247)

### 5.4 规则切换与 DNS

rule 模式按订阅顺序编译，select 的实际选择最终到 DIRECT 才可绕过；无法在内核证明安全的非 DIRECT 条件截断后续放行。保留 `no-resolve` 及规则顺序；带 `no-resolve` 的 DIRECT 地址规则不得遮蔽仍应代理的域名，无法判定时发 fake-ip 或留在核心。global/关绕过不放行普通公网 IPv4；direct 也不能放过 fake-ip。新旧规则对连接的影响按 §4.5 计算。

一次切换分三个可核验的步骤：

1. 对车主可控的写操作，先在同一控制器内登记新代次，收紧旧 DIRECT（拿不准就暂时取消相关绕过），使已失去资格的硬件流退出旧路径；若旧路径尚未排除，不确认该次切换已完成。桥接的模式/选组/规则 provider 写操作遵守同一顺序。例外：`domain` 规则集的刷新不经收紧和换表直接交给核心，因为内核链从不读它，它的名字在 DNS 过滤表里本来就是假地址。
2. 改核心状态，读回 `/configs`、`/proxies` 及实际 provider；DNS 过滤表变化才热重载。读取、应用或核对失败，保持保守表并重试。外部 provider 的内容、成员或选组可以自主改变。无法在更新前证明始终 DIRECT 的动态范围，从首次开放绕过前就留在核心，或让更新先经过控制器收紧放行；不得等看到文件变化才补救已误放的包。按内容而非 mtime 跟随替换，60 s 兜底只用于核对，不是允许直连的宽限。
3. 新 DNS/选组/规则确认一致后才扩大允许绕过的范围。客户端用路由器 DNS 先前发出的真实 A **新建连接**，也按新策略处理：对可能切换的域名稳定使用 fake-ip，并覆盖已发出、可能命中不变 DIRECT 前缀的旧地址。无法可靠区分时收起相关绕过；若核心也不能判明可直连，不能回落到 DIRECT。允许因此少用部分硬件加速。清 conntrack、只测新 DNS 回答或固定等几分钟，都不构成旧地址已受保护的证据。

### 5.5 热重载的成功条件

本期热重载用于**同一配置的 DNS 过滤表变化**。`PUT /configs?force=false` 的 JSON `payload` 是完整托管配置，保留实际 mode、log-level、`interface-name`、端口和 secret；秘密不入日志。v1.19.33 会暂停接入、更新代理/规则/DNS，继承 fake-ip 映射并按缓存恢复选组。暂停期间不仅新 TCP 受影响，既有 UDP/QUIC 的上行包也可能丢失。

204 只证明入口完成调用：provider 初始化错误可能只写日志，节点组为空时默认 `COMPATIBLE` 可直连。收到 204 后核对实际模式和接口、实际选组及必要 provider（不得意外退回 COMPATIBLE）、监听/下载代理状态，并向 1053 查询本次应该改变答案的测试域名或可验证等价项。**超时是结果未知**，读回能确认才提交，否则保持收紧并回退到校验后的保留拦截重启。切换订阅/配置继续保留上一份可用配置与选择；若以后也使用热重载，另验失败回滚、旧连接和内存。[配置入口](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/hub/route/configs.go#L405-L454) · [provider 加载](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/hub/executor/executor.go#L318-L338) · [UDP 检查](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/tunnel/tunnel.go#L420-L441)

### 5.6 出口变化

以**实际装过、撤过或改变的出口**为准：从未装路由的失败连接和扫描不触发重启；装过路由后才失败的会话及从已有会话切走的失败操作，仍要通知 Mihomo。相同出口不重复重启；完全没有出口时不重启，同一接口上补上 IPv6 也不重启。v4 有效变化立即处理；v6 持续 5 s 才处理，相关重启至少间隔 60 s；蜂窝沿用 15 s 出口审计和旧连接是否搁浅的判断。校验在托管配置文本（屏蔽 secret、去掉顶层 `interface-name`）、核心二进制和 geodata 依赖都相同时复用：保留最近 4 个通过的指纹（中继和蜂窝的配置、上一份配置），存在 `/data/zte-agent-mihomo/validated`，同一次开机内跨 agent 重启有效。所以只换出口接口时不重跑 `mihomo -t`。DNS 过滤表变化后走重启回退须重新 `mihomo -t`。

## 6. Wi-Fi 中继

### 6.1 会话与取消

会话没有显式阶段（规范的 `Idle/Scanning/Connecting/Active/Recovering/Disconnecting/RecoveryPending` 未实现，§8）。代码里只有 `Inner` 的 `session: Option<Session>`、开机恢复的 `restoring` 和日志文件是否存在：状态里的 `connected` 是“有选中的网络且有租约”，`recovery_required` 是“日志存在且未连接”，所以扫描、连接进行中和拆除等 CAC 的几十秒里也显示需要恢复。活动会话上的扫描保留其路由。掉关联由 `Association` 计时：12 s 内（`ASSOCIATION_GRACE`）回来且旧租约及助手仍有效则续约，否则拆除。车主断开、有效地址变更、热点关闭或连接取消走同一拆除路径；撤销失败时日志保留。运行中不后台重连；开机只恢复最近一次符合条件的成功连接，不轮询全部已保存网络。

先校验车主请求，再变更取消令牌和排队；各等待点和最终发布前都查同一代次，迟到的成功不能复活已断开的会话。仅在成功连接到开放网络或已有匹配凭据时写 `resume.json`；手动断开清除，掉线保留。热点被关掉时只有车主自己关的（`hotspot::off_by_owner`：`wifi_onoff_by_user`，或射频、SSID 的 `disabled`）才清除它；固件暂时关着 Wi-Fi（关机充电模式里 `wifi_onoff` 是 0）时会话照样拆除，重启选择保留，开机恢复跳过这次尝试（只有单元测试，路由器上没有复现）。开机恢复沿用有界重试（约 17 min），手动操作和车主关闭热点可取消。记住凭据与开机恢复是不同的意图。残留监视器核对本次 boot 的 PID、进程身份/私有参数，不因进程恰叫 `iw event` 而杀掉人工观测；已知会切 SELinux 域的无线及 DHCP 助手按私有路径清理。

连接顺序：先建受保护的 STA（§4.3），启动 supplicant，处理热点和 DFS 开关，关联并取得 DHCP。校验地址、网关和冲突后，先装地址、路由、NAT、转发防护和 DNS 数据面，策略规则最后；核实出口再接管可选的 IPA、resolv/门户和 IPv6，并发布会话。断开时停止 IPA 监视器，撤 RA/可选 IPv6、IPA main 路由、IPv4 选路和 DNS；实际出口改变即通知 Mihomo，不等后续最长 80 s 的 CAC。STA 确认断联才恢复热点，INPUT 防护最后撤。

### 6.2 运行检查和无线设置

每 3 s 只在活动会话观测 wpa 状态（经控制套接字，最多等 2 s）、带会话标识的租约、助手及热点开关。`decide`（`wifi_relay.rs`）区分关联宽限、有效续约、只变 DNS 与真正掉线；DNS 变化由 uplink 一处更新 resolv 标记行和下载器快照。IPv6 根据剩余寿命、DAD、优先级归属与保留 LAN 前缀维护路由/地址；撤 RA 在撤 NAT66 前。未变化路径的自有地址、路由、策略规则和 RA 由 `check_owned` 检查，只在 `net_guard` 触发已安静的那一拍、读失败后的下一拍、续写生存时间之前，或距上次满 15 s（`ipv6::CHECK_EVERY`）时运行：不发厂商触发的删除最晚约 15 s 发现（车主 2026-11-12 接受）。普通 IPv6 租约失效只撤可选片段，不能拆掉仍工作的 IPv4 及基线防护。时钟复核在调用线程上进行，最多等 3 s 取得中继的 `op`，不跨功能持锁。

上游省电仍按车主的 `keep-power-save` 意图在关联时处理，与路由器自身省电模式分开。删除不可靠的带宽自动调优（D5）；关联时的一次性宽度复位也在 2026-11-12 删除，agent 不再运行 `iwpriv … chwidth`，热点仍使用的信道/带宽解析在 `hotspot.rs`；取消 tuning API 和页面选项，已存 `auto` 迁为 `off`，保留其余网络参数。DFS 切信道开关：每次关联前确认厂商键 `wireless.zte_mbb.dfs_channel_switch_disable=1`（持久，车主批准；没有其他未提交的 `wireless` 改动时才提交），再 `iwpriv wlan2 disableDfsCS 0`。上下游共用射频、DFS 窗口、真实读回和恢复热点的固件要求继续遵守[设备指南](../../CLAUDE.md)。

## 7. IPA 硬件转发

只有 IPACM 开机时读到的配置列着 STA、正确的 `main` 默认路由和 HW 模式同时具备时，才可能卸载 IPv4。B31 的原厂配置已列着 `ath20`，agent 只读它（`offload.config`：`listed` / `not_listed` / `unavailable`）并负责 main 路由；HW/SW 模式归厂商，agent 不读、不切、不审计、不核验（车主决定，2026-11-12）：工作模式为极速模式（`Nomal_mode`）时加速打开，其他工作模式、厂商限速、省电和 `ipa_disable` 会关掉它，`Ai_mode`（出厂默认）和 `Game_mode` 随流量切换。IPACM 在启动时读接口表；不能用运行时重启 ipacm 补救。B31 的邻居退役和客户端 ARP STALE 仅在 `wa_inner_version=BD_CNMU5250V1.0.0B31` 且 ipacm 二进制哈希匹配时启用；不匹配时不加 main 路由，显示原因，走 CPU。详见[硬件转发说明](relay-hw-offload.md)。

状态机在 `wifi_relay::offload`，设备读写经 `IpacmPort`（配置状态、车主开关、指纹、监视器、加和撤 main 路由），用假实现跑状态转换和失败矩阵；main 路由在会话的 `Transaction` 里，conntrack 重置经 `netfx`。

| 状态 | 转换和所有权 |
| --- | --- |
| Off | 不需要或做不到：无会话、配置未加载、车主关闭、指纹不符、加路由失败（已加的部分先撤掉，快照不会在路由可能还在时报 Off）。 |
| Routed | main 防护和默认路由在位，邻居和客户端监视器在运行。卸载是否真的发生取决于厂商的模式，agent 不确认。 |
| Releasing | 停监视器，删 main 路由；失败保留恢复信息，停在这里不报 Off；仍要求开启时，撤完后重新加。路径变化（开、关、移除、重装）才通知 conntrack 重置 LAN IPv4。 |

从上一版升级时，日志里可能还有已删除的模式步骤的撤销（`@u60-relay-ipa sw`）：恢复和拆除时 `Cmd::undo` 跳过它并记 `[net] skipped an undo`，IPACM 停在当时的模式，直到厂商下次切换。

2026-11-12 之前的版本把 `u60sta0` 条目写进 IPACM 配置（安装要整机重启，另有备份、标记和原子替换）；这一套已删除，`POST /api/wifi-relay/offload` 只接受 `{"enabled":bool}`。页面有一行 “IPA CONFIGURATION” 显示配置状态，在路由就位时写“极速模式下走硬件（IPA），其他工作模式走 CPU”，并单列“公网 IPv4 当前由 Mihomo 处理”。

## 8. 规定了但未实现

下面各项在 2026-11-10 的规范里规定过，代码里没有。前面各节写的是代码现状；这里列出规范原意、现状和推迟原因，供以后决定是否实现。

| 规范 | 代码现状 | 为什么没做 |
| --- | --- | --- |
| `EffectSet` 层（§4.1、§4.2）：每个 owner 一个 set，`declare` 批量声明或替换、`withdraw`、`step`；分类型资源 `NftTable`、`LegacyChain`、`LegacyHook`，自有链整链替换，钩子查存在、无重复和相对终局规则的位置 | `net_tools::Transaction` 的命令步骤加 `netfx::effect::NftTables`；资源类型从 argv 推断（`Cmd::checkable`、`Cmd::present_in`、`firewall::listed_rule`）；legacy 规则逐条写、逐条核对，重复副本只在撤销时清除，只有门户 RETURN 查位置 | 车主决定暂不做（2026-11-12）。评审 D 第 9 条：整体统一要 1–2 周，旧日志 `{boot, undo: Vec<Cmd>}` 必须仍能被旧版撤销，风险高 |
| 中继控制器线程（§3）：一个线程串行处理扫描、连接、换网、断开、开机恢复和 3 s 检查，车主请求进队列 | 操作在调用线程上执行，由 `op` 锁串行，等待没有上限；tick 持 `inner` 做设备 I/O | 车主决定暂不做（2026-11-12）。评审 D 第 5 条估计完整控制器 3–5 天、中高风险；它另提出两步小改（会话阶段进快照、车主请求等 `op` 设上限），约 1 天 |
| 中继会话阶段（§6.1）：`Idle/Scanning/Connecting/Active/Recovering/Disconnecting/RecoveryPending` | 只有 `Option<Session>`、`restoring` 和日志是否存在；操作进行中状态也显示 `recovery_required` | 随中继控制器一起推迟（评审 D 第 5 条） |
| 中继发布带代次的出口快照（§3） | `Message::Egress` 不带内容，Mihomo 自己观测；租约 DNS 经 `set_subscription_dns` 传给下载器 | 评审 D 第 2 节认为影响小，没有单独安排 |
| HTTP 只读快照（I2、§3） | 中继状态每次读几个文件，还要等 conntrack 的状态锁（不再写文件：`ipacm-loaded` 随安装一起删了） | 未安排；评审 D 第 8 条建议在 `publish` 时算好这些值 |
| Mihomo 后台任务与带代次的结果（§3、§5.1） | 校验、规则集 PUT、热重载、`nft -f`、conntrack 删除都在控制器线程上同步做，其间核心退出和命令排队；只有 HTTPS 时钟校验移到了自己的线程。换配置时校验降低优先级，但不是后台任务 | 评审 E 第 11 条：取决于把准备步骤移到 Hold 之前（第 4 条）后还剩多少阻塞。第 4 条已做（2026-11-12），剩下的阻塞是否值得做后台任务，还没有评估 |
| `follow::plan / decide`（§5.1、I6）：纯函数决定保持、换链、重载或重启 | 决定写在 `Controller::follow`/`reload`/`restart` 里，和 `Port` 调用交错；靠 `Port` 的假实现重放 | 评审 E 第 11 条没有给出推迟理由；它指出这种交错让“中途失败之后”的记账容易出错 |
| conntrack 请求在 200 ms 内合并（§4.5） | 只有“变化之后开始的成功删除可抵账”和失败待重试请求的并集 | 未安排 |
| nft 表的内容核验（§4.2：首次应用、集合变更或异常后核验全量内容） | 只比代次标记和每条链的规则条数 | 评审 E 第 11 条：ZTE 不碰 nft，没有别的写入者，可以接受 |

另有两项是规范里带门槛、按门槛暂不启用的：核心出站标志位 M13（`ids::CORE_OUT_MARK` 为 `None`，等设备核对空闲位）和 IPv4 MASQUERADE 迁到 nft（D11，等 ≥220 Mbit/s 硬件下载证明不影响卸载）。
