# Wi-Fi 中继与 Mihomo：架构

定稿：2026-11-10，原是目标规范；2026-11-12 起改为描述代码现状。规定了但没有实现的部分集中在[第 8 节](#8-规定了但未实现)，正文在相应位置写“未实现（§8）”。车主在 2026-11-12 决定实现的 `EffectSet` 层和中继控制器线程已在批次 5 完成，验证范围见[实现记录](relay-mihomo-implementation.md#batch-5)。[版本与验收](relay-mihomo-refactor-plan.md)是 v1–v6 的交付顺序。[产品说明](mihomo-relay-prd.md)描述已发布行为；[设备约束](../../CLAUDE.md)适用于全部版本。车主已确定自动恢复、provider 自主刷新零误直连和旧真实地址保护；[验收条件](relay-mihomo-refactor-plan.md#owner-decisions)同样适用于 v2/v3。

## 1. 不变式

| 编号 | 实现与验收共同遵守的约束 | 代码现状 |
| --- | --- | --- |
| I1 | 中继和 Mihomo 的 nft、iptables-legacy、地址、路由、策略规则、sysctl、conntrack 写入只经 `netfx`，可撤销资源归 `netfx::effect::EffectSet`；一项资源只有一个 owner。agent 不写 IPACM 的配置文件（`wifi_relay::offload` 只读它）；核心进程、托管配置及影响路由的核心 API 写操作由 Mihomo 控制器排序。ZTE 是外部写入者；WireGuard 和 TTL 的 legacy 链不在本次迁移范围。 | 随 `cargo test` 的源码扫描（`netfx::boundary`）识别资源和步骤，10 项例外见 §4。agent 既不写 IPACM 的配置，也不写它的 HW/SW 模式（§7）。 |
| I2 | 不持跨功能锁做设备 I/O。HTTP 读状态只取快照；在单线程 Tokio 上不得阻塞等待控制器、运行命令或调用阻塞 HTTP。中继的关联、CAC、撤销或核对不能挡住 Mihomo 的退出处理、重试或 brnf 修复。 | `relay` 与 `mihomo` 各自串行执行设备操作。中继会话由控制器独占，状态和扫描列表经短锁发布，`active()`、`owns_network()` 读原子值和准入登记（§3）。 |
| I3 | 对可撤销的自有效果，先持久记录本次开机的撤销依据，再生效；只能撤自己的东西。部分执行、执行前被杀、重复撤销都可恢复。conntrack 删除不可逆，按已生效的策略代次记录结果，不伪造 undo。 | `EffectSet` 在批量生效前一次持久写入撤销，日志为 `{boot, undo: Vec<Cmd>}`，撤销遇错保留剩余项（§4.1）。 |
| I4 | 控制器主导的计划内重启、重载和规则切换，必须先收紧受影响的内核绕过，核心不可接包时阻断本应拦截的流量，核验后才扩大 DIRECT。provider 自主刷新也不允许误直连；用旧 DNS 真实 A 新建的连接必须遵守新策略，无法证明可直连的流量不得绕过。agent 仍在且确认核心意外退出，或计划内重启最终失败时，按 D3 撤常规拦截、显示正在直连并重试。单次 nft 写失败、PUT 超时或读回失败本身不授权直连。 | 由 Mihomo 控制器按 §5.4 的顺序做。 |
| I5 | 在有 nft 支持的本机网络层，拒绝放在 agent 的 nft 表；穿过厂商 DROP/reject 的放行和门户 RETURN 留 legacy。nft 里的 return/accept 都不能替代 legacy 的放行。NAT 是地址转换，迁移有单独门槛。 | 相符：`wifi_relay::uplink` 一处拼装。 |
| I6 | 决策输入包括意图、有效观测、先前状态和单调时间，输出为动作；设备读写在适配器。可用假时钟和假设备重放退出、重试、切换和撤销。 | Mihomo 的 `Port`、IPA 的 `IpacmPort` 和中继的 `controller::Port` 都可用假实现重放，中继测试推进假时钟，继续使用纯函数 `decide`/`lease_change`/`Association`。Mihomo 的决策和 `Port` 调用仍交错（`follow::plan/decide` 未实现，§8），IPv6 仍无自己的端口。 |
| I7 | 持久意图、实际观测、希望应用的计划与最近确认生效的计划分开。状态页不能因配置已保存、命令已发出或核心进程在运行就显示“已生效”。 | `EffectSet` 中的 nft 表分开记目标和已确认代次；中继控制器在最终发布前检查取消，只在操作结束后仍有日志且没有待处理断开时才报 `recovery_required`（§6.1）。Mihomo 每代的绕过设置存在 `Prepared.bypass`，计划不直接读取意图文件。 |

## 2. 产品与设备边界

- 管理端拒绝来自 `rmnet*` 或中继上游 `ath20`（按确切名字）的对端（D1），沿用现有接口分类、本机/Tailnet 例外和失败策略。它只保护 agent 的 9090/9443，不能代替对所有设备监听端口的上游 INPUT 防护。
- 保留双栈，不做“IPv4 优先”（D4、M14）。透明代理处理从 `br-lan` 进入的 TCP/UDP；本机、私网等例外仍走原路径，不代理路由器的一般 OUTPUT。外网 IPv6 始终进核心，没有 IPv6 fake-ip 池。只有符合 DIRECT 的 IPv4 可绕过核心并有机会被 IPA 卸载。默认不开绕过。
- TPROXY 工作时必须将 `bridge-nf-call-iptables` 和 `bridge-nf-call-ip6tables` 设为 0；车主接受在此期间依赖 brnf 的访客隔离失效。固件会重写 legacy、路由与 sysctl；B31 没有 `NFT_FIB_INET` 和 nft bridge family。使用分开的 `ip` / `ip6` 表，链名避开 `fwd`、`post`、`c`。
- 中继 CPU 转发抢在 ZTE 的部分 FORWARD 过滤之前；IPA 卸载的流也不走这条 CPU 路径。开启相关家长控制或网址过滤时页面提示实际影响（D8）。不主动开启蜂窝、不重启 ipacm、不踢客户端。蜂窝协调不在本次范围。

## 3. 线程、锁、消息与状态

Mihomo 和中继各用一个串行控制器线程。中继的会话、扫描列表、最近错误、阶段、关联计时、guard 游标和开机恢复日程由 `relay` 线程独占。跨功能占用由 `netfx::admission` 登记（§4.6）。两者之间的运行时业务通知为中继装过或撤过路由后发 `Message::Egress`；核心退出、HTTP 命令和重试定时器各自进入 Mihomo 控制器。

| 执行者 | 代码现状 |
| --- | --- |
| `relay` | 按到达顺序处理带回复的 Boot、Restore、Scan、Connect、PowerSave、Offload、Forget、Clock，以及 Disconnect、Tick、内部 Retry/Wake。设备操作经 `controller::Port`，实际为 `wifi_relay.rs::DevicePort`，测试用脚本化假端口和假时钟。会话选定网络后每 3 s 检查，`net_guard` 安静后立即排 Tick，长操作中的触发合并成一次后续检查。车主请求等待准入与开始执行合计最多 3 s，开始后等结果，放弃的请求不会迟到执行。断开由本线程拆除（§6.1）。线程 panic 记日志并 abort，由 guard 重启 agent 后接管连接。 |
| `mihomo` | 串行处理车主命令、影响路由的桥接写、出口变化、`net_guard` 唤醒、子进程退出、重试和规则集刷新。慢调用都在本线程同步做：启动前的 `mihomo -t`（最长 30 s）、规则集 PUT（30 s）、热重载 PUT（15 s）、`nft -f`（20 s）、最多 64 次 `conntrack -D`（各 8 s）；其间核心退出和车主命令排队，命令最多等 150 s（`COMMAND_WAIT`）。后台任务和带代次的后台结果未实现（§8）。计划内重启、DNS 过滤表热重载和选中订阅的变更刷新都由控制器准备并校验 `candidate.yaml`，不覆盖正在服务的 `config.yaml`；旧核心服务期间的校验降低优先级（`GOMAXPROCS=1`、`GOMEMLIMIT=128MiB`、nice 10），仍同步占用控制器线程。保存/选择配置及非选中订阅的变更刷新仍在调用方校验；字节相同的刷新不编译、不校验。经中继启动核心时的 HTTPS 时钟校验在自己的线程（`mihomo-clock`，同时只有一个）上跑，核心不等它。控制器线程 panic 时记一行日志并结束 agent（`Controller::supervised` → `abort`），由 `zte-agent guard` 重新拉起，新 agent 接管本次开机的表。 |
| `mihomo-core-wait` | 每个子进程只有一个回收者。停止路径给已确认属于该代的进程发信号；等待者负责 wait/reap，回送 `Exited { generation, how }`。控制器忽略旧代退出和已取消的定时器。 |
| `net-guard`、`net-guard-sample` | 订阅 inotify/ubus、合并触发，只负责唤醒：各 owner 在自己的循环里问 `Cursor::due()`，所以一个 owner 忙时不挡别的 owner。采样线程在触发后的 3 s 内维护已登记的 sysctl。`relay-neigh` / `relay-lan` 归当前 IPA 会话，退出后不能再操作下一次会话。 |
| HTTP、页面、Zashboard | Mihomo 页面读控制器发布的不可变快照；车主命令交给控制器。重启或热重载期间，普通控制命令排队，桥接写回 503。已放行的在途写必须与切换排序，不能凭请求开始时读到的 Running 快照跨代写入。保留桥接的现有认证、同源和端点限制。 |

中继的 `resume.json`、已保存网络、IPv6/省电和 IPA 开关表达车主意图。Mihomo 的 `enabled`、`cn-direct`、`profiles.json` 表达启用、绕过和配置选择。托管配置开启 `profile.store-selected` 和 `profile.store-fake-ip`；`selected.json` 只为启动前生成配置提供初值，第一张带 DIRECT 放行的运行表必须依据**本代就绪后**实际读到的模式和选组。

其他线程只共享状态/扫描列表快照、`active`/`owned` 原子值、取消单元、队列发送端、合并 Tick 的标志及准入登记。取消单元保存恢复代次、恢复目标、待断开、工作/拆除状态和空闲断开的回复。锁序为取消单元 → 请求开始握手 → 快照。请求的开始与放弃在同一握手锁下决定，控制器执行期间登记 `RELAY_OPERATION`。

端口的粗粒度操作为 `scan`、`join`（准备、交接或清理旧会话、关联、DHCP 和计划）、`cleanup`、`adopt`、`recover`。运行检查用 `observe_link`、`observe`、`renew`、`maintain`，意图和设置用 `target`、`clear`、`persist`、`hotspot`、`power_save`、`offload`、`forget`、`clock`。关联和拆除日志已去掉 `lock_ms`。

中继状态（`WifiRelay::status`）只读内存。`publish` 预先计算重启选择 `autostart`、残留日志、`offload.config`/`enabled`、`power_save.auto_off` 和已保存网络；GET 复制快照，再读内存里的时钟错误、Mihomo IPv4 路径和连接重置历史。历史有独立的 `RESULTS` 短锁，不在删除期间持有。状态请求不读文件，也不更改恢复意图。

出口：中继不发布出口快照（未实现，§8）。`Message::Egress` 不带内容，Mihomo 自己观测出口（`mihomo/egress.rs`），判定哪些变化需要重启；中继在 `publish` 时把租约 DNS（没有时用网关）交给下载器（`set_subscription_dns`），会话结束清空。核心关着或正在安装时不为出口消息报错或重启；在 Backoff 中，一个新的 IPv4 出口会让控制器立即重试（§5.2）。

## 4. 网络效果层（`netfx::effect::EffectSet`）

I1 的写入边界有随 `cargo test` 运行的源码扫描测试（`netfx::boundary`），识别 `EffectSet` 资源与步骤以及 `netfx` 的写入路径，覆盖 legacy、nft、地址、路由、策略规则、sysctl 和 conntrack。扫描在命令构造处识别写入，覆盖所有 `ip` 对象、iptables/ip6tables 及 restore、nft、conntrack、sysctl 和 `/proc/sys` 写入。它用轻量词法扫描跳过注释、无关字符串、测试及只读检查。WireGuard 和 TTL 的既有 legacy 写入按 §4.7 不在范围内。

例外逐项匹配文件、函数和命令，并记录原因；失去匹配的例外会使测试失败。当前 `netfx::boundary::ALLOWED` 有 10 项，包括 `wifi_relay::prepare` 的站点 MAC 设置和 link-up（日志撤销接口），已记账的 `@u60-relay-steer` 内部 backlog 写入，IPv6 的两处 `addr change` 寿命刷新和两个路由工厂，以及两个 IPACM 监视器的三种邻居写入。IPv6 地址撤销已纳入资源路径。`netfx` 提供有界命令（`exec`）、私有文件（`files`）、名字与编号（`ids`）、唯一的 conntrack 写入者（`conntrack`）、效果层（`effect`）和准入（`admission`）。

### 4.1 日志、撤销与资源归属

一份日志对应一个 `netfx::effect::EffectSet`。`new(owner, path)` 新建，`load` 读取本次开机的日志，`current` 检查 boot，`recover` 撤销残留。`declare(resources)` 先把整批撤销一次持久写盘，再按顺序应用，连续的同工具 legacy 资源合成 `iptables-restore`/`ip6tables-restore --noflush --wait 2` 事务。已持有的资源按键替换，`adopt` 接管已有日志和资源，`step` 为命令式步骤先记撤销再运行。`withdraw(keys)` 撤指定资源，`release()` 撤全部，均从最新的 undo 开始，遇第一个失败即停并保留剩余项，仍报 `Network cleanup paused: …`。每次拆除在失败或结束时保存一次日志，全部撤完则删除日志。`journaled` 查撤销命令，`tables_status`/`tables_confirmed` 查询 nft 状态。

资源类型在 `netfx/effect/resources.rs` 中定义，从描述生成键、应用、核对和 undo。`net_tools.rs` 保留日志命令 `Cmd`、命令式 `Step`、核对列表 `Pass`、结果 `Reconciled` 和进程工具。旧事务、argv 资源推断及计划构造器已删除，内部命令由 `netfx/effect/internal.rs` 的处理表分发。

nft 撤销由所属 set 记账，Mihomo 为 `@u60-mihomo-nft remove`，中继为 `@u60-relay-nft remove ip` 和 `@u60-relay-nft remove ip6`。

归属以 owner 和已记账资源为准。nft 表须有本 owner 的代次标记，legacy 自有链首次用 `-N` 声明，同名外部链会被拒绝并保留（`tests/relay-firewall-qa`）。中途失败按日志反序撤回，包含可能尚未执行的步骤，因此 undo 须接受对象已不存在且只匹配自有对象。工具或锁失败时保留日志及 `owns_network`。确定已撤的依据为列表里没有该链，或 `iptables` 退出 1 并报 B31 的两种缺失措辞之一（`netfx::effect::legacy::no_rule`）。自有规则的副本逐一删除，自有 `U60_*` 链在没有外部跳转后清空并删除，其他规则只执行原有的精确撤销（`legacy::undo`）。

### 4.2 资源、核验与日志兼容

| 资源 | 取得后如何维护 |
| --- | --- |
| nft 表（族、表名） | 一个表一个 owner。用 `nft -f` 整表原子替换，过期集合随之消失；两族放入同一 nft 批处理。分别保留目标代次和最后一次读回确认的代次。写失败时目标仍待重试；读回失败是“未确认”。内容与已确认目标相同、且读回仍在内核里时不再载入。核对用一次 `nft -t list ruleset` 读两族（ZTE 不写 nft，里面只有 agent 的表），比对代次标记和每条链的**规则条数**；集合元素被清空或规则被等量替换查不出来（内容核验未实现，§8；没有别的写入者碰 nft）。 |
| `LegacyChain` | 描述一条自有 `U60_*` 链及有序规则。首次用 `-N` 创建，替换/修复时将 `:NAME - [0:0]` 和全部规则放进同一 restore 事务，核对内容和顺序，undo 为 `-X`。B31 两族实测该声明会清空再填充自有链，证据为 `measurements/b5-qa-scripts/restore-chain-probe.txt`。 |
| `LegacyHook` | 描述厂商链里跳向自有链或带 `zte-agent*` 注释的一条规则，核对恰有一份，重复时修复。`InsertFirst` 在添加/补回时插第一条，之后保留厂商在其前面插入的规则（INPUT、FORWARD、IPv4 MASQUERADE）。`BeforeVendor` 每次检查位置，将排在厂商 DNAT 后的门户 RETURN 在同一 restore 事务里删除并插到第一条。目标链就位后才应用钩子，undo 为精确 `-D`。 |
| `Route`、`Rule`、`Addr`、`Sysctl` | 从族、接口、表、优先级等描述生成 `ip … add`/`del` 及核验。sysctl 首次记原值，向 guard 登记采样，undo 为 `@u60-sysctl key original`。IPv6 寿命、DAD 和冲突由会话根据活租约核验（§6.2）。 |
| `Internal`（`@u60-*`） | 名称对应 `netfx/effect/internal.rs` 的处理表，`Cmd::run`/`Cmd::undo` 据此调用无线、漫游、RA、DNS、门户开关、steering、省电和 nft 等处理器。处理器声明可核对性，射频切换等命令式操作只在操作流程中执行。 |

中继的五个 set 各对应原有日志文件。

| 日志 | 资源归属 |
| --- | --- |
| `wireless.json` | IPv4 `U60_RELAY_IN` 与 INPUT 钩子、两族 nft 表、站点、漫游、热点信道和关联，`uplink` 共享此 set 并声明表。 |
| `network.json` | IPv4 地址、路由、`U60_RELAY_FWD` 与 FORWARD 钩子、MASQUERADE、策略规则，以及 steering、省电和 IPA main 路由。 |
| `dns.json` | 两族门户 RETURN、解析器、门户开关。 |
| `ipv6-setup.json` | 站点 IPv6 sysctl、`U60_R6_IN` 及 INPUT 钩子。 |
| `ipv6-network.json` | IPv6 地址、路由、`U60_R6_FWD` 及钩子、策略规则、RA。 |

Mihomo 在自己的目录持有 `network.json`，仍写同样的九条 undo，顺序相同。两者都沿用 `{boot, undo: Vec<Cmd>}`。`ra-runtime.json` 保留专用覆盖值、owner、boot id 和 `withdrawing`，外部设置的零寿命仍由其归属判断保护。不同 boot 清理旧日志，本次开机的孤儿和旧日志即使没有启用意图也要清理。批次 5 在隔离 Linux 用 `ef58bd4` 二进制完整撤销新日志，新版撤旧日志和接管布局由旧日志字面量单测及真机活动会话升级覆盖，具体范围见实现记录。

升级和自动回退使用同一恢复契约：新版本读 v1；只要旧 A/B 槽或救援 Stable 仍可能启动，新版写出的日志就必须可被它**解析且完整撤销**。可在 v1 的 `{boot, undo: Vec<Cmd>}` 外壳增加新字段，但 `undo` 必须是最老受支持版本确实执行得了的命令。做不到就延后激活该效果，或先交付不依赖候选 agent 的兼容恢复器。跳过未知 `@u60-*` 只用于尽力处理历史残留，不算回退验收。手动先关功能不是 OTA 自动回退的前提。

### 4.3 防火墙：先在 nft 排除合法流量，再由 legacy 放行

`wifi_relay::uplink` 统一拼装两族的 `u60_relay`，`ipv6` 只提供租约有效期间的片段。`iifname` 形式的上游 INPUT 防护在 `ath20` 拉起前建立，纯扫描也建立；取得租约后扩展表，释放路由时先缩回仅防护，确认 STA 断联/移除后才撤。以下顺序是规则规范；“返回”指退出**本 agent 的防护链**，之后仍受厂商规则约束。

| 方向 | nft 自有规则 | 必要的 legacy 例外 |
| --- | --- | --- |
| 上游 INPUT v4/v6，`filter - 1` | 只约束 `iifname ath20`。v4 允许 established/related 和 DHCP 67→68 后 drop。未请求 IPv6 或尚未启用发现时保持上游 v6 关闭；发现开始前才允许 established/related、RA（链路本地源、跳数 255）、NS/NA（跳数 255）、ICMPv6 错误 1–4、DHCPv6 547→546，拒绝其余。 | v6 需要 `U60_R6_IN` 在 ZTE reject 前放行。v4 在证明首租、单播续租、广播重绑定和已建立回程都能穿过厂商 INPUT 前保留相应放行；仅看到 ESTABLISHED 规则不够。 |
| IPv4 FORWARD，`filter - 1` | 先返回 `br-lan → ath20`，再返回 `ath20 → br-lan` 的 established/related；然后 drop 其余从/向 `ath20` 的流量。其他接口保持原路径。 | `U60_RELAY_FWD` 放行同样的合法流量，共两条（去程、已建立/相关的回程）。 |
| IPv6 FORWARD / OUTPUT | 从 `br-lan` 向 `rmnet*` **先 reject**，不让后面的本地/组播例外覆盖它。NAT66 有效时返回经认可 LAN 源到 `ath20` 的去程、从该接口到 LAN 的 established/related 回程，再拒绝其他涉及该上游的转发。基线对其余 LAN 转发保留 `fc00::/7`、`fe80::/10`、`ff00::/8` 的本地例外，拒绝其他外部 v6；与中继无关的转发不受影响。OUTPUT 只需一条向 `rmnet*` 的拒绝。 | 合法 NAT66 流仍经 `U60_R6_FWD` 穿过厂商过滤。OUTPUT 拒绝归**中继基线**，覆盖 IPv6 未开启、租约丢失、NAT66 撤销后仍有 IPv4 中继的时段。 |
| DNS、门户和地址转换 | `u60_mihomo` LAN DNS 优先于 `u60_relay`；中继区分 LAN DNS 与路由器 DNS，保留管理地址和必要的本地例外。核心出站采用经设备核对的独立掩码位后，中继 DNS OUTPUT 遇该位返回（M13；尚未启用，`ids::CORE_OUT_MARK` 为 `None`）。NAT66 只匹配中继上游出口；IPv4 MASQUERADE 迁移须通过 D11（未迁移）。 | 门户 `redirect_chain` 的两族 RETURN 必须位于厂商 DNAT **之前**；`-C` 成功不能证明位置正确。厂商只在 `zwrt_redirect.redirect.switch=1` 时写 DNAT；中继会话期间 agent 用易失 uci 改动把它设成 0。开关改动和两条 RETURN 都记在 `dns.json`，5 GHz 之间交接时原样交给新会话（之前的版本交接时释放开关几秒，期间的 fw3 重载写入过 DNAT）。RETURN 仍保留，以防开关读到 1。IPv4 MASQUERADE 留在 legacy，带注释 `zte-agent-wifi-relay`。 |
| 自有 legacy 规则的身份 | — | 在 `U60_*` 链里、跳到 `U60_*` 链，或带 `zte-agent*` 注释（`netfx::effect::legacy::owned_rule`）。站点名不算身份：厂商的 IPACM 文件也列着 `ath20`。 |

IPv4 自有链为 `U60_RELAY_IN`、`U60_RELAY_FWD`，IPv6 为 `U60_R6_IN`、`U60_R6_FWD`。IPv6 INPUT 直接挂 `-i ath20 -j U60_R6_IN`。跨版本接管时，旧会话的 IPv6 `U60_RELAY_IN` 及跳转随旧日志保留到该会话拆除。

### 4.4 ZTE 改写后的核对

`net-guard` 以脚本 IN_OPEN（`net_guard::WATCHED`）、ubus 事件（`EVENTS`）和 60 s 兜底调度，每个事件都算一次触发。触发后约 2 s 静默再全量核对（唤醒各 owner）；确实补回资源后，5 s 再查一次。触发后的 3 s 内，每 0.5 s 只读已声明的 sysctl，发现被改才写；写前确认仍是同一所有者和代次。0.5 s 是采样目标，不是设备恢复上界。

一次核对（`EffectSet::reconcile`/`reconcile_only`）用 `net_tools::Pass` 让同一线程上的各 set 共用列表，每个工具/表及每族 `ip` 对象种类列一次，修复后使列表失效再读。只有确定缺失或不符合资源声明才修复，列表或工具失败报 `… not checked: …`，下次再查，nft 载入失败带具体错误。自有链按整链内容和顺序修复，若工具仍以预测外的形式列出，记一次 `[net] listed in a form not predicted: …`，保存这次读回供后续核对。仅由 `-C` 找到的钩子保留并记一次日志。钩子核对副本数，只有门户 RETURN 持续核对位置（§4.2）。

guard 修复日志列应用命令或资源描述，例如 `iptables -t nat hook redirect_chain -i br-lan -m comment --comment zte-agent-wifi-relay -j RETURN`。忙的 owner 不挡其他 owner，本轮失败的资源保留待办。一次 reload、连续 reload、restart/flush 和只丢一个钩子分别验收。中继 IPv6 的地址、路由、策略规则和 RA 仍由 IPv6 会话检查（§6.2）。

中继连上后的那次 fw3 重载来自 agent 自己：IPv6 的 `ubus call network.interface.lan set_data` 让 netifd 跑 `iface` hotplug（`ifupdate`），`20-firewall` 随即 `fw3 -q reload`；重载运行厂商的 `firewall_init.sh`，把 brnf 写成 1 并清空 `redirect_chain`（2026-11-12 实测，[硬件转发](relay-hw-offload.md)第 5 节）。

### 4.5 conntrack：删除范围、代次、结果

只有 `netfx::conntrack` 删除条目，直接执行 `conntrack`，不经 shell。范围为 `Lan { v4, v6 }` 或 `Destinations(IPv4 前缀)`；后者也必须限定 LAN 来源，不能删路由器或其他接口的连接。每个请求带原因、范围及相应路径改变的代次/时刻。

- 同时考虑新旧计划的**首条命中结果**。只有两边直到最后一个放行点的有效判定都能以纯目的 IPv4 区间表达时，才用“旧 DIRECT 减新 DIRECT”。例如在原 DIRECT /24 前加 `DST-PORT,443,PROXY`，虽然 DIRECT 条文本身没变，已有 443 硬件流也必须退出。来源、端口、协议、复合条件或全域兜底无法可靠求差时，退回 LAN IPv4；超过 64 段同样退回（D10）。纯目的集合没有失去放行时，不为了重编同一张表清连接。UDP 不享受已有 TCP 的 socket 固定；需改路径时也纳入相应范围。
- 没有合并窗口（规范的“200 ms 内合并”未实现，§8）。合并只有两种：已完成的一次删除只有在**它开始于本次路径变化之后**、成功并覆盖全部请求范围时才可抵账；失败待重试的请求与下一个请求取并集，一次删除了结两者。删除在状态锁内依次进行。保留有界诊断，区分“成功删除、有证据的零匹配、操作失败”：conntrack-tools 1.4.8 的退出码 1 也可能是 netlink 错误，不能单凭返回码判断。部分失败记录待重试，不报告“已重置”。[conntrack-tools 1.4.8 源码包](https://www.netfilter.org/projects/conntrack-tools/files/conntrack-tools-1.4.8.tar.xz) 中的 `print_stats`（零匹配）和 `OTHER_PROBLEM`（操作失败）是两个不同分支。
- 删除 conntrack 不是给 TCP 发送 RST，也不是清理客户端 DNS 缓存。UI 按实际范围及结果显示。已卸载的流要以失去 DIRECT 的真实硬件流验证；路径没变的流在 B31 上能很快重新卸载。

### 4.6 准入 `Admission`

准入锁只登记/释放资源占用，不跨 ubus、Wi-Fi 重载、配置写盘或 CAC。扫描、连接、启动及恢复开始前先声明占用；清理失败时仍拥有残留资源。外部写入在同一临界区检查冲突并登记自己的操作，等待取得准入最多 3 s，超时回 409；自动连接看护不等。厂商异步 Wi-Fi reload 的冲突占用跟到 5 GHz 热点连续两次 `ENABLED`（相隔 2 s，最长 120 s）才释放。

中继的扫描、连接、省电、硬件转发开关、忘记网络和时钟请求由 HTTP 阻塞池取得准入并入队，对准入和控制器开始执行合计最多等 `admission::WAIT`（3 s）。等不到时回 HTTP 409，JSON 为 `{"ok":false,"error":"A network operation is in progress (<phase>); retry after it finishes","phase":…}`，并在握手锁下放弃请求，控制器随后跳过它。开始后调用方等结果。厂商写入或 Wi-Fi 尚在应用的冲突也回 409，其他操作失败仍回 503。HTTP gate 另有限时。断开立即取消代次并登记待断开，由控制器拆除，空闲时调用方等待拆完（§6.1）。

厂商防火墙、LAN 修改与中继或 Mihomo 冲突；热点、访客、USB 修改按中继所有权判断。固定 DHCP 保留仍按自身写入/重载需要串行，不因任一功能运行就一律拒绝。长操作用 Slow lane；取消须能在两个 Slow 名额都被长操作占用时递增令牌、通知控制器，不在 Tokio 线程上等设备。

### 4.7 名字和编号 `netfx::ids`

| 范围 | 保留值与用途 |
| --- | --- |
| 策略路由 | Mihomo `pref 18620`、`fwmark 0x700/0xff00` → 表 60625 的本地路由；中继 `pref 18640` → 表 60631；IPA 的 main 默认路由和 unreachable 用 metric 60631。核心出站标志不能碰 TPROXY 或 ZTE 已用位。 |
| 表、接口、端口 | `ip`/`ip6 u60_relay` 归中继，`ip`/`ip6 u60_mihomo` 归代理。STA 为 `ath20`（B31 原厂 IPACM 配置列着它）；2026-11-12 之前的版本用的名字（`u60sta0`、`u60mh0`）不再识别。1053：DNS；17894：TPROXY；127.0.0.1:17893：认证下载；127.0.0.1:19090：核心控制；9090/9443：agent。 |
| 地址、其他 owner | `198.18.0.0/16` 是 fake-ip。统一登记地址常量，但代理私网例外、中继 DNS 例外、策略表 throw 和 IPA main 防护分别取其所需子集；不能把所有酒店私网都 throw。WireGuard 和 TTL 的自有链在这里登记，不在写入扫描范围内。 |

## 5. Mihomo

### 5.1 意图、核心与规则规划

`controller` 持有意图和已发布快照，记着内核可能持有的表（最后确认的一张，加上之后声明而未确认的各张：`reconcile` 以后可能把最后一张载入），收紧与否和“失去 DIRECT”的范围（`routing::lost_from`）都按这些表算，`reconcile` 载入的表也反映到发布的 bypass；它并决定保持、换链、重载或重启：这些决定写在 `Controller::follow`/`reload`/`restart` 里，和 `Port` 的设备调用交错（规范里纯函数的 `follow::plan / decide` 未实现，§8）；`core` 独占进程、托管 `config.yaml` 和控制器写操作；`intercept` 生成网络资源；`routing` 编译订阅规则及 DNS 过滤表，`routing::lost` 算出需清除的连接范围；`egress` 负责出口观测与去抖。慢操作在控制器线程上同步执行（§3），没有带代次的后台结果（§8）。

每个核心代次在 `Prepared.bypass` 保存实际采用的绕过设置；所有计划都用它，`cn-direct` 文件只表示车主意图。`geodata-mode` 保留订阅原值；绕过打开而核心使用 `geoip.metadb` 时，状态 `notice` 说明 GEOIP 规则不能在内核绕过。强制改用 `GeoIP.dat` 会让离线启动依赖可能缺失的文件，所以不这样做。托管配置仅在 `keep-alive-idle`、`keep-alive-interval`、`disable-keep-alive` 三键全部缺省时写入 120 s 空闲和 30 s 间隔（`mihomo.rs::config_with_lan_host`）。路由器的 `TcpExt TCPKeepAlive` 计数从 60 s 内 88 次（核心打开 87 个描述符）降为 120 s 内 12 次，即每分钟 6 次（核心打开 99 个描述符，启动后 441 s）；来源为 `measurements/b4-final/mihomo-refresh.txt`、`keepalive-later.txt`，位置和条件见[批次 4](relay-mihomo-implementation.md#batch-4)。

`mihomo::geoip` 按当前文件保留已载入代码的缓存（范围最多 8 MiB、最多 1024 个代码），解析先读国家代码，不为不需要的国家分配 CIDR 范围；`ranges::subtract` 和 `union` 线性扫描，`v6_only_in_use` 复用已解析的规则目标。这些优化的计时仅来自 Mac release 测试，未在路由器上测时（批次 4）。

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

热重载用于同一配置的 DNS 过滤表变化，以及选中订阅的手动或定时刷新。字节相同的源只更新时间戳和刷新元数据，不编译、不校验；变化的选中订阅由控制器校验候选一次，再按收紧、写配置、`PUT /configs`、读回、只重置失去 DIRECT 的范围、装新计划的顺序处理。切换配置、修改生效配置内容和修改扩展仍按配置变更走计划内重启。

`PUT /configs?force=false` 的 JSON `payload` 是完整托管配置，保留实际 mode、log-level、`interface-name` 和 secret；秘密不入日志。`reload::needs_restart` 是纯函数，将热重载不能应用的变化送去计划内重启：经典监听及 LAN 访问设置、外部控制器及认证/TLS/界面设置、QUIC GSO/ECN、入站 TFO/MPTCP，以及删除原有的 `geodata-mode: true`。v1.19.33 的 `ApplyConfig` 暂停新连接，替换代理、规则、provider 和 DNS，不关闭已有连接；`force=false` 保留经典监听。通常继承 fake-ip 映射并按缓存恢复选组，但全新持久缓存的第一次热重载可能清空一次 fake-ip 池，后续重载保留映射（`component/fakeip/pool.go::restoreState`；本机真实核心脚本已复现，未在路由器验证，未作规避）。暂停期间既有 UDP/QUIC 的上行包也可能丢失。

204 只证明入口完成调用：provider 初始化错误可能只写日志，节点组为空时默认 `COMPATIBLE` 可直连。收到 204 后核对实际模式和接口、实际选组及必要 provider（不得意外退回 COMPATIBLE）、监听/下载代理状态；DNS 过滤表改变时还向 1053 查询答案必须改变的测试域名。原成员仍在时选组必须保留；订阅删除了旧成员时核验新选择。核心拒绝重载或核验失败时保持收紧，用已经通过校验的候选重启，不再校验一遍。**订阅内容改变后的 PUT 超时是结果未知，直接走上述重启**；同一源的 DNS 过滤表重载超时仍可由读回证明成功。新核心起不来时，用 `Run.prepared` 中最后应用的配置回退，控制器不再另存 `previous`。失败回退和首次重载丢映射均未在路由器验证；成功刷新及验证范围见批次 4。[配置入口](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/hub/route/configs.go#L405-L454) · [provider 加载](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/hub/executor/executor.go#L318-L338) · [UDP 检查](https://github.com/MetaCubeX/mihomo/blob/v1.19.33/tunnel/tunnel.go#L420-L441)

### 5.6 出口变化

以**实际装过、撤过或改变的出口**为准：从未装路由的失败连接和扫描不触发重启；装过路由后才失败的会话及从已有会话切走的失败操作，仍要通知 Mihomo。相同出口不重复重启；完全没有出口时不重启，同一接口上补上 IPv6 也不重启。v4 有效变化立即处理；v6 持续 5 s 才处理，相关重启至少间隔 60 s；蜂窝沿用 15 s 出口审计和旧连接是否搁浅的判断。校验在托管配置文本（屏蔽 secret、去掉顶层 `interface-name`）、核心二进制和 geodata 依赖都相同时复用：保留最近 4 个通过的指纹（中继和蜂窝的配置、上一份配置），存在 `/data/zte-agent-mihomo/validated`，同一次开机内跨 agent 重启有效。所以只换出口接口时不重跑 `mihomo -t`。热重载失败的重启直接复用已校验候选（§5.5）。

## 6. Wi-Fi 中继

### 6.1 会话与取消

会话发布 `phase`：`idle`、`scanning`、`connecting`、`active`、`recovering`、`disconnecting`、`recovery_pending`。`recovering` 包括等待关联恢复和 agent 启动后的恢复；恢复任务中的实际扫描/连接仍显示对应阶段。`connected` 仍是“有选中的网络且有租约”，不能代替阶段。`recovery_required` 只有在日志尚存、阶段为 `idle` 或 `recovery_pending` 且没有待断开时才为真，操作中不显示“需要恢复”。无读者的恒定顶层字段 `experimental`、`cellular_fallback`、`internet` 已删除，`ipv6.internet` 保留。活动会话上的扫描保留其路由。掉关联由 `Association` 计时：12 s 内（`ASSOCIATION_GRACE`）回来且旧租约及助手仍有效则续约，否则拆除。车主断开、有效地址变更、热点关闭或连接取消走同一拆除路径；撤销失败时日志保留。运行中不后台重连；开机只恢复最近一次符合条件的成功连接，不轮询全部已保存网络。

Disconnect 先更新取消代次和待断开标志，发布 `disconnecting`，走 General lane。控制器工作中立即回 HTTP 200，控制器在处理下一条消息和发布被取消操作的结果之前拆除。控制器空闲时调用方等待拆除回复，可能等热点返回原信道，批次 5 真机为 65.17 s。拆除中的额外断开合并。页面异步接受后写“Disconnect requested”，拆完才写“Relay disconnected”，测量范围见批次 5。

Connect 从已发布扫描列表校验选择，然后取消待恢复，再取得准入并入队，整个请求共用一个 3 s 等待期限。选择校验只取快照短锁，tick 的设备工作可以同时进行；超时放弃后不会迟到运行设备操作（单元测试 `a_connect_validates_during_tick_and_uses_the_same_wait_without_late_device_work`）。车主 Connect 抢占正在 join 的开机恢复仍未在真机验证。join 的步骤之间、扫描轮次之间和最终发布前检查取消代次。已开始的热点信道切换必须运行到结束，批次 5 曾因在切换内部检查取消而导致撤销被拒，修复和回归见实现记录。

`start()` 在其他请求前排 Boot，接管本次开机的有效会话或回滚残留。`net-restore` 的 `recover_idle()` 是等待完成的第二次幂等 Boot。`RESTORE_WAITS` 由控制器定时器安排，两次尝试之间可处理其他请求并立即接受取消，`restore()` 仍等待整个恢复结束。仅在成功连接到开放网络或已有匹配凭据时写 `resume.json`，手动断开清除，掉线保留。热点被关掉时只有车主自己的开关（`hotspot::off_by_owner`）才清除它，固件关机充电模式临时关闭 Wi-Fi 时保留重启选择并跳过本次恢复尝试（只有单元测试，路由器上没有复现修复）。开机恢复沿用约 17 min 的有界等待，手动操作和车主关闭热点可取消。记住凭据和重启恢复分别记录。残留监视器按本次 boot 的 PID、身份和私有参数清理，已知切 SELinux 域的无线及 DHCP 助手按私有路径清理。

连接顺序：先建受保护的 STA（§4.3），启动 supplicant，处理热点和 DFS 开关，关联并取得 DHCP。校验地址、网关和冲突后，先装地址、路由、NAT、转发防护和 DNS 数据面，策略规则最后；核实出口再接管可选的 IPA、resolv/门户和 IPv6，并发布会话。断开时停止 IPA 监视器，撤 RA/可选 IPv6、IPA main 路由、IPv4 选路和 DNS；实际出口改变即通知 Mihomo，不等后续最长 80 s 的 CAC。STA 确认断联才恢复热点，INPUT 防护最后撤。

### 6.2 运行检查和无线设置

控制器每 3 s 只在会话有选中网络时经端口观测 wpa 状态（控制套接字，最多等 2 s）、带会话标识的租约、助手及热点开关，`net_guard` 安静后可提前触发。`decide`（`wifi_relay.rs`）区分关联宽限、有效续约、只变 DNS 与真正掉线；DNS 变化由 uplink 一处更新 resolv 标记行和下载器快照。IPv6 根据剩余寿命、DAD、优先级归属与保留 LAN 前缀维护路由/地址，撤 RA 在撤 NAT66 前。`check_owned` 在触发安静、读取失败重试、续写寿命前或距上次满 15 s 时检查（`ipv6::CHECK_EVERY`，车主 2026-11-12 接受）。普通 IPv6 租约失效只撤可选片段。时钟复核作为 Clock 请求在 `relay` 线程执行，准入与开始执行共用 3 s 等待。

上游省电仍按车主的 `keep-power-save` 意图在关联时处理，与路由器自身省电模式分开。删除不可靠的带宽自动调优（D5）；关联时的一次性宽度复位也在 2026-11-12 删除，agent 不再运行 `iwpriv … chwidth`，热点仍使用的信道/带宽解析在 `hotspot.rs`；取消 tuning API 和页面选项，已存 `auto` 迁为 `off`，保留其余网络参数。DFS 切信道开关：每次关联前确认厂商键 `wireless.zte_mbb.dfs_channel_switch_disable=1`（持久，车主批准；没有其他未提交的 `wireless` 改动时才提交），再 `iwpriv wlan2 disableDfsCS 0`。上下游共用射频、DFS 窗口、真实读回和恢复热点的固件要求继续遵守[设备指南](../../CLAUDE.md)。

## 7. IPA 硬件转发

只有 IPACM 开机时读到的配置列着 STA、正确的 `main` 默认路由和 HW 模式同时具备时，才可能卸载 IPv4。B31 的原厂配置已列着 `ath20`，agent 只读它（`offload.config`：`listed` / `not_listed` / `unavailable`）并负责 main 路由；HW/SW 模式归厂商，agent 不读、不切、不审计、不核验（车主决定，2026-11-12）：工作模式为极速模式（`Nomal_mode`）时加速打开，其他工作模式、厂商限速、省电和 `ipa_disable` 会关掉它，`Ai_mode`（出厂默认）和 `Game_mode` 随流量切换。IPACM 在启动时读接口表；不能用运行时重启 ipacm 补救。B31 的邻居退役和客户端 ARP STALE 仅在 `wa_inner_version=BD_CNMU5250V1.0.0B31` 且 ipacm 二进制哈希匹配时启用；不匹配时不加 main 路由，显示原因，走 CPU。详见[硬件转发说明](relay-hw-offload.md)。

状态机在 `wifi_relay::offload`，设备读写经 `IpacmPort`（配置状态、车主开关、指纹、监视器、加和撤 main 路由），用假实现跑状态转换和失败矩阵；main 路由归会话的 `network` set，conntrack 重置经 `netfx`。

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
| 中继发布带代次的出口快照（§3） | `Message::Egress` 不带内容，Mihomo 自己观测；租约 DNS 经 `set_subscription_dns` 传给下载器 | 评审 D 第 2 节认为影响小，没有单独安排 |
| Mihomo 后台任务与带代次的结果（§3、§5.1） | 校验、规则集 PUT、热重载、`nft -f`、conntrack 删除仍在控制器线程上同步做，其间核心退出和命令排队；只有 HTTPS 时钟校验有自己的线程。选中订阅刷新已改为控制器校验一次、热重载；相同源跳过编译/校验，失败重启复用候选。校验的 `background=true` 表示低优先级，不是后台线程 | 评审 E 第 11 条建议评估剩余阻塞；准备步骤已移到 Hold 前，批次 4 又减少重复校验并优化规则计算，但尚未实现后台结果机制 |
| `follow::plan / decide`（§5.1、I6）：纯函数决定保持、换链、重载或重启 | 决定写在 `Controller::follow`/`reload`/`restart` 里，和 `Port` 调用交错；靠 `Port` 的假实现重放 | 评审 E 第 11 条没有给出推迟理由；它指出这种交错让“中途失败之后”的记账容易出错 |
| conntrack 请求在 200 ms 内合并（§4.5） | 只有“变化之后开始的成功删除可抵账”和失败待重试请求的并集 | 未安排 |
| nft 表的内容核验（§4.2：首次应用、集合变更或异常后核验全量内容） | 只比代次标记和每条链的规则条数 | 评审 E 第 11 条：ZTE 不碰 nft，没有别的写入者，可以接受 |

批次 5 已完成中继控制器和 `EffectSet`，其中尚待实现的是中继出口快照、IPv6 自己的设备端口，以及门户 RETURN 以外钩子的持续位置约束，后者按 D8 保留厂商后来插到前面的过滤规则，使车主开启的过滤继续生效。

另有两项是规范里带门槛、按门槛暂不启用的：核心出站标志位 M13（`ids::CORE_OUT_MARK` 为 `None`，等设备核对空闲位）和 IPv4 MASQUERADE 迁到 nft（D11，等 ≥220 Mbit/s 硬件下载证明不影响卸载）。

2026-11-12 批次 4 已完成原表中的“中继会话阶段”和“HTTP 只读快照”，所以从未实现清单移除；验证范围见[实现记录](relay-mihomo-implementation.md#batch-4)。

## 9. 实验过、没有采用的两种接入厂商防火墙的办法（2026-11-12）

两项都在车主的 B31 上做了实验，都是易失的（重启即消失），实验后防火墙规则与实验前逐行相同。记录在
`measurements/b4-fw3/`（`fwprobe.log`、`nf-nat-warning-times.txt`、`second-masquerade-control.txt`）。

### 9.1 让 fw3 在每次重载后运行我们的脚本

- **做法**：`ubus call service add '{"name":…,"data":{"firewall":[{"type":"script","path":…,"family":"any","reload":true}]}}'`。
  fw3 每次运行都读 procd 的 `firewall` 数据，确实运行了这个脚本；`service delete` 之后数据消失。
- **结果**：脚本在重载开始后 0.06 秒就运行了，那时 brnf 还是 0、`redirect_chain` 还有我们的 RETURN。厂商的
  `firewall_init.sh` 排在它之后，又跑了约 3 秒，把 brnf 写成 1、清空 `redirect_chain`。这个版本的 fw3 先运行
  ubus 提供的 include，再运行 UCI 里的 include。
- **结论**：没法用它在厂商脚本之后同步补回，所以没有采用。现在的做法（inotify 加 0.5 秒采样）在 brnf 被改后
  0.2–0.9 秒内改回，RETURN 在重载结束后约 2 秒补回。

### 9.2 让中继站点成为 fw3 `wan` 区的成员

- **做法**：`ubus call network add_dynamic '{"name":"u60relay","proto":"none"}'`，
  `network.interface.u60relay set_data '{"zone":"wan"}'`，再 `add_device '{"name":"ath20","link-ext":true}'`
  （`link-ext` 让 netifd 不清空接口上已有的地址和路由）。接口约 1.5 秒后 up，`20-firewall` 自动执行一次
  `fw3 reload`，fw3 生成了 `zone_wan_input`、`zone_wan_forward`、`zone_wan_dest_ACCEPT -o ath20`、
  nat `zone_wan_postrouting`（MASQUERADE）和 mangle 的 TCPMSS 规则，IPv4 和 IPv6 都有。
- **对中继和 IPA 的影响**：没有。站点的地址、关联、路由都没动，中继保持连接；103 MB 下载只有 83 个包走内核
  （全走 CPU 约 70,857 个），`close_ipa_acce=0`。删掉我们自己的 FORWARD 跳转和 MASQUERADE 之后，新连接正常，
  51 MB 下载只有 60 个包走内核。`network.interface.u60relay remove` 不影响站点，区规则在下一次 fw3 reload 消失。
- **没有采用的原因**：
  1. 能去掉的只有两条转发放行链和 IPv4 MASQUERADE。fw3 reload 本来就不删这些（它只删带 `!fw3` 注释的规则），
     每次 reload 被改回去的是 brnf 和门户 RETURN，这两样进了区也还是我们自己维护。
  2. 每次连接多一次 fw3 reload（约 3 秒）。每次 reload 把 brnf 写成 1 两次，各持续 0.3–0.9 秒，这期间 Mihomo 的
     TPROXY 在桥接路径上失效。
  3. 两条匹配站点的 MASQUERADE 同时存在时内核报 `nf_nat_setup_info` 警告并丢掉新连接：区规则和我们的规则并存的
     23 秒里 19 次，其中有 Mihomo 自己发起的连接；去掉我们的规则后是 0 次。对照实验（不进区，只多加一条
     MASQUERADE）12 秒 9 次。所以两套规则在更新、接管这些过渡时刻绝不能并存。
  4. fw3 的 `wan` 区比我们现在放得宽：LAN 到上游的 IPv6 不限源地址，厂商的端口转发（`zone_wan_prerouting`）对上游
     一侧生效。要保持现在的行为，得在 nft 表里补拒绝规则，并重做 `tests/relay-firewall-qa` 的验收。
  5. 要多管一个 netifd 动态接口的生命周期（netifd 重启会丢掉它，要能发现并重建）。
- **会得到的好处**：厂商的家长控制和网址过滤（`forwarding_rule`）会像对蜂窝一样对中继流量生效；`fw3 restart`
  之后转发不用等我们补规则。车主需要这两样时再做，按一次独立的防火墙改版来验收。
