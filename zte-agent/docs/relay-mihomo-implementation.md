# Wi-Fi 中继与 Mihomo：实现与验收记录

本文记录 [版本与验收](relay-mihomo-refactor-plan.md) 中 v1–v6 在本仓库里的实际落地情况，
按“源码已实现 / 本机或隔离环境已验证 / 仍待设备验证”分开。行为规范以
[架构规范](relay-mihomo-architecture.md) 为准；车主选择 Q1=A、Q2=A、Q3=A（2026-11-10）。
没有设备结果的项目一律记为未验，不按单测或代码存在算作通过。

构建与体积均为同一次 `cargo build --locked --release --target aarch64-unknown-linux-musl -p zte-agent`
的产物（本 Mac 上用 `/tmp/u60-cross-tools` 的 zig 包装器链接，`xcrun llvm-size -A` 取 section Total，
`gzip -n -9 | wc -c` 取压缩后字节）。对照基线：Total 8,915,528 B，gzip 4,385,216 B。

## v1 · 基线与小修（阶段 0、1）

**源码已实现**

| 条目 | 位置与做法 |
| --- | --- |
| S2、N10 | `netfx::exec`（有界、无 shell、超时杀整个进程组）、`netfx::files`（0700/0600 原子写）、`netfx::ids`（名字与编号登记，测试查重；代理私网、中继 DNS 例外、throw/IPA 防护各取各自子集）。 |
| N9 | `ubus::uci_get` 经 `netfx::exec::run` 限时 3 s。 |
| U2 | `netlog!` 宏给中继、Mihomo、`net_guard`、`netfx` 的日志行加 CLOCK_BOOTTIME 秒数（毫秒精度）。 |
| N8、U1 | `netfx::conntrack`：直接执行 `conntrack -D`，丢弃不定长的标准输出，读有界的标准错误，按 conntrack-tools 1.4.8 的 `print_stats`/`exit_error` 区分“删除了 N 条”“零匹配（计数 0 且返回 1）”“操作失败（返回码同为 1）”。失败留作待办，由中继/Mihomo 看护重试并与后续请求合并；只有在路径变化之后开始、成功且覆盖全部范围的删除才能抵账；最近 8 次结果进 `/api/mihomo/status` 和 `/api/wifi-relay/status` 的 `connection_resets`。页面提示改为按实际结果（`reset_note`）。 |
| N1 | 中继每拍在 `net_guard` 到期时用 `wireless.reconcile_only(firewall_step)` 核对上游 INPUT 防护（已有）。 |
| D1、N3 | `httpd::mobile` 把 `u60sta*` 对端与 `rmnet*` 一样拒绝。 |
| D9、N6 | 交互写操作经 `netfx::admission::enter` 最多等 3 s（Wi-Fi、访客、LAN、USB、固定 DHCP、厂商防火墙、中继时钟复核）；自动看护（`conn_watchdog`）仍不等。 |
| M2、M10、R4 | 只有装过路由的会话（`Session::routed`）在拆除时通知 Mihomo；扫描、未装路由就失败的连接、重复拆除都不通知；核心关闭/安装中收到通知不报错。 |
| M8 | 规则集文件按内容哈希判断变化，只改 mtime 不重编（`routing::Source::changed`）。 |
| R2 | 监视器记录改为“PID + `/proc/<pid>/stat` 启动时间 + boot id”，`stop_strays` 只停记录里的那个进程，发信号前再核对身份。 |
| H5 | 记录 `IPACM_cfg.xml` 就地截断改写的崩溃/掉电风险（[硬件转发](relay-hw-offload.md) 第 1 节），修复在 v4。 |
| 日志兼容 | 省电步骤的撤销改为普通 `iw dev u60sta0 set power_save on`：已部署的 HEAD（c253113）能执行它，不再依赖“跳过未知 `@u60-*`”。其余 v1 写入的撤销项与 HEAD 的命令表一致。 |

**本机已验证**：`cargo test --locked -p zte-agent -- --test-threads=4` 1479 通过、0 失败（3 个需设备的忽略）。
新增/修改的测试：`netfx::conntrack::tests`（同返回码零匹配与失败、只认路径变化之后的删除、失败待重试、零匹配显示为 none、目的范围与 >64 段退回整网段）、
`netfx::exec::tests::{an_exit_code_is_an_answer_not_a_failure, a_start_time_is_read_past_a_command_name_with_spaces_and_parentheses}`、
`wifi_relay::offload::monitor::tests`（记录只认本次开机的同一进程）、`wifi_relay::tests::strays_are_only_relay_helpers_on_our_interface_and_paths`（人工同名 `iw event`、复用 PID 不误杀）、
`wifi_relay::tests::only_a_session_that_installed_routes_tells_mihomo_its_uplink_changed`、
`mihomo::tests::core_operations_refuse_while_installing_without_occupying_the_network_lock`（关闭/安装中收到出口通知不报错）、
`wifi_relay::power_save::tests::the_step_turns_it_off_and_its_undo_back_on`。原有的 `offload::monitor` 测试在 macOS 上失败（把记录直接写进系统临时目录、`sh -c` 末条命令不 exec），已修正。

**发布构建**：section Total 8,942,228 B（+26,700），gzip 4,402,496 B（+17,280）。增量包含 v1 开始前工作区里已有的部分实现。

**仍待设备验证（需维护窗口）**：真实 fw3 reload 后的核对；`scripts/probe-admission.sh` 两分钟无副作用准入探测（分开统计“正在操作”的 409 与资源冲突的 409）；
真实 `conntrack -D` 的三种结果；中继省电撤销在 HEAD 版本上的执行。

## v2 · 效果层与 Mihomo 控制器（阶段 2、3）

**源码已实现**

| 条目 | 位置与做法 |
| --- | --- |
| S1、S2 | `netfx::effect::NftTables`：两族同名表一个 `nft -f` 批处理整表替换（建空表、删、重定义），带代次标记（未挂钩链 `state` 里的规则注释），用 `nft -t` 读回标记确认（不列集合元素，不受 256 KiB 输出上限影响）；目标与已确认代次分开，失败、超时或读回失败都保留目标由 `reconcile` 重试；没有本 owner 标记的同名表一律视为外部，不接管。`Transaction` 增加 `load`/`current`/`journaled`/`adopt`（接管本次开机上个 agent 的日志，沿用日志里的原始 sysctl 值，缺失才补做）。中继仍直接用 `Transaction`（v4、v5 迁移）。 |
| M1、M3、U3 | `mihomo::controller`：单线程串行处理车主命令、路由写、出口、核心退出、重试、`net_guard` 核对和规则集刷新，不取中继的网络锁；状态 Off/Starting/Running/Restarting/Backoff/CleanupPending 发布为快照，页面只读快照。`mihomo::core`：每个进程一个代次、一个回收者（先 `waitid(WNOWAIT)` 再在锁内回收，停止信号不会打到复用的 PID），旧代次退出被忽略。D3：确认退出或计划内重启最终失败 → 撤拦截、sysctl、策略路由，只留 fake-ip 的 TCP reset/UDP reject 和入口防护；D2 退避 5/15/30/60 s 后每 5 min，60 s 内 3 次直接 5 min，运行 5 min 清零；车主关闭使排队的重试失效。车主发起的启动失败释放资源并保持关闭；开机恢复失败进入退避。页面显示状态、正在直连、失败次数和下次重试。 |
| 拦截表 | `mihomo::intercept`：Guard（核心前只有入口防护）、Hold（不绕过任何地址）、Full（计划链）、FakeReject（D3）。`to_core` 末尾常驻 TCP/UDP drop；已有透明 TCP 用 `socket transparent 1 socket wildcard 0` 放在 DIRECT 返回前。 |
| M4–M6、D10 | `routing::lost`：新旧链直到最后放行点都只按目的地址判断时按首个命中求“旧放行减新放行”，旧链不纯重置整个 LAN IPv4，新链不纯重置旧放行全部范围，>64 段重置整个 LAN；没有失去放行的不删。 |
| 计划内重启 | 先装 Hold（确认不了就不停旧核心），停旧核心，新核心在拦截后面启动；新配置失败回退上一份配置；最终失败才 D3。路由写（控制台/Zashboard 的模式、选组、规则集）先收紧、再写核心、读回、只重置失去 DIRECT 的范围、再装新链；收紧确认不了就拒绝写入。重启中桥接写回 503，控制台写排队。每 60 s 读回模式和选择，有差异按同样顺序跟随。 |
| M9、D7 | `mihomo::egress`：中继通知的 IPv4 出口变化立即重启；只 IPv6 变化需持续 5 s，且至少间隔 60 s；蜂窝下 15 s 审计只在出口会搁浅连接时重启；重复通知不重启。 |
| M11、M12 | 桥接写经控制器排序（`routing_write_async`，Tokio 上 await oneshot），保留原有认证、同源、端点限制；规则文本（含 `no-resolve`）原样交给核心。 |
| Q1 | `src/guard.rs`：agent 启动时派生独立会话的 `zte-agent guard <pid> <starttime>`，agent 意外退出后重跑开机启动脚本（脚本的锁和身份检查保证单实例）；OTA `pending` 标记期间交给更新助手，`/tmp/zte-agent-run/stopped` 表示有意停止；连续 3 次起不来先 `network-recover`（直连）再继续以 5 min 间隔尝试；保留上一份日志为 `/tmp/zte-agent.previous.log`。新 agent 在车主意图仍开、日志与表属于本次开机时接管（Hold、日志里的原始 sysctl 值），直接起新核心，不经直连窗口；中继恢复撤掉旧路由后通知 Mihomo。 |
| Q2 | 托管配置删除 `http` 规则集的 `interval`，核心不再自行刷新；控制器按订阅间隔刷新（失败 10 min 后再试），刷新期间该规则集按未知处理（DIRECT 跳过、非 DIRECT 截断），读回后装新链；`file` 规则集（核心按文件变化重载）始终按未知处理。DNS 过滤表里会刷新的规则集只给假地址，目标不是 DIRECT 的这类规则集之后全部假地址。 |
| Q3 | DNS 过滤表只取决于配置和绕过开关：只有直接写 `DIRECT` 的固定域名规则给真实地址，策略组后面的域名一律假地址（即使当前选 DIRECT），切组不改 DNS；订阅自己的黑名单排在规则之后。客户端从路由器 DNS 拿不到可切换域名的真实地址，旧真实 A 的前提不出现。 |

**本机/隔离环境已验证**

- 开发机 `cargo test --locked -p zte-agent -- --test-threads=4`：1505 通过、0 失败（两次）；`doh::listener_tests::listener_serves_cache_then_stops_promptly_and_rebinds_same_port` 偶发端口竞争（既有问题，单独运行通过）。新增：`netfx::effect::tests`（五项，含 A→B 失败重试、已提交但读回失败、>256 KiB 集合）、`mihomo::core::tests`、`mihomo::controller::tests`（十二项：旧代次退出、关闭后的旧重试、清理失败待恢复、D3 与退避档位、车主失败与开机恢复、收紧后写入与精确重置、重启中拒绝写、配置失败回退、agent 重启接管、就绪超时与取消、安装中延后）、`mihomo::intercept::tests`、`mihomo::egress::tests`、`mihomo::routing::tests`（Q2/Q3 过滤表、`lost`）、`mihomo::tests::every_journaled_undo_is_one_the_previous_agent_runs`、`http_rule_sets_lose_their_interval_and_the_controller_keeps_it`、`guard::tests`、`web::tests::network::a_core_failure_shows_direct_traffic_failures_and_the_next_retry`。
- 隔离 Linux QA（OrbStack arm64 Docker，`--privileged --network none`，`zte-agent/tests/mihomo-qa`，使用生产生成器导出的批处理）：23 项全部通过——五种表形态加载并读回标记；IPv6 半边无效时两族都不变；Hold 下 v4/v6 进监听；无监听时 v4/v6 被丢弃而非直连（`NFT_BREAK`）；DIRECT 段直连、其余进核心；已被核心持有的连接在其目的段改为 DIRECT 后仍进核心；新 SYN 到远端 17894 在代理段被拦截、在 DIRECT 段直连而不被通配监听吞掉；D3 下 fake-ip TCP 立即 reset、UDP 立即拒绝、其余直连；**已部署的 HEAD（c253113）二进制和本版二进制的 `network-recover` 都能完整撤销本版日志**（规则、路由、表、sysctl、日志文件）；其他开机的日志被丢弃不重放。
- 隔离 Linux QA，aarch64 测试二进制在容器内运行 `isolated_ownership_and_interrupted_journals`：预放的外部同名表、路由表内外部路由、外部占用的优先级均被拒绝且不写日志、原样保留；运行中崩溃、在每一步之后中断、撤销进行到一半中断后，恢复都能完整收敛。同一测试二进制在容器内跑全量非忽略测试：1501 通过，3 个失败均为容器环境所致（读源码文件的检查、release 下不触发的 debug 断言、二维码子进程）。

**发布构建**：section Total 9,043,068 B（较 v1 +100,840），gzip 4,448,690 B（+46,194）。

**仍待设备验证（需维护窗口）**

- 真实核心：计划内重启、切组、切出口时用双出口探针确认代理探针不出现酒店/蜂窝出口；D3 首轮约 10 s 目标（检测、5 s 退避、客户端恢复分别计时）；启动错误、3 次短期退出、车主取消、撤销失败。
- 真实 IPv4 硬件长流经独立 `IP-CIDR` 规则从 DIRECT 切走后在记录时间内停止旧出口或改经核心，另一条未变的 DIRECT 下载继续；前置 `DST-PORT,443,PROXY`、来源条件、组合规则、>64 段及两次变化相隔 <200 ms 的反例；反方向切到 DIRECT 时核心中的 TCP 继续，UDP 另测。
- Q1：Running 与计划切换中分别杀 agent（无人工、单一 owner、DNS 与出口恢复）；OTA 试运行中候选死亡交给更新助手回旧槽；HEAD 旧槽实际执行本版日志（同 boot OTA 回退）。
- Q2：延迟更新通知，在规则集刷新前、中、后持续探测，应代理的请求不出现直连出口。
- Q3：切组前用路由器 DNS 解析可切换域名（应得到假地址），切组后新建连接不出现直连出口。
- B31 空闲时复测 `NFT_BREAK`、已有透明 TCP、新 SYN 到 17894 与表替换（内核 5.15.194 源码已确认支持 `NFT_SOCKET_WILDCARD`）。
- 订阅含每日刷新规则集时的吞吐与 CPU 对照（大部分域名改走核心是 Q2/Q3 的已知代价）。

## v3 · 热重载（阶段 4）

**源码已实现（M7）**：Q3 之后 DNS 过滤表只随配置和绕过开关变化，所以同一配置下的过滤表变化只来自绕过开关（`Message::Bypass`）。控制器先收紧（Hold，确认不了就拒绝），按运行中的配置重新生成托管配置（同一 secret、实际 mode/log-level、出口接口和端口，只换 DNS 过滤表），`PUT /configs?force=false` 提交完整配置；无论答复是 204、错误还是超时，都读回核对：模式、出口接口、各组选择与之前一致且没有退到 `COMPATIBLE`、配置里的规则集都在、下载代理和透明监听在，并向 1053 查询一个答案必须改变的名字（`routing::reload_probe`：默认动作变了用永不解析的 `u60-reload-probe.invalid`，否则用固定 DIRECT 的 `DOMAIN`/`DOMAIN-SUFFIX` 名字），按新过滤表应为假地址/非假地址。确认后才装新链并只重置失去 DIRECT 的连接；确认不了改走保留拦截的计划内重启。重载期间状态为 `reloading`，桥接写回 503。整份订阅/配置切换仍走重启并保留上一份可用配置。

**本机已验证**：`mihomo::controller::tests::a_dns_filter_change_reloads_tightened_and_falls_back_to_a_restart`（重载时内核为 Hold、同一核心代次；204 但读回不证明 → 计划内重启；超时但读回证明 → 提交不重启；过滤表不变只跟随内核链）、`mihomo::tests::a_reload_is_confirmed_only_by_what_the_core_reports`（COMPATIBLE 回退、选择未恢复、规则集缺失、模式/出口接口变化、无答复均不算确认）、`mihomo::routing::tests::a_reload_probe_is_a_name_whose_answer_must_change`、`mihomo::dns::tests::the_first_address_skips_a_cname_and_an_error_has_none`。

**仍待设备验证（需维护窗口）**：真实核心上 204 但 provider 为空、退到 `COMPATIBLE`、客户端超时而核心已 apply；保留旧选择与运行时接口；双出口探针分别观测已有 TCP 与 UDP/QUIC/hy2；连续 10 次重载记录暂停时长（日志 `elapsed_ms`）、实际丢包和内存趋势；“新查 DNS”与“复用切换前缓存的真实 A”两项测试（Q3：可切换域名本就只得到假地址）。

## v4 · 中继控制器与 IPA（阶段 5、6）

**源码已实现**

| 条目 | 位置与做法 |
| --- | --- |
| 准入（N6 扩展，§4.6） | `netfx::admission`：网络锁只用来检查和登记占用（`admit`/`begin` 返回 `Claim`，释放即注销），不跨 ubus、Wi-Fi 重载、写盘或 CAC。中继的车主操作（扫描、连接、设置）登记 `RELAY_OPERATION`，厂商写入或异步 Wi-Fi reload 未完成时拒绝；断开总能登记。热点、访客、LAN、USB、厂商防火墙写入最多等 3 s 中继操作，资源确实冲突时立即 409，并在写入期间持有自己的登记。`zwrt_wlan reload` 的占用跟到 5 GHz 热点连续两次 `ENABLED`（最长 120 s）才释放。固定 DHCP 保留只串行自己的写入。`POST /api/wifi-relay/disconnect` 改走 General lane，两个 Slow 名额被占满时取消仍能进入。 |
| R1、R3 | 中继自己的操作和 3 s 看护改用私有锁串行（不再用共享网络锁）；3 s 看护的判断提成纯函数 `decide`（`Decision::Teardown/Hold/Keep`，按热点关闭、助手退出、租约更换、关联超时的先后）。开机恢复撤掉旧路由后通知 Mihomo。 |
| N7、出口 | 只有装过/撤过路由才通知 Mihomo（v1）；租约 DNS 变化经 `publish` 更新下载器，不论核心是否运行；会话结束清空。 |
| H1–H4 | `wifi_relay::offload`：显式状态 Off/Engaging/Hardware/Software/Releasing，设备读写经 `IpacmPort`；接管失败撤回部分路由和模式；释放失败停在 Releasing 不报 Off；车主限制出现释放、解除后审计重新接管；有负载时的回程计数才算“已确认卸载”，释放后有负载才确认回到 CPU；B31 固件指纹（`wa_inner_version` 与 `/usr/bin/ipacm` SHA-256，只读查询得到）不符时不接管并写明原因。页面区分 HW 模式、已确认卸载、公网 IPv4 由 Mihomo 处理。 |
| H5 | `IPACM_cfg.xml` 改为同一文件系统完整副本 + 属主/权限/SELinux 标签复制与核对 + `rename` + 目录 fsync，失败删除副本、原文件不动。 |

**本机已验证**：开发机全量 1521 通过。新增：`netfx::admission::tests::writes_and_relay_operations_admit_each_other_in_short_sections`、`an_occupation_lasts_until_released_or_its_bound`；`wifi_relay::offload::tests` 五项（先模式后路由、释放先路由后模式并恢复原模式、CPU 路径确认；固件不符/车主限制不接管、限制解除重新接管、限制出现释放；路由失败交还模式、释放失败停在 Releasing；ZTE 改回 SW 时只切换不新增日志、有负载 CPU 路径最多重新挂载 3 次、少量回程包确认卸载；B31 指纹；整文件替换保留权限、rename 失败时原文件完整且副本删除）；`wifi_relay::tests::an_observation_decides_teardown_hold_or_keep_in_order`；`mihomo::tests::mihomo_never_waits_for_the_relays_network_lock`（中继持锁期间 Mihomo 的开关、出口通知、绕过切换、关闭都在 5 s 内返回）；`net_tools::tests::a_reconcile_after_a_release_never_reapplies_the_released_step`（释放 brnf 后迟到的核对不写回运行值）；`server::tests` 中断开走 General lane。

**发布构建（v3 与 v4 合并测量）**：section Total 9,078,168 B（较 v2 +35,100），gzip 4,468,611 B（+19,921）。15 条编译警告均为 `auth`、`events`、`httpd` 中既有的未用代码，与本次改动无关。

**仍待设备验证（需维护窗口）**：wireless 撤销阻塞最长 CAC 时触发 Mihomo 的 sysctl 修复和核心退出（退出检测 ≤2 s）；有效会话上的扫描、换网前校验失败、错密码且从未装路由、装路由后才失败、重复断开、关联 12 s 内恢复与超时、清理失败；厂商异步 Wi-Fi reload 后马上连接、两个 Slow 请求期间手动取消；核心关闭时变更租约 DNS 后断联，下载器不再用旧地址。IPA 矩阵：首次安装需重启、同 boot 曾加载后再装、打开/关闭/移除、车主限制出现与解除、指纹不符、main 路由失败；受控 TCP 负载下的回程计数；配置写入后的属主、权限、SELinux 标签、备份及下次开机加载。绝不运行时重启 ipacm。

## v5 · 防火墙、NAT 和改写恢复（阶段 7）

**源码已实现**

| 条目 | 位置与做法 |
| --- | --- |
| §4.3 布局 | `wifi_relay::uplink` 一处拼装两族 `u60_relay`，经 `NftTables` 两族同批整表替换、读回代次标记；`ipv6` 只通过 `uplink::Shared` 增减自己的部分。上游防护（INPUT：v4 已建立/相关与 DHCP 67→68 返回、其余 drop；v6 在发现开始前全部 drop；所有经 `u60sta0` 的转发 drop）在 `u60sta0` 拉起前建立，纯扫描也有；取得租约后扩展；释放路由前先缩回仅防护；无线日志撤销（STA 断联后）才删表。表名被无本 owner 标记的表占用时拒绝接管。 |
| 转发与 IPv6 | IPv4 FORWARD：`br-lan → u60sta0`、回程已建立/相关返回在 drop 之前。IPv6 FORWARD：从 `br-lan` 到 `rmnet*` 第一条 reject；NAT66 有效时认可源去程与回程返回在上游 drop 之前；随后 `fc00::/7`、`fe80::/10`、`ff00::/8` 返回，其余 reject。只有一条由中继基线拥有的 IPv6 OUTPUT `rmnet*` reject（原 `U60_RELAY_OUT`、`U60_R6_OUT` 两条合并）。发现阶段的 v6 INPUT 只开 RA（链路本地源、跳数 255）、NS/NA（跳数 255）、ICMPv6 错误 1–4、DHCPv6 547→546。 |
| N2/N4（legacy 只留放行） | `U60_RELAY_IN`、`U60_RELAY_FWD`（保留独立 TCP 回程计数规则）、`U60_R6_IN`、`U60_R6_FWD` 只含 ACCEPT；去掉其中的 DROP。`U60_RELAY_V6`、`U60_RELAY_OUT`、`U60_R6_OUT`、`U60_R6_NAT` 退役（`ids::RETIRED_RELAY_CHAINS`，旧日志仍可撤销）。 |
| NAT66（D6） | 迁到 `ip6 u60_relay` 的 postrouting `srcnat - 1`，只匹配 `oifname u60sta0`。B31 只读查询 `/proc/config.gz`：`CONFIG_NFT_MASQ=y`、`CONFIG_NFT_REJECT_IPV6=y`。IPv4 MASQUERADE 仍在 legacy（D11 未证明）。 |
| 门户 RETURN | `@u60-relay-portal-return`：读 `-S redirect_chain`，RETURN 必须排在所有厂商规则之前；缺失则插到第一条，排在后面则在同一个 `iptables-restore --noflush` 事务里删除再插到第一条，期间不缺失、不碰厂商规则。撤销仍是旧版能执行的 `-D`。核对按位置判断，不只看 `-C`。 |
| M13 | `ids::CORE_OUT_MARK`（默认 `None`，候选 `0x01000000`）：设置后中继 DNS OUTPUT 链遇该位返回、Mihomo 托管配置写 `routing-mark`。B31 只读检查：ZTE 脚本用 `0x3f00`（`0x100`/`0x300`/`0xf00` 掩码）和 `0x40000000`，TPROXY `0xff00`；Tailscale 常用 `0xff0000`。设备核对前不部署。 |
| N5（`net_guard` 时序） | 触发安静 2 s 后唤醒中继和 Mihomo 立即核对（`on_settled`，Mihomo `Message::Guard`）；核对确实补回后 5 s 再查（`Cursor::after`）；每次触发后的 3 s 内每 0.5 s 只读 owner 持有的 `@u60-sysctl`，被改才写，写在登记锁内确认同一 owner/代次（`Transaction` 应用时 `hold`，撤销前 `release`，恢复日志时整体注销）；agent 自己运行 `ipacm_switch.sh` 时按路径只计一次触发，其他脚本与 ubus 照常（`own_run`）；inotify 事件按 watch 描述符区分路径，读不出来源时仍算一次。 |
| 写入边界（§3、I1） | `netfx::boundary`：随 `cargo test` 扫描中继与 Mihomo 的非测试源码，禁止直接起 `iptables`/`nft`/`conntrack`/`ip`/`sysctl` 进程、`Cmd` 直接执行 legacy/地址/路由/策略写或任何 `nft` 写、直接写 `/proc/sys/net`；白名单两项（`@u60-relay-steer` 步骤自身、IPv6 会话对已登记地址/路由的寿命 `change`），附自检用例。Mihomo `@u60-mihomo-nft remove` 改经 `netfx::effect::Device`（读不出不算已删除）。断开前的上游 `disable_ipv6=1` 改为无线日志步骤。 |

**本机/隔离环境已验证**

- 开发机 `cargo test --locked -p zte-agent -- --test-threads=4`：1533 通过、0 失败、5 忽略。新增/改写：`wifi_relay::uplink::tests`（仅防护时两族关闭、发现只开所需、转发返回在 drop 前、v6 `rmnet*` 先 reject 且 OUTPUT 只一条、v4/v6 DNS、M13 只在给出标志时出现、畸形网络不进 nft、日志项撤销为旧版命令、部件一批增减且失败保留为目标、外部同名表不接管）、`wifi_relay::portal::tests::the_redirect_return_must_come_before_every_vendor_rule`、`wifi_relay::tests::legacy_rules_only_accept_what_must_pass_the_vendors_rejects`、`net_guard::tests`（5 s 复查、只在持有时写回、自身脚本只计一次）、`netfx::boundary` 两项、IPv6 计划相关测试改写。
- 隔离 Linux QA（OrbStack arm64 内核 7.2.12、nft 1.0.6、legacy iptables 1.8.9，`zte-agent/tests/relay-firewall-qa`，生产生成器导出的批处理与日志）：36 项全部通过——五种布局 `nft -c` 通过、两族同批载入并读回标记，IPv6 半边无效时两族都不变；legacy restore 事务在自有链上生效、只含放行，同名链存在时重放失败且不接管不清空；仅防护时上游到 9090（v4/v6）不可达、只放 DHCP 67→68、不转发、v6 在发现前关闭；装路由后 LAN IPv4 经 legacy MASQUERADE 出上游，上游新建到 LAN/路由器被丢，LAN 与路由器到 `rmnet*` 的 IPv6 被拒绝，无 NAT66 时 LAN IPv6 不出上游，LAN/路由器 DNS 去 Wi-Fi 解析器、访问路由器的 DNS 留本地；NAT66 时认可源以中继地址出上游并收到回复、其他源与上游新建都不通、DHCPv6 回复可达而 9090 仍关、LAN IPv6 DNS 由路由器回答、路由器 IPv6 DNS 去上游或无解析器时被拒绝；门户 RETURN 在厂商 DNAT 后时被一次事务移到第一条，之后 LAN 网页流量不再被 DNAT，缺失时插到第一条；**HEAD（c253113）和本版 `network-recover` 都能完整撤销本版中继日志**（两族表、自有链、门户 RETURN、MASQUERADE、日志文件）。IPv6 拒绝在 veth 上约 1 s 才得到 `refused`（两次一致）：推测零延迟路径上 ICMPv6 错误到达时 `connect()` 仍持有套接字，内核只记软错误，1 s 后重传的 SYN 才使连接失败；结果是拒绝而非丢弃或连通。

**发布构建**：section Total 9,112,644 B（较 v4 +34,476），gzip 4,485,924 B（+17,313）。

**仍待设备验证（需维护窗口）**：真实内核上的纯扫描、关联、首租/单播续租/广播重绑定与断开全周期防护；从第二台上游设备访问 v4/v6 9090/9443 及其他监听；RA/NS/NA 与错误 ICMPv6；IPv4/IPv6 双向数据；IPv6 关闭、租约过期和重装期间的蜂窝出口防护；合法 LAN/本地/组播路径。连续两次 fw3 reload、restart/flush、只丢单钩子、厂商在前面插终局规则、脚本与自身事件重叠；记录 brnf 和门户 RETURN 的实际恢复时间与 5 s 复查。NAT66 实际双向连接；IPv4 MASQUERADE 继续留 legacy（D11 的 ≥220 Mbit/s 硬件下载与回程计数验证未做，不迁移）。M13 空闲标志位核对与核心明文 DNS 原目的验证（未部署）。

## v6 · 无线调优退役与发布文档（阶段 8）

**源码已实现**

| 条目 | 位置与做法 |
| --- | --- |
| 删除调优 | 删除 `wifi_relay/width_watch.rs`（采样器与 watcher）、`wifi_relay/llstats.rs`、`wifi_relay/width/`（状态机、`widths.json` 历史、热点保护快照及其测试）、会话里的 `LinkWidth`/`tuning`、3 s 看护中的 `tune_width`、扫描时记录的邻居列表、`POST /api/wifi-relay/tuning`、`set_tuning`、`POST /ui/relay/tuning` 及页面/控制台的带宽选择和“Saved bandwidth”。`network_clock::WifiClock::verified_utc` 只为宽度历史服务，随之删除（含其 5 个测试）。 |
| 保留 | `wifi_relay/width.rs` 只剩每次关联后的一次宽度复位（先窄一档、等 1 s、回到协商宽度并读回）和热点需要的 `parse_channel`。 |
| 迁移 | `saved-wifi.json` 里旧的 `width_mode`（含 `auto`）被忽略，读作保持协商带宽，下次写入时去掉；旧版 agent 读到没有该字段的记录按 `off` 处理。连接请求里旧页面带来的 `width_mode` 被忽略。记住网络现在只保存密码，不勾选“记住”时不再写入仅含偏好的记录。状态不再有 `width_mode`/`width`/`width_state`，`frequency` 取自所选网络。 |
| D8 提示 | 服务端渲染页与响应式控制台（`ui/relay.js`、`ui/relay-model.js`）在中继连接时说明：路由器的家长控制、网址过滤对经中继的设备不生效（CPU 路径在其之前放行，硬件转发完全绕过），只有中继 IPv4 能硬件转发，IPv6（NAT66）和经 Clash 的流量走 CPU；IPv6 状态写明“由 CPU 转发”。B31 的家长控制存于厂商时间管理数据库而非 UCI（只读查询 `uci show` 只有 `parentctl_display`/`url_filter_display` 显示开关），所以提示在连接时一律显示，没有按开关是否打开来显示。 |
| 文档 | 同步[产品说明](mihomo-relay-prd.md)（Q1–Q3、D2/D3、热重载、准入、防火墙布局、带宽、D8 与 Q2/Q3 代价）、[网络扩展](network-extensions.md)（API 表、带宽自适应一节标为已删除）、[硬件转发](relay-hw-offload.md)、[中继生命周期](relay-lifecycle.md)、[Web UI](web-ui.md)、[响应式控制台](responsive-console.md)、仓库 `CLAUDE.md` 与 `CHANGELOG.md`（Unreleased）。 |
| S3–S5 | 计划正文没有给出 S3–S5 的具体定义。本次已有的拆分：`netfx`（exec/files/ids/conntrack/effect/admission）、`mihomo::{controller,core,intercept,egress,routing}`、`wifi_relay::{uplink,offload,power_save,width}`；未再做无规范依据的拆分，留待车主确认。 |

**本机已验证**：开发机全量 `cargo test --locked -p zte-agent -- --test-threads=4`：1426 通过、0 失败、6 忽略（较 v5 少约 107 个，即删除的调优/采样测试）。新增/改写：`wifi_relay::width::tests`（关联复位经窄一档并读回、信道解析与宽度代码）、`wifi_relay::saved::tests::a_saved_width_choice_is_ignored_and_dropped_and_passwords_stay`、`web::tests::network::{relay_page_offers_no_bandwidth_choice_and_states_what_router_filters_skip, relay_connect_forwards_no_width_choice_and_still_needs_confirmation, relay_shows_the_upstream_band_with_its_negotiated_bandwidth, relay_hides_the_upstream_link_without_a_connected_band, relay_network_names_are_escaped_as_plain_text}`。响应式控制台：`node ui/tests/relay-model.cjs` 通过；`ui/tests/relay.cjs`（Playwright + 本机 Chrome，临时安装在 `/tmp/u60-test`）通过，含无带宽选择、旧状态字段不显示、D8 提示仅在连接时显示、请求体不带 `width_mode`、不访问 `/api/wifi-relay/tuning`；`cellular.cjs`、`mihomo.cjs` 回归通过。

**发布构建**：section Total 9,023,720 B（较 v5 −88,924），gzip 4,439,064 B（−46,860）；较重构前基线 +108,192 / +53,848。体积下降来自删除的调优代码，不代表性能或体积门槛已达标。

**仍待设备验证（需维护窗口）**：使用含旧选项（`width_mode: auto`）的已保存网络连接，凭据与恢复选择仍有效、关联后一次性宽度复位仍执行；W_Game 5 GHz 与另约时段的 W 2.4 GHz 各测一次，热点恢复与硬件路径；页面/API 与旧设置迁移；设备上的旧 `/data/zte-agent-relay/widths.json` 不再读写（回退旧版仍可用），保留待车主决定是否删除。

## 最终复验（v1–v6 全部改动之后，同一份源码）

- 开发机：`cargo test --locked -p zte-agent -- --test-threads=4` 1426 通过、0 失败、6 忽略（另有集成测试 1 项通过），`doh::listener_tests::listener_serves_cache_then_stops_promptly_and_rebinds_same_port` 的偶发端口竞争为既有问题。15 条编译警告均在 `auth`、`events`、`httpd`、`ota`、`conn_watchdog` 的既有未用代码。
- 发布构建：section Total 9,023,720 B，gzip 4,439,064 B（同 v6）。
- 隔离 Linux QA（OrbStack arm64，`--privileged --network none`，最终二进制，重新导出的批处理）：Mihomo 表与日志 `tests/mihomo-qa` 23/23；中继防火墙 `tests/relay-firewall-qa` 36/36；aarch64 测试二进制的 `isolated_ownership_and_interrupted_journals` 通过。两套 QA 中 HEAD（c253113）与本版的 `network-recover` 都完整撤销本版日志。
- aarch64 测试二进制在容器内（root）跑全量非忽略测试：1421 通过，4 个失败均为环境所致——两个读源码文件的检查（容器内看不到源码路径）、一个只在 debug 构建触发的断言、一个二维码子进程测试。此轮修正了两个只在 root/Linux 下才暴露的 v4 测试问题：`net_tools::tests::a_reconcile_after_a_release_never_reapplies_the_released_step` 原先在核对之后才读期望值，且以 root 运行时会改写真实的 brnf（现在先读、结束时写回并断言）；`offload::tests::the_configuration_is_replaced_whole_and_a_failure_keeps_the_original` 原先靠目录 0500 制造失败，root 不受限（现在 root 下改用目录占位的目标）。
- 响应式控制台：`node ui/tests/relay-model.cjs`、Playwright `ui/tests/relay.cjs`、`cellular.cjs`、`mihomo.cjs` 通过。

**汇总：仍须设备维护窗口的项目**见上面各版本“仍待设备验证”。没有任何一项按单测、隔离 QA 或代码存在记为设备通过；B31 在本次全程只做了只读查询（`/proc/config.gz`、`iptables -S`/`nft list` 中的 mark 与 `redirect_chain`、`uci show` 键名），没有部署、杀进程、改规则或切换中继/IPA。

## 设备验收（B31，2026-11-10）

部署：`./setup.sh --build --adb --serial <B31> --factory-password --no-ssh`，同一份源码加下面的 guard 修复（部署件与本机 release sha256 一致，`e4712eb8…`）。环境：内核 5.15.194；中继上游 W_Game 5260 MHz（另测 W 2412 MHz），Mihomo 1.19.33 规则模式、DIRECT 旁路开，节点 `JP-hy2-gou-IPv6`（服务器只有 IPv6 地址）与一个 VLESS 节点；蜂窝数据在测试期间未连接。

测试客户端：前段为接热点 G 的开发 Mac（先退出 Mac 自己的 Clash Verge，否则出口与 DNS 都被它接管）；后段为路由器上的 netns `u60t`（veth 挂 `br-lan`，192.168.0.254，SLAAC 得到 ULA），不再切换车主的 Wi-Fi。直连出口为酒店 223.80.68.165，代理出口为 38.49.38.215。双出口探针每约 0.2 s 新建连接：代理域名（fake-ip）、代理字面地址 `1.1.1.1/cdn-cgi/trace`、经核心直连、内核旁路直连（真实国内地址），另有两条 400 KB/s 长下载（代理 ovh、内核旁路 tuna）。“漏出”指代理探针出现酒店出口。

**设备上发现并已修复**：`guard.rs` 的 `Device::start` 原先经 `netfx::exec::run` 运行启动脚本，该函数在工具退出后对整个进程组发 SIGKILL，把启动脚本刚拉起的 agent 一并杀掉，于是每次重启都失败，形成重启循环（约 20 个 guard 进程）。现场用 TERM 结束 guard、`/data/zte-agent network-recover` 清网、重跑启动脚本恢复。修复：新 `run_launcher()` 让启动脚本 `setsid` 并自带超时等待，超时只杀启动脚本本身；`spawn()` 在主 agent 启动时清除 `/tmp/zte-agent-run/stopped`（日志 `the stop marker was cleared`）。新测试 `guard::tests::what_the_launcher_starts_outlives_it_and_a_hung_launcher_is_given_up`。修复后全量 `cargo test --locked -p zte-agent -- --test-threads=4`：1427 通过、0 失败、6 忽略（另有集成测试 1 项通过）。发布构建 section Total 9,027,852 B（较 v6 +4,132），gzip 4,439,022 B（−42）。

**设备已验证**

| 项目 | 结果 |
| --- | --- |
| 部署与接管 | 中继 1 次尝试恢复（启动后约 82 s），Mihomo 运行，NAT66 已配；中继表全部就位且有生成标记；legacy 只剩放行链（v4 9 条、v6 17 条 U60 规则），已退役链不存在；门户 RETURN 在 v4/v6 都排第一；brnf=0。`/api/wifi-relay/tuning` 返回 404，状态里没有宽度字段。 |
| 上游 INPUT 防护 | 从上游侧（同网段的 Mac）访问 192.168.2.124：TCP 9090/9443/53/80/22/2222/1053/17894/19090 全部超时、ping 无回应；IPv6 全局与链路本地地址的 9090/9443/53 不通、ping6 无回应。与部署前基线一致。 |
| 连续两次 fw3 reload（各约 2.5 s） | brnf 在触发后 61/83/865/75 ms 写回；门户 RETURN 缺失约 3.6 s 后由 guard 补回（`@u60-relay-portal-return`）；legacy 钩子未丢，nft 表不受影响。 |
| 只丢单钩子、厂商终局规则在前 | 删除 `FORWARD -j U60_RELAY_FWD` 并在 `redirect_chain` 里 RETURN 之前插入测试 DNAT：53.5 s 后由 60 s 兜底复查修复（手工 iptables 没有触发源，符合设计），RETURN 回到第一位，测试 DNAT 本身未被动，测后移除。 |
| `firewall restart` | brnf 在 774/228 ms 写回；全部 legacy 中继链、MASQUERADE、门户、`U60_R6_IN`/`U60_R6_FWD` 在重启完成后 3.4 s 补齐；nft 不受影响。 |
| D3：`kill -9` 核心 | 34 ms 检测到并撤拦截（`direct until the core is back`），+6.2 s 重试，+10.9 s 恢复运行；conntrack 重置删除 200 条。 |
| IPA 开关 | 关：CPU 路径，conntrack 重置删除 86 条；开：回到硬件，IPACM 重新挂接，重置删除 9 条，`main` 默认路由与 metric 60631 的 unreachable 就位。有负载后 `offload_confirmed` 为 true。 |
| Q1：`kill -9` agent（修复后） | guard 0.16 s 察觉，4 s 后新 agent 启动，只有一个主进程；Mihomo 接管本次开机的拦截，约 14 s 回到运行。中继未被接管，见下面“发现”。 |
| 车主停止 | 有 `stopped` 标记时 guard 记录 `stopped on purpose: not restarting`。 |
| 回退兼容 | 上一版已部署 agent（`0.1.0 (ea52c22f9e3a)`）的 `network-recover` 完整撤销本版日志：退出码 0，65 s；表、规则、日志归零，brnf 回到 11，pacing 回到 200/120，`u60sta0` 删除。之后启动脚本重新拉起本版并清除标记。 |
| v6 迁移与 W_Game 完整周期 | 3 条已保存网络都设为 `width_mode: auto` 后：断开 65 s（CAC），扫描 3 s（无宽度字段），空密码连接 W_Game 8 s 成功；IPv6 配置完成、硬件路径、autostart 为 true，日志有一次协商宽度复位（160 MHz）。之后 `saved-wifi.json` 没有 `width_mode`，3 条记录与密码保留，写出 `resume.json`。全程 300 s 上游探测 0 命中。旧 `/data/zte-agent-relay/widths.json` 修改时间仍为 11-03，未被改写。 |
| W 2.4 GHz（IPv6 关） | 从 W_Game 切到 W 共 75.8 s；宽度复位到协商的 40 MHz，硬件路径，热点回到 36/160。LAN 客户端没有 IPv6 默认路由，ping6 报 Network unreachable，TCP6 不可达。切回 W_Game（IPv6 开）10.5 s 返回，约 21 s 后 IPv6 为 `configured`。 |
| 计划内重启 ×2 | 扩展覆盖改动触发 `restarting: the profile changed`：核心从停止到运行 4.3–4.8 s；代理探针中断 4.7–6.2 s，0 漏出。 |
| 切组 | `选择代理`→DIRECT 时代理探针走酒店出口（组本身选了直连，属预期）；切回 `手动选择` 后 1.2–1.6 s 回到代理出口，之后 0 漏出。`直连`→`选择代理` 时旁路清空（全部进核心），LAN IPv4 整体重置 288–454 条；`Netflix`→`直连`→`选择代理` 切回时只按 36 段目的重置（0 条），与 `routing::lost` 的范围一致。 |
| 硬件长流失去 DIRECT | 内核旁路的 tuna 长下载在 `直连`→`选择代理` 后：conntrack 在请求后 0.35 s 删除，旧流在删除后仍收数据 7.7–9.4 s 才中断（curl 55/56），见“发现”。 |
| Q3 | 路由器 DNS 对 `api.bilibili.com` 给出假地址 198.18.0.191；`哔哩哔哩` 切到 `选择代理` 后，6/6 次新连接走代理出口；切回后恢复直连。用第三方 DoH 拿到的真实 A（并非路由器 DNS 发出）前后都按 GEOIP CN 旁路直连，不在 Q3 覆盖范围内。 |
| Q2 | 用扩展覆盖把 EHentai（非 DIRECT，持有 `ip_0`）与 GoogleFCM（DIRECT，持有 `ip_1`）的间隔设为 60 s：290 s 内控制器刷新 6 次（`refreshed rule set …`）。刷新 EHentai 时整链收紧为只剩 `goto to_core` 1.36–1.43 s；刷新 GoogleFCM 时只撤 `ip_1` 的 return 1.45–1.86 s；刷新期间 0 漏出、代理探针无中断。测后撤掉覆盖，`profiles.json` 按备份写回（sha256 与原文件一致）。 |
| 热重载 ×10 | 切换 `cn-direct`：日志 `elapsed_ms` 174–266，全部 `verified=None`（确认成功）；API 往返 3.4–4.0 s（含 2.6–2.9 s 校验）。10 次中 4 次出现 1.2–2.0 s 的代理探针中断，0 漏出；关旁路的 5 次重置 298–382 条。核心 RSS 83,484→102,252 kB，agent 8,760–9,780 kB，MemAvailable 748,492→721,484 kB。 |
| 已有透明 TCP 与表替换 | 代理长下载连续经过 4 次切组和 10 次热重载都没有重连（只有 1–2.5 s 的停顿）。 |
| NAT66 与 IPv4 双向（netns 客户端） | ping6 `2400:3200::1` 4/4，conntrack 显示 ULA 伪装为 `2409:…:7b2c`；TCP6 到国内地址经核心直连 200。IPv4：代理上传 3 MB 200（1.6 MB/s），旁路上传被对端在 0.9 MB 时以 200 收下，旁路下载 20 MB 6.1 MB/s，代理下载 10 MB 1.2 MB/s。LAN 侧 RA（SLAAC 地址与默认路由）和 ND 正常，上游 RA 学到网关。 |
| IPv6 关闭时不出蜂窝 | LAN 无 IPv6 默认路由；`ip6 u60_relay` 的 `br-lan`→`rmnet*` reject 与 output `rmnet*` reject 在位。蜂窝数据未连接，未实际走到蜂窝路径。 |
| 节点切换与断网切出口 | 330 s 探针内：`手动选择` 切到 VLESS、中继切 W（IPv6 关）再切回 W_Game（IPv6 开）、切回 hy2 节点，0 漏出；断开加关联期间中断约 70 s，之后每次核心重启中断 4–7 s。 |
| 准入探针 | 中继与 Mihomo 运行时 120 s：780 次全部为资源冲突 409，“正在操作”409 为 0，网关 503 为 0。中继切换期间 120 s：288 次中冲突 409 为 261、“正在操作”409 为 27，放行 0，网关 503 为 0。 |
| conntrack 结果 | 实际出现“N deleted”和按段重置“0 deleted”两种；失败结果未出现。 |

**设备上的发现**（第 1、2、3 条已修复，第 7 条已加提示，见下一节；其余未改代码）

1. （已修复）Q1 中继不被接管：agent 被杀后新 agent 停掉 4 个遗留助手，拆除后经恢复流程重连，中继中断约 84 s；Mihomo 随出口变化又重启 3 次（generation 2–4）。
2. （已修复）一次中继重连带来 2–3 次核心计划内重启：断开时出口变化、连上后出口变化、16–17 s 后 IPv6 出口变化，每次代理与经核心的直连（含 DNS）中断 4–7 s。
3. （已修复）拆除顺序：扫描或断开结束时，中继表比 `u60sta0` 删除早 0.3–0.4 s，此时接口仍为管理 UP、未关联（flags 0x1003）。建立时接口在表加载前处于 down（0x1002，约 0.3 s），符合“接口 UP 之前防护就位”。可把表的声明与日志放到 `iw phy … interface add` 之前，让逆序撤销先删接口。
4. 硬件流在 conntrack 删除后仍走旧出口 7.7–9.4 s（客户端侧以 400 KB/s 计）。另外改经代理后新连 tuna 在 33–76 s 内收不到数据，可能是镜像对境外地址的处理，未查证。
5. 核心 RSS 每次热重载约增长 2 MB（10 次 83,484→102,252 kB），未观察是否会回落。
6. Mac 上的 UDP 试验：同一源端口先发往直连目的、再发往应代理的 Google STUN，后者也从酒店出口出去，而 Google STUN 地址不在任何内核旁路集合里。推测是核心按源地址复用 UDP 会话（先命中的规则决定出口），不是内核旁路所致。经 hy2 节点的 UDP（STUN、非 53 端口 DNS）核心只有上行 20–45 B、没有下行；路由器上没有 UDP 客户端工具，VLESS 节点未测。
7. （已加提示）节点只有 IPv6 地址而中继 IPv6 关闭时，Mihomo 仍显示 running，但所有代理连接报 `network is unreachable`，页面没有提示（W 测试期间实际造成谷歌不可达）。
8. 两个节点都没有 IPv6 出口：经代理的 IPv6（如 `2606:4700:4700::1111`）在核心自己的延迟测试里也失败，与拦截无关。

**仍待设备验证**：中继与 Mihomo 都关闭时的准入探针；D3 的启动错误、3 次短期退出、车主取消、撤销失败与分项计时；OTA 试运行中的 Q1 与同 boot 旧槽执行本版日志；IPA 矩阵其余各项（首次安装需重启、同 boot 再装、移除、车主限制出现/解除、指纹不符、main 路由失败、配置写入属主/SELinux/下次开机加载）与 D11 的 ≥220 Mbit/s 硬件下载；v4 中继控制器的失败路径（有效会话上扫描、换网前校验失败、错密码、装路由后失败、重复断开、12 s 内关联恢复与超时、清理失败、厂商异步 Wi-Fi reload、两个 Slow 请求期间取消、租约 DNS 变化）；v5 的首租/单播续租/广播重绑定全周期、错误 ICMPv6、IPv6 租约过期与重装期间的蜂窝防护、合法 LAN/本地/组播路径、脚本与自身事件重叠、M13；v2 的规则反例（前置 `DST-PORT,443`、来源条件、组合规则、>64 段、两次变化相隔 <200 ms）、反方向切到 DIRECT 的 UDP、`NFT_BREAK`、每日刷新规则集时的吞吐与 CPU；v3 的 204 但 provider 为空退到 `COMPATIBLE`、客户端超时而核心已 apply；能转发 UDP 的节点上的代理 UDP/QUIC；所有蜂窝场景。

**本次留在 B31 上的备份**（`/data/zte-agent-backup/`；2026-11-11 已按车主要求连同 `fw-reload-test/`、`ipacm/`、`zwrt_router/` 全部删除）：`pre-v6-agent/zte-agent.orig`（部署前的 agent，sha256 `106caee6…`，回退测试用）；`v6-saved-wifi/saved-wifi.json.orig`（迁移测试改 `width_mode` 前）；`v6-profiles/profiles.json.orig`、`selected.json.orig`（扩展覆盖测试前；`profiles.json` 已按它写回）。测试结束时 B31 处于正常服务：中继 W_Game、IPv6 与 NAT66 开、硬件路径、省电关，Mihomo 规则模式运行、选组与 `cn-direct` 为测试前的值。

## 设备验收后的修复（2026-11-10）

车主要求：agent 重启和中继切换尽量只重启一次核心，不要拖很久。下面三组针对同一份源码。

**源码已实现**

| 条目 | 位置与做法 |
| --- | --- |
| 一次切换只重启一次核心 | `mihomo/egress.rs` 的 `change`：完全没有出口（`Gone`）不重启，核心保留原参照，下一个出口与它比较；同一接口上新增或撤掉地址、改网关、撤掉一族（`Adopt`）只更新参照；IPv4 移动（换接口、接口重建、丢了源地址）或首次出现才立即重启；IPv6 移动仍按 5 s 持续、60 s 间隔。看门狗不再因核心参照是中继接口就跳过：中继走后出现蜂窝出口，持续 5 s 即重启。`mihomo.rs` 的 `prepare` 每次都写入 `mode`/`log-level`，首次启动与重启的配置文本一致；通过的校验指纹（只有哈希和文件身份）连同 boot id 存为 `/data/zte-agent-mihomo/validated`，重启后的 agent 在同一次开机里复用。 |
| agent 重启接管中继（Q1） | 新 `wifi_relay/adopt.rs`：`recover_idle` 在有 `resume.json`、路由日志属本次开机、热点开着时先尝试接管。核对 `wpa_supplicant`（私有配置路径、PID 与启动时间）处于 COMPLETED 且是车主那个网络，唯一的 IPv4 租约有效且地址仍在 `u60sta0` 上；只停 IPA 的两个监听进程，保留 supplicant 和 `odhcp6c`；`Transaction::load` 接过三份日志，按租约重建的计划逐步 `Transaction::adopt`（仍在的不再执行，此后由 `reconcile` 覆盖）；`uplink::Shared::adopt` 一次加载整表。`udhcpc` 与 agent 同属一个 SELinux 域，随 agent 退出，所以新开一个，按新会话路径请求原地址，租约一致才接管。`offload::Runtime::adopt` 用日志里的原模式撤销，不重新挂载 IPACM。IPv6 由 `ipv6::Upstream::adopt` 同样接管，不一致时只重启 IPv6。任何一项不符即放弃，按原来的回滚加恢复处理。助手句柄改为 `Helper`（自己的子进程，或按 PID 加启动时间认定的接管进程）。 |
| 拆除顺序 | `prepare` 先建 INPUT 防护和中继表，再 `iw phy … interface add`；逆序撤销先删接口，再撤防护。 |
| IPv6 节点提示 | `routing::Routes::v6_only_in_use` 沿规则目标（全局模式为 `GLOBAL`）、`select` 的当前选择和自动组的全部成员，找出能用到、服务器只有 IPv6 地址的节点；出口没有 IPv6 时 `/api/mihomo/status` 的 `notice` 写明，Mihomo 页面和控制台在错误同一位置显示。 |
| 5 GHz 之间切换不等 CAC | `handover`（`wifi_relay.rs`）：已连 5 GHz 网络时再连另一个 5 GHz 网络，只拆旧会话的硬件路径、IPv6、路由、DNS、租约和关联；中继网卡、supplicant、防护表和热点日志（其撤销仍回车主的信道）交给新会话。`hotspot::restage` 把热点从中继带去的 DFS 信道切回非 DFS 的 20 MHz 过渡信道（不记日志、不需雷达检测），再 `reconfigure` 加 `reconnect` 关联新网络，由驱动把热点带过去。B31 实测热点留在 DFS 信道 52/160 时中继在同一信道上关联不上（一直 SCANNING），所以必须先回过渡信道。交接失败就按原流程完整拆除。出口标识加上中继所连 AP 的 BSSID（`iw dev u60sta0 link`）：换了网络即使接口和地址不变也重启核心；同一 AP 重连不重启。重连同一个 AP（BSSID 相同）且 IPv6 已配好时，IPv6 整体交给新会话（`odhcp6c`、地址、路由、NAT66 和给 LAN 的 RA 都不动，`Upstream::configured`），不再重新获取。切到或离开 2.4 GHz 仍按原流程。 |

**本机已验证**：开发机全量 `cargo test --locked -p zte-agent -- --test-threads=4`：1438 通过、0 失败、6 忽略（另有集成测试 1 项通过）；响应式控制台 `node ui/tests/mihomo-model.cjs` 与 Playwright `ui/tests/mihomo.cjs` 通过。新增 `egress::tests::{a_relay_switch_restarts_the_core_once_when_the_new_uplink_is_up, a_core_left_on_the_relays_interface_follows_cellular_once_it_appears}`、`controller::tests::a_relay_switch_restarts_the_core_once`、`routing::tests::an_ipv6_only_node_counts_only_where_traffic_can_reach_it`、`mihomo::tests::a_validation_is_remembered_for_this_boot_only`、`adopt::tests::{only_the_owners_completed_association_is_taken_over, the_session_supplicant_is_told_from_recovery_and_other_ones, exactly_one_previous_lease_is_taken}`、`ipv6::tests::only_the_relays_own_ipv6_client_is_taken_over`、`web::tests::network::a_node_that_needs_ipv6_the_uplink_lacks_is_shown_as_an_alert`、`egress::tests::another_access_point_behind_the_relay_moves_the_egress`、`hotspot::tests::a_handed_over_hotspot_leaves_its_dfs_channel_for_the_non_dfs_staging_one`。发布构建 section Total 9,071,372 B（较上节 +43,520），gzip 4,460,665 B（+21,643）。本 Mac 重启后 `/tmp/u60-cross-tools` 丢失，按 Zig 0.15.2 重建了包装器（滤掉 `--fix-cortex-a53-843419` 和 Rust 自带的 crt 对象，改用 Zig 的），增量里可能有一部分来自工具链。

**设备已验证**（B31，路由器上 netns 测试客户端跑双出口探针，不切换车主的 Wi-Fi）

| 项目 | 结果 |
| --- | --- |
| 部署即计划内重启（四次） | 每次都接管：`u60sta0` 不重建（ifindex 不变），选路规则一直在，supplicant PID 不变；接管耗时 3.25 s、3.19 s，加上 IPv6 接管后为 1.45 s、1.49 s。Mihomo 只启动一次，IPv6 回来时 `core kept running`。 |
| `kill -9` agent（IPv6 接管前） | 守护进程 2.5 s 拉起；中继 3.4 s 接管；校验复用，核心在击杀后 7.7 s 运行。内核旁路直连 0 失败，硬件长下载只停 2.2 s；代理中断 13 s（IPv6 重启期间，仅有 IPv6 地址的节点不可达）；0 漏出。 |
| `kill -9` agent（最终） | 守护进程 2.5 s 拉起；中继 1.1 s 接管（只停 2 个监听，`odhcp6c` 保留）；核心在击杀后 6.9 s 运行；代理中断 7.7 s，经核心的直连 6.4 s，内核旁路直连 0 失败；0 漏出。修复前同一操作中继断约 84 s，核心另重启 3 次。 |
| 中继重连 W_Game→W_Game | 断开时 `no egress; the core keeps running`，连上时一次 `restarting: the egress changed`，IPv6 回来时 `core kept running`：整次切换核心只重启一次（修复前 3 次）。总中断约 85 s，主要是拆除时热点 160 MHz 的 CAC，与核心无关。 |
| 校验复用 | 最终部署的接管启动为 `validation reused`（与上一次重启的配置文本一致）。 |
| 5 GHz 切换（W_Game→W_Game） | 连接请求 11.0 s 返回（修复前 74–85 s）。热点 52/160 → 1.1 s 后 36/20 → 中继关联 → 再 1.1 s 回到 52/160，没有回 36/160；`u60sta0` 不重建（ifindex 77 不变）。同一 AP、同一地址，Mihomo 未重启（`no egress` 后 `core kept running`）。探针：直连中断 3.7 s；代理中断 16 s，等 IPv6 重新取得（所选节点只有 IPv6 地址）。之后 `wireless.json` 仍只有一条回 36/160 的撤销和一条断开关联，撤销顺序为先删接口、再撤中继表和 INPUT 防护（上面拆除顺序的修复在设备上的体现）。 |
| 同一 AP 重连带 IPv6 交接 | 连接请求 8.1 s 返回，返回时 IPv6 已是 `configured`。测试客户端每 0.2 s 经 NAT66 ping `2400:3200::1`：整次切换只有一个约 1 s 的失败窗口（原来约 10 s）。代理探针 0 失败、代理长下载无停顿（只有 IPv6 地址的节点一直可达），Mihomo 未重启；IPv4 直连中断 3.7 s；热点 52/160 → 36/20 → 52/160 共 1.4 s。 |

**仍待设备验证与已知限制**：IPv6 节点提示未在设备上复现（需要再关一次中继 IPv6）。接管期间核心未就绪时，内核按设计把流量全部交给核心（Hold）：核心刚开始监听、整表尚未加载的约 3 s 里，走 CPU 路径的直连 TCP 会被核心的监听端回 RST（最终一次 `kill -9` 中 tuna 长下载因此断开），硬件转发中的流不受影响；保留此行为，避免核心未核验期间有流量绕过它。切到 2.4 GHz 网络和断开时热点仍要回车主的 160 MHz 信道并做 CAC（约 65 s）；换到另一个 5 GHz 网络（含不同信道）未在设备上测（为不改动车主正在用的上游，只测了同一网络重连）；换到另一个 AP 时 IPv6 仍重新获取（约 10 s）。未修复：发现 4（硬件流在 conntrack 删除后仍走旧出口 7.7–9.4 s，取决于 IPACM）、5（核心热重载内存增长）、6（核心按源端口复用 UDP 会话，属 Mihomo 自身行为）、8（节点没有 IPv6 出口）。
