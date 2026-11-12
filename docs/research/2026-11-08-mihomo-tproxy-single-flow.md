# Mihomo 透明代理：TPROXY/REDIRECT 单连接为什么慢（2026-11-08）

前半部分是研究和临时实验；最后采用的方案（TPROXY + agent 自己的 nft 表 + pacing 1000 +
brnf 0）见"采用的方案"一节，已经实现并部署。实验环境：U60 Pro B31，内核 5.15，中继连 W_Game 52/160，
IPA 处于 HW 模式；Mac 连热点 G。用 HTTP 从 tuna/nju 镜像下载 12 秒，只有 Mac 到这两个镜像的
流量被强制经过 Mihomo（规则判定直连）。单位 Mbit/s；Mihomo 一列是它占单核的百分比。

## 结论

**单连接慢是 TSQ 的时间项造成的，不是 Mihomo 的问题。** 走 TPROXY/REDIRECT 时，"设备 → Mac"
这一段是设备本机发出的 TCP，要经过 wlan2（qcacld，不走 mac80211）。TSQ 允许压在网卡里的数据量是
`min(tcp_limit_output_bytes, sk_pacing_rate >> sk_pacing_shift)`：

- `sk_pacing_shift` 默认是 10，后一项约等于 1 ms 的发送量；
- mac80211 驱动会把 shift 调成 8（约 4 ms），qcacld 不会调；
- Wi-Fi 确认发送完成又比较慢。

所以单流在途数据一直被卡住，只调大 `tcp_limit_output_bytes` 没有用。
`net.ipv4.tcp_pacing_ss_ratio` 和 `tcp_pacing_ca_ratio`（默认 200 和 120，上限 1000）会按比例
放大 `sk_pacing_rate`，也就放大了这一项。这里没有 fq，这两个值只影响 TSQ，不会真的做 pacing。

TUN 模式下，核心的 TCP 写进 TUN 就算发送完成，回给 Mac 的包走转发路径，不受 TSQ 限制，
但 Mihomo 用户态会占满约一个核。

## 数据

**本机发送基线**（iperf3，设备发给 Mac，不经过 Mihomo）

| 设置 | 单连接 | 4 连接 |
| --- | ---: | ---: |
| 默认（200/120，tlob 约 494 KB） | 174.7 | 611.4 |
| pacing ratio 1000/1000 | **840.1** | — |
| pacing ratio 1000/1000，tlob 4 MB | 814.5 | — |
| 只把 tlob 调到 4 MB | 190.4 | — |

HW 模式本身不拖慢本机发送：11/03 在 SW 模式下，单连接是 137–185，4 连接是 458–481。
wlan2 的 scatter-gather 是 `off [fixed]`，br-lan 跟随端口，SG 和 GSO 都打不开。

**经过 Mihomo 的 IPv4 TCP**

| 路径 | brnf | pacing | 单连接（tuna / nju） | 4 连接 | Mihomo |
| --- | :---: | :---: | ---: | ---: | ---: |
| TUN（现状） | 1 | 200/120 | 125.3 / 131.6 | 107.5 | 约 90% |
| TUN | 1 | 1000 | 132.5 / 129.8 | — | 约 90% |
| TPROXY | 0 | 200/120 | 61.4 / 73.9 | 195.0 | 9–14% |
| TPROXY | 0 | 1000 | **237.2 / 208.4** | 240.6 | 33–42% |
| REDIRECT | 1 | 200/120 | 54.5 / 103.8 | 187.7 | 9–16% |
| REDIRECT | 1 | 1000 | **235.1 / 172.6** | 242.7 | 35–38% |
| REDIRECT IPv6 | 1 | 1000 | 222.5（tuna） | — | 40% |

约 240 是这两个镜像、空口和上游的共同上限（硬件转发直连也是约 240）。

**REDIRECT 单连接在不同 pacing ratio 下的表现，以及负载下 Mac ping 设备的平均延迟**

| pacing ratio | 单连接 | 负载下 ping 平均 |
| --- | ---: | ---: |
| 200 | 105.9 | 10.1 ms |
| 400 | 162.9 | 13.1 ms |
| 600 | 160.3 | 11.2 ms |
| 1000 | 236.3 | 11.7 ms |

空闲时 ping 平均 5.9 ms。调到 1000 没有带来明显的额外排队延迟。

**UDP**：TPROXY 转发 NTP，brnf=1 时失败（规则命中了，但 Mihomo 收不到），brnf=0 时成功。
TCP 的 TPROXY 在 brnf=1 下同样不通（侧边对话：连接停在 SYN_SENT）。REDIRECT 改的是目标地址，
不依赖套接字分配，所以 brnf=1 下 IPv4 和 IPv6 都能用。

侧边对话的补充数据：独立实例上 TUN 开 `gso:true`，单连接 145–161，4 连接约 125，CPU 仍然
约 0.9 个核。GSO 不能热切换。

## nftables 实验

- B31 有 nftables 1.0.8，内核带 NFT_TPROXY、NFT_SOCKET、NF_TABLES_INET 和
  NFT_FIB_IPV4/IPV6，但**没有 NFT_FIB_INET**（inet 表里的 `fib` 返回 ENOENT），也没有
  NF_TABLES_BRIDGE。所以表要按协议族分成 `ip` 和 `ip6` 两张。
- nft 和 legacy iptables 同时生效。ZTE 只改写 legacy，不碰 nft。nft 里的 accept 不能推翻
  legacy 的 DROP，所以要穿过 ZTE DROP 的例外（`U60_RELAY_FWD`、`redirect_chain` 的
  RETURN）留在 legacy。
- nft 的 tproxy 同样需要 brnf=0：brnf=1 时 TCP 规则计数在涨但 curl 失败，UDP NTP 也失败；
  brnf=0 时都正常，pacing 1000 下 TCP 单连接 239.1 / 229.2。
- `fib daddr type local return`、interval 集合、`socket transparent 1`、`tproxy to :17894`、
  `dstnat - 1` 的 DNS 重定向和 input drop 都通过了 `nft -c`。链名 `fwd`、`post`、`c` 是语法错误。

## 采用的方案（已实现）

用户的取舍：接受 brnf=0（访客隔离之类的 LAN 内部过滤在 Mihomo 运行期间失效）；不做国内
IPv6 内核绕过，IPv6 全部交给 Mihomo，代码简单一些。

1. **TCP 和 UDP 都走 TPROXY**，规则放在 `ip`/`ip6 u60_mihomo` 两张 nft 表里：prerouting
   （`mangle - 1`）排除非 br-lan、DNS、本机地址（`fib daddr type local`）、私网/组播和国内
   IPv4 集合，然后对已建立的透明套接字打标记，其余 TPROXY 到 17894，标记 `0x700/0xff00`；
   pref 18620 把这个标记送到 60625 表（`local default dev lo`）。`dns` 链（`dstnat - 1`）把
   LAN 的 53 重定向到 1053；`input` 链只允许 br-lan/lo 访问 1053 和 17894。
2. **Mihomo 运行期间**：`tcp_pacing_ss_ratio`/`tcp_pacing_ca_ratio` = 1000，
   `bridge-nf-call-ip(6)tables` = 0。都是 Transaction 里的 `@u60-sysctl` 步骤，停止时恢复
   启动前读到的值。
3. ZTE 在中继连上后、fw3 重载后会把 brnf 改回 1，由 `net_guard` 自动改回 0
   （`zte-agent/docs/relay-hw-offload.md` 第 5 节）。2026-11-12 注：中继连上后的那次也是 fw3 重载，
   由 agent 自己的 IPv6 `set_data` 引起（同一节）。
4. 没有用 REDIRECT：它只能处理 TCP，UDP 还得留一个 TUN，代码更复杂。

部署后的实测（Mac 绑定 en0，tuna 镜像，15 秒）：IPv6 和 IPv4 经过 Mihomo 单连接
190.6–238.6，4 连接 235.2；Mihomo 占单核 31–44%（TUN 时约 90%）；UDP 的 v4/v6 DIRECT
双向正常。详见 `zte-agent/docs/relay-hw-offload.md` 末尾一节。

## 注意

- agent 的私有下载代理占用了 `127.0.0.1:17893`。实验时 redir 端口一开始和它撞了，
  PATCH 没有报错就静默失败了。实现里 TPROXY 用 17894，启动前先检查端口能否绑定。
- Mac 优先走 IPv6，测 IPv4 路径时要用 `curl -4`。
- Mac 上开着 Clash Verge TUN 时，测试要绑定 en0（`curl --interface en0`），并用
  `--resolve` 填路由器 DNS（`dig @192.168.0.1`）解析出的地址，否则流量先经过 Mac 自己的
  Clash，系统 DNS 还会返回 Clash 的假地址。
- 开着国内直连时，国内 IPv4 走内核/HW，不经过 Mihomo；测核心路径要用 IPv6，或者临时关掉
  国内直连。
