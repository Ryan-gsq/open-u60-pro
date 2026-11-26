# B31 fw3 接入实验（2026-11-12）

> 历史记录。适用 B31 当时的防火墙与测试构建。原始日志为开发机留档，现行决定见
> [架构 §9](../relay-mihomo-architecture.md#9-实验过没有采用的两种接入厂商防火墙的办法2026-11-12)。

两项都在车主的 B31 上做了实验，都是易失的（重启即消失），实验后防火墙规则与实验前逐行相同。记录在
`measurements/b4-fw3/`（`fwprobe.log`、`nf-nat-warning-times.txt`、`second-masquerade-control.txt`）。

## 9.1 让 fw3 在每次重载后运行我们的脚本

- **做法**：`ubus call service add '{"name":…,"data":{"firewall":[{"type":"script","path":…,"family":"any","reload":true}]}}'`。
  fw3 每次运行都读 procd 的 `firewall` 数据，确实运行了这个脚本；`service delete` 之后数据消失。
- **结果**：脚本在重载开始后 0.06 秒就运行了，那时 brnf 还是 0、`redirect_chain` 还有我们的 RETURN。厂商的
  `firewall_init.sh` 排在它之后，又跑了约 3 秒，把 brnf 写成 1、清空 `redirect_chain`。这个版本的 fw3 先运行
  ubus 提供的 include，再运行 UCI 里的 include。
- **结论**：没法用它在厂商脚本之后同步补回，所以没有采用。现在的做法（inotify 加 0.5 秒采样）在 brnf 被改后
  0.2–0.9 秒内改回，RETURN 在重载结束后约 2 秒补回。

## 9.2 让中继站点成为 fw3 `wan` 区的成员

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
