# 开着 ADB 时 Mac 的 USB 网络（owner decision 66）

2026-11-11。只要 ZTE 用的是带 ADB 的调试组合，agent 就在 USB gadget 上加第二个配置
`c.2`（CDC ECM + ADB）：Windows 仍用配置 1 的 RNDIS，macOS 自己选配置 2 的 ECM。
全自动，面板里没有开关（owner 选择）。代码：`src/usb_net.rs`。

## 为什么 Mac 原来没有 USB 网络

- macOS 只带 CDC ECM/NCM 驱动（`AppleUserECM`、`AppleUSBNCM`），没有 RNDIS 驱动。
  RNDIS 接口在 `ioreg` 里能看到，但没有驱动接管，网络设置里也就没有网卡。
- ZTE 的内核会识别主机：Windows 会请求 MS OS 描述符，日志里记作
  `[ZTE_USB] OS TYPE is OS_TYPE_MAC/OS_TYPE_Linux`。但它只在普通（user）模式下才据此切换：
  开机先是光盘模式 `0x1225`，识别后 Mac/Linux 切到 `0x1405`（`ecm_gsi,mass_storage`）。
  Mac 网络设置里那个 “ZTE Mobile Broadband”（`en16`，idProduct 5125）就是这时留下的。
- 打开 ADB 后（`debug_enable`，内核组合 `0x81`），组合固定为
  `0x19d2:0x1404 rndis_gsi,diag,serial,modem,mass_storage,ffs,dpl,qdss`：
  内核照样识别出 Mac，但不再切换，所以 Mac 一直只有 RNDIS。
- ZTE 的 `zwrt_bsp.usb` 只有 `list`，没有 `set`，固件里也没有选 RNDIS/ECM 的接口。

## 做法

- `c.2` 里只有两个链接：`u60-ecm → functions/gsi.ecm` 和 `u60-adb → functions/ffs.adb`。
  链接名特意避开 ZTE 用的 `f1`…`fN`；配置字符串是 `ECM`，`bmAttributes`、`MaxPower` 从 `c.1` 抄。
- 加的条件：`c.1` 同时有 `gsi.rndis` 和 `ffs.adb`，并且有 `gsi.ecm` 这个功能。
  其他组合（普通模式、光盘模式等）由 ZTE 自己按主机切换，agent 只负责删掉留下的 `c.2`。
  有 `c.3` 以上的配置、`c.2` 里有不是 agent 建的链接、或者 ZTE 正在切换时，一概不动。
- ZTE 的 `network.lan.ifname` 本来就有 `ecm0`，Mac 选中配置 2 后 `ecm0` 自动加入 `br-lan`，
  Mac 通过 DHCP 拿到 `192.168.0.x`。
- Linux 主机没测：两个配置 Linux 都有驱动，用哪个由内核自己选。

## ZTE 重建 USB 组合时

开机、user/debug 模式切换、主机发切换命令时，ZTE 都会运行 `/sbin/usb/compositions/usb_switch`。
它只重建 `c.1`：先 `rm configs/c*/f*` 删掉所有链接（包括 `c.2` 的），再 `rm -rf configs/c.2`。
configfs 的属性文件删不掉，BusyBox `rm -rf` 只要有子项删除失败就不会执行 `rmdir`，所以空的 `c.2`
一直留着；接着 ZTE 绑定 UDC 时内核因为配置 2 里没有功能而拒绝（`-EINVAL`），
**整个 USB 都断了，ADB 也一样**。

agent 用 inotify 监听这个脚本的 `IN_OPEN` 和 `IN_CLOSE_NOWRITE`（每次运行都会打开、结束时关闭），
最后一个事件后安静 1 秒再检查。`/tmp/usb_bind_in_progress` 是 `start` 时最多再等 30 秒。检查结果：

- 调试组合：重新链接 `c.2` 并绑定。这次绑定取代了 ZTE 失败的那次，主机只看到一次连接。
- 其他组合：删掉 `c.2` 再绑定。
- 线插上时的 `START_PERIPHERAL` 也会运行这个脚本，但这时 `c.2` 是完整的，agent 什么都不做。

除此之外没有定时器；只有 inotify 不可用时才改为每分钟检查一次。

**风险**：agent 被有意停止（`/tmp/zte-agent-run/stopped`）或卸载以后，如果 ZTE 再重建组合，
USB（包括 ADB）会一直断着，直到 agent 再次启动（启动时立即修复，不等 60 秒）或者重启路由器
（重启后 configfs 里没有 `c.2`）。只在线一直插着、ZTE 又恰好重建时才会遇到。

## 开发 Mac 的上网路径（2026-11-12）

Mac 选中配置 2 后，macOS 把 USB 服务 “ZTE Mobile Broadband” 排在 Wi-Fi 之前，Mac 的默认路由就经过路由器。
于是中继断开会切断 Mac 的外网，跑在这台 Mac 上的 agent 会话也随之断开。在路由器上把 `ecm0` 关掉不会让
macOS 切到 Wi-Fi（2026-11-12：默认路由经 `en16` 走路由器，`en0` 仍连着 Wi-Fi；`ip link set ecm0 down` 7 秒后
`en16` 仍是活动的、默认路由仍走它、外网不通，`ip link set ecm0 up` 后恢复；`measurements/observations-2026-11-12.md`）。测试中继断开前，先给 Mac 一条不经过路由器的外网路径。

## 修改配置时暂停 adbd

configfs 只允许在 gadget 解绑时增删配置和链接。可解绑后，`adbd` 的 FunctionFS 会收到 unbind，
它在约 20 ms 内就把 UDC 绑回去，之后的 `ln` 和绑定都会失败（`EBUSY`/`EINVAL`）。
所以修改期间先用 `SIGSTOP` 暂停所有 `adbd`，改完（约 0.1 s）再用 `SIGCONT` 恢复。
agent 每次启动都会先给 `adbd` 发一次 `SIGCONT`，以防上一个 agent 恰好在暂停期间死掉。

## 重新连接与启动时机

修改一个已经绑定的 gadget，主机会看到 USB 断开再连上，ADB 断开约 2 秒。
agent 启动时如果需要这样做（第一次装上这个功能时），会推迟 60 秒，让 `setup.sh` 后面的 ADB
验证先跑完；如果 gadget 已经解绑（USB 已断，比如 agent 停止期间 ZTE 重建过），就立即修复。
配置已经完整时什么都不做，所以平时的部署和 agent 重启不会让 USB 重新连接。

## 设备测试（2026-11-11，Mac：macOS 26，Apple Silicon）

| 场景 | 结果 |
| --- | --- |
| 首次部署 | 推迟 60 s 后添加；ADB 断约 2 s；Mac 选配置 2，`en16` 约 4 s 拿到 DHCP 地址 |
| ZTE 用调试组合重建 | ZTE 的绑定失败（`UDC` 空、`c.2` 空）；脚本结束后 1.0 s agent 重新链接并绑定；ADB 断约 2 s，`en16` 约 5 s 恢复 |
| ZTE 切到 `diag,ffs`，再切回 | 删除 `c.2` 并绑定（只剩 1 个配置，ADB 正常）；切回调试组合后又加回来 |
| 断开再连接（`soft_connect`） | 仍选配置 2，agent 不动作 |
| agent 被杀，guard 拉起 | 不动作，USB 不断 |
| agent 停止期间 ZTE 重建 | USB 全断；agent 启动后约 2.6 s 修复 |
| 下载速度（清华镜像，各 10 s × 2） | `en16` 186–234 Mbit/s，Wi-Fi `en0` 121–142 Mbit/s；路由器 CPU 两者都约 45%（Mihomo 开着，走 CPU） |
| 硬件转发（中继上行，Mihomo 与 `cn-direct` 开，各 10 s） | 直连镜像真实 IP（`curl --resolve`，内核绕过核心）：USB 148.9 Mbit/s，内核只转发 460 个包，`ecm0` 只过了 704/1,758 个包，CPU 15%、软中断 1.9%；Wi-Fi 106.5 Mbit/s、转发 203 个包、CPU 14%。按域名（fake-ip，进 Mihomo 核心）：USB 113.7 Mbit/s，`ecm0` 过了 22,559/100,747 个包，CPU 39%、软中断 20%；Wi-Fi 132.4 Mbit/s、CPU 42%。 |

所以 USB 和 Wi-Fi 一样：内核直连的连接由 IPA 硬件转发（`gsi.ecm` 的数据经 GSI 直接进出 IPA，
原厂 `IPACM_cfg.xml` 里 `ecm0` 是 `LAN`），进 Mihomo 核心的连接都在 CPU 上。

没有测：Windows（预期用配置 1 的 RNDIS）、真实拔插线、Linux 主机、蜂窝上行时的硬件转发。

release 二进制 `size -A` Total 9,093,120、`gzip -9` 4,471,439 字节（之前 9,071,372 / 4,460,675；
增加 21.2 KiB / 10.5 KiB）。
