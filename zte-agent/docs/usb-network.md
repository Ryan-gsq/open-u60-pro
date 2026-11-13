# 开着 ADB 时的 USB 网络（owner decision 66）

2026-11-13。带 RNDIS 和 ADB 的调试组合由 agent 维护为唯一配置 `c.1`，按顺序放
`gsi.rndis`、`gsi.ecm`、`ffs.adb`。Windows 使用 RNDIS，macOS 使用 ECM，两边共用 ADB。
代码见 `src/usb_net.rs`。

## Windows 自动识别的依据

旧实现给原厂调试组合增加 `c.2`，里面是 ECM 和 ADB。macOS 26 实测会选择配置 2。
Windows 测试中出现过父设备直接绑定 RNDIS、ADB 子接口消失的情况。手动将父设备绑定到
`usbccgp` 后，RNDIS、ADB 和联网恢复。

Windows 默认匹配 `USB\COMPOSITE` 要求设备只有一个配置。保留双配置、只改为 `EF/02/01`
并换序列号的实验仍失败。单配置的 `RNDIS + ECM + ADB`、`EF/02/01` 和新序列号已经通过
Windows 自动枚举实验，出现复合设备、RNDIS 和 ADB。实验电脑已有 ADB 驱动，全新 Windows
的 ADB 驱动安装仍待确认。微软规则见
[Enumeration of the USB composite parent device](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/enumeration-of-the-composite-parent-device)。

本版先交付这个三功能组合。诊断、串口、存储、DPL、QDSS 的函数对象保留在 gadget 中，
主机当前只看到 RNDIS、ECM、ADB。保留全部调试接口的布局需要另做端点和双平台稳定性验证。

## 配置和迁移

- `c.1/f1 → functions/gsi.rndis`，`f2 → functions/gsi.ecm`，`f3 → functions/ffs.adb`。
  RNDIS 最先链接，接口编号随此顺序分配。网络继续使用原厂 GSI/IPA 函数。
- 设备类为 `EF/02/01`。USB 序列号在原值后加固定后缀 `-u60net1`，让 Windows 为新布局
  重新枚举。重复执行保持同一序列号。ADB 的 `-s` 参数应使用新值。
- 仅在 `c.1` 同时包含 RNDIS、ADB 且 ECM 函数存在时应用。电源银行/USB 网卡的 host
  角色、厂商切换中的状态、额外配置或带第三方链接的 `c.2` 都等下一次合法状态再判断。
- 迁移旧 `c.2` 时检查链接名和函数目标，只接受旧的 `u60-adb`、`u60-ecm`，也接受 ZTE
  重建留下的空配置。先保存链接、语言字符串、功耗属性及设备描述符，再删除旧配置。
- `c.1` 的功耗、配置字符串沿用已有值。编辑或绑定失败会恢复原链接、旧 `c.2` 的属性、
  设备类和序列号，再绑定 UDC。恢复失败会明确记录在日志中。此次单配置转换失败后等
  agent 重启再尝试，避免不停重新枚举。
- ZTE 的 `network.lan.ifname` 已包含 `ecm0` 和 `rndis0`，实际使用的网口进入 `br-lan`，
  主机通过 DHCP 获得 `192.168.0.x`。

## ZTE 重建与 adbd

`/sbin/usb/compositions/usb_switch` 负责原厂组合和 `START_PERIPHERAL`。模块监听脚本
`IN_OPEN`/`IN_CLOSE_NOWRITE`，最后一个事件后安静 1 秒再修复。切换标志 `start` 最多等待
30 秒。仅 inotify 不可用时每分钟检查。

链接使用 ZTE 自己会清理的 `f1`…`f3`。原厂重建完调试组合后，agent 再收敛为三功能。
普通模式、光盘模式继续由原厂管理，并清理本模块遗留的旧 `c.2`。

编辑时先暂停所有 `adbd`，再解绑 UDC、改配置、重绑，最后恢复 `adbd`。FunctionFS 会在
解绑约 20 ms 后自行重绑，暂停覆盖整个事务。每次 agent 启动先恢复 `adbd`，处理上次进程
恰好退出在暂停阶段的情况。

首次启动如果要修改已绑定的设备，推迟 60 秒，让 `setup.sh` 的 ADB 验证完成。已解绑时
立即修复。布局完整且已绑定时重复执行直接结束。

旧版 `c.2` 的 configfs 属性不能用 BusyBox `rm -rf` 清理，空配置会让原厂 UDC 绑定失败。
迁移过程逐个移除语言目录和配置目录。迁移成功后，原厂重建可自行清掉 `c.1/f*`。

## 开发 Mac 的联网路径

Mac 曾将 USB 服务 “ZTE Mobile Broadband” 排在 Wi-Fi 之前，默认路由因此经过路由器。
测试中继断开前，先给 Mac 一条独立外网路径。仅关闭路由器 `ecm0` 会留下 Mac 的原路由。
新序列号和接口编号可能产生新的 macOS 网络服务，应通过 `networksetup -listnetworkserviceorder`
和 `ioreg` 确认接口，再用 `curl --interface <接口>` 验证 USB 路径。

## 验证记录

### 2026-11-11 的旧双配置

macOS 26 的 ECM、ADB、原厂重建、软件断开再连接及 agent 重启通过。直连镜像下载
148.9 Mbit/s 时，内核仅转发 460 个包，路由器 CPU 15%，支持 ECM 使用 IPA 硬件转发。
该记录对应旧布局。

### 2026-11-13 的单配置

本地 `cargo test --locked -p zte-agent usb_net:: -- --nocapture` 8 项通过，覆盖单配置、旧布局
迁移、重复执行、原厂重建、host/第三方配置保护、绑定失败恢复及恢复失败日志。新增单配置
回归在旧实现上失败，修改后通过。

通过 `setup.sh --build --adb --serial 0123456789ABCDEF --factory-password --no-ssh` 部署到
slot A。设备上运行的文件 SHA-256 与本地 release 一致。

| 检查 | 实测结果 |
| --- | --- |
| 原始 USB 描述符 | 唯一配置 1、设备类 EF/02/01，RNDIS 接口 0/1、ECM 接口 2/3、ADB 接口 4 |
| Mac 驱动与 DHCP | 自动加载 AppleUserECM，en16 获得 192.168.0.75，USB 序列号 0123456789ABCDEF-u60net1 |
| 绑定 en16 联网 | 路由器页面 HTTP 303，外网 HTTPS 200，curl 源地址为 USB 地址 |
| ADB | 新序列号自动重新连接，shell 和文件传输通过 |
| 原厂重建 | 实际调用原厂 usb_switch 重建完整调试组合，inotify 收敛回三功能，ECM 与 ADB 恢复 |
| 软件断开再连接 | soft_connect 断开 2 秒后重连，ADB、USB HTTPS 正常 |
| agent 重启 | PID 更换后布局完整，USB HTTPS 和 ADB 正常，USB 修复日志未出现新增重配 |
| 重启后连续检查 | 约 105 秒内 6 次绑定 USB 的 HTTPS、ADB 和单配置检查全部通过 |
| GSI/IPA 与短测速 | 指定 en16 和镜像真实 IPv4，15 秒下载 446,840,814 字节，238.28 Mbit/s；CPU 18.8%，softirq 2.6%；内核转发仅 537 包、ecm0 RX/TX 36/529 包，USB GSI 计数增加 |

测速使用清华镜像 `ubuntu-24.04.4-live-server-amd64.iso`，`curl --resolve` 固定当时真实地址
101.6.15.130，15 秒到时主动停止。上行为 Wi-Fi 中继，Mihomo 运行，直连请求由内核绕过核心。
大量下载与少量内核包计数、GSI 活动一致，支持本版继续使用 IPA 硬件转发。

测试前 Mac 的 “ZTE Mobile Broadband” 服务被禁用，验证期间将它启用，结束后恢复禁用。
再次在这台 Mac 上使用 USB 网络时需启用该服务。
切回原 Wi-Fi 配置后的附带检查中，系统解析 `www.microsoft.com` 得到 198.18.2.53，
路由器 DNS 返回 198.18.10.49。前者 HTTPS 证书域名校验失败，用 `--resolve` 指定后者
得到 HTTP 200。USB 验证使用 DHCP 的网络配置且连续 HTTPS 通过；这个 Wi-Fi DNS
差异另行保留为观察结果。

release `aarch64-linux-musl-size -A` Total 为 9,214,032，`gzip -9` 为 4,527,626 字节。
修改前为 9,209,540 / 4,525,395 字节，分别增加 4,492 / 2,231 字节。
本机使用 GNU binutils 的 `size`，通过 `aarch64-linux-musl-size` 同名链接调用。
SHA-256 为 `c0b2eb4b00f0d75469f59267edaaff23b127ff9a5cb70e9a58da2435cddc6b92`。

Windows 本次 release 的实际联网、全新系统 ADB 驱动、两平台真实拔插和冷启动仍待实测。
