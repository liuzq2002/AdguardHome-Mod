# TUN 分析与「给 AdGuardHome 加 TUN」的可行性

这个问题分两半：**mihomo 的 TUN 是怎么工作的**，以及**这套东西搬到 AdGuardHome（尤其是本仓库的 Android/Magisk 场景）值不值**。

参考源码（本次实际拉取、阅读的版本）：

| 仓库 | 版本 | 位置 |
| --- | --- | --- |
| `MetaCubeX/mihomo`（`Meta` 分支） | `ab405bad` | `C:\Users\juana\Documents\ChatGPT\_refs\mihomo` |
| `MetaCubeX/sing-tun`（mihomo 的 TUN 底层库） | `0399d71` | `C:\Users\juana\Documents\ChatGPT\_refs\sing-tun` |
| `AdguardTeam/dnsproxy`（AGH 的 DNS 引擎） | `HEAD` | `C:\Users\juana\Documents\ChatGPT\_refs\dnsproxy` |
| `liuzq2002/Adguard-Home-For-Magisk-Mod` | `HEAD` | `C:\Users\juana\Documents\ChatGPT\_refs\Adguard-Home-For-Magisk-Mod` |

## 0. 结论先行

1. **TUN 本身不神秘，也不难**：一句话就是「内核给你一个 L3 虚拟网卡，你从文件描述符里读写裸 IP 包」。难的是它周围的三件事——**路由接管、用户态协议栈、环路规避**。
2. **技术上加 TUN 是可行的**：sing-tun 只用 `system` 栈时可以在 `CGO_ENABLED=0 GOOS=linux GOARCH=arm64` 下干净编译，实测给二进制增加约 **1.8 MB**（带 gVisor 约 **4.0 MB**），对本仓库的发布体积影响很小。许可证也兼容（AGH / mihomo / sing-tun 都是 GPL-3.0）。
3. **如果 TUN 只是为了"抢 DNS"，收益接近于零**：AGH 是 DNS 服务器，不是代理，而抢 DNS 这件事现在模块里的 `iptables ... REDIRECT --to-ports` 已经用十分之一的复杂度做到了。这一路只值得抄 mihomo 的 `auto-redirect`（netfilter 重定向）和 `ip rule`/fwmark 那套"排除自己、绕过环路"的机制，见第 5 节。
4. **如果 TUN 是为了 SNI 阻断（在 TLS ClientHello 里读域名拦广告），结论完全不同——这个场景才真正需要 L3 拦截**。而且好消息是：**mihomo 已经把整套引擎写完了**（`sniffer` + `tun` + `REJECT` 规则），AGH 缺的只是"把域名规则喂给谁"。完整分析见第 9 节。
5. 一句话取舍：抓 DNS 用 netfilter 就够；抓 SNI 需要 L3 拦截，但**优先复用现成的 mihomo，其次用 NFQUEUE，最后才考虑在 AGH 里造 TUN**。

## 1. mihomo 的 TUN 原理

### 1.1 五层结构

mihomo 的 TUN 不是一个组件，而是一条流水线，从下到上依次是：

| 层 | 干什么 | 关键代码 |
| --- | --- | --- |
| 设备层 | 创建/打开虚拟网卡，拿到一个能读写 IP 包的 fd | `sing-tun/tun_linux.go:272` `open()`、`tun_linux.go:49` `New()` |
| 配置层 | 给网卡配地址、MTU、路由表、策略路由 | `tun_linux.go:303` `configure()`、`tun_linux.go:921` `setRoute()`、`tun_linux.go:935` `setRules()` |
| 栈层 | 把裸 IP 包还原成"一条 TCP 连接 / 一个 UDP 包" | `sing-tun/stack.go:40` `NewStack()`：`system` / `gvisor` / `mixed` / `mips` |
| 处理层 | 拿到 (源地址, 目标地址, 载荷) 之后决定怎么处置 | `mihomo/listener/sing_tun/server.go:136` `New()` → `handler` |
| 策略层 | 哪些进程/网卡/端口不走 TUN，怎么重定向，怎么防环路 | `tun_rules.go:23` `BuildAndroidRules`、`redirect_linux.go:45` `NewAutoRedirect` |

### 1.2 设备层：TUN 到底是什么

Linux/Android 上就是一个字符设备：

```
fd = open("/dev/net/tun")            // 新 Android 上是 /dev/tun，见 tun_linux.go:264
ioctl(fd, TUNSETIFF, "aghtun0")      // 声明我要一张点对点三层网卡
   flags = IFF_TUN | IFF_NO_PI       // 只要 IP 包，不要 4 字节的包信息头
read(fd)  -> 一个完整的 IPv4/IPv6 包（内核路由送进来的）
write(fd) -> 一个完整的 IPv4/IPv6 包（伪装成从这张网卡收到的）
```

关键点：**内核不会替你处理 TCP 状态机**。你写进去一个 SYN，内核就会把它当成"网卡上收到的包"交给本地协议栈——这正是后面 `system` 栈的取巧之处。

### 1.3 路由层：为什么必须动路由

网卡建好还没用，必须让内核愿意把包交给它：

* `auto-route` 会往 TUN 上挂 `0.0.0.0/0` 和 `::/0`（`tun_rules.go:106` `BuildAutoRouteRanges`），内核于是把"所有出网流量"选路到 TUN。**这一步是全局影响**：TUN 里没人处理的流量不会"漏回"正常网卡，只会被丢掉。
* 为了避免把 gateway / 自身流量也卷进去，sing-tun 用**策略路由**：单独的表（默认 2022）+ `ip rule`（默认优先级 9000）按 fwmark、UID 范围、源/目标端口、网卡做分流（`tun_linux.go:935` `setRules()`）。
* 上游流量（TUN 里的包真的要发出去）被改写后重新注入，用 fwmark 标记，靠 `ip rule` 走 main 表出去，从而**不会再次落回 TUN**（否则就是无限循环）。
* `auto-redirect`（Linux 专有）则走了另一条路：不接管默认路由，而是用 nftables/iptables 的 `REDIRECT`/`TPROXY` 把命中的连接**直接塞给本地 `redirectServer`**（`redirect_server.go:30`）。它依然要求 `auto-route` 已开启，但主要靠 **fwmark 模式**（`AutoRedirectMarkMode`）配合 `ip rule` 精确挑流量。

### 1.4 栈层：TCP 是最贵的那部分

UDP 好办：一个包进、一个包出，无状态。TCP 不行，你得自己实现握手、序号、重传、窗口。sing-tun 给了两种答案：

* `gvisor` / `mixed`：用 gVisor 的 netstack 在用户态实现完整 TCP/IP（`stack_gvisor.go`、`stack_mixed.go`）。纯 Go、无内核依赖，但要拖进一整个 netstack。
* `system`：**不实现 TCP，借用内核的**。做法很巧——收到 TUN 里的 TCP 包后，它改写目的地址和端口，指向本进程在 TUN 地址上监听的一个真实 socket，然后把包**再写回 TUN**（`stack_system.go:414` `processIPv4TCP`），于是内核的 TCP 栈替它完成握手。真正的目标地址存在 NAT 表里，accept 之后由 handler 拿回原目标。

### 1.5 处理层与 DNS 劫持

handler 拿到连接/包之后，DNS 是特殊分支（`listener/sing_tun/dns.go`）：

* `ShouldHijackDns()`（`dns.go:21`）判断目标端口是不是 53；mihomo 里 `dns-hijack` 默认就是 `0.0.0.0:53`（`config/config.go:547`），也就是**所有明文 DNS 一律截胡**，无论目标 IP 是什么。
* UDP 分支：把 DNS 报文交给内核 DNS 解析器，响应再作为一个"来自原始目标 IP"的 UDP 包写回 TUN（`dns.go:38`）。
* TCP 分支：把连接丢给 `resolver.RelayDnsConn`（`dns.go:30`），由内部 DNS 模块应答。
* 注意：**被劫持的 DNS 走的是 mihomo 自己的 DNS 模块，不是外部 DNS 服务器**。它并不认识 AdGuardHome。

### 1.6 Android 特有的坑（本仓库最相关）

sing-tun 在 Android 上多做了三件事，也正好说明了"给 AGH 加 TUN"会踩到什么：

1. **设备节点不同**：新 Android 用 `/dev/tun`，sing-tun 会探测（`tun_linux.go:264`）。
2. **包名 → UID 映射**：`packages_android.go:27` 会去读 `/data/system/packages.xml`（支持 ABX 二进制格式），并用 fswatch 监听变化，才能实现 `include-package` / `exclude-package`。`tun_rules.go:23` `BuildAndroidRules` 把这些包名换算成 `ip rule` 的 UID 范围（每个 Android 用户占 100000 个 UID）。
3. **netd 的路由表冲突**：Android 每个网络、每个 App 都有自己的一套路由表和规则，`ip rule` 必须插在很靠后的优先级（默认 9000），并且在网络切换时重建（`tun_linux.go` 里的 `InterfaceMonitor` 回调）。手机上频繁切 Wi-Fi/移动数据，这是最容易"用着用着断网"的地方。

## 2. AdGuardHome 这一侧：现状与差距

### 2.1 AGH 只做 DNS，而且是以"服务器"的姿态做

AGH 的 DNS 引擎是 dnsproxy：它**自己开 socket**（`dnsproxy/proxy/serverudp.go:41` 的 `ListenPacket`、`servertcp.go:41` 的 `Listen`），收包 → 过滤 → 转发上游 → 回包。所有监听地址都是 `*net.UDPAddr` / `*net.TCPAddr`（`internal/dnsforward/config.go:817` `preparePlain`）。

值得庆幸的是，**过滤链本身和 socket 解耦**：`internal/dnsforward/requesthandler.go:19` 的 `ServeDNS(ctx, *proxy.Proxy, *proxy.DNSContext)` 只依赖 `DNSContext` 里的 `Req / Res / Addr / Proto`（`dnsproxy/proxy/dnscontext.go:16`）。这意味着「不经过 socket 的 DNS 查询」是能喂进 AGH 过滤链的，这是加 TUN 唯一的技术基础。

### 2.2 AGH 现有的"抢 DNS"手段

* 让用户/系统把 DNS 指向它（桌面、路由器、Android 的"私人 DNS"）。
* `internal/ipset`（**只有 Linux**）：把解析出来的 IP 加进 ipset，供防火墙/代理分流。这是 AGH 里唯一的 netlink 代码，也证明 AGH 并不排斥平台相关代码。
* 本仓库的 Magisk 模块：`Adguardhome/scripts/iptables.sh` 用 `nat/OUTPUT` 把 53 端口 `REDIRECT` 到 AGH 的随机端口，并 DROP 掉 853（DoT）和全部 IPv6 DNS。**这就是"DNS 劫持"的工业标准做法**，比 TUN 便宜得多。

### 2.3 差距清单

| 能力 | mihomo | AGH 现状 |
| --- | --- | --- |
| 创建 TUN 设备 | 有 | 无 |
| 用户态协议栈 | 有（gvisor / system） | 无 |
| 路由/策略路由管理 | 有（netlink + fwmark + UID） | 无（只有 ipset 的 netlink） |
| netfilter 重定向 | 有（内建、自愈、支持 nftables/iptables） | 无（靠模块外挂 shell 脚本） |
| DNS 劫持 | 有（`dns-hijack`） | **有，但靠外部 REDIRECT** |
| 环路规避 | fwmark + UID 排除 | 无（脚本没有排除自身 UID） |

## 3. 三个必须知道的硬约束

这三点决定了"加 TUN"的性价比，绕不过去：

1. **建 TUN 必须 root / CAP_NET_ADMIN**。Magisk 场景天然满足；但 AGH 若在配置里设了 `user:`，会在启动时降权（`internal/home/home.go:253`），TUN 与路由必须在降权之前建好。
2. **"只劫持 DNS"和"接管默认路由"是矛盾的**。TUN 只有拿到流量才有机会看 DNS，而拿到流量的方式是抢默认路由；一旦抢了，TUN 里不处理的东西就等于黑洞。所以纯 DNS 场景只有两条路：
   * 用 netfilter 重定向（不碰路由）——现有方案；
   * 或者用 fwmark + `ip rule` 只把 53 端口这条路引到 TUN（可行，但要自己写一套策略路由，且要处理环路）。
   mihomo 能用"全量 TUN"是因为它**本来就要转发所有流量**；AGH 转发不了，这就是本质差异。
3. **AGH 自己的上游查询会被自己的规则劫持**。现在的脚本 `iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT` 对 AGH 自己发出去的明文 53 查询同样生效（模块默认用 DoH 上游所以没暴露）。任何形式的劫持方案都必须排除自身进程（UID 或 fwmark）——这正是 mihomo `ExcludeUID` / `AutoRedirectMarkMode` 解决的同一个问题。

## 4. 实测：集成成本有多大

用 `C:\Users\juana\tools\go\bin\go.exe`，`GOOS=linux GOARCH=arm64 CGO_ENABLED=0`，`-trimpath -ldflags="-s -w"`，真实引用 `tun.New` / `tun.NewStack` / `tun.NewAutoRedirect`（避免链接器把代码删掉），探针在 `C:\Users\juana\Documents\ChatGPT\_refs\tunprobe`：

| 构建 | 二进制 |
| --- | --- |
| 基线（不含 sing-tun） | 1.50 MB |
| + sing-tun（`system`/`mips` 栈，不带 gVisor） | 3.31 MB（**+1.81 MB**） |
| + sing-tun 带 `-tags with_gvisor` | 5.50 MB（**+4.00 MB**） |

结论：**体积不是障碍**，纯 DNS 劫持用 `system` 栈就够，增量不到 2 MB。真正的成本在代码复杂度、生命周期管理、以及"网络一切换就得重建规则"的稳定性上。

其它依赖层面的结论：

* sing-tun 在 linux 下**不需要外部命令**：设备与路由走 netlink，nftables 用自己的纯 Go 实现（`metacubex/nftables`）。只有 `auto-redirect` 的 iptables 后端会 `exec` `iptables`（`redirect_linux.go:62` 在 Android 上硬编码 `/system/bin/iptables`，`redirect_linux.go:91` 才去 `LookPath`）。
* Windows 的 wintun 代码全是 `_windows.go`，`CGO_ENABLED=0` 交叉编译不受影响。
* 许可证：AGH（GPL-3.0）、mihomo / sing-tun（GPL-3.0），可直接依赖。

## 5. 方案对比与推荐

| | A. 内建 netfilter 重定向（推荐） | B. 内建 TUN 只劫持 DNS | C. 与现成 TUN 共存 |
| --- | --- | --- | --- |
| 做法 | 把模块 `iptables.sh` 的逻辑搬进 AGH：启动/网络变化时维护 REDIRECT 规则，按 UID/fwmark 排除自身 | 移植 sing-tun，`fwmark + ip rule` 把 53 引到 TUN，handler 合成 `proxy.DNSContext` 调 AGH 过滤链 | 不改 AGH；mihomo/Box 等模块做 TUN，`dns.nameserver` 指向 AGH |
| 新增代码量 | 小（几百行，含 v6 对称处理与自愈） | 大（设备+路由+栈+handler+权限+生命周期，参考实现约数千行） | 零 |
| 体积 | +0 | +1.8 ~ 4 MB | +0 |
| 需要 root | 是 | 是 | 是（代理模块本身要） |
| 收益 | 去掉易碎的 shell 守护；规则自愈；可顺手修掉 v6 只 DROP 不接管、自身环路两个隐患 | 不依赖 netfilter；v4/v6 统一；为将来"非 root / VpnService"留路 | 立刻可用 |
| 风险 | Android netd 会清规则，需监听网络事件重建 | 网络切换易断网；与代理模块的 TUN 打架（只能有一张默认路由网卡） | AGH 与代理模块的联动配置要维护 |

**推荐按 A → C 组合走**，B 只在下面这种明确需求下才值得做：需要一张不依赖 netfilter 的 DNS 入口，或者将来要做 Android `VpnService` 版（非 root）。

### 5.1 方案 A 的落地要点

1. 新增 `internal/redirect`（`redirect_linux.go` + `redirect_others.go` + `redirect_stub`），生命周期挂在 `internal/home/home.go` 的 `run()`（`home.go:780` `configureOS` 之前创建，避免降权后失败），`Shutdown` 时清理。
2. 规则要**四件事齐全**，否则就是现在脚本的水平：
   * v4/v6 都 REDIRECT 到 AGH 的 DNS 端口（现在 v6 是 DROP，IPv6-only 网络会没 DNS）；
   * 排除 AGH 自身 UID / 或给自身出站打 fwmark（否则明文 53 上游死循环）；
   * 排除回环与 TUN 接口（避免和代理模块互相套娃）；
   * 监听网络变化（`netlink` 的 `RTMGRP_IPV4_ROUTE` / Android 的 `InterfaceMonitor`）自动重建，替代 `while true; sleep 5` 守护。
3. 实现方式二选一：复用 AGH 已有的 `ti-mo/netfilter` + `mdlayher/netlink`（无外部依赖，和 `ipset` 一致），或照抄 mihomo `redirect_iptables.go` 的 `exec iptables`（实现快，但依赖系统有 `iptables`/`nft`，Android 上要处理 `/system/bin/iptables`）。

### 5.2 如果一定要做方案 B（最小可行设计）

1. **依赖**：`github.com/metacubex/sing-tun`，只编 `system` 栈；不引 gVisor（省 2.2 MB）。
2. **设备**：`Options{Name:"aghtun0", MTU:1500, Inet4Address: 172.19.0.1/30, AutoRoute:false}`；**不要开 `AutoRoute`**，改用 policy routing 只挑 53 端口。
3. **引流量**：`iptables -t mangle -A OUTPUT -p udp/tcp --dport 53 -j MARK --set-mark 0x1` + `ip rule add fwmark 0x1 lookup 100 priority 9000` + `ip route add default dev aghtun0 table 100`（v6 同理），并对 AGH 自身 UID 做 `-m owner ! --uid-owner` 排除。
4. **Handler**：实现 `tun.Handler`，只处理 53 端口：
   * UDP：`NewPacket` 里 `dns.Msg.Unpack` → 合成 `&proxy.DNSContext{Proto: proxy.ProtoUDP, Req: msg, Addr: 客户端地址}` → 调 `dnsforward.Server.ServeDNS(ctx, s.dnsProxy, dctx)` → `dctx.Res.Pack()` 写回。需要给 `dnsforward.Server` 暴露一个"接收裸报文"的入口，并在 ctx 里放 logger（`slogutil.LoggerFromContext` 是硬要求）。
   * TCP：走 `sing.ListenerHandler` 的 `NewConnection`，同样合成 `DNSContext`（`Proto: proxy.ProtoTCP`），注意 2 字节长度前缀。
   * 非 53 流量：直接丢（因为只有 53 被引进来，正常情况下不会出现）。
5. **客户端地址**：TUN 模式下 `Addr` 是所有 App 的真实源地址，AGH 的"客户端"识别、查询日志、统计都能直接受益；但要注意 Android 上同一台设备所有 App 都是 `127.0.0.1` 之外的同一个 IP，如果将来想按包名区分，得再引入 `packages_android.go` 那套 UID 解析。
6. **不要碰 ICMP**：AGH 不需要，`Options` 里保持默认丢弃即可，省掉一堆边界情况。

## 6. 验证清单（真机上做）

1. `AdGuardHome --check-config` 通过，配置里没有新的必填项（默认关闭 TUN/重定向）。
2. 功能关闭时行为与现状完全一致（开关默认关，避免影响现有用户）。
3. 打开后：
   * `dig @8.8.8.8 example.com`（绕过系统 DNS）能被 AGH 记录并拦截；
   * `ip rule` / `iptables -t nat -L -n -v` 里规则存在且在切 Wi-Fi、切数据、飞行模式往返后自动重建；
   * AGH 自己的上游查询不被劫持（看查询日志里没有自己查自己）；
   * 关闭 AGH 或崩溃后网络恢复（TUN 消失、规则清理）——**这条最容易出事，必须有兜底**。
4. IPv6：`dig -6 @2001:4860:4860::8888` 也能被接管（对比现状的 DROP）。

## 7. 代码坐标速查

mihomo（`_refs/mihomo`）：

* `listener/sing_tun/server.go:136` — TUN listener 的组装入口
* `listener/sing_tun/server.go:479` — 创建设备；`server.go:504` — 创建协议栈
* `listener/sing_tun/dns.go:21,30,38` — DNS 劫持判定与 UDP/TCP 分支
* `listener/sing_tun/server_android.go:49` — Android 包名规则桥接
* `config/config.go:547` — `dns-hijack` 默认 `0.0.0.0:53`

sing-tun（`_refs/sing-tun`）：

* `tun_linux.go:272` / `:289` — `/dev/net/tun` 或 `/dev/tun` + `TUNSETIFF`
* `tun_linux.go:303` — 地址、MTU、路由
* `tun_linux.go:921` / `:935` — 路由与 `ip rule`
* `stack.go:40` — 四种栈的入口
* `stack_system.go:414` / `:659` — TCP 回灌技巧 / UDP 直通
* `tun_rules.go:23` / `:158` — Android 包名规则 / 默认路由范围
* `packages_android.go:27` — `/data/system/packages.xml` 解析
* `redirect_linux.go:45` / `redirect_server.go:30` — auto-redirect 与本地重定向服务

AGH（本仓库）：

* `internal/dnsforward/requesthandler.go:19` — 过滤链入口 `ServeDNS`（方案 B 的注入点）
* `internal/dnsforward/config.go:343` / `:817` — dnsproxy 配置与明文监听地址
* `internal/dnsforward/dnsforward.go:417` / `:735` — DNS 服务启停
* `internal/ipset/ipset_linux.go` — 现成的 Linux netlink 先例
* `internal/home/home.go:780` / `:882` — 启动顺序（`configureOS` 降权 → `initDNS`）
* `../Adguard-Home-For-Magisk-Mod/Adguardhome/scripts/iptables.sh` — 现有 REDIRECT 方案

## 8. 场景修正：TUN 用于 SNI 阻断拦截广告

前提变了，结论也跟着变。这一节专门回答"用 TUN 读 SNI 来拦广告"。

### 8.1 SNI 阻断的原理

TLS 握手的第一个 record 是明文 `ClientHello`，里面的 `server_name` 扩展带着我们要的域名（ECH 启用时除外）。所以：

```
TCP 流的前 1~2 KB → 解析 ClientHello → 拿到 SNI → 查域名规则
      ├─ 命中 → RST / DROP，连接根本建不起来
      └─ 未命中 → 原样放行
```

它和 DNS 过滤是互补关系，**能补上 DNS 层补不了的洞**：

* App 自己走 DoH（443 端口，绕开系统 DNS）的，DNS 过滤看不到，但它的 TLS 连接里 SNI 是明文的 → 能拦。
* Ad SDK 直接把 IP 写死在代码里、不做 DNS 查询的 → 能拦。
* 代价是拦不掉"广告和内容同域名"的那种（模块 README 里已经写明的限制），也拦不住 SNI 是 IP、或无 SNI 的连接。

### 8.2 关键发现：这件事 mihomo 已经做完了

不需要从零写。mihomo 的 SNI 链路是完整且现成的：

| 环节 | 代码 | 说明 |
| --- | --- | --- |
| ClientHello 解析 | `component/sniffer/tls_sniffer.go` 的 `SniffTLS` / `ReadClientHello` | 约 200 行纯 Go，处理跨 TLS record 的分片、按需字节数返回 |
| 何时嗅探 / 读多少 | `component/sniffer/dispatcher.go` | TCP peek，200ms 超时，上限 64 KiB |
| 接到 TUN 连接上 | `tunnel/tunnel.go:527` `snifferDispatcher.TCPSniff(conn, metadata)` | 嗅探成功后把域名写进 `metadata.Host` |
| 用域名下判决 | 同文件随后的 `resolveMetadata(metadata)` | 于是 `DOMAIN-SUFFIX,ads.example,REJECT` 直接生效 |
| QUIC 变体 | `component/sniffer/quic_sniffer.go` | 用 RFC 9001 的初始密钥解 QUIC Initial 拿 SNI，约 20 KB 代码 |

也就是说：**mihomo 的 `tun` + `sniffer` + 一条域名 REJECT 规则 = 完整的 SNI 阻断**，今天就能配出来。缺的只是"广告域名清单"——而清单恰好是 AGH 的强项（GOODBYEADS + 自定义规则 + 自动更新）。

所以真正要解决的问题从"给 AGH 加 TUN"变成：**AGH 的域名规则怎么变成 mihomo 能吃的 REJECT 规则**。

### 8.3 三条路线

| | 路线 1：复用 mihomo（推荐先验证） | 路线 2：AGH 内建 NFQUEUE | 路线 3：AGH 内建 TUN |
| --- | --- | --- | --- |
| 捕获 | mihomo 的 TUN（已有） | `mangle` + `NFQUEUE` | TUN + fwmark/`ip rule` |
| 是否需要转发流量 | 是，但 mihomo 本来就是转发器 | **否**，判决放行后内核自己走 | 是，AGH 要中转所有 443 |
| 域名判定 | mihomo 自己的规则 | 调 AGH 的 `CheckHostRules` | 调 AGH 的 `CheckHostRules` |
| 新增代码 | 一个规则导出（几十行） | 约 1000 行 | 约 1000~2000 行 + 路由风险 |
| 内核依赖 | 无 | 需要 `NFQUEUE`/`xt_NFQUEUE` | 需要 TUN（Android 是 `/dev/tun`） |
| 主要风险 | 依赖用户装了代理模块 | 内核可能没编 NFQUEUE；QUIC 要另处理 | 路由接管、环路、Android netd、AGH 变代理 |

### 8.4 为什么"只加 SNI 阻断"时 NFQUEUE 比 TUN 好

这是本节的核心技术判断。TUN 的代价全部来自"你把包从内核手里接过来，就得自己还回去"；而 SNI 阻断**只需要看一眼第一个包、下一个判决**，不需要接管流量：

1. **不抢路由**：放行的连接完全走内核原路径，不改行为、不掉速、不影响其他 App。
2. **不需要实现转发**：AGH 不会变成代理，也就不需要处理并发、半关闭、超时、吞吐。
3. **不需要 TCP 状态机**：Netfilter 交给你的是已经属于某条 TCP 流的包，不存在"自己实现握手"的问题。
4. **环路好处理**：只要排除 AGH 自身就行。

做法（骨架，具体端口/UID 按真机调整）：

```sh
iptables -t mangle -N AGH_SNI
iptables -t mangle -A OUTPUT -j AGH_SNI
iptables -t mangle -A AGH_SNI -p tcp -m multiport --dports 443,8443 \
  -m connbytes --connbytes 1:4 --connbytes-dir original --connbytes-mode packets \
  -m owner ! --uid-owner <AGH_UID> -j NFQUEUE --queue-num 100 --queue-bypass
```

AGH 侧：用 nfnetlink_queue（`github.com/florianl/go-nfqueue`，或自己写 netlink）收包 → 取 TCP payload → 解析 ClientHello → 拿 SNI → 调 `(*filtering.DNSFilter).CheckHostRules(host, dns.TypeA, setts)`（`internal/filtering/filtering.go:472`，就是 AGH 自己那套规则引擎，**不需要重新实现规则匹配**）→ 命中 `NF_DROP`，否则 `NF_ACCEPT`。`connbytes 1:4` 保证每条连接只有头几个包进用户态，后续包零开销。

必须注意的点：

* **QUIC**：`-p udp --dport 443 -j DROP` 让浏览器回退到 TCP TLS，是最省事的做法（代价是牺牲 HTTP/3）。想连 QUIC 一起嗅探，就得移植 `quic_sniffer.go` 那套初始密钥解密，成本高一个量级。
* **内核支持**：Android 内核不一定编了 `NETFILTER_XT_TARGET_NFQUEUE`。真机上先用一条 `iptables -t mangle -I OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 1` 试，报错就说明这条路不通，得退回路线 1 或 3。
* **别把自己排队**：AGH 自己出站的 443（DoH 上游、过滤器更新）必须用 `owner` 或 mark 排除，否则它自己会被自己的队列卡住。
* **跨包 ClientHello**：要缓存同一连接的多个包再解析（`SniffTLS` 的返回值就是"还需要多少字节"，可直接复用）。
* **ECH**：启用 Encrypted ClientHello 后 SNI 不可见，这条路线会静默失效（目前还不是主流）。

### 8.5 如果坚持走 TUN（路线 3 的最小设计）

1. **只引 TCP/443（可加 8443）进 TUN**，不要开 `auto-route`：`iptables -t mangle ... -j MARK --set-mark 0x1` + `ip rule add fwmark 0x1 lookup 100 priority 9000` + `ip route add default dev aghtun0 table 100`，其余流量完全不受影响。
2. 用 sing-tun 的 `system` 栈：TUN 收到 SYN 后回灌内核，本进程 accept 到的是带"真实目标地址"的普通 `net.Conn`（`stack_system.go:414`）。
3. handler 逻辑很短：peek ClientHello → 取 SNI → `CheckHostRules` 判定 → 命中就 `Close()`（等价 RST）；未命中就 `dial` 真实目标并双向 `io.Copy`。SNI 解析直接移植 `SniffTLS`。
4. **必须给自己的出站 socket 打 `SO_MARK`**：转发用的 dial 会再产生一条去 443 的出站连接，如果也被 mark 命中就会回到 TUN，形成死循环。mihomo 用 `dialer.DefaultRoutingMark` 解决这个问题（`component/dialer/options.go:14`、`component/dialer/dialer.go:130`），这是本项目必须照抄的一处细节。
5. UDP/443 直接丢，逼回退 TCP；IPv6 同样用 `ip -6 rule`/`ip6tables` 对称处理。
6. 清楚代价：AGH 从此是"所有 HTTPS 的中转站"，吞吐、并发、半关闭、超时、IPv6、网络切换重建规则，全部要自己扛；而路线 2 里这些都由内核负责。

### 8.6 建议的推进顺序

1. **先花半天验证收益**（路线 1）：把 AGH 的域名规则导成 mihomo 的 `rule-provider`（`behavior: domain`），配好 `tun.enable` + `sniffer.sniff.TLS.ports: [443]` + `DOMAIN-SUFFIX,...,REJECT`，拿现在"DNS 拦不住的广告"当样本对比。**先证明 SNI 阻断确实有价值**，再谈在 AGH 里内建。
2. 收益确认、又不想依赖代理模块，就走**路线 2（NFQUEUE）**：代码量最小、风险最低，而且能直接复用 AGH 的规则引擎。
3. 只有在"内核没有 NFQUEUE"或"要完全不依赖 netfilter / 将来做非 root VpnService"时，才值得上**路线 3（TUN）**。

## 9. 兼容性：TUN 更稳，但"和代理模块共存"这个维度它更差

"兼容性更好"要拆成两个维度看，这两个维度的结论是相反的。

### 9.1 三个维度对比

| 维度 | TUN | NFQUEUE |
| --- | --- | --- |
| 设备/内核是否支持 | **好**：Android 的 VpnService 本身就建在 tun 驱动上，任何能跑 VPN/代理 TUN 的机型都有 TUN；`/dev/tun` 或 `/dev/net/tun` | **不确定**：要内核编了 `NETFILTER_XT_TARGET_NFQUEUE`（iptables 后端）或 nft `queue` 表达式，还需要 conntrack/`XT_CONNBYTES`。厂商内核可能裁剪，**必须真机实测** |
| 与代理模块（TUN 模式）共存 | **差**：TUN 必须抢默认路由或至少抢一条策略路由，而代理模块在 TUN 模式下正是靠这个工作，两者零和 | **好**：工作在 `mangle OUTPUT`，位置是"包已生成、路由还没决策"，和对方的 TUN 是**串联**而不是竞争 |
| 失败模式 | **差**：AGH 抢了默认路由后崩溃 = 整机断网 | **好**：`--queue-bypass` 下 AGH 挂了只是不拦广告，网络照常 |

### 9.2 共存冲突的具体证据（不是纸上推演）

拉取了两个被本模块声明兼容的代理模块，它们对内核做的事：

| 模块 | TUN 模式怎么走 | 非 TUN 模式怎么走 |
| --- | --- | --- |
| `box_for_magisk`（`box/scripts/box.iptables`） | 只加 `FORWARD -i/-o <tun> -j ACCEPT`，路由交给内核 auto-route；mark=`16777216/16777216`、`table=2024`、`pref=100` | `mangle OUTPUT -j MARK --set-xmark <fwmark>` + `ip rule add fwmark ... table 2024`；并把 `udp/53` TPROXY 到自己的 DNS 端口 |
| `akashaProxy`（`module/src/scripts/tun.proxy`、`redirect.proxy`） | `ip -4 rule add fwmark <mark> table <table> pref <pref>` + `mangle -A KERNEL_OUT -j MARK --set-xmark <mark>` | `nat -A KERNEL_OUT -p udp --dport 53 -j REDIRECT --to-ports <dns_port>` |
| `mihomo` / `sing-tun` | 默认 `table=2022`、`rule=9000`、`auto-route` 挂 `0.0.0.0/0` | `auto-redirect` 走 nftables REDIRECT/TPROXY |

结论很直接：

1. **TUN 模式是零和的**。两张 TUN 网卡、两套 `ip rule`，优先级高的拿走流量，另一个什么都看不到。而且这三个模块的 table/pref/mark 各不相同（2024/100、2022/9000、akashaProxy 自定义），AGH 无论选哪套默认值都会撞上其中一个；它们的守护脚本还会周期性重建规则，造成规则抖动。
2. **TUN 串联的语义也是错的**。假设 AGH 优先级更高：流量先进 AGH 的 TUN，AGH 转发时若不打 `SO_MARK` 会回环，打了 `SO_MARK` 又会绕过代理直连出去——**用户的代理直接失效**。假设代理优先级更高：AGH 什么都看不到。也就是说 TUN 只能二选一（AGH 全接管 / 代理全接管），**没有"AGH 只看 SNI、其余交给代理"的位置**。
3. **NFQUEUE 恰好提供了这个位置**：AGH 在 OUTPUT 上看一眼 TLS 第一个包，命中就丢，未命中就放行，包随后照常进入代理的 TUN。责任边界清晰，互不抢路由。
4. 顺带一个**现存**问题（和加不加 SNI 无关）：非 TUN 模式下 `akashaProxy`/`box` 都会往 `nat OUTPUT` 插 `--dport 53 -j REDIRECT` 指向自己的 DNS 端口，这跟本模块 `iptables.sh` 里那条 `-I OUTPUT -j ADGUARD`（同样是 OUTPUT 上的 REDIRECT）**直接打架**——同一条链里先命中者生效，两边都有 5 秒守护循环，谁刷得快谁赢。现在靠 `ProxyConfig.sh` 改对方配置里的 DNS 绕过，只覆盖它认识的那几个模块。

### 9.3 结论

* **"设备能不能跑起来"：TUN 更保险。** 这是 TUN 唯一的、也是真实的优势。
* **"和代理模块共不共存"：NFQUEUE 明显更好。** 对你的部署（模块明确要兼容 Box / AkashaProxy / Clash MIX / Surfing，而且这些模块常用 TUN 模式）来说，这个维度是决定性的。
* 所以顺序应该是：**先让代理模块自己做 SNI 阻断**（mihomo 自带 sniffer + REJECT，零冲突，AGH 只提供域名清单）→ 不行再上 **NFQUEUE**（真机先验证内核支持）→ 只有在"内核没有 NFQUEUE"且"代理模块也不带 TUN/sniffer"时才考虑 **TUN**。
* 如果内核既没有 NFQUEUE、代理又在用 TUN，那么唯一不打架的做法是**不要给 AGH 加 TUN**：用代理的 TUN + sniffer，或者让用户关掉代理的 TUN 模式改用 redirect/tproxy。

### 9.4 真机验证清单

```sh
# 1. 代理模块开 TUN 之后，先把现状拍个快照，看有没有和 AGH 撞车
ip rule show
ip route show table all | head -40
iptables -t mangle -S
iptables -t nat -S

# 2. 验证内核是否支持 NFQUEUE（报 "No chain/target/match by that name" 就是不支持）
iptables -t mangle -N AGH_SNI_TEST
iptables -t mangle -I OUTPUT -j AGH_SNI_TEST
iptables -t mangle -A AGH_SNI_TEST -p tcp --dport 443 -j NFQUEUE --queue-num 9 --queue-bypass
# 然后正常打开几个 https 网站：有 --queue-bypass 且无人读队列时应放行，网络不断即说明规则可用
iptables -t mangle -D OUTPUT -j AGH_SNI_TEST && iptables -t mangle -X AGH_SNI_TEST

# 3. 顺便确认 QUIC 现状（决定要不要顺带处理 UDP/443）
iptables -S OUTPUT | grep -i 'udp.*443'
```

一个容易忽略的坑：代理 TUN 模式 + HTTP/3 时，广告流量走 QUIC，SNI 被加密，**SNI 阻断会直接漏掉这部分**。要么在代理侧打开 QUIC sniffer，要么把 `udp/443` 丢掉逼回退 TCP（`box_for_magisk` 里就有现成的 `quic="disable"` 开关，做的是 `iptables -A OUTPUT -p udp --dport 443 -j REJECT`）。

## 10. 附录：对《AGH 魔改 v4.0：TUN + SNI 拦截》计划书的评估

结论：**目标可行，但这套方案（按它写的机制）不可行。** 它想解决的"放行之后怎么不被 TUN 接管"是真问题，但给出的核心机制是错的；而它明确"绝对禁止"的 NFQUEUE，恰好是唯一能正确实现"看一眼再放行"的机制。

### 10.1 计划的核心主张

* 只让 TCP 443 的**首包**进 TUN，用 `CONNMARK` 让"已建立连接"的后续包不进 TUN。
* 读到首包 → 解析 TLS ClientHello 取 SNI → 命中则构造 RST 写回 TUN；未命中则**把首包原样写回 TUN**，由内核转发到物理网卡。
* "关键修正"：放行的包**必须写回 TUN**，不能"什么都不做"。
* 明确禁止：用户态协议栈（gVisor）、NFQUEUE、eBPF、AF_PACKET。

### 10.2 四个致命问题

**问题 1："首包"里根本没有 SNI。** TCP 建连的第一个包是 SYN，载荷为 0。TLS ClientHello 出现在**第 4 个包**（SYN → SYN-ACK → ACK → ClientHello），而且 ClientHello 较大时会跨多个 TCP 段（这也是 mihomo 的 `SniffTLS` 要处理"还需要多少字节"的原因）。按计划对首包调 `extractSNI(pkt)` 只会返回空串，于是**永远走放行分支**——功能等于没实现。这一点用 tcpdump 十秒就能确认。

**问题 2：CONNMARK 规则与"后续包不进 TUN"自相矛盾。**

```sh
# 计划里的两条规则
iptables -t mangle -A OUTPUT -p tcp --dport 443 -m conntrack --ctstate NEW -j CONNMARK --set-xmark 0x400000/0x400000
iptables -t mangle -A OUTPUT -p tcp --dport 443 -j CONNMARK --restore-mark --nfmask 0x400000 --ctmask 0x400000
```

第一条给整条连接打 connmark，第二条把 connmark 恢复成**每个包**的 mark。结果是：这条连接的所有包都带 `0x400000`，全都被 `ip rule fwmark ... lookup 100` 送进 TUN。要么改成只标记 SYN（那就回到问题 1：SYN 没有 SNI），要么承认整条连接都进 TUN（那就必须转发整条流，见问题 3）。两句话互相打架。

**问题 3："原样写回 TUN 让内核转发"是 martian/forwarding 路径，而且方向搞反了。**

把包写进 TUN，等于"内核从 tun 这个网口**收到**了这个包"。而这个包的源地址是本机地址、目的是远端地址，于是内核按**转发**处理：

* 需要 `net.ipv4.ip_forward=1`（否则直接丢）；
* 需要 `accept_local=1` 且 `rp_filter=0`，否则内核以 **martian source** 丢弃（`dmesg` 里能看到 "martian source ... inbound packet on tun0"）；
* 即使全部满足，转发查的是 **main 表**：如果默认路由是**代理模块的 TUN**（正是本项目的场景），这个包会被转进代理的 TUN，代理看到一个"源地址是设备自身 IP"的伪造流量；如果默认路由是物理网卡，则这条连接绕过代理直连出去——代理对它彻底失效。

对照真正的 sing-tun 实现，方向是反的：sing-tun 写回 TUN 的包**永远是指向 App 的**（源 = 本来的远端地址、目的 = App 地址，即"本地投递"，见 `stack_system.go:887` 起的各 `WritePacket`：`SetDestinationAddress(ipHdr.SourceAddress()); SetSourceAddr(destination.Addr)`），出站方向用的是**真实 socket**（mihomo `tunnel/tunnel.go:577` 的 `proxy.DialContext`）。**sing-tun 从不做"源=本机地址、目的=远端"的注入**，所以计划里"mihomo 就是这么干的"属于误读。

**问题 4：它禁掉了唯一正确的工具。** "看一眼包、然后决定放行或丢弃"的正规机制就是 NFQUEUE：内核把包交给用户态，用户态回 `NF_ACCEPT`，包继续走内核原有的转发路径——没有重注入、没有 martian、不依赖 `ip_forward`/`accept_local`，而且天然能看到从第 4 个包开始的 ClientHello。把 NFQUEUE 列入"绝对禁止"，等于主动放弃了唯一不需要用户态协议栈的解法。

### 10.3 次要问题（真实但不致命）

* 硬编码 `/dev/net/tun`：新 Android 上是 `/dev/tun`（sing-tun 会两个都探测）。
* 只覆盖 IPv4/TCP 443：没有 ip6tables 对称处理，也没管 QUIC/HTTP-3（QUIC 的 SNI 是加密的，不处理就漏掉这部分广告流量）。
* 没有排除 AGH 自身的 443 出站（DoH 上游、过滤器更新）。
* 与代理模块的规则共存只提了一句"动态探测"，mark 值"硬编码 0x400000"和"启动时扫描空闲位"自相矛盾；也没提 table 100 在 Android 上与 netd 表的冲突（见第 9 节）。
* API 对不上本仓库：实际入口是 `(*filtering.DNSFilter).CheckHostRules(host, rrtype, *Settings)` / `CheckHost(host, qtype, *Settings)`，不存在 `CheckHost(sni)`。
* RST 注入本身是可行的（源=服务器、目的=App 的包会被本地投递），但序列号/窗口要按 RFC 793 严格构造，且只能在"读完 ClientHello 之后"才发——那时连接已建立，语义上更像"中途掐断"而不是"拒绝连接"。

### 10.4 计划里对的部分

* 问题定性对：TUN 本质是**全量接管**架构，"只截首包"确实是坑，这一点抓得准。
* 参考 sing-tun / mihomo 的方向对。
* 工程习惯对：先在独立 netns 里做最小原型再上真机；新代码集中在 `internal/tunproxy/` 以避免和上游合并冲突；风险表列了 connmark 可用性、fwmark 冲突、代理共存、上游合并冲突。
* **"阶段一：netns 原型"是整份计划里最有价值的一条**——而且这一步会立刻证伪整套方案（写入的包要么被当 martian 丢掉，要么被转进别的 TUN；同时 SNI 永远解析不出来）。计划里的这个自检设计，恰恰是它能被快速否定、从而省下大量瞎改成本的原因，值得保留。

### 10.5 修正后的做法（二选一）

* **方案 A（推荐）**：NFQUEUE + `mangle` 上限制前几个包 + 复用 AGH 的 `CheckHostRules`，命中 `NF_DROP`、未命中 `NF_ACCEPT`。细节见 8.4；这是唯一"不需要转发、不需要协议栈、不抢路由"的解法。
* **方案 B（一定要 TUN 就必须这么做）**：用 sing-tun 的 `system` 栈，让内核帮它完成握手，然后在 handler 里 peek ClientHello → 判断 → 命中 `Close()`、未命中 `dial` 真实目标 + 双向 `io.Copy`，并给自身出站 socket 打 `SO_MARK` 防环路。这不是 1000 行，而是"迷你 mihomo"，并且和代理的 TUN 存在路由竞争（见第 9 节）。细节见 8.5。

### 10.6 实测：把计划书的"阶段一"直接跑出来

不靠推理，按计划书自己的要求做了 netns 原型（脚本在 `C:\Users\juana\Documents\ChatGPT\_refs\tunprobe\tun_exp\`，WSL2 + 内核 6.18，`run.sh` 用主表路由复现"分流"，`run2.sh` 用计划书原样的 `fwmark → table 100 → default dev tun0` + `iif tun0 lookup main` 规则）：

| 观察到的事实 | 结果 |
| --- | --- |
| TUN 里读到的包长什么样 | 两个脚本、两个阶段共 4 次运行，**读到的永远是 `payload=0` 的裸 SYN**，`tls_clienthello=False`；因为握手无法完成，ClientHello 从未出现过 |
| 写回 TUN 的包去哪了 | 默认 sysctl 下：`InReceives=7, InAddrErrors=7` —— **写回的包 100% 被内核按地址错误/martian 丢弃**，`ForwDatagrams=0`，物理链路侧收到 0 个包，App 三次连接全部超时 |
| 打开 `ip_forward=1` + `accept_local=1` + `rp_filter=0` 之后 | 仍然 **0 个包离开盒子**；`run2` 里 `ForwDatagrams=7` 但链路侧依然是 0，App 直接 `No route to host` / 超时 |
| 源地址 | 走 `fwmark → table 100 → default dev tun0` 时，App 的 SYN 源地址变成 **172.19.0.1（TUN 自己的地址）**，而不是手机的真实出口地址——即使包真发出去了，服务器也回不来 |
| 对照（sing-tun 的正确做法） | mihomo 的出站是**真实 socket**（`tunnel/tunnel.go:577` 的 `proxy.DialContext`），写回 TUN 的包只用于回给 App 做本地投递，从不做"源=本机、目的=远端"的注入 |

也就是说：计划书里那个"关键修正"（把首包原样写回 TUN 让内核转发）**在干净环境里都跑不通**，而且原因是机制性的，不是调几个参数能补的。它自己的"阶段一 netns 原型"这一步做得非常好——因为它能在半天之内把整份方案否掉，而不是等到写完 1000 行代码上了真机才发现。

## 11. 「一定要 TUN」时的冲突解决方案

### 11.1 先看清冲突的本质

两张 L3 拦截网卡**不能并联，只能串联**。而串联时谁在外层，是由"谁必须看到原始流量"决定的：

* SNI 阻断必须读到原始 TLS 字节，所以 **AGH 必须在外层**（先拿到包）。
* 代理必须拿到 AGH 放行之后的连接，所以**代理只能在内层**（成为 AGH 的转发目标）。

这就强制出一个结论：**代理不能再占着 TUN**。这同时解释了为什么"两张 TUN 共存"即使做出来也没有意义——代理的 TUN 在外层，AGH 就看不到 443；AGH 在外层，代理就拿不到 443，除非 AGH 再把 443 转发给代理，而那已经等价于"只有一张有意义的 TUN"了。

### 11.2 方案 A（推荐）：单 TUN，代理降级为本地入站

```
App ──► 内核路由 ──► AGH 的 TUN（唯一的 L3 层）
                        ├─ 解析 ClientHello 得到 SNI
                        │    ├─ 命中黑名单 → Close（等价 RST）
                        │    └─ 未命中 → socks5 dial 127.0.0.1:<proxy mixed-port>（目标=原始 destination）
                        │                    └─► 代理出站（规则/鉴权照常，但它不再拥有 TUN）
                        └─ UDP/443 → REJECT，逼浏览器回退 TCP（QUIC 的 SNI 是加密的，不丢就拦不住）
```

要点：

1. **代理切到 socks/mixed 模式、关掉它的 TUN。** 本模块的 `ProxyConfig.sh` 已经在改代理配置，扩展成"按开关把 `tun.enable` 置 false 并确保 `mixed-port` 可用"即可。akashaProxy 自己就有先例：socks 模式下它的脚本会执行 `yamlcli -f <cfg> set "tun.enable" false`。
2. **环路防护用"专用 UID 自我排除"，这是生态里的标准做法。** akashaProxy 的 `tun.proxy` 第一条规则就是 `iptables -t mangle -A KERNEL_OUT -m owner --uid-owner ${kernel_user} --gid-owner ${kernel_group} -j RETURN`：给核心进程一套专用 uid/gid，再在捕获规则里排除它。AGH 照做：

```sh
iptables -t mangle -N AGH_OUT
iptables -t mangle -I OUTPUT -j AGH_OUT
iptables -t mangle -A AGH_OUT -o lo -j RETURN
iptables -t mangle -A AGH_OUT -m owner --uid-owner $AGH_UID -j RETURN     # 自己出站，绝不抓
iptables -t mangle -A AGH_OUT -m owner --uid-owner $PROXY_UID -j RETURN   # 代理出站，绝不抓
iptables -t mangle -A AGH_OUT -p tcp -m multiport --dports 443,8443 \
    -m owner --uid-owner 10000-19999 -j MARK --set-xmark 0x400000/0x400000
iptables -t mangle -A AGH_OUT -p udp --dport 443 -m owner --uid-owner 10000-19999 -j REJECT
```

   `--uid-owner 10000-19999` 是 Android user 0 的 App UID 段（多用户要按 `userId*100000` 展开，模式可参考 sing-tun `tun_rules.go` 的 `BuildAndroidRules`）。**两条 RETURN 是双保险：即使将来放宽了 App UID 限制，"自己不抓自己"仍然保证不会环路。**
3. **使用独立的 mark / 表 / 优先级**，并在启动时扫描占用，见 11.5 的表。
4. **UDP 要么 REJECT 443 逼回退 TCP，要么老老实实实现 socks5 UDP ASSOCIATE。** 前者一天能做完，后者是另一个量级，建议先做前者。
5. **生命周期必须做幂等**：`ip rule`/`ip route` 是持久化的，AGH 崩溃不会自动清理——启动先清残留、退出时清理、模块脚本再兜底。否则一次崩溃就是整机断网。

工作量现实估计：sing-tun `system` 栈 + SNI peek（移植 `SniffTLS`）+ socks5 客户端 + 规则管理 ≈ **2000~2500 行**，比原计划的 1000 行多——因为真正要写的是"透明网关 + 转发"，不是"只读首包"。

代价：**fake-ip 用不了了**（fake-ip 是代理自己当 DNS 时生成的，现在 DNS 归 AGH），依赖 fake-ip 做域名分流的配置会受影响；非 TLS 协议也拿不到域名信息。这两点要在动手前接受。

### 11.3 方案 B（保留代理 TUN）：双 TUN 按端口切分

如果坚持代理继续用 TUN，就只能按"AGH 只吃 443，其余交给代理的 TUN"来切分，并且必须同时满足：

1. AGH 的 `ip rule` 优先级**必须比代理的靠前**（数值更小），否则包先被代理的规则挑走，AGH 永远看不到 443。
2. 代理必须仍然开放本地 socks/mixed 入站，AGH 把放行的 443 转发给它。否则代理对这些 443 完全失效——用户会发现"开了 SNI 阻断之后代理就不管用了"。
3. 双方的 mark/table/pref 全部错开，并且要接受代理模块的守护脚本周期性重建规则（box 是 `table 2024 / pref 100`，mihomo 默认 `table 2022 / rule 9000`，akashaProxy 是配置项）：谁后写谁生效。
4. QUIC 归属要明确：AGH 丢 UDP/443 的话，代理就不要再劫持一遍。

结论：**能做，但没有收益。** 第 2 条已经把方案 B 实际退化成了方案 A 的拓扑，只是多留了一张互相踩的 TUN，还多了"对每个代理模块和机型调参数"的长期维护成本。

### 11.4 方案 C（兜底）：能力协商，二选一

启动时检测是否已有别人的 TUN（`ip rule show` 里出现 2022/9000、`ip link show` 里有 meta/tun0/sing-box 等）。若有，则 AGH **不建 TUN**，自动降级为"DNS 拦截 + 域名清单导出"。这是最稳的工程做法，也符合"模块脚本本来就在管理代理配置"这个现实。

### 11.5 三种资源的占用表（防撞车）

| 组件 | 路由表 | `ip rule` 优先级 | fwmark |
| --- | --- | --- | --- |
| mihomo / sing-tun 默认 | `2022` | `9000`（fallback `32768`） | input `0x2023` / output `0x2024` |
| box_for_magisk | `2024` | `100` | `0x1000000/0x1000000` |
| akashaProxy | 配置项 | 配置项 | 配置项 |
| 建议 AGH | `2025` 起，或扫描空闲 | 方案 A 任意空闲；方案 B 必须小于代理的 | 高位，如 `0x400000` |

启动时按这张表扫描（`ip rule show`、`ip route show table all`、`iptables -t mangle -S`），选一个没被占用的值，并把选中值写进日志——这比硬编码可靠得多。

### 11.6 无论选哪个方案都必须做的五件事

1. **专用 UID + 自我排除**：Android 上唯一可靠的防环路手段（因为默认大家都是 root）。
2. **独立 mark/表/优先级 + 启动扫描**：不要用任何一家的默认值。
3. **幂等 + 兜底清理**：启动先清残留、退出清理、模块脚本再加一道（规则不清 = 断网）。
4. **IPv6 对称**（`ip -6 rule` / `ip6tables`）+ **QUIC 明确处理**（丢或嗅探，不能不管）。
5. **DNS 劫持归属唯一**：AGH 的 53 重定向和代理的 53 重定向（box 的 `clash_dns_forward`、akashaProxy 的 `KERNEL_OUT -p udp --dport 53 -j REDIRECT`）现在会互相打架，TUN 方案下必须明确"53 只由 AGH 抓"，否则谁先命中谁赢、规则还会抖动。

## 12. 附录：对《AGH NFQUEUE 方案》的评估与实测

### 12.1 结论

**机制选对了，包选择写错了。**

在"绝对不能牺牲代理 TUN"这个约束下，NFQUEUE 确实是最优解：它工作在 netfilter 层、位于路由之前，和代理的 TUN 天然串联；判决 DROP 的包根本到不了代理；`--queue-bypass` 还能在 AGH 挂掉时自动放行。它对 Network Namespace 的否定方向也是对的。

但它的匹配条件是 `-m conntrack --ctstate NEW`，也就是**只把 SYN 送进队列**——SYN 没有载荷，永远解析不出 SNI，于是永远返回 ACCEPT。**照这份计划实现出来，功能等于没做。** 这和 v4.0 计划书是同一个根因。

### 12.2 实测（WSL2 内核 6.18，真实 TLS 流量，脚本见 `_refs/nfqprobe/`）

| 规则 | 队列里看到什么 | curl 结果 |
| --- | --- | --- |
| 计划书原样：`--ctstate NEW` | **只有 1 个包：裸 SYN，`payload=0`，SNI 为空** | `http=200`，**什么都没拦到** |
| 改成 `--connbytes 1:3 packets`，命中即 DROP | SYN → ACK → 1448 字节 → 123 字节（**这一段才含 `SNI=example.com`**）→ DROP | **仍然 `http=200`**：TCP 重传了被丢的段，重传已落在 connbytes 窗口之外，直接绕过 |
| 再用 `--connbytes 0:20000 bytes` + **按连接记忆、后续包继续 DROP** | SNI 命中后连续 DROP 了 10+ 个重传（共 17 个包） | **连接失败（超时）** ✔ |
| 同样的规则，黑名单置空 | 同样解析出 `SNI=example.com` | `http=200`（证明上一条的失败确实来自拦截，而不是规则把网断了） |

### 12.3 实测顺带发现的两件事

* **ClientHello 会跨 TCP 段**：实测第一个数据段 1448 字节里没有 SNI，SNI 在紧随其后的 123 字节段里。所以除了"不能只看首包"，**只看第一个数据包也不行**，必须按连接拼接前若干段再解析（`SniffTLS` 那套"还需要多少字节"的逻辑就是干这个的）。
* **SNI 阻断在 fake-ip + 代理 TUN 场景下依然有效**：本次测试的目的地址是 `198.18.0.4`（fake-ip 段），说明流量当时正穿过宿主机上的代理（TUN + fake-ip）。SNI 是明文，不受 fake-ip 影响，命中判定照常工作——这正好覆盖了本项目的真实场景。

### 12.4 计划书里其它必须改的点

* **不要用 `libnetfilter_queue`（C 库）**：会直接破坏本 mod `CGO_ENABLED=0 GOOS=linux GOARCH=arm64` 的交叉编译。用纯 Go 的 `github.com/florianl/go-nfqueue/v2`（底层是 mdlayher/netlink，无 CGO）——本次实测就是用它，`Copymode: NfQnlCopyPacket` + `AfFamily: AF_INET` 即可。
* **`--ctstate NEW` 换成 `-m connbytes`**，推荐按字节给一个足够大的窗口（如 `0:20000`）以覆盖 TCP 重传；同时用户态必须**按连接记住判决**，对已判定为拦截的连接持续返回 DROP。
* **队列号别用 0**（`--queue-num 0` 最容易和别的工具撞车），启动时检测队列是否已被占用。
* **IPv6 要对称**：计划书只写了 iptables，`ip6tables` 同样需要一份。
* **QUIC 完全没提**：HTTP/3 走 UDP/443，不走这条 TCP 路径，SNI 阻断对它无效。最省事是 `-p udp --dport 443 -j REJECT` 逼回退 TCP。
* **API 对不上本仓库**：`CheckHost(host)` 实际是 `CheckHostRules(host, rrtype, *filtering.Settings)`（`internal/filtering/filtering.go:472`）。
* **判决必须极快**：NFQUEUE 是"内核把包交给你"，消费者卡住会拖慢整机 443；不能在判决路径里做同步磁盘 IO 或上游查询（日志/统计要异步）。`--queue-bypass` 只在队列满时生效，救不了"消费者 hang"。
* **"绝大多数 Android 内核都支持 NFQUEUE"过于乐观**：`xt_NFQUEUE`/`xt_connbytes` 在 GKI 与厂商内核中未必编入。这是整个方案唯一的硬件风险，必须先在真机上用一条 `iptables -t mangle -A OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 7 --queue-bypass` 验证（报 `No chain/target/match by that name` 就是不支持）。

### 12.5 对 Network Namespace 那段的评价

结论（netns 不可行）是对的，理由可以说得更准：**`tc mirred` 镜像只复制、不改判决**，所以镜像里的 AGH 无法真正阻断原始包，只能事后补一个 RST，而且要跨 namespace 注入、与已建立的连接赛跑。它比 NFQUEUE 差的不是"性能"或"复杂度"，而是**它天生没有 DROP 这个动作**。

## 13. 补一个更好的选择：nat REDIRECT + 本地 TLS relay（已实测）

在"不能牺牲代理 TUN"这个约束下，除了 NFQUEUE 还有一条路，而且它只用到**你设备上已经被验证可用的机制**：`nat REDIRECT`（本模块现在就是用它在生产环境里劫持 53 端口的）。

### 13.1 原理

```sh
# 只抓 App 的 443（root 的代理和 AGH 天然不被抓）
iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner 10000-19999 \
    -j REDIRECT --to-ports <AGH_SNI_PORT>
```

AGH 在本地端口上 accept 到连接后：

1. 用 `SO_ORIGINAL_DST` 拿回**原始目的地址**（REDIRECT 之前的）；
2. 从 TCP 流里 peek 出 ClientHello（**内核已经帮你把跨段重组好了**），解析 SNI；
3. 命中黑名单 → `SetLinger(0)` + `Close()`，直接给 App 一个 RST；
4. 未命中 → 拨到代理模块的本地 socks5/mixed 入站，双向 `io.Copy` 转发（于是代理的规则、节点、分流全都继续生效）。

### 13.2 实测（脚本 `_refs/redirprobe/`）

| 场景 | 结果 |
| --- | --- |
| 黑名单里有 `example.com`，以 App UID 发起的请求 | **14 毫秒失败**（curl exit 35）：relay 读到 `dst=198.18.0.4:443 sni="example.com"`，立刻 RST |
| 同一时刻 root 自己的请求（模拟代理/AGH 出站） | `http=200`，**完全没被 REDIRECT 命中** |
| 黑名单置空，同样以 App UID 请求 | `http=200`，relay 透明转发，功能不受影响 |

注意实测里的目的地址 `198.18.0.4` 是 fake-ip：说明 `SO_ORIGINAL_DST` 在这种"代理 TUN + fake-ip"环境里依然拿得到正确的目的，SNI 也照常解析。

### 13.3 为什么它比 NFQUEUE 更贴合约束

* **只用 nat REDIRECT**：本模块已经用它做 DNS 劫持并在目标机型上跑通，不存在"内核没编 NFQUEUE"这种未知风险。
* **不建 TUN、不动路由**：代理的 TUN 完全不受影响，也不存在两张 TUN 抢路由的问题。
* **只匹配 App UID**：代理和 AGH 自己的出站天然不被抓，不需要给谁改配置、也不需要专用 uid（对比方案 A 要改代理配置，方案 11.2 要专用 uid）。
* **判决干净**：AGH 自己持有这个 socket，拦截 = 立即 RST。不存在 12.2 里那种"DROP 被 TCP 重传绕过"的问题，也不需要按连接记忆状态。
* **SNI 重组免费**：内核 TCP 栈已经处理了分片/跨段，不需要像 NFQUEUE 那样自己拼接前几段。

### 13.4 代价与注意

* **AGH 要转发全部 App HTTPS**（用户态 TCP relay）：这是它相对 NFQUEUE 唯一的实质劣势——NFQUEUE 只让头几个包进用户态、其余由内核直通；这里整条连接的数据都要过 AGH。吞吐、延迟、并发、半关闭、超时都要自己扛。
* **必须用 socks5 客户端把放行的连接交给代理的本地入站**，否则等于绕过代理（用户会发现"开了 SNI 阻断代理就不管用了"）。好处是可以顺手把 SNI 域名传给代理，比代理自己嗅探还准。
* **QUIC 要单独处理**：UDP/443 不走这条 TCP 路径，要么 `-j REJECT` 逼回退 TCP，要么也 REDIRECT 到 AGH 处理。
* **IPv6 对称**：`ip6tables -t nat` 同样需要一份。
* **Android 上按 App UID 段匹配**：user 0 是 10000-19999，多用户要按 `userId*100000` 展开；顺手也应该把现有 DNS 劫持脚本改成只匹配 App UID——现在它把 AGH 自己的 53 上游也一起劫持了，只是靠默认走 DoH 才没暴露。

### 13.5 三条可行路线对比

| | NFQUEUE | nat REDIRECT + relay | TUN |
| --- | --- | --- | --- |
| 内核依赖 | `xt_NFQUEUE` + `xt_connbytes`（Android 上未知） | nat REDIRECT（**目标机型已验证**） | tun 设备（已知可用） |
| 动路由 | 否 | 否 | 是 |
| 代理 TUN | 保留 | 保留 | 必须让出 |
| 拦截语义 | 逐包 DROP（会被重传绕过，需按连接记忆） | 自己持 socket，直接 RST | 需自己转发 |
| SNI 重组 | 需自己拼接跨段 | 内核已完成 | system 栈已完成 |
| 性能代价 | 最小（仅头几个包） | 全部 App HTTPS 经 AGH 转发 | 全部流量经 AGH 转发 |
| 代码量 | ~800-1200 行 | ~1000-1500 行 | ~2000-2500 行 |

## 14. 场景：没有代理模块（纯 AdGuardHome）

### 14.1 好消息：冲突全部消失

前面第 9、11 章关于"两张 TUN 抢路由""谁在外层""代理配置"的分析，在没有代理模块的场景下**全部不再适用**。没有第二张 TUN、没有对手的 `ip rule`、没有需要保留的代理 TUN——TUN 从"最差选择"变回"可用选项"。

### 14.2 但换来了三个新约束

* **放行的连接没人接管了**：必须由 AGH 自己直连（或让内核直通）。有代理时 AGH 只需把连接交给 socks 入站；没有代理时，"放行"意味着 AGH 必须以某种方式把流量送到目的地。
* **QUIC/HTTP-3 没人管**：有代理时可以打开代理的 QUIC sniffer，没有代理就只能自己丢 `UDP/443` 逼浏览器回退 TCP（否则 HTTP/3 流量完全绕过 SNI 阻断）。
* **失败模式更致命**：没有代理兜底，AGH 崩溃后若规则/路由残留，TUN 会整机断网、REDIRECT 会让 HTTPS 全部连接被拒。

### 14.3 无代理场景的方案排名

| 维度 | NFQUEUE | REDIRECT + relay（直连） | 单 TUN |
| --- | --- | --- | --- |
| 内核依赖 | `xt_NFQUEUE`（**未知**） | `nat REDIRECT`（**本机已验证**） | tun（需体检） |
| 放行的流量怎么走 | **内核原生直通**（无需 relay） | AGH relay 到真实目标 | AGH relay 到真实目标 |
| AGH 挂了的后果 | 自动放行 | HTTPS 不通（需守护兜底） | 断网（需守护兜底） |
| 性能 | 最好（仅头几包进用户态） | 中（全部 App HTTPS 经 AGH） | 中（全部流量经 AGH） |
| 实现复杂度 | 中（还要按连接记忆防重传绕过） | **最低**（直连，无代理时不需要 socks5 客户端） | 高（sing-tun + 路由 + 生命周期） |
| 额外能力 | 无 | 无 | 将来可自己分流/代理 |

结论：**内核依赖最小、实现最简单的是 `REDIRECT + relay`（直连）**；**行为最稳、性能最好的是 `NFQUEUE`**；TUN 在没有代理时终于可用，但仍是最重的一条，只有在"以后还想让 AGH 自己做分流"时才值得。

### 14.4 无代理时的规则骨架

```sh
APPUIDS="--uid-owner 10000-19999"   # 多用户按 userId*100000 展开

# 方案 C：REDIRECT + 直连 relay
iptables  -t nat -A OUTPUT -p tcp --dport 443 -m owner $APPUIDS -j REDIRECT --to-ports 8443
ip6tables -t nat -A OUTPUT -p tcp --dport 443 -m owner $APPUIDS -j REDIRECT --to-ports 8443
iptables  -A OUTPUT -p udp --dport 443 -m owner $APPUIDS -j REJECT   # 逼 QUIC 回退 TCP

# 方案 B：NFQUEUE（注意用 connbytes 而不是 --ctstate NEW）
iptables -t mangle -A AGH_NFQ -p tcp --dport 443 -m owner $APPUIDS \
    -m connbytes --connbytes 0:20000 --connbytes-dir original --connbytes-mode bytes \
    -j NFQUEUE --queue-num 7 --queue-bypass
```

关键点：两种情况都**只抓 App UID**。这样 AGH 自己的出站（root）永远不被抓，环路问题从源头消失，既不需要 `SO_MARK`，也不需要专用 uid——这比"抓全部再排除自己"简单得多，也是无代理场景下最省事的一点。

### 14.5 设计建议：把 relay 的上游做成可配置

把 relay 的目标抽象成 `upstream = direct | socks5://127.0.0.1:7890` 两种模式，用同一份代码路径实现。这样：

* 现在没有代理 → 用 `direct`，SNI 命中即 RST，未命中直连；
* 以后装了代理模块 → 改成 `socks5://...`，放行的连接自动交给代理，代理的规则/分流照常生效，**不需要改任何其他代码**；
* 而且 `direct` 模式下 AGH 是 root、目标地址来自 `SO_ORIGINAL_DST`，不需要 fake-ip 处理（无代理时本来也没有 fake-ip）。

## 15. 一句话回答

分两种目标：

* **抓 DNS**：不用 TUN。把 mihomo 的 `auto-redirect` + `ip rule`/fwmark 那套"自愈的 netfilter 重定向与环路规避"搬进 AGH，退役模块里的 shell 守护脚本（第 5 节方案 A）。
* **抓 SNI 拦广告**：确实需要 L3 拦截，但**优先复用现成的 mihomo**——它已经把 ClientHello 解析、嗅探调度、QUIC 嗅探、REJECT 规则全写好了，AGH 只要把域名规则导出成它的 `rule-provider` 就能用（第 8.3 节路线 1）。要收进 AGH 自己实现，**首选 NFQUEUE 而不是 TUN**：不抢路由、不转发流量、复用 AGH 现成的 `CheckHostRules`，代码量和风险都低一个量级（路线 2）。TUN 只在 NFQUEUE 不可用、或将来要做非 root 的 VpnService 版时才值得动（路线 3）。
* **关于"TUN 兼容性更好"**：只在"设备/内核能不能跑"这一个维度成立（有 VPN 就有 TUN，NFQUEUE 可能没编进内核）。但在"和代理模块共存"这个维度恰好相反——代理模块 TUN 模式靠的就是抢默认路由/`ip rule`（Box: table 2024/pref 100，mihomo: table 2022/rule 9000，AkashaProxy 自定义），AGH 再插一张 TUN 是零和竞争，且串联语义本身就不对；同时还失去了 `--queue-bypass` 的优雅降级（AGH 崩了不会断网）。详见第 9 节。
* **关于那份 v4.0 计划书**：目标可行，机制不可行，**已在 WSL2 内核上按它的"阶段一"实测证伪**。三处硬伤：TCP 首包是 SYN、没有 SNI（实测 TUN 里读到的永远是无载荷 SYN，ClientHello 从未出现）；`CONNMARK --restore-mark` 会把整条连接都送进 TUN，和"后续包不进 TUN"矛盾；"把包原样写回 TUN 交给内核转发"实测 100% 被当地址错误丢弃，打开 `ip_forward`/`accept_local`/`rp_filter` 之后依然一个包都没出去，而 sing-tun 实际用的是真实 socket 出站、写回 TUN 只用于回给 App。它禁掉的 NFQUEUE 恰恰是唯一正确的"看一眼再放行"机制。详见第 10 节。
* **关于"一定要 TUN"**：冲突的本质是"两张 L3 网卡不能并联、只能串联"，而 SNI 必须在外层，所以**代理不能再占着 TUN**。干净的解只有一个——AGH 的 TUN 是唯一的 TUN，代理降级为本地 socks/mixed 入站，AGH 把放行的连接转发给它；环路靠"专用 UID 自我排除"（akashaProxy 等模块的标准做法）+ 独立 mark/表/优先级 + 自身 `SO_MARK` 兜底。双 TUN 按端口切分虽然能做，但没有收益、还要长期为每个代理模块和机型调参。详见第 11 节。
* **关于《AGH NFQUEUE 方案》**：在"不能牺牲代理 TUN"的约束下，它的**机制选对了**（NFQUEUE 是唯一正解），但**包选择写错了**：`--ctstate NEW` 只把 SYN 送进队列，而 SYN 没有 SNI，照抄会永远拦不住任何东西。实测还发现第二个坑：即使改成 `connbytes` 拿到 SNI，单次 DROP 会被 **TCP 重传绕过**（curl 依然 200）。可行写法是 `--connbytes 0:20000 bytes` + **按连接记住判决、对已拦截的连接持续 DROP**，实测能真正阻断；同时要用纯 Go 的 `florianl/go-nfqueue`（不要 `libnetfilter_queue`，否则破坏 CGO_ENABLED=0 交叉编译）。详见第 12 节。
* **另一个更好的选择**：`nat REDIRECT`（只匹配 App UID）+ AGH 本地 TLS relay。它只用你机器上已被验证可用的 nat REDIRECT（现在就在用它劫持 53），不建 TUN、不动路由、不依赖 NFQUEUE 内核模块，代理的 TUN 完全保留；AGH 自己持有 socket，所以命中即 RST（实测 14ms 失败），没有重传绕过、也不用手动拼 ClientHello。代价是全部 App HTTPS 要经 AGH 转发（比 NFQUEUE 重，但比 TUN 轻），并需要一个 socks5 客户端把放行的连接交给代理。详见第 13 节。
* **如果没有代理模块**：第 9、11 章的冲突分析全部作废（没有第二张 TUN 可抢），但要自己直连放行的流量、自己丢 UDP/443 管 QUIC。排序变为：NFQUEUE（性能与失败模式最好，依赖未知）→ REDIRECT + 直连 relay（内核依赖最小、代码最少，已验证）→ TUN（终于可用但仍最重）。建议把 relay 上游做成 `direct | socks5://...` 可配置，以后装了代理模块零改动切换。详见第 14 节。
