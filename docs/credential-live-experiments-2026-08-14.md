# 2026-08-14 凭据型 live 实验

## 前置状态

- 会话文件：`~/.hermes/xidian-session.json`，权限 `0600`，2026-08-14 11:35:47 +0800 更新；
- 只读 `session-check` 与 `clientResource` 预检通过；
- 资源快照为 code 0，包含 1361 条 IP 资源、523 条 domain 资源、1 个 node group；
- `202.117.112.70:443/tcp` 仍由 appId `2f206920-c9a7-11f0-8b22-4f20181761d8` 覆盖；
- node preflight：`61.150.43.94:441` 72 ms 成功，`10.255.57.11:441` 10 s 超时；
- 当前没有运行中的 Hermes E7/E11 service，不存在同设备并发 L3 owner；
- 当前资源快照没有非空 `ipv6AddressList`，E17 前置条件不成立。

资源快照只含服务端策略，不复制会话、Cookie、SID、SignKey 或 browser trace 到实验目录。

## 安全边界

生产节点只接收正常客户端会发送的已授权流量。本轮不做：

- E12 的伪 `0x84..0x87` 服务端响应注入；
- E14 的 unknown command、迟到 `53 00` 或 malformed `0x97` 注入；
- E16 的非 echo UDP、大于 MTU 的畸形包或未经授权目标；
- E17 的无 IPv6 资源 `0x16` 强制触发；
- E19 的 payload 猜测或 raw/framed 自动探测。

这些项分别保持 `L=等待自然触发/受控官方客户端` 或 `blocked`，不能因为本轮零样本写成反证。

## 串行矩阵

| 顺序 | Arm | 操作 | 判据 |
|---:|---|---|---|
| 1 | B0 session | `session-check` | 失败则整轮停止 |
| 2 | Resource | 保存当次 policy snapshot | 目标和节点必须仍被广告 |
| 3 | B0 TCP | `gsoft.xidian.edu.cn:443` tunnel HTTPS | 握手和 HTTPS round-trip 成功 |
| 4 | E15 Idle | L3 auth-only，75 s，无 `0x14` keepalive | heartbeat sent/ACK、close reason、最终新流 auth |
| 5 | E15 Active | 同目标，每 20 s 一个正常 `0x14` | 与 Idle 比较 heartbeat 仍按固定周期发送；只描述 Hermes |
| 6 | E7 midpoint | 5400 s hold，每 1800 s 一个 `0x14` | PASS 将数据空闲阈值从 `(60, ~3600]` 收窄到 `(1800, ~3600]` |
| 7 | B0-final | session-check + TCP HTTPS | 任一失败则候选只保留现象，不作稳定结论 |

三条 L3 arm 串行，避免已知的一设备后建会话淘汰前一会话。E7 长臂的 debug 日志同时被动观察：

- E12：是否自然出现 outer status `0x84..0x87`；
- E15：heartbeat sent/ACK、普通 command write 和关闭类别；
- E17：是否意外出现 `0x96`；
- E18：`0x94` 是 length-prefixed 还是 token-framed、packet bytes 和对齐状态；
- A5/E14 被动项：迟到 protocol message、unknown command、`0x97`。

## 启动与留档

runner：`scripts/credential-live-observation.sh`

systemd unit：`scripts/hermes-credential-live-observation.service`

输出目录：`debug_logs/<timestamp>-credential-live/`，目录权限 `0700`。每臂单独日志，`summary.log`
记录开始、结束、退出码和基线标记。日志不得外传；结论只提取无秘密的计数、状态和长度元数据。

本机 user manager 的 linger 当前为 `no`。锁屏不会停止实验；若完全退出桌面登录会终止 user service，
这种情况只能记为本地中断，不能记为网关关闭。

## 启动记录

### 14:25 首次尝试

runner 在任何网络候选 arm 前以 `session_not_fresh` 退出。随后在线复核旧文件返回
`75500002 / The session is invalid`。该次只产生四行本地审计记录，没有发起 TCP 或 L3 候选连接：

`debug_logs/2026-08-14-142515-credential-live/summary.log`

### 14:41 新凭据启动

用户于 14:40:11 +0800 再次更新 `~/.hermes/xidian-session.json`。权限仍为 `0600`；独立
`session-check` 显示 `LoggedIn`、onlineInfo username present、`passed=true`。

systemd oneshot 于 14:41:43 +0800 启动，输出目录：

`debug_logs/2026-08-14-144143-credential-live/`

启动后的已完成基线：

| Arm | 结果 | 耗时 |
|---|---:|---:|
| B0 session-check | exit 0 | 7 s |
| resource snapshot | exit 0，response 1,324,948 bytes | 19 s |
| B0 TCP tunnel HTTPS | exit 0 | 37 s |

初始 B0 通过后 runner 已进入 E15 Idle。后续 arm、退出码和被动 wire 计数由同目录
`summary.log` 自动追加；最终结论必须等待 B0-final，不能根据 service 仍在运行提前判 PASS。

## 最终结果

运行于 16:18:44 +0800 结束。systemd 显示 exit 1，但失败来自所有网络 arm 结束后的本地摘要函数：
在 `set -u` 下同一条 `local` 声明过早引用 `arm`，报 `arm: 未绑定的变量`。runner 已修复为分开
初始化变量。该错误没有中断或改变任何网络 arm；它只导致自动 wire 计数没有追加到 `summary.log`。

### 基线

| Arm | 结果 |
|---|---|
| B0 session-check | exit 0 |
| B0 TCP HTTPS | handshake、目标证书验证、HTTP 200；67,355 bytes |
| B0-final session-check | exit 0 |
| B0-final TCP HTTPS | handshake、目标证书验证、HTTP 200；67,361 bytes |

两次 TCP response 都是 13 个 read chunk 且 `clean_eof=false`。因此它们证明正常应用路径在实验前后
可用，但没有触发 E13 所需的目标主动 EOF，不能据此决定 close trailer/profile。

### E15 Hermes live 对照

| Arm | 结果 |
|---|---|
| Idle 75 s | PASS；same session；0 data keepalive；heartbeat 3/3；2 次 flow auth outcome；0 timeout |
| Active 75 s | PASS；20/40/60 s 共 3 次 40-byte data；3 次 length-prefixed `0x94`；heartbeat 3/3；0 timeout |

Active 在普通 command write 存在时仍按 25 秒固定周期发送 heartbeat，符合 Hermes 当前实现。
这不是官方客户端 `hasWrite` 调度的证据；E15 官方 L 仍需 instrumentation。

### E7 1800 秒中点

L3 session 保持同一个 `Arc` 和 VIP `10.210.29.72`，完整存活 5400 秒：

- 第一次非 heartbeat 活动在 elapsed=1800 s；此前 session 始终健康且 heartbeat 全 ACK；
- elapsed=1800/3600 s 各发送一次 40-byte packet，均收到 length-prefixed 40-byte `0x94`；
- 5400 s 时 session 仍未关闭，heartbeat 216/216、drop 0、auth timeout 0；
- 最终新源端口 flow auth 成功，随后由 caller 正常关闭；
- 首尾控制面和 TCP HTTPS B0 均通过。

因此服务端数据空闲阈值的 live 下界可从 60 秒提高到 **1800 秒**，当前范围收窄为
`(1800 s, ~3600 s]`。

CLI 最终记录 `passed=false`、exit 1，不是 gateway/session failure。原因是本地 conntrack idle TTL
为 300 秒：1800/3600 秒发送前旧 flow 都已淘汰并重新授权，最终统计为 4 request/4 outcome，违反
E7 原有“恰好 2 次 auth”的短间隔判据。该重鉴权使 1800 秒后的续存机制无法只归因于 `0x14`；但
**第一次 1800 秒前没有额外 auth/data**，所以“空闲 session 至少存活 1800 秒”的下界不受影响。

### 被动事件

三条 L3 arm 合计观察到 5 个下行 data frame，全部为 40-byte length-prefixed：Active 3、长臂 2。
未观察到 transient auth、token-framed `0x94`、second-VIP、protocol message、unknown command 或
VIP update。按实验纪律，这些只记为本观察窗口 `L=未触发`，不构成反证。
