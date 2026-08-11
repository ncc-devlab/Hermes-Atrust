# 协议二义性与未决问题登记

本文件收纳 Hermes 中**依据不足、存在二义、或与参考实现存在已知分歧**的每一处判断。
架构文档的「未确认协议关卡」只列结论，这里列**理由、二义区间、误判后的症状、以及判定实验**。

任何 live 失败在归因到「实现 bug」之前，先在本表里找是否已有对应条目。

**给服务端实现者：** 本文按「客户端还不确定什么」组织。若你要的是
「一台服务端需要表现出什么行为才能与真实客户端互通」，读
[`server-behaviour-inferences.md`](server-behaviour-inferences.md)——
同一批实测结果，按服务端视角重写，并标出了与 `Hermes-aTrust-Server`
现有 `docs/protocol.md` 的分歧点。

## 依据强度分级

| 级别 | 含义 |
|---|---|
| **L0** | 官方网关 `atrust.xidian.edu.cn` 实测/抓包确认 |
| **L1** | zju-connect（`/home/nancunchild/projects/zju-connect`，已被证实可用于真实 aTrust 网关） |
| **L2** | `Hermes-aTrust-Server`——由抓包和控制台表现**重建**的服务端推测，**不是证据** |
| **L3** | 纯推断／从帧结构自洽性倒推，无外部依据 |

L2 单独出现时等同于「未验证」：该服务端与 Hermes 客户端互通只证明两个实现一致，
不证明任何一个正确。2026-07-31 的 VIP 长度 bug 就是这样被 L2 掩盖了两天的。

---

## A. L3 帧层

### A1 — `0x94` 下行双格式的切分依据 <a id="a1"></a>

**依据：L1**（zju-connect `l3tunnelconn.go::readDataRespPayload`，Hermes
`atrust-protocol::l3_frame::classify_data_resp_prefix`，两者逐行等价）

**现状实现。** `05 94` 之后不存在格式标志位。判别完全依赖 body 头两字节的数值：

```text
n = u16::from_be(body[0..2])
0 < n <= 4096   →  长度前缀分支：其后 n 字节是一个完整 IP 包
否则            →  token 帧分支：tokenLen | token | reserved(2) | count | [u16 len][pkt]...
```

**为什么是这个判据，而不是别的。** 三条约束把它逼成唯一可行解：

1. **服务端确实会用两种布局下发同一个 `0x94` 命令**，且不带任何区分字段。这是协议的
   既成事实，不是客户端的选择；
2. **不能靠「像不像 IP 包」判别。** 一个 IPv4 包以 `45 00` 开头，作为 u16-be 是 17664，
   已经落在 token 分支区间。也就是说「裸 IP 包」和「长度前缀 + IP 包」在数值上天然可分，
   但代价是判据必须信任长度前缀恒存在（见下方二义区间 3）；
3. **4096 这个上界是隧道 MTU 的上界假设**，不是协议声明的常量。zju-connect 写作
   `maxDataPayload = 4096`，来源同样未知。

**二义区间（三处，全部真实可达）：**

| # | 条件 | 后果 |
|---|---|---|
| 1 | token 帧且 `tokenLen ≤ 15` | 头两字节 = `tokenLen*256 + token[0]` ≤ 4095，落入长度前缀区间 → **误判**，其后按 token 首字节起算长度，流立即错位 |
| 2 | token 帧且 `tokenLen == 16 && token[0] == 0` | 数值恰为 4096，同上 **误判** |
| 3 | 长度前缀分支且 `n == 0` 或 `n > 4096` | 落入 token 分支 → **误判**。即隧道下行单包超过 4096 字节时协议直接失同步 |

**因此判据成立的前提是两条服务端不变量，而服务端从未声明过它们：**

- `connectToken` 的字节长度 **≥ 17**（或 = 16 且首字节非零）；
- 下行 IP 包长度恒 **≤ 4096**。

**误判后的症状。** 不是解析报错，而是**流错位**：后续每一帧的边界都偏移，
表现为「跑一会儿之后帧头不是 `05`」「随机 UnexpectedVersion」「隧道无征兆卡死」。
症状离原因很远，所以这一条必须在排查表最前面。

**L0（2026-07-31 E5）：** 西电 `connect_token_len=32`（≥17，判据安全）；
下行 `data_resp layout=length_prefixed`（TCP SYN 应答 44 字节 IP 包）。
未见 `connect_token_ambiguous`。**A1 在西电首样本上成立。**

**L0 第二样本（2026-08-04，经 `atrust-client` 门面回环）：** 目标
`202.117.115.138:80`，另一个 `appId`、另一个会话、另一个 VIP，仍是
`connect_token_len=32`、下行 `layout=length_prefixed`（44 字节 TCP 应答），
无 `connect_token_ambiguous`、无 `ignored_command`。两个独立样本都落在安全区间。

**L0 第三样本（2026-08-06，1.5 小时保活会话）：** 目标 `202.117.112.70:443`
（`gsoft.xidian.edu.cn` 的地址，见 [B8](#b8)），**178 帧下行全部是 `layout=length_prefixed`**，
每帧 40 字节（裸 SYN/ACK）。这是目前最大的一批下行样本。

**因此 token-framed 分支至今零观测。** 三个独立会话、三个 appId、178 + 2 帧下行，
全部落在 length-prefixed 分支。判据本身没有被证伪，但**它的另一半从未被执行过**——
`n > 4096` 区间和 token 布局的解析代码在 live 上一行都没跑过。这不是"已验证"，
是"未触发"，仍归 [E6](#e6)。

**判定实验：** [E5](#e5)——token 长度已决；大包/token 分支样本仍待（[E6](#e6)）。

**已加固（2026-07-31）：** `L3Session` 拿到 `connectToken` 时若长度 < 17
（`MIN_UNAMBIGUOUS_CONNECT_TOKEN`）立即发 `connect_token_ambiguous` WARN，
把「未来某天错位」提前成「握手时就报警」。

### A2 — VIP 应答体的长度表 <a id="a2"></a>

**依据：L1**（zju-connect `l3tunnelconn.go::authTunnel` / `vipPayloadLength`）

VIP 帧为 `05 <status> <reserved> <addrType>` + `vipPayloadLength(addrType)` 字节。
现表：`1 → 6`，`4 → 18`，`5 → 22`，其它 `→ 4`。

**L0（2026-07-31 E4）：** 西电 `addrType=1`，`vip_data_len=6`，
`vip_data_hex=0ad21dc80000` → IPv4 `10.210.29.200`，**尾 2 字节为 `00 00`**
（不是 `18 00` 掩码位数假说的正例；仍可能是保留/零填充）。长度表 `1 → 6` 在西电成立。

**仍未决：**

- 尾 2 字节语义（零是否恒定、非零时是否掩码/其它）；
- `addrType = 4`（18）和 `5`（22）**西电仍未观察到**，长度仍来自 zju-connect；
- 默认分支的 4 字节是纯兜底，用途是**保持流同步**而不是解析地址——未知类型时先把
  body 读完再报错，否则半消费的帧会毒化这条连接；
- zju-connect **自身两处不一致**：`ip.go::getIP` 只读 8 字节整帧，
  `l3tunnelconn.go::authTunnel` 读 10。以 `authTunnel` 为准，因为它的连接要继续用。
  Hermes 曾照 `getIP` 实现，导致长连接从第一帧起错位（2026-07-31 修复）。

**10 字节已由 L0 定论（2026-08-05 复核既有日志）：** 此前只是「以 authTunnel 为准」的推理，
现在有直接反证。`2026-08-04-e7-heartbeat-ack-30s-live.log` 里 VIP 帧之后
`heartbeat_requests_sent=1 heartbeat_acks_received=1`——`05 95 00 00` 被正确解析；
`2026-08-04-e7-4h.log` 的会话连续 3420 秒 `session_closed=false`，全程无 framing 错误。
若 VIP 多消费了 2 字节，25 秒内的第一个心跳应答就会错位并触发 `FramingError` 关闭会话。
**因此 8 字节（zju `getIP` 的读法）是错的，Hermes 现行的 10 字节正确，无需修改。**
这同时说明 `getIP` 的 8 字节在 zju 里之所以无害，只是因为它读完立刻关连接。

**判定实验：** [E4](#e4)（`vip_data_hex` trace）——长度已决；尾字节语义仍开。

**掩码假说已证伪，且这个问题本身是伪问题（2026-07-31）。** 见 [A8](#a8)：
zju-connect 根本不从 VIP 推导掩码，尾 2 字节它一次都没读过。

### A8 — 隧道 MTU 与路由模型（掩码问题的真正答案） <a id="a8"></a>

**依据：L1**（zju-connect `stack/tun/stack.go`、`stack_linux.go`、`stack_windows.go`、
`stack/gvisor/stack.go`、`client/atrust/parse.go`）

E4 的尾 2 字节是 `00 00` 之后，我曾把「VIP 的前缀长度无处可取」列为接 TUN 的阻塞项。
**查完 zju-connect 后这个担心不成立——它压根不需要那个掩码：**

| 问题 | zju-connect 的做法 | 出处 |
|---|---|---|
| VIP 掩码 | **恒 `/32`**，不从任何帧推导 | `stack_linux.go:71` `ip + "/32"`；`gvisor/stack.go:160` `PrefixLen: 32`；Windows 走 `route add ... mask` |
| 隧道 MTU | **硬编码 1400**，不协商 | `stack/tun/stack.go:26` `const MTU uint32 = 1400` |
| 走哪些网段 | **完全来自资源表**，逐条 `ip route add <target> dev <tun>` | `stack_linux.go:48` `AddRoute` |
| 资源表里的网段怎么来 | `parse.go` 把 host 串按 IP／CIDR／`a-b` 三种形态解析成 `IPMin..IPMax` | `parse.go:118-150` |

也就是说 **VIP 只是一个 /32 的源地址，不承载任何子网信息**；「哪些流量进隧道」由资源表
独立决定。VIP body 尾部那 2 字节 zju-connect 从头到尾没有读过——`vipPayloadLength` 读 6 是
为了**保持流同步**，只有前 4 字节进 IP。

**对 Hermes 的直接结论：** TUN 层按 `<vip>/32` 配地址，路由按资源表逐条下，MTU 取 1400。
尾 2 字节保留在 `vip_data` 里供将来对照，但**不进任何决策路径**。

**仍未决：** 1400 这个 MTU 同样是 zju-connect 的常量而非服务端声明。它与 [A1](#a1)
第三条二义区间（下行 > 4096 失同步）的关系是：**上行**受 TUN MTU 约束不会越界，
**下行**没有任何东西保证服务端不发更大的包。这正是 [E6](#e6) 要测的。

### A3 — 每命令的帧头不对称 <a id="a3"></a>

**依据：L1 + L2**

`0x93`（AUTH_RESP）和 `0x96`（SECOND_VIP_RESP）在 u16 长度**之前**多一个 status 字节
（5 字节头）；`0x95` 和所有未知命令用通用 `<u16 len>`（4 字节头）；`0x94` 用 [A1](#a1) 的双格式。

**未决：** 这个「哪些命令带 status」的名单是**枚举出来的，不是规则**。没有任何依据说明
下一个新命令属于哪一类。Hermes 现在对未知命令按通用 4 字节头跳过（见 [A4](#a4)），
若某个未知命令实际是 status-先于-长度 布局，跳过会读少 1 字节并错位。

### A4 — 未知 `05 <cmd>` 的处理策略 <a id="a4"></a>

**依据：L1**（zju-connect `readFrame` 对未知命令用通用长度布局跳过）

**现状：** WARN 记录 + 按 `<u16 len>` 跳过，会话继续。

**这是一次被推翻的设计决定。** 早期实现选择「未知命令直接杀会话，让新帧在联调期立刻暴露」。
该权衡是错的：代价是一条健康隧道死掉，而通用长度布局的宽容正是已验证客户端能保持同步的机制。
2026-07-31 改为跳过。

**2026-08-05 对照复核：会话路径与 zju 完全一致，无需改动。** 逐项核对
`session.rs::next_frame` / `dispatch` 与 zju `readFrame` / `readLoop`：
`53 00` 跳过、未知 `05 <cmd>` 按 `<u16 len>` 跳过、非 `05`/`53` 帧头致命、
`0x94` 双布局判据同为 `0 < n ≤ 4096`（常量都是 4096）、`0x93` 非零 status 都会先尝试从 JSON
取 `conntrackHash` 唤醒等待方、心跳 25 秒——全部相同。
**同一形态的分歧只出现在它前面的 Get-IP 握手，见 [A9](#a9)。**

**残留风险：** 见 [A3](#a3)。跳过一个实际带 status 的未知命令会静默错位。

### A5 — 会话中途的 `53 00` 嵌套协议消息 <a id="a5"></a>

**依据：L1**

`53 00 <u16 len> <body>` 不只出现在 Get-IP 阶段，**会话中途也会出现**。Hermes 早期把它
判为版本错乱并杀会话，现已按嵌套消息消费。

**L0 样本（2026-07-31 E4 Get-IP）：**
`{"code":0,"data":{"deviceID":"644B123B"},"message":"OK"}`
（`deviceID` 为短十六进制串，与会话内 32 字节 `device_id` 形态不同）。

**仍未决：** body 内容 **Hermes 一律不解析**。若其中某类消息携带的是可操作状态
（会话被踢下线、策略变更、需要重新鉴权），Hermes 会当作噪声丢掉，表现为
「隧道还在但所有流突然不通」。

**已插桩（2026-08-06）：** `Inbound::Protocol` 现在携带 body，每条以 `info` 记录内容
（`atrust_l3.session.protocol_message`），并在 session 上保留最多 64 条（`protocol_messages()`，
计数器记真实总数），E7 每个 sample 输出 `protocol_messages_seen`。

**L0 负面结果（2026-08-06，共九条会话）：`protocol_messages_seen` 全程为 0。**
覆盖 2.5 小时保活、1 小时空闲、1.5 小时双向流量，以及 [B8](#b8) 里被顶掉的五条会话。
会话中途**一次 `53 00` 都没有出现**。

其中最有价值的是被顶掉的那五条：**网关是在主动把它们挤下线，这正是最该发一条解释性消息的场合，
但它什么都没发，直接关连接。** 加上空闲超时那条也是无预告直接关——目前没有任何证据表明
`53 00` 会承载可操作状态，两种最可能触发它的场景都已经排除。

仍**不结案**：并发登录挤下线（另一台设备登录同一账号）和管理员踢人尚未触发过，
而那是剩下的候选场景。插桩留着，成本为零。

### A6 — `0x95` 心跳应答体 <a id="a6"></a>

**依据：L1**。body 被完整消费但内容忽略。是否携带服务端侧的会话计时/配额信息未知。

### A7 — `0x16` / `0x96` second VIP <a id="a7"></a>

**依据：L3**。请求触发条件和用途均未确认。已知 `addrType = 5` 的 VIP 帧本身就同时带
IPv4 和 IPv6，与 second-VIP 是否互斥、还是分别服务不同场景，无依据。
Hermes 能解码 `0x96` 但从不主动发 `0x16`。

**行为分歧（2026-08-05 对照，未改）：** 两边都不主动请求（zju 的 `cmdSecondVipReq`
发送处是注释掉的 TODO），所以 `0x96` 只可能是服务端不请自来。但收到之后：

| | zju `handleSecondVipResp` | Hermes `Inbound::SecondVip` |
|---|---|---|
| status ≠ 0 | 记日志返回 | 记日志返回 |
| status = 0 | `extractVIPs` 递归扫 JSON 里所有能解析成 IP 的字符串，调 `onVIP` **换掉当前 VIP** | 只记 `debug` 日志，不改状态 |

若网关真的不请自来下发 second VIP，zju 会重新绑定源地址而 Hermes 继续用旧 VIP，
表现为「隧道存活、心跳正常，但回包全部丢失」。**未改**：`0x96` 在西电一次都没观察到，
`extractVIPs` 那种「扫出任何像 IP 的字符串就换地址」的做法本身也不适合照抄——
在确认帧含义之前，照抄一个可能误换地址的逻辑比忽略它更危险。

### A9 — Get-IP 阶段未知帧头是致命的（**新发现的分歧**） <a id="a9"></a>

**依据：L1**（对照 zju-connect `ip.go::getIP`）。**2026-08-05 对照发现，尚未修改。**

这是 [D4](#d4) 那个缺陷的同一形态：本端比参考实现严格，多出来的严格性没有依据支撑。

| 收到的 2 字节帧头 | zju `ip.go::getIP` | Hermes `get_ipv4` |
|---|---|---|
| `53 00` | 读 body，**要求含 `OK`**，否则报错 | 读 body 存入 `status_bodies`，**不校验内容** |
| `05 00` | 读 6 字节，返回 VIP | 读 `status`/`addrType` + body，返回 VIP |
| `05 d0` | 无分支——落到循环末尾，**消费 2 字节继续** | 显式 `continue` |
| 其它任何值 | 同上，**消费 2 字节继续** | `UnexpectedHeader` → **整个 Get-IP 失败** |

关键在最后一行：zju 的 `if / else if` 链**没有 `else`**，任何不认识的 2 字节头都被吞掉后
继续循环；Hermes 白名单之外一律致命。同一个节点同一个端口上，TCP 隧道路径**已经确证**会发
`05 81`（见 [D4](#d4) 与 `debug_logs/2026-08-03-e9-first-debug.log`）。Get-IP 用的是不同的
init 帧，但没有任何依据说明 `05 81` 不会出现在这里——如果出现，zju 照常拿到 VIP，
Hermes 直接失败，且失败点距离真正原因很远。

**注意 Hermes 内部也不自洽**：`session.rs::next_frame` 对未知 `05 <cmd>` 是跳过的
（[A4](#a4)，且那正是一次被推翻的「严格」决定），但它前面的 `get_ipv4` 仍然是严格的。
同一条连接上，握手阶段严格、会话阶段宽容。

**为什么暂不改：** 现在没有任何一次 Get-IP 因此失败的观测。按 [A4](#a4) 的教训，宽容是对的
方向；但那次改动是有 L1 依据的（zju 明确用通用长度布局跳过），而这里要吞掉的是**没有长度字段
的未知 2 字节头**——盲目跳过 2 字节，遇到真正的带长度帧就会从中间切开，把一个清晰的报错换成
一次静默错位。在拿到「Get-IP 阶段实际会出现哪些帧头」的 L0 证据之前，保留报错更有利于定位。

**判定实验（2026-08-05 已执行）：** `get_ipv4` 现在对**每个**帧头都打
`atrust_l3.get_ip.header`（不只失败时），并在 `UnexpectedHeader` 前用 500 ms 上限多读至多
64 字节，把尾巴以十六进制记进 `atrust_l3.get_ip.unexpected_header`——帧头本身说明不了它有没有
长度字段，而那正是决定「能不能安全跳过」的前提。

**L0 结果：5/5 一致，未触发。** 同一会话、节点 `61.150.43.94:441`、约 3 分钟内连续 5 次
Get-IP，帧头序列每次都是且仅是：

```
05 d0        method ack
53 00        {"code":0,"data":{"deviceID":"644B123B"},"message":"OK"}
05 00        VIP，addrType=1，vip_data_len=6 → 10.210.29.61（5 次同一个 VIP）
```

**这条实验没有解决 A9，只是给它划了边界。** 结论应当读作「西电此刻不发白名单以外的帧头」，
而不是「节点永远不发」：样本只覆盖一个节点、一个会话、一种 `addrType`、无并发无压力，
另一个广告端点 `10.255.57.11:441` 当前不可达因而无法交叉验证。

**因此维持不改**，理由比之前更硬：既没有观察到严格性造成失败，也**仍然没有**拿到任何未知帧的
真实布局——在不知道布局的情况下盲目跳 2 字节，只是把一个清晰报错换成静默错位。
插桩留在代码里：它是零成本的，而且是唯一能在这件事真发生时留下证据的东西。
`53 00` 不校验 `OK` 的分歧同理，仍等同一批数据。

---

## B. 鉴权与会话

### B1 — SignKey 的来源与绑定关系 <a id="b1"></a>

**依据：L2 only**——这是当前最薄的一环。

参考服务端的模型是：客户端生成、不上传；服务端若已绑定 `sign_key_hex` 则硬校验 HMAC，
否则从 wire JSON 的 `signKey` 字段 first-write-wins 学习，再否则放行。
**这个模型完全来自那个重建服务端，没有任何 L0/L1 佐证。**

Hermes 现在用一个临时随机 SignKey，对参考服务端能打通——但那恰恰是 L2 循环论证的典型：
服务端「不绑定就放行」的行为如果是重建时猜的，西电可能根本不是这样。

**L0（2026-07-31 E3）：** 同一 CAS 会话下，正确 `sign_key_hex` 与仅翻转首字符的坏 key，
对 TCP 隧道握手**均成功**（目标 `202.117.115.138:80` / 新OA）。按判读表：
**西电当前不硬校验 TCP init 的 HMAC**（或等价于未绑定 + 不学习）。
临时随机 SignKey 模型在西电 TCP 路径上**不阻塞**；[B1](#b1) 降级为非阻塞。

**L0（2026-08-04 E3b）：L3 `0x13` 路径同样不校验 HMAC。** 同一 CAS 会话下，正确 key
与仅翻转 `sign_key_hex` 首字符的坏 key 都返回了 32 字节 connect token；换新源端口
（新 flow key）重跑坏 key 仍然授权，排除了「命中服务端对上一次的缓存授权」。

**因此 [B1](#b1) 整体降级为非阻塞。** 临时随机 SignKey 模型在西电的 TCP 与 L3 两条路径上
都不阻塞，E5/E6 可以推进。

**仍未决：** 是否存在独立注册接口。注意 L3 auth JSON **不携带 `signKey` 字段**
（唯一签名相关字段是 `xRequestSig`），所以参考服务端那套「从 wire JSON 的 `signKey`
first-write-wins 学习」的模型在这条路径上**不可能成立**——服务端根本收不到 key。
剩下的可能只有「未绑定且不校验」，或者「绑定了别的 key 但不校验」。

**这个结论只覆盖西电，且只覆盖当前配置。** 它是「服务端没开这道校验」，不是
「协议不需要签名」。另一个网关、或西电改配置后，同样的坏 key 会立刻失败，
而症状会伪装成帧格式问题——这正是当初把它列为 1 号闸门的理由。

**判定实验：** TCP 侧见 [E3](#e3)；L3 侧见 [E3b](#e3b)。两者均已完成。

### B2 — Get-IP 请求中的 `0x0053` <a id="b2"></a>

**依据：L1（已决）**，但需要一次 L0 复核。

`0x0053` = 83 是**动态长度**，`authTunnel::wrapAuthReqData` 动态计算；`getIP` 里写死
只是 73 字符 SID 的巧合。Hermes 的动态实现正确。

**残留：** 西电的 SID 若恰好也是 73 字符，这条 live 不具备区分力。复核需要一个
**长度不等于 73** 的 SID。若拿不到，就只能维持 L1。

### B3 — flow key 不含协议号 <a id="b3"></a>

**依据：L1（逐字符一致）**

`connTrackKey` = `{atype}:{src}:{sport}-{dst}:{dport}`，没有协议号。

**未决：** 这意味着**同四元组的 TCP 流和 UDP 流会共用一条 conntrack 表项**。这是服务端
的真实语义，还是 zju-connect 的一个恰好没被踩到的简化？无依据。真踩到时的症状是
「UDP 流复用了 TCP 流的 connectToken」——服务端大概率拒绝或静默丢包。

注意 `atype` 在两处是**不同的命名空间**：鉴权 JSON 里是 `0x0800`（EtherType），
flow key 里是 `4`。两者都是经验值。

### B4 — 8 秒鉴权超时 / 25 秒心跳 <a id="b4"></a>

**依据：L1**。两个常量都来自 zju-connect 源码，**服务端从未声明**。西电的实际容忍窗口未知。
心跳过慢会被服务端静默断开，过快在大规模部署下可能触发限流。

### B5 — 鉴权失败后的重试语义（已对齐） <a id="b5"></a>

`L3SessionManager` 现在拥有节点组的一条可重建会话：连接关闭时最多重连 5 次；8 秒 flow-auth
超时会作废整条连接、重新 Get-IP 和鉴权一次。显式策略拒绝、坏帧和配置错误不重试。
建连类瞬时失败和连接失效会轮转到同组下一可达端点；显式 `--node` 仍固定单点。
`L3SessionManagerCache` 按 `nodeGroupId` 复用 manager，且只在同一 SID/TLS 作用域内共享。
这与 zju-connect 的边界一致，同时保持 TUN、DNS 和系统路由在管理器之外。

### B7 — 网关会话寿命与失效信号 <a id="b7"></a>

**依据：L0（2026-08-03 实测一次）。**

15:16 保存的 CAS 会话在 18:56 复用时被拒：`code 75500002 / "The session is invalid"`。
因此**寿命上界 < 3 小时 40 分**；是绝对 TTL 还是空闲超时**未区分**——两次使用之间没有
任何请求，两种模型都能解释这次观测。区分实验：保存后每 30 分钟打一次 `onlineInfo`，
看它能否延到 3.7 小时以上。

**第二样本（2026-08-04）：** 会话 02:40 UTC 保存，03:40 仍成功完成 `authConfig`、
`onlineInfo`、两次 `clientResource` 和一次 L3 flow auth；06:34 再跑时 `authConfig` 仍返回结构，
但 `onlineInfo` 报同一 `75500002`。它再次确认失效业务码和小时级寿命，但由于 03:40 到 06:34
之间没有 30 分钟心跳请求，仍不能区分绝对 TTL 与空闲超时，也不比第一样本的上界更紧。

**实现后果（已处理）：** 同一个业务码会经由两个不同的错误类型到达调用方——`authConfig`
报 `AuthError::AuthenticationRejected`，`clientResource` 报 `AuthError::Resource(Rejected)`，
`AuthError::is_session_invalid()` 同时识别两者。`ResourceCache` 据此把它**升级**为
`HermesEvent::SessionInvalidated` 而不是计入连续失败计数：重试永远修不好它，而一个只会
反复 `warn` 的刷新循环会让整个运行时停在一张只会越来越旧的资源表上。

**第三样本（2026-08-06，[E7](#e7) 的副产品）：** 会话 10:03 保存，13:51 启动第三条臂时
`authConfig` 直接返回 `75500002`。**约 3 小时 48 分**，与前两个样本的小时级上界一致。
这次期间**有**持续的控制面与数据面活动（两条 L3 会话共约 3.5 小时、`clientResource` 拉取、
持续 heartbeat），却仍然过期——**因此绝对 TTL 的解释现在明显更有利，空闲超时基本可排除**。
注意这与 [E7](#e7) 刚定论的 L3 连接空闲超时是**两个不同的计时器**：控制面 SID 约 3.7 小时
且活动不续期，L3 连接约 1 小时且出向数据可续期。

**对实验纪律的影响：** 任何需要正负对照的实验（[E3](#e3)、[E3b](#e3b)）必须在同一个会话里
连续跑完，中间不能夹一次重新登录。**任何超过约 3.5 小时的实验必须把最重要的臂排在最前**，
否则末尾的臂会因 SID 过期而失去可判读性——[E7](#e7) 的 C 臂就是这样丢掉的。

### B8 — 一台设备同时只有一条 L3 会话（**新发现**） <a id="b8"></a>

**依据：L0（2026-08-06，六路并发注册）。**

用同一份会话材料（同一 SID、deviceId、connectionId）同时起六个进程，各自做 Get-IP 并各自建
L3 会话，打同一个节点 `61.150.43.94:441`：

| 臂 | 建立 | 死亡 | keepalive |
|---|---|---|---:|
| guard-60 | 06:42:54 | 06:43:54 | 60 s |
| idle-0 | 06:43:09 | 06:44:09 | 无 |
| k-300 | 06:43:31 | 06:44:31 | 300 s |
| k-900 | 06:43:48 | 06:44:48 | 900 s |
| k-1800 | 06:44:11 | 06:45:11 | 1800 s |
| **inbound-60** | 06:44:30 | **存活 5455 s，`passed=true`** | 60 s |

三个事实定死了结论：**六条会话拿到的是同一个 VIP `10.210.29.47`**；每条都在建立后 25 秒内
死亡（`heartbeat_requests_sent=0`，而心跳是 25 秒一次，所以连第一次心跳都没轮到——60 秒才被
发现只是采样粒度）；每条的死亡时刻都对应下一条建立的时刻（间隔 15–23 秒），最后建立的那条活下来。

**结论：网关按设备发放 VIP，一台设备同时只维持一条 L3 会话，重复注册后建者胜。**
这也解释了此前 [A9](#a9) 实验里连续 5 次 Get-IP 全部返回同一个 `10.210.29.61`。

**这不是"一个账号只能开一个页面"。** 多标签页在 VPN 模型里是同一条隧道内的多条 **flow**，
不是多条会话：一台设备一个 TUN、一个 VIP、一条 L3 隧道，所有应用的包按五元组拆成不同 flow，
每条单独用 `0x13` 授权。这条路径已由 [E8](#e8) 验证——一条会话、一个 VIP、两条并发 flow、
四个竞争调用方全部成功（`tracked_flows=2`、`auth_timeouts=0`）。上面那个实验是**病态的**：
同一台设备在网关那里注册了六次，网关的处理完全合理。

**一条被推翻的推论，记在这里防止重提。** 本条最初被写成「Hermes 的 `L3SessionManagerCache`
按 node group 分键，在多 node group 部署上会开出互相残杀的 L3 会话」。**这个推论错了。**
zju-connect 的 `L3Tunnel` 持有的是 `t.conns[nodeGroupID]`——同样按 node group 分键、一个 group
一条连接，与 Hermes 一致，且 zju 长期在跑。而且上面六条会话全部打在**同一个 node group 的
同一个节点**上，那是重复注册的情形，根本不覆盖「不同 node group」的情形——从一个案例推到了
它不覆盖的另一个案例上。

**真正的空白：** 两条打到**不同 node group** 的 L3 会话能否共存，我们没有依据。西电只广告一个
node group，本地测不了；zju 常规这么跑算 L1 依据。若将来遇到多 node group 部署，这是第一个要验的点。

**对实验纪律的影响（新增）：** **L3 实验不能靠并发多臂来省时间。** 同一账号并行起多条会话，
除最后一条外全部会在一分钟内死掉，且死法（`read_error`、心跳计数 0）看起来像网络问题而不是
被顶掉。2026-08-06 的阈值扫描就是这样整批作废的——守卫臂（已知能存活 2.5 小时的 60 秒间隔）
同样死亡，是唯一让这批数据被判为无效而不是被误读成「阈值 < 60 秒」的东西。
配合 [B7](#b7) 的 ~3h48m SID 寿命，多档扫描应改为**单会话内递增间隔**，而不是并行或串行多臂。

### B6 — 资源定期刷新（已实现，刷新周期仍需 live 调优） <a id="b6"></a>

`ResourceCache` 原子发布同一响应生成的 `ClientResources + ResourceIndex`，刷新失败时保留最后一次
成功代际。L3 的刷新通知会更新已有节点组 manager 的后续重连候选，并驱逐服务端已删除的节点组；
不会仅因候选排序变化中断健康会话。当前默认周期 60 秒是客户端策略，服务端没有声明 TTL，仍需
通过长会话观察请求成本、策略生效延迟和会话过期行为。

---

## C. 资源匹配

### C1 — 资源表重叠时的优先级（**已知故意分歧**） <a id="c1"></a>

zju-connect **没有统一的资源优先级**：L3 `processIPV4` 是按服务端原始顺序的
first-match；TCP tunnel 的 IP 匹配循环不 `break`，后命中的 `appId` / `nodeGroupId`
会覆盖前者，实际是 last-match；域名资源放进 Go `map`，重复 key 后写覆盖，重叠后又受
无序迭代影响。Hermes `ResourceIndex` 则统一按「地址范围最窄 → 端口范围最窄 →
精确协议先于 `all` → 原始顺序」确定性排序。

**表存在重叠时两者选出不同的 `appId` / `nodeGroupId`。**

**决定（2026-07-31，用户）：维持 Hermes 的 specificity 排序**，理由是「zju-connect 能用」
不等于「zju-connect 正确」——也可能只是 ZJU 的表恰好不重叠。

**E9 已确认西电网关接受任一覆盖目标的合法候选，而不是只接受唯一的首条或最具体项。**
因此 specificity 与 zju-connect L3 first-match 在当前西电资源表上都能通过授权；但完全无关的
`appId` 会被拒绝，所以 matcher 仍必须筛掉不覆盖目标、端口或协议的资源。该结论不能自动外推
到其他网关，`nodeGroupId` 不同的重叠项也仍需作为一个整体选择。

#### L0 量化结果（2026-07-31，E2，西电 1361 条 IP 资源）

对 2035 个采样点（每条资源取 `IPMin` / `IPMax` / 中点 × 端口下界 / 上界 / 80）：

| 协议 | 命中 | 重叠（候选 > 1） | **两种排序选出不同 appId** |
|---|---|---|---|
| TCP | 2035 | 1510（**74%**） | **1235（60%）** |
| UDP | 444 | 80（18%） | 14（3%） |

**分歧不是边缘情况，是 TCP 的多数情况。** 主因是表里存在**排在很前面的宽泛兜底条目**，
例如 `10.0.0.1-10.255.255.254`（`all`，全端口）。zju-connect 的 **L3 first-match**
会把几乎所有 10.x 流量都归给那一个 `appId`；Hermes 则按最窄条目归给具体应用。
典型分歧（`zju` 列特指 L3）：

```
10.168.76.172:8355  zju→290b1940 (10.0.0.1-10.255.255.254)  hermes→34a33d00 (10.168.76.172)
202.117.112.71:8081 zju→27bf5f60 (202.117.112.1-.254)       hermes→316772f0 (202.117.112.71)
202.117.112.9:53    zju→27bf5f60 (202.117.112.1-.254)       hermes→2b306a40 (202.117.112.9-.14)
```

**判定实验：** [E9](#e9) 已完成。对 `202.117.112.71:8081`，Hermes specificity 候选
`316772f0...` 与原始首条 `27bf5f60...` 在 TCP 和 L3 两条路径都通过了 app 授权；无关候选
`66238e10...` 分别收到 TCP `0x02` 和 L3 `0x82`。这排除了“服务端只承认一种排序”的模型，
支持“任一匹配资源都可授权”的模型。

### C2 — ICMP 如何命中资源 <a id="c2"></a>

**依据：L1**。zju-connect 的 L3 matcher 判据是
`Protocol == "icmp" || == "all"` 且不比较端口；但当前 aTrust `parse.go` 只把
`tcp` / `udp` / `all` 放入 `ipResources`，所以服务端显式 `icmp` 条目实际上会在进入
matcher 前被丢弃。这是 zju-connect 自身 parser/matcher 的不一致，不应照搬。
Hermes 解析并匹配显式 `icmp`，同时允许 ICMP 命中 `all`。

**L0（2026-07-31 E5 附带）：** 对只有 `tcp:80` 资源的目的地发 ICMP echo，
`0x13` 返回 **`auth status 0x82`**。这是第一条服务端侧证据：
**网关在 flow auth 阶段真的比较协议，并对协议不匹配显式拒绝。**
连带结论：西电资源表里没有 ICMP 授权的目的地时，隧道内 ping 不通**不是 bug**，
`--probe icmp-echo` 也因此不能作为通用回环探针（[E6](#e6) 需要换 UDP）。

**仍未决：** 西电的表是否存在 `icmp` 协议值的条目（E2 的采样里未专门统计）；
`0x82` 是否专指协议不匹配，还是「资源不授权」的通用码。

### C3 — 域名通配符语义 <a id="c3"></a>

**依据：L3**。现按 `*.example.edu` 覆盖任意子域**但不含 apex** 实现。服务端是否同此未知。

### C4 — 端口 `0` 与倒置区间 <a id="c4"></a>

**依据：L1**。zju-connect 除 `Atoi` 外不做任何校验，因此保留。Hermes 曾把它们整条丢弃，
造成**静默丢失真实策略**（ICMP 资源的端口通常就是 `0`），2026-07-31 改为保留。

**未决：** 保留之后这些条目的**匹配语义**仍未定义——端口 `0` 是「任意端口」还是「仅端口 0」？
倒置区间（min > max）是空集还是应当交换？现实现按字面比较，即两者都近似于空集
（ICMP 不比较端口所以不受影响）。

---

## D. 端点与网络路径

### D1 — 数据面节点的真实地址 <a id="d1"></a>

**2026-07-31 实测（L0），推翻了此前文档中「外网 :441 TCP 超时」的记录：**

| 目标 | TCP | TLS | 结论 |
|---|---|---|---|
| `atrust.xidian.edu.cn` → `61.150.43.99:443` | ✅ | ✅ 有效证书 `*.xidian.edu.cn` | **控制面**，`authConfig` 正常 |
| `61.150.43.99:441` | ✅ 接受 | ❌ 无 ServerHello（无论是否带 SNI） | 死端口 |
| `61.150.43.94:443` | ✅ | ✅ `*.xidian.edu.cn` | 另一个 vhost，aTrust API 返回 **404**，非控制面 |
| **`61.150.43.94:441`** | ✅ | **✅ 81 ms**，自签证书 `C=CN, ST=Hunan, O=Sangfor, OU=SSL, CN=sdp` | **真实数据面节点，公网当前可达** |

`atrust.xidian.edu.cn` 只有一条 A 记录（`.99`），`.94` 不在 DNS 中，
因此它必然来自 `clientResource` 的节点组或官方客户端下发。

**未决：** `10.255.57.11` 是内网地址，外网不可达。**两个端点各自从哪里来、
`clientResource` 里的原始形态是什么，尚未确认**（见 [E1](#e1)）。
特别注意 Hermes 会把 `{{sdpcHost}}` 占位符替换为**控制面主机名**（`atrust.xidian.edu.cn`）。

**端点选择已改为实测驱动（2026-07-31）：** 旧行为是 `primary_nodes()`——取第一组的第一个端点，
**完全不做可达性检查**。这在西电这种「内网地址 + 公网地址同组」的配置下必然选错，
且失败长得像协议超时。新实现 `atrust_auth::select_node`：并行探测每一个已广告端点，
按「可达优先 → 握手时延升序」排序取第一名；探测失败的端点其 elapsed 是超时值，
不代表时延，因此永不参与竞争。显式 `--node` 优先于时延，但**必须在广告列表内且必须应答**，
否则报错而不是回退（见 [D3](#d3)）。

### D2 — 数据面节点对 SNI 的行为（**新发现，影响实现**） <a id="d2"></a>

**依据：L0，2026-07-31 实测，四组对照：**

| ClientHello | 结果 |
|---|---|
| 不带 SNI | ✅ 握手成功（TLS 1.3 或 1.2 均可） |
| `servername = atrust.xidian.edu.cn` | ❌ 服务端静默丢弃，无任何响应 |
| `servername = sdp` | ❌ 同上 |
| `servername = 61.150.43.94`（作为名字） | ❌ 同上 |

**结论：任何 SNI 扩展都会让 `61.150.43.94:441` 静默不响应**，与名字内容无关，与 TLS 版本无关。

**这解释了此前所有「441 不可达」的误判**——那些探测要么打在 `.99`，要么带了 SNI。

**此前 Hermes 只是恰好正确：** `hermes-transport::connect_tls` 用
`ServerName::try_from(host)`，rustls 对 **IP 字面量不发送 SNI**（RFC 6066），
所以按 IP 指定节点能通；但只要节点地址是主机名（`{{sdpcHost}}` 占位符路径正是如此），
rustls 就会发 SNI，连接静默挂死且无任何错误。

**已修（2026-07-31）：** `client_config` 显式设 `enable_sni = false`，两种 `TlsPolicy` 都覆盖，
由单测 `data_plane_tls_never_sends_sni` 守住。证书名校验不受影响——它用的是传给
`connect` 的 `ServerName`，与该开关无关。控制面走 reqwest 独立配置，不受影响。

**这条修复是端点延迟测量正确性的前提**：不修的话，任何主机名端点都会被测成 timeout，
从而在排序里被判为不可达，而真实原因只是我们发了 SNI。

### D3 — 显式 `--node` 的 fail-closed 语义 <a id="d3"></a>

**这是一条实现决定，不是协议未决项**，记在这里是因为它会直接改变实验的可判读性。

`select_node` 对显式端点有三种拒绝，都不回退：

| 情况 | 行为 | 理由 |
|---|---|---|
| 不在广告列表 | `NotAdvertised` 报错，**且不发起任何探测** | fail-closed 的意义就是根本不去碰它。服务端没广告的地址要么是过期笔记要么是误导，向它发起连接就是把会话材料送去网关从未指过的地方 |
| 在列表内但探测失败 | `RequestedUnreachable` 报错 | 静默换一个节点会让此后所有测量**不可归因**——你以为测的是 `.94`，实际测的是 `.11` |
| 格式非法 | `MalformedAddress` 报错 | — |

主机名比较**大小写不敏感但不做 DNS 解析**：一个解析到广告 IP 的名字仍然是另一个地址，
把它当成同一个会重新引入 fail-closed 正要消除的那种模糊。

**逃生舱：`--allow-unadvertised-node`。** 它把第一种情况降级为 WARN 并仍然探测。
存在的理由很具体：广告列表本身正在被调查（[E1](#e1) 还没跑），而已知可用的
`61.150.43.94:441` 可能根本不在列表里。**跑完 E1 之后就不应该再需要它**——
如果还需要，那本身就是一条要记录的发现。

### D4 — TCP connect 成功后首个应用数据触发关闭 <a id="d4"></a>

**参考行为（L1）：** zju-connect 的 `tcpTunnelConn` 将 `01 00 <u16 len> <payload>` 暴露为
普通 `net.Conn`；上层 `net/http.Transport` 对 HTTPS 自然再套一层目标 TLS。Hermes 的
`TcpTunnel` 同样实现 `AsyncRead + AsyncWrite`，并按相同布局封装数据。目标 TLS 必须启用
目标域名 SNI，不能继承数据节点的 no-SNI 特例。

**本地状态：** `atrust-probe tcp-dial --send-https` 已实现双层 TLS、独立目标证书策略、
有界多帧响应累计和总超时。空 AsyncWrite 不再错误地产生零长度 probe 帧；数据阶段的
结构化 `code=0, message=OK` 与地址阶段使用同一严格成功判定。以上均有本地测试，但本地
mock 只能证明实现自洽，证据级别不是 L0。

**L0（2026-08-05，同会话 zju-connect 对照）：** live-only 测试从 `0600` Hermes session 文件
注入完全相同的 SID、DeviceID、ConnectionID、SignKey 和资源正文，固定使用广告节点
`61.150.43.94:441`。精确资源旁路下三个域名均完成 aTrust 授权、目标 TLS 和 HTTP 200：

| 目标 | aTrust 授权 | 目标 TLS | HTTP body |
|---|---:|---:|---:|
| `www.xidian.edu.cn:443` | 约 140 ms | TLS 1.2 | 163772 B |
| `www.cnki.net:443` | 约 271 ms | TLS 1.3 | 105912 B |
| `gsoft.xidian.edu.cn:443` | 约 102 ms | TLS 1.2 | 66583 B |

这证明 `01 00 <u16 len> <payload>` 应用帧布局和透明流分层正确，推翻了“目标服务或 appId
普遍不可用”的解释。Hermes 对同一个 gsoft 目标仍在 rustls ClientHello 后收到
`01 01 00 00` 并报 `tls handshake eof`。Go 默认 ClientHello 为 1507 B；禁用 PQ key-share、
只保留 X25519/P-256 后缩为 281 B，仍协商 TLS 1.2 `0xc030` 并成功。Rustls ClientHello 为
246 B。因此问题已经收敛为**目标 TLS ClientHello 扩展/指纹差异**，不是长度、PQ、SNI、
基础 cipher suite 或 aTrust 应用 framing。

**zju-connect 资源匹配的两个独立缺陷（不应复制）：** 同域名的 80/443 条目写入单值 map 时
互相覆盖，使 www.xidian/CNKI 的原生 443 匹配为空；IP 重叠使用 last-match，使
`10.255.72.81:80/443` 选到无关 appId 并立即收到 `no 'appId' field`。注入精确资源后两个 IP
目标不再策略拒绝，而是在约 15 秒收到 `05 03 network unreachable`，说明当前数据节点到该
内网地址无路由。Hermes 的 specificity 在这两个目标上选择了正确的软件正版化资源。

**已解决（2026-08-05，见本节末尾）：** 此处及以下关于“外层 TLS 会话存在不可见差异”的推论
全部是错误方向——根因是本端把节点的 padding 读成了关闭。保留这些记录是为了说明排除过程，
不要再据此继续做 TLS 层实验。此前两个 HTTP 80 目标的关闭是另一组样本，不应与本问题合并归因。

**ClientHello wire 差分（2026-08-05）：** 本地无凭据捕获确认 Go classic 和 rustls 分别为
281 B、246 B，都是一个 TLS record，并各自落入一个 aTrust app frame。两边共同发送 SNI、
status request、EMS、point formats、TLS 1.2/1.3、X25519 key share，且都不发 ALPN。Go 独有
`renegotiation_info`、SCT、`signature_algorithms_cert`；rustls 独有 `psk_key_exchange_modes`、
空 `session_ticket`，并用 SCSV 表示安全重协商。扩展顺序和 cipher 顺序完全不同，JA3 分别为
`5c4e3d1520f523c80030e4bb4085e740` 与 `a59be6093cc1047d346455f4726ab681`。

把 Go 限制为与 rustls 相同的 6 个 TLS 1.2 AEAD suites，并使用
`X25519/P-256/P-384` 后，ClientHello 为 275 B，gsoft 仍协商 TLS 1.2 `0xc030` 并返回
HTTP 200。因此 CBC 支持、supported groups 集合和 TLS 1.2 suite 能力基本可排除；下一轮应
优先比较/消除扩展集合与顺序、signature algorithms 顺序和 TLS 1.3 suite 排序。

**完整差分结果（2026-08-05）：内层 ClientHello 不是根因。** rustls 0.23.42 临时分支增加了
实验 profile，可精确控制扩展集合/顺序、signature algorithms 和 cipher 顺序。生成的 275 B
内层 ClientHello 与成功的 Go 样本除 random、session ID 和 X25519 公钥外逐字节一致，Hermes
仍收到 `01 01 00 00`。交叉注入给出决定性反证：

| 外层隧道 | 注入的内层 ClientHello | 结果 |
|---|---|---|
| zju-connect / Go TLS | rustls 生成的 275 B 精确 Go profile | 返回 TLS ServerHello |
| Hermes / rustls | 已成功的 Go 275 B 原始样本 | `01 01 00 00` |
| Hermes / rustls | 直接 `write_app/read_app`，绕过 AsyncRead/AsyncWrite | `01 01 00 00` |

因此内层 rustls、X25519 公钥、`TcpTunnel` 流适配层均可排除。两端的签名后 init frame（906 B）
和 destination frame（26 B）SHA-256 完全一致；透明代理还确认 Hermes 外层 TLS 对 init、dest、
probe、app 分别产生单独 record，明文长度依次为 906、26、4、279，与 Go 相同。外层均协商
TLS 1.3 / AES-256-GCM；rustls TLS 1.2-only、OpenSSL TLS 1.3 和 `TCP_NODELAY` 也全部失败。

进一步把外层 rustls ClientHello 魔改为 Go classic profile 后，两者均为 247 B，除三个随机字段
外逐字节一致，结果仍不变。当前最窄结论是：**数据节点在完成相同 aTrust 握手后，对 Go TLS
外层会话返回应用数据，但对 Tokio 上的 rustls/OpenSSL 会话返回关闭；差异不在可见 ClientHello、
协议版本、cipher、TLS record 边界或 aTrust 明文。** 下一步不应继续修改内层 TLS，而应使用
Go TLS underlay/最小 Go sidecar 做 Hermes 外层对照，或捕获并比较解密后的外层 TLS 会话事件。

**Go FFI underlay 结果（2026-08-05）：仍为阴性。** 新增实验性 Go `c-shared` 库，通过 Unix
socketpair 把进程内 Go `crypto/tls` 会话暴露给 Tokio，并依次测试三个替换层级：

1. 仅用 Go TLS 替换外层 rustls，Hermes 保持 setup/framing；
2. Go TLS 同时完成 init、destination、address OK、probe 和 connect status；
3. Go TLS 同时拥有与 zju `tcpTunnelConn` 相同的 `01 00` application framing。

Rust→Go 桥使用私有长度前缀，确保每次 Rust write 对应一次 Go `tls.Conn.Write`；Go 模块版本也
与 zju-connect 对齐为 `1.25.6`。三个层级均在首个目标响应前关闭，最后一级表现为桥接端
`BrokenPipe`。紧接着用同一会话重跑 zju raw ClientHello 阳性对照，约 96 ms 完成 aTrust setup
并收到 TLS ServerHello，因此不能归因于会话失效、节点限流或目标状态变化。

这推翻了“只要换成 Go TLS/Go framing 就会成功”的产品假设。剩余差异位于 zju `DialTCP` 的
连接上下文、调度/时序或尚未记录的 socket 行为；下一步应直接在 zju 与 FFI 库内记录同一组
非敏感时间点和 socket options，而不是继续替换更多 TLS 层。

**已定位并修复（2026-08-05）：根因是本端读帧过严，不在 TLS，也不在 zju 的连接上下文。**
数据节点在 `05 00` connect status 之后、任何应用数据之前，紧接着发送 8 个字节：
`01 01 00 00` 后跟 `00 00 00 00`。这段内容对 Hermes 和 zju 是一样的，区别在两边怎么读它：

| 帧 | zju `tcpTunnelConn::Read` | 修复前的 Hermes `try_decode_app` |
|---|---|---|
| `01 01 00 00` | trailer 非 `30 30`，消费 4 字节后继续 | 视为服务端关闭，返回 EOF |
| `00 00`（padding） | 分支链没有 `else`，消费 2 字节后继续 | `UnexpectedFrame` 报错 |
| `01 01 30 30` | 真正的关闭 | — |

也就是说 `01 01 00 00` **不是**服务端关闭。服务端关闭是 `01 01 30 30`（ASCII `"00"`），
本次修复后的成功会话在响应读完时确实收到了它（`close_frame trailer0=48 trailer1=48`）。
`01 01 00 00` 只是本端 `Close()` 发出去的关闭帧，两个方向并不对称。

修复后同一会话、同一节点 `61.150.43.94:441`、同一 appId 下三个目标全部通过，
**且目标证书是完整校验的（`certificate_verified=true`）**：

| 目标 | HTTP | body | 同日 zju 对照 |
|---|---:|---:|---:|
| `gsoft.xidian.edu.cn:443` | 200 | 67361 B | 66583 B |
| `www.xidian.edu.cn:443` | 200 | 164887 B | 163772 B |
| `www.cnki.net:443` | 200 | 106360 B | 105912 B |

body 大小是动态内容，两侧不会逐字节相同；量级一致即可。zju 对照是在 Hermes 失败之后、
用同一个 session 文件当场跑的（94 ms，HTTP 200），所以"两端此刻都可用"是验证过的前提，
不是引用历史结果。

**为什么此前所有 TLS 实验都是阴性**：失败发生在读第一个响应帧时，早于任何 TLS 指纹能起
作用的位置。逐字节对齐内层 ClientHello、外层 ClientHello，乃至把整个外层 TLS 换成 Go，
都不可能改变一个本端解析错误。文档此前把“Hermes 在 ClientHello 之后收到 `01 01 00 00`”
读成了服务端的响应，实际那 8 个字节在我们发出 ClientHello 之前就已经在缓冲区里——
日志时间戳相差 66 µs，而该节点 RTT 约 88 ms。

**因此上面 Go FFI 段落的结论作废**：三个层级失败的原因是 FFI 桥
`copyApplicationResponses` 复制了同一个缺陷（`01 01` 一律终止、未知头 `default: return`），
桥先自行拆除，Rust 端才看到 `BrokenPipe`，而不是节点关闭。那三条"阴性"不构成关于节点的证据。

**Go FFI 实验已删除。** `crates/hermes-go-tls-ffi`、`experiments/go-tls-ffi`，以及
`HERMES_NODE_TLS_BACKEND=go-ffi` 相关的 `NodeTlsStream` 枚举、`connect_go_tls_atrust` 和
`TcpTunnel` 的 framing 旁路全部移除，节点 TLS 回到单一 rustls 实现。保留一个基于错误前提的
可选传输层，只会让后来者以为"换 Go TLS"仍是一个待验证选项。上面的段落作为排除过程的记录保留。

**已排除（同日实测，负面对照）：** 新增 `tcp-dial --skip-node-probe` 跳过 dial 前的节点
延迟探测后，失败逐字节不变。dial 前那次“完整 TLS 握手后零应用字节丢弃”的探测与本问题无关。

**现在的容忍规则**：未识别的 2 字节头消费后继续，与 zju 一致，但加了 1024 字节上界，
使真正的流失步仍然可见。`05 81` 在数据阶段也按 2 字节跳过。

---

## E. 判定实验

**[D1](#d1) 改变了整个测试计划的前提：数据面节点 `61.150.43.94:441` 当前公网可达，
因此 E1–E5 全部不需要进校。** 唯一不能远程完成的是 CAS 交互登录里的人工环节
（IDS 表单 + 滑块 + 短信），但那本来也不受地理位置限制。

### 通用前置与纪律

```bash
cargo build -p atrust-probe          # 后续所有命令用 ./target/debug/atrust-probe
chromedriver --port=9515 &           # 仅 E1 的 cas-login 需要
```

三条硬性纪律，违反其一实验结果就不可信或不安全：

1. **节点地址写 IP。** SNI 本身已经在客户端侧关掉（[D2](#d2)），但 `atrust.xidian.edu.cn`
   解析到的 `.99:441` 是死端口，所以 `--node atrust.xidian.edu.cn:441` 仍然打不通；
2. **数据面必须 `--insecure-tls`。** 节点证书是自签的 `CN=sdp`，默认 `Verify` 策略必然失败。
   注意这是全局开关，同时也放松了控制面校验；
3. **`--session-file` 和 `--browser-trace-file` 内含实时凭据**（cookies、SID、SignKey、
   登录 POST body），文件权限 0600。**不得贴进任何报告、issue 或聊天记录。**
   诊断只贴 `--log-file` 的内容。

### E1 — 节点组原始形态与两个端点的来源 <a id="e1"></a>

**回答：** [D1](#d1)。`61.150.43.94` 与 `10.255.57.11` 在 `clientResource` 里各自长什么样，
谁是 major，Hermes 默认会选中哪一个。

```bash
# 1) CAS 登录并落盘会话（人工完成 IDS + 滑块 + 短信，然后关闭浏览器窗口）
./target/debug/atrust-probe --host atrust.xidian.edu.cn \
  --log-file /tmp/e1-login.log \
  cas-login --login-domain cas42187 \
  --session-file ~/.hermes/xidian-session.json

# 2) 保存资源体（服务端策略，不含凭据，可以离线反复分析）
./target/debug/atrust-probe --host atrust.xidian.edu.cn \
  client-resource --session-file ~/.hermes/xidian-session.json \
  --save-body /tmp/xidian-resource.json

# 3) 节点组原始形态
jq '.data.appList.data.config.nodeGroupConf' /tmp/xidian-resource.json

# 4) 实测排序：并行探测每个已广告端点，报告时延与最终选择
./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e1-nodes.log \
  node-probe --session-file ~/.hermes/xidian-session.json --timeout-seconds 10

grep -E "node_select.candidate|node_select.chosen" /tmp/e1-nodes.log
```

**要读出的四个事实：**

- `majorNodeGroup.id` 是哪个组；
- `nodeGroupList[].addressInfo[]` 里两个端点的 **原始 `address` 字符串**——
  是 IP 字面量、主机名，还是 `{{sdpcHost}}` 占位符；
- 两者的 **先后顺序**：`primary_nodes()` 取的是每组第一个，没有延迟评分。
  若 `10.255.57.11` 排在前面，则**不带 `--node` 的所有命令都会连到不可达地址**；
- 是否存在第三个此前没注意到的端点。

**若 `.94` 根本不在 `clientResource` 里**，那它的来源就只能是官方客户端下发或历史配置，
这本身是一条需要记录的新事实——意味着还有一条 Hermes 没走过的节点下发路径。
**此时 E3–E5 的 `--node 61.150.43.94:441` 会被 fail-closed 拒绝**（[D3](#d3)），
必须显式加 `--allow-unadvertised-node`，并把「用了逃生舱」记进实验记录。

### E2 — 资源表重叠量化（[C1](#c1)） <a id="e2"></a>

**纯离线，不碰网络，不需要会话。** 拿到 `/tmp/xidian-resource.json` 之后随时可做，
而且**应当在任何数据面实验之前做完**——否则后面每一次失败都要重新怀疑这一条。

```bash
# 单个目的地：看排名第一的 appId，以及所有被压下去的候选
./target/debug/atrust-probe --host atrust.xidian.edu.cn \
  resource-match --resource-file /tmp/xidian-resource.json \
  --target 202.117.112.1:80 --protocol tcp --show-all
```

`--show-all` 输出多于一条候选的目的地，就是 Hermes 的 specificity 排序与
zju-connect 的 first-match **可能分歧**的点。要统计的量：

- 有多少个目的地命中 **> 1** 条资源（重叠总数）；
- 其中**第一名与「原始顺序第一条」不同**的有多少个（真正分歧数）。

分歧数为 0 → [C1](#c1) 在西电这张表上不可达，后续 live 失败可以放心排除它。
分歧数 > 0 → 记下具体目的地，E3/E5 的 `--target` **必须避开**它们，否则实验结果不可解释。

### E3 — SignKey 是否真被校验（[B1](#b1)，**1 号闸门**） <a id="e3"></a>

**为什么排第一：** 它的答案决定后面所有失败往哪个方向查。如果西电硬校验 SignKey，
而 Hermes 用的是临时随机 key，那么 E4/E5 会全部失败，且症状会伪装成帧格式问题。

**做法：同一会话跑两次，只差一个十六进制字符。**

```bash
# 用 E2 的结果挑一个「无重叠」的授权目的地和它的 appId
TARGET=<ip>:80
APPID=<E2 输出的 app_id>

# A 组：正确的 SignKey
./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e3-good.log \
  tcp-dial --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 --target "$TARGET" --app-id "$APPID" --send-http

# B 组：翻掉 sign_key_hex 的第一个字符
jq '.sign_key_hex |= ((if .[0:1] == "0" then "1" else "0" end) + .[1:])' \
  ~/.hermes/xidian-session.json > ~/.hermes/xidian-session-badsig.json
chmod 600 ~/.hermes/xidian-session-badsig.json

./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e3-bad.log \
  tcp-dial --session-file ~/.hermes/xidian-session-badsig.json \
  --node 61.150.43.94:441 --target "$TARGET" --app-id "$APPID" --send-http
```

**判读表：**

| A 组 | B 组 | 结论 |
|---|---|---|
| 成功 | 失败 | **SignKey 被硬校验。** Hermes 的临时随机 key 模型不成立，必须先解决 SignKey 来源才谈 L3 |
| 成功 | 成功 | **未校验**（或首次写入即学习）。[B1](#b1) 降级为非阻塞项，可直接进 E4 |
| 失败 | 失败 | **不可判读。** 失败在更早的环节（会话过期、appId 不对、目的地未授权），先修这个再重跑，**不要**据此下任何 SignKey 结论 |
| 失败 | 成功 | 实验有误，检查是不是两次用错了文件 |

**跑完立即删除** `xidian-session-badsig.json`。

### E3b — L3 `0x13` 是否校验 HMAC（[B1](#b1) 的另一半） <a id="e3b"></a>

**为什么不能沿用 E3 的结论：** E3 测的是 TCP init 的签名，L3 flow auth 是另一段 JSON、
另一个签名覆盖范围，服务端可以只在一侧启用校验。E5 只有正样本，不具备区分力。

**判据选 `l3-session --auth-only` 而不是 `tcp-dial`：** 它在 2026-08-03 的 E9 里有一次
**同日正样本**（`202.117.112.71:8081` + `316772f0…` 返回了 connect token），一次往返约
1 秒，且把「鉴权」与「数据面」隔开，失败原因唯一。

```bash
# A 组：正确的 SignKey（正对照，应当返回 connect token）
./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e3b-good.log \
  l3-session --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 --target 202.117.112.71:8081 \
  --probe tcp-syn --auth-only --connect-timeout-seconds 20

# B 组：同一会话，只翻转 sign_key_hex 的首字符
python3 - <<'EOF'
import json, pathlib
p = pathlib.Path.home() / ".hermes/xidian-session.json"
d = json.loads(p.read_text())
k = d["sign_key_hex"]
d["sign_key_hex"] = ("1" if k[0] == "0" else "0") + k[1:]
out = p.with_name("xidian-session-badsig.json")
out.write_text(json.dumps(d)); out.chmod(0o600)
EOF

./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e3b-bad.log \
  l3-session --session-file ~/.hermes/xidian-session-badsig.json \
  --node 61.150.43.94:441 --target 202.117.112.71:8081 \
  --probe tcp-syn --auth-only --connect-timeout-seconds 20

rm -f ~/.hermes/xidian-session-badsig.json
grep -E "flow_authorized|flow_rejected|auth status" /tmp/e3b-good.log /tmp/e3b-bad.log
```

**判读表：**

| A 组 | B 组 | 结论 |
|---|---|---|
| 授权 | 拒绝 | **L3 硬校验 HMAC。** provisional key 模型在 L3 上不成立，SignKey 来源变成 L3 的阻塞项 |
| 授权 | 授权 | **L3 也不校验。** [B1](#b1) 整体降级为非阻塞，E5/E6 可以放心推进 |
| 拒绝 | 拒绝 | **不可判读**（会话过期 / appId 不再覆盖 / 节点不可达），先修再重跑 |
| 拒绝 | 授权 | 实验有误，检查是否用错了文件 |

**实测结果（L0，2026-08-04，会话保存于 10:40，三次运行均在 02:44–02:48 UTC 内）：**

| 组 | SignKey | flow key | 结果 |
|---|---|---|---|
| A | 正确 | `4:10.210.29.114:40000-202.117.112.71:8081` | 授权，`connect_token_len=32` |
| B | 首字符翻转（`0`→`1`，其余 63 字符相同） | 同 A | 授权，`connect_token_len=32` |
| C | 同 B | `…:40077-…`（新源端口） | 授权，`connect_token_len=32` |

**C 组是必须的。** A 与 B 用了完全相同的五元组，若服务端对该 flow 有缓存授权，
B 的成功就无法归因到「不校验」。换源端口后仍然授权，该解释被排除。

**判据具备区分力，不是「什么都放行」：** [E9](#e9) 已证明同一条 L3 auth 路径会拒绝——
无关 `appId` 立刻返回 `auth status 0x82`。所以这里的两次通过是真的通过。

**结论：成功/成功 → 西电 L3 不硬校验 HMAC。** 记入 [B1](#b1)。

**验证过的实现前提：** `restore_session` 走 `StoredSession::to_material()`，其中
`SignKey::from_hex(&self.sign_key_hex)` 直接取文件里的值——不会在恢复时重新生成
provisional key。若走的是 CAS/密码登录路径（`build_session_material`），key 是新随机的，
这个实验就不成立。

**两组必须在同一个会话里连续跑完。** 网关会话寿命实测 < 3.7 小时
（2026-08-03：15:16 保存的会话在 18:56 复用时返回 `75500002 / The session is invalid`），
中间隔一次重新登录就等于换了变量。

### E4 — VIP 帧真实布局（[A2](#a2)） <a id="e4"></a>

一次 TLS 连接的代价，不启动 L3 会话、不动 TUN／DNS／路由。

```bash
./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e4.log --browser-trace-file /tmp/e4-trace.jsonl \
  get-ip --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 --timeout-seconds 20

jq 'select(.event=="get_ip_succeeded")' /tmp/e4-trace.jsonl
```

**要读出的：**

- `address_type` —— 西电实际用 1 还是 5。若是 5，则 VIP 同时带 IPv6，
  [A7](#a7) 的 second-VIP 问题可能因此有解；
- `vip_data_hex` 的**字节数**：`addrType=1` 应为 **6**。若实际是 4 或 8，
  [A2](#a2) 的长度表就是错的，且这条连接后续必然错位；
- **IPv4 之后那 2 个字节的值** —— 这是 [A2](#a2) 唯一悬而未决的部分。
  若形如 `18 00`（24 = 掩码位数）就基本可以定性了；
- `status_bodies` —— `53 00` 消息的文本，[A5](#a5) 的唯一可观察样本。

`/tmp/e4-trace.jsonl` 含凭据，读完即删。

### E5 — `0x94` 真实分支、token 长度与端到端回环（[A1](#a1)） <a id="e5"></a>

**只有 E3 判定为「未校验」或 SignKey 问题已解决后才做。**

```bash
HERMES_LOG=debug ./target/debug/atrust-probe \
  --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e5.log \
  l3-session --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 \
  --target <E2 选定的目的地 IP>:0 \
  --probe icmp-echo \
  --connect-timeout-seconds 20 --reply-timeout-seconds 10
```

先跑 `--auth-only` 确认鉴权本身能过，再去掉它跑回环——把「鉴权失败」和「数据面失败」
分成两次可判读的实验，而不是一次混在一起。

**要 grep 的三行：**

```bash
grep -E "connect_token_len|connect_token_ambiguous" /tmp/e5.log   # A1 的前提是否成立
grep "data_resp" /tmp/e5.log                                       # layout= 是哪一支
grep "ignored_command" /tmp/e5.log                                 # A3/A4：出现未知命令就是新发现
```

**判读：**

- `connect_token_len` **≥ 17** → [A1](#a1) 的第一条不变量在西电成立，判据安全；
  **< 17** → 判据在西电**必然误判**，`0x94` 的双格式实现要立即重做（这正是新加的
  `connect_token_ambiguous` 告警存在的理由）；
- `layout=length_prefixed` 且 `bytes` 逼近 4096 → 第三条二义区间迫近，需要确认隧道 MTU；
- 出现 `ignored_command` → 记录 `cmd` 值，这是 [A3](#a3)/[A4](#a4) 的第一手证据。

### E9 — 服务端对 `appId` 的裁决（[C1](#c1) 的决定性实验） <a id="e9"></a>

E2 证明 specificity 与原始首条的分歧覆盖 60% 的 TCP 采样点。2026-08-03 分别在
TCP tunnel 和 L3 flow auth 上测试同一已知分歧目标的 specificity、原始首条与无关负对照。

以下命令是自动匹配改造前的历史实验记录。当时 `--app-id` 可覆盖 matcher；当前参数仅作为
自动匹配结果的断言，不一致会 fail-closed，因此不能再用它注入负对照。

```bash
# 从 E2 的分歧清单选择一个目标；实测时该端口已不再可连接
TARGET=202.117.112.71:8081

# A：Hermes 的选择（最窄条目）
./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e9-specific-debug.log \
  tcp-dial --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 --target "$TARGET" \
  --app-id 316772f0-c9a7-11f0-8b22-4f20181761d8 \
  --handshake-timeout-seconds 20

# B：原始顺序第一条（zju-connect L3 的选择）
./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e9-first-debug.log \
  tcp-dial --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 --target "$TARGET" \
  --app-id 27bf5f60-c9a7-11f0-8b22-4f20181761d8 \
  --handshake-timeout-seconds 20
```

**实测结果（L0，2026-08-03）：**

| 路径 | specificity `316772f0...` | 原始首条 `27bf5f60...` | 无关 `66238e10...` |
|---|---|---|---|
| TCP tunnel | 地址阶段通过，约 15 秒后目标连接 `0x03` | 地址阶段通过，约 15 秒后目标连接 `0x03` | 约 0.1 秒立即 `0x02` |
| L3 `tcp-syn --auth-only` | 返回 connect token | 返回 connect token | `auth status 0x82` |

TCP 的 `0x03` 出现在合法候选通过地址响应后、节点尝试连接目标约 15 秒之后；无关 appId 的
`0x02` 则立即返回，因此不能把两个合法候选的 `0x03` 读成 app 授权失败。默认 8 秒 handshake
timeout 会在 `0x03` 到达前先报超时，E9 必须使用至少 20 秒。两条路径共同证明：

1. 网关确实按目标、协议、端口与 `appId` 的关系做授权，无关 appId 会被拒绝；
2. 重叠时不强制唯一的 first-match 或 specificity，两个覆盖目标的候选都有效；
3. Hermes 可继续使用确定性的 specificity，不必为了西电兼容性改成 first-match；
4. 该样本所有候选同属一个 node group，尚未验证跨 node-group 重叠时的行为。

### 实验索引

| ID | 目标 | 依赖 | 需在校内 |
|---|---|---|---|
| [E1](#e1) | 节点组原始形态与两个端点来源（[D1](#d1)） | 人工 CAS 登录 | **否** |
| [E2](#e2) | 资源表重叠量化（[C1](#c1)） | E1 的 `--save-body` | **否**（纯离线） |
| [E3](#e3) | SignKey 是否真被校验，TCP 侧（[B1](#b1)，已完成） | E1、E2 | **否** |
| [E3b](#e3b) | SignKey 是否真被校验，L3 `0x13` 侧（[B1](#b1)，已完成） | 一个新鲜会话 | **否** |
| [E4](#e4) | VIP 帧真实布局（[A2](#a2)、[A5](#a5)） | E1 | **否** |
| [E5](#e5) | `0x94` 分支与 token 长度（[A1](#a1)、[A3](#a3)、[A4](#a4)） | E3 判定通过 | **否** |
| **[E9](#e9)** | **服务端是否按 `appId` 裁决（[C1](#c1)，已完成）** | E2 的分歧清单 | **否** |
| [E10](#a9) | Get-IP 帧头全集（[A9](#a9)，已执行，未触发） | 一个有效会话 | **否** |
| [E11](#e11) | 无人值守 SID 续期 | 一次人工 CAS/MFA bootstrap + 持久 browser profile | **否** |

**接 TUN 前还欠的三关：**

- **E6 — 大包 / MTU / token 分支。** E5 只证明了 44 字节；[A1](#a1) 的 `n > 4096` 区间和
  整个 token 分支**一次都没被触发过**。UDP 探针与 `--payload-bytes` 已实现，live 尚待一个
  资源表授权且会原样回显 datagram 的 UDP echo 目标；
- **E7 — 长会话存活。已定论（2026-08-06）：约 1 小时的关闭是数据空闲超时，heartbeat 不重置它，
  出向 `0x14` 可以。** 保活臂跑满 2.5 小时且保持后新流授权成功，同目标空闲对照臂约 61 分钟被关。
  剩余：空闲阈值仍在 (60 s, ~3600 s]，一次并发扫描尝试因 [B8](#b8) 整批作废；下一轮应改为
  单会话内递增间隔。入向已有首个样本（178 帧），但「入向单独能否续期」不可构造；
- **E8 — 并发多流。** 2 flow × 2 caller 的离线反序回包与西电 live 均已通过；

### E6 — UDP 大包、MTU 与 `0x94` 分支 <a id="e6"></a>

`--payload-bytes N` 中的 `N` 只计算 UDP application payload，不含 8 字节 UDP 头和 20 字节
IPv4 头；缺省为 32，合法范围 `0..=65507`，用于非 UDP 探针会直接报错。payload 是确定性字节序列，
回包必须满足反向地址/端口、IP/UDP 长度、checksum 和 payload 全部一致；UDP 超时、连接提前关闭、
畸形或内容不符都会让命令非零退出。因此该实验必须使用**受控 UDP echo**，不能拿 DNS 之类的普通
UDP 服务替代。

```bash
./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e6-1372.log \
  l3-session --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 --target <AUTHORIZED_ECHO_IP>:<PORT> \
  --probe udp --payload-bytes 1372 --src-port 40000 \
  --connect-timeout-seconds 20 --reply-timeout-seconds 10
```

第一档 `1372 + 8 + 20 = 1400`，正好覆盖计划中的 TUN MTU；随后从较小值逐步二分到路径上限。
`4068` payload 产生 4096 字节 IP 包，是 length-prefixed 判别的最后边界；`4069` 产生 4097 字节，
但远超 MTU 1400，且当前探针设置 DF，所以**不能把它当普通上行 echo 用例**。要触发大于 4096 的下行，
应让受控服务用一个小请求生成大响应；在实现 IP 分片重组前，分片回包同样不能判读为 framing 结论。
每档检查 `l3.data_layout_observed`、`packet_sent/received` 与退出状态，不得仅以「授权成功」判定 E6 成功。

**2026-08-04 live 预检：** 对资源表明确覆盖的 `202.117.112.9:53/udp` 使用
`--payload-bytes 1372 --auth-only`，VIP `10.210.29.114`，flow auth 成功并返回 32 字节
connect token。这只证明 UDP 路由、五元组和 `0x13` 授权路径可用；`auth-only` 没有发送 datagram，
因此不能据此声称 1400 MTU、echo 校验或 `0x94` 分支已通过。完整 E6 仍等受控 echo 目标。

### E7 — 长会话与 heartbeat 存活 <a id="e7"></a>

探针的判据不是「进程睡够了」，而是同一条 L3 session 在保持前后分别授权两个不同源端口的新流：
末次授权必须成功、`Arc<L3Session>` 与 VIP 必须不变、wire 上必须恰好新增两个 `0x13` verdict，且期间
不能 closed 或 timeout。`--status-interval-seconds` 周期记录 conntrack、drop 与授权计数。

先用 30 秒跨过一个默认 25 秒 heartbeat 做接线预检，再用 4 小时覆盖此前控制面 `<3h40` 的寿命观测：

```bash
# 接线预检
./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e7-30s.log \
  l3-session --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 --target 202.117.112.71:8081 \
  --probe tcp-syn --auth-only --src-port 41000 \
  --hold-seconds 30 --heartbeat-seconds 25 --status-interval-seconds 10 \
  --resource-refresh-seconds 3600 --connect-timeout-seconds 20

# 正式运行：保留 60 秒资源刷新，观察控制面和 L3 是否一起存活
# 将 --hold-seconds 改为 14400，--status-interval-seconds 改为 60，
# 并把 --resource-refresh-seconds 改为 60。
```

正式运行还应再做一次 `resource-refresh-seconds > hold-seconds` 的隔离对照，以区分资源刷新是否延长
控制面 SID。一次自动重连不能伪装成 PASS，因为最终 session pointer 必须与开始时相同。

**30 秒预检（L0，2026-08-04 06:53–06:54 UTC）：通过。** VIP `10.210.29.188`，保持前后
源端口 `41000/41001` 的两个新流都返回 verdict；same session=true、wire request=2、verdict=2、
timeout=0、drop=0。保持跨过一个 25 秒 heartbeat 后第二次授权仍成功。日志 `/tmp/e7-30s.log`。

**长跑结果（L0，2026-08-04 06:55–07:53 UTC）：57–58 分钟时被服务端断开。** 参数为
`hold=14400`、heartbeat=25 秒、resource refresh=20000 秒（长于 hold），源端口从 `43000`
开始。3420 秒采样仍是 `session_closed=false`，3480 秒采样首次变为 true，期间 auth in-flight=0、
drop=0；探针随即以 `E7 session closed during the hold` 非零退出，没有执行末次新流授权。
因此这不是「4 小时失败后的模糊结果」，而是**西电已建立 L3 连接寿命落在 57–58 分钟**的直接样本。
日志 `/tmp/e7-4h.log`。

历史调试日志已按文件修改日期归档到本地 `debug_logs/`，命名为 `日期-简述.log`；目录可能包含有效期内
会话信息，因此保持 git ignored，不进入版本库。上述两份 E7 日志分别归档为
`debug_logs/2026-08-04-e7-30s.log` 和 `debug_logs/2026-08-04-e7-4h.log`。

本组隔离了控制面刷新，尚不能判断断开是服务端 L3 绝对寿命、heartbeat ACK 容忍策略，还是控制面
SID 在连接内的联动失效。下一组应保持其它变量不变，只把 resource refresh 改为 60 秒；若仍在约
58 分钟断开，控制面续期解释基本可排除。heartbeat ACK 计数现已增加，可确认断开前是否先停止 ACK。

**已定论（L0，2026-08-06）：约一小时的寿命是「数据空闲超时」，不是绝对上限；
而且 heartbeat 不重置它。** 此前所有长跑都是 `--auth-only`，一个 `0x14` 都没发过，
两种解释无法区分。新增 `--data-keepalive-seconds`，在**已授权的同一条流**上周期发数据包
（`send_ipv4`，不产生额外 `0x13`，`auth_requests_sent` 全程为 1，因此不引入授权流量这个混杂）。
三条臂**串行**执行（同一 SID 上并发两条 L3 会话会引入「网关是否容忍并发会话」这个新变量）：

| 臂 | 目标 | keepalive | 结果 |
|---|---|---:|---|
| B 处理组 | `202.117.112.71:8081` | 60 s | **跑满 9000 s（2.5 h）**，`passed=true`、`same_session=true`、149 次 keepalive 零失败、heartbeat 360/360、drop 0，保持后新流授权成功 |
| A 对照组 | **同一目标** | 无 | **3600–3660 s（约 61 分钟）**被服务端关闭，`read_error`（对端不发 close_notify） |
| C 泛化 | `202.117.124.116:443`（不同 appId） | 60 s | **未取得结果**：启动 9 秒即 `75500002 The session is invalid`，是控制面 SID 过期，不是协议发现（见 [B7](#b7)） |

A 与 B **只差 keepalive 一个变量**（同目标、同 appId、同节点、同 node group、同一天前后相接），
所以这个对照是可判读的。A 的死法尤其关键：**关闭前最后一次 heartbeat 仍被 ACK（145/145），
服务端不是先停止 ACK 再关，而是直接关。** 因此 `0x15`/`0x95` 心跳**不是**这个计时器的 keepalive。

历史样本 57–58 分钟（08-04，隔离刷新）、约 54 分钟（08-04，刷新 60 s）与本次约 61 分钟一致，
都聚在 55–61 分钟。

**两个尚未收窄的点：**

- 阈值本身未二分。只知道 60 秒间隔足以维持、完全不发足以在约 1 小时被关；真实空闲窗口在
  (60 s, ~3600 s] 之间的什么位置未测；
- B 全程 `session.data_resp` 计数为 **0**——keepalive 是 TCP SYN，目标没有回包。
  因此本实验只证明**出向 `0x14` 足以重置计时器**，入向数据是否也能、或是否必需，无依据。

**阈值扫描尝试失败（2026-08-06 下午）：整批作废，原因是 [B8](#b8)，不是阈值。**
六路并发臂（60 / 0 / 300 / 900 / 1800 秒间隔）里五条在建立后一分钟内全部死亡，与间隔无关。
**守卫臂是唯一让这批数据被判为无效而不是被误读的东西**：60 秒间隔上午刚串行跑满 2.5 小时，
它在并发环境下同样死亡，直接指向并发本身。六条会话拿到同一个 VIP，符合 [B8](#b8) 的
「一设备一会话、后建者胜」。阈值仍停在 (60 s, ~3600 s]。

**唯一有效的一条臂（最后建立、因而等价于串行）给出了入向的首个样本：**
目标 `202.117.112.70:443`（`gsoft.xidian.edu.cn` 的地址，L3 授权，appId `2f206920`），
`--hold-seconds 5400`：

```
probe.e7.result passed=true hold_seconds=5400 same_session=true vip=10.210.29.47
  heartbeat_requests_sent=216 heartbeat_acks_received=216 auth_timeouts=0 tracked_flows=2
71 次 keepalive 零失败，session.data_resp 178 帧（全部 length_prefixed，40 字节）
protocol_messages_seen=0
```

**这是第一个已知在 L3 上真会应答的目标**——此前 `202.117.112.71:8081` 的 SYN 从来没有回包，
无法区分「端口关着」和「L3 根本不回传」。现在可以确定是前者。

但**它仍然不能回答「入向单独能否续期」**：这条臂出向入向都有。而那个问题恐怕不可构造——
任何入向都要由出向触发，除非目标会主动推数据。有实践意义的版本（一条跑着双向真实流量的会话
会不会被空闲断开）已经答了：**不会**，1.5 小时保持后新流授权仍成功。

**接 TUN 的直接后果：** 一条空闲的 VPN 会在约 1 小时后被静默断开，且心跳看起来一切正常。
`L3SessionManager` 的重连路径已验证可用（2026-08-05 强制重连 `passed=true`、98 ms、VIP 不变），
所以这不是阻塞项；但「靠 heartbeat 就能保活」是错的，不能作为设计前提。

**2026-08-04 诊断增强：** session 现在分别记录成功 write+flush 的 heartbeat 数、收到的 `0x95` ACK
数、最后 ACK 的墙钟时间与单调 age。关闭时首个原因按 `peer_eof`、`read_error`、`write_error`、
`flush_error`、`framing_error` 等稳定类别保留，同时保存详情和关闭时间，后续 caller shutdown 不再覆盖
真正原因。E7 每个 sample 及 trace 都包含这些字段。

`--reconnect-after-close` 保持原 E7 默认判据不变，但在观测到原 session 关闭后，通过正常 manager 路径
建立新 session，按新 VIP 重建源端口 `+1` 的 packet 并授权；只有 session pointer 已替换、新连接未关闭、
新授权恰好产生一个 request/verdict 且无 timeout 才通过。固定 lease 与自动重连可用同一次 70 分钟运行验证：

```bash
./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e7-lease-refresh60-reconnect.log \
  l3-session --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 --target 202.117.112.71:8081 \
  --probe tcp-syn --auth-only --src-port 45000 \
  --hold-seconds 4200 --heartbeat-seconds 25 --status-interval-seconds 10 \
  --resource-refresh-seconds 60 --connect-timeout-seconds 20 \
  --reconnect-after-close
```

若 ACK 一直增长且最后 ACK age 在断开前仍接近 25 秒，同时 refresh=60 的连接仍在约 57–58 分钟收到
`peer_eof`，则固定 L3 lease 的解释得到强支持。2026-08-04 的新指标 live 预检被控制面在建连前以
`75500002 / The session is invalid` 拒绝，未产生 L3 样本；日志归档为
`debug_logs/2026-08-04-e7-heartbeat-metrics-session-invalid.log`，需新鲜 CAS 会话后复跑上述命令。

**refresh=60 + ACK + 重连结果（L0，2026-08-04 09:56–10:50 UTC）：原连接关闭，重连失败。**
原 session 在 elapsed=3240 秒仍健康，3250 秒采样首次 closed；关闭类别为 `read_error`，详情是 peer
未发送 TLS `close_notify` 的 unexpected EOF。断开前 heartbeat sent=129、ACK=129，没有未应答心跳；
最后 ACK 在关闭采样前约 25.6 秒返回。资源 generation 44 在关闭前约 17 秒仍刷新成功，drop=0、auth
in-flight=0，因此 heartbeat 丢失、资源刷新停止、本地拥塞和 systemd 终止均可排除。manager 随即尝试
新 Get-IP，但 peer 直接 `early eof`，所以本次进程 FAIL 的直接原因是新 session 无法建立，而不是原
session 的关闭原因未识别。

本次 L3 连接自身约存活 54 分 10 秒，低于上一样本的 57–58 分钟；但按 CAS 会话文件保存时间对齐，
两次从保存到断开分别约为 62 分 43 秒和 63 分 30 秒。连接寿命随“登录后多久才开始 E7”而变化，
登录到断开的绝对时间却都接近 63 分钟。这组证据反对“Get-IP 后固定 L3 lease”，更支持认证/SID 派生的
约一小时绝对到期；周期 `clientResource` 成功不续期该数据面授权。到期后用同一 SID 自动重连预计无法
成功，因此固定寿命和 manager 重连不能再合并为一个 PASS：下一次应在新鲜会话建立后主动关闭 L3，
单独验证 SID 有效期内的自动重连；认证到期则需要上层重新登录并替换 runtime session material。

完整日志：`debug_logs/2026-08-04-e7-lease-refresh60-reconnect.log`。

**新鲜 SID 主动断线重连（L0，2026-08-05 02:30 UTC）：通过。** 为避免再次把认证到期和重连能力
混在一起，E7 新增 `--force-reconnect-after-seconds`，仅与 `--reconnect-after-close` 配合使用。该模式
在指定时间调用 runtime 的正常 reconnect 控制路径，保留原 session 统计，再要求 manager 建立不同
`Arc<L3Session>`、按新 VIP 重建 packet 并授权一个新源端口流：

```bash
HERMES_LOG=info ./target/debug/atrust-probe \
  --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e7-fresh-forced-reconnect.log \
  l3-session --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 --target 202.117.112.71:8081 \
  --probe tcp-syn --auth-only --src-port 46000 \
  --hold-seconds 90 --heartbeat-seconds 25 --status-interval-seconds 10 \
  --resource-refresh-seconds 60 --connect-timeout-seconds 20 \
  --reconnect-after-close --force-reconnect-after-seconds 30
```

原 session 在 30 秒时以 `caller` 原因关闭，关闭前 heartbeat sent=1、ACK=1、drop=0；原 VIP 为
`10.210.29.66`。manager 在约 98 ms 内完成新 Get-IP，session pointer 确认已替换，新 VIP 仍为
`10.210.29.66`，因此没有 `L3VipChanged` 事件。新 Get-IP status 仍为 code=0/OK，源端口 `46001`
的新流在 replacement session 上产生且仅产生一个 wire request、一个 verdict、零 timeout。由关闭到
新流授权完成约 124 ms。这证明 SID 有效期内的主动断线、惰性重建、VIP 复核和新流授权链路正常；
此前自然到期后的 early EOF 应归因于凭证生命周期，而不是通用 L3 重连故障。

日志：`debug_logs/2026-08-05-e7-fresh-forced-reconnect.log`。

### E8 — 并发多流与同流去重 <a id="e8"></a>

最小矩阵为两个不同源端口（两个 flow），每个 flow 同时两个 caller。四个任务由同一个 barrier 释放；
PASS 要求四个 caller 全成功，但 wire `0x13` 恰好只有两个、两个 verdict、零 timeout、峰值在途授权至少
为二、conntrack 恰好增加两项，且所有结果仍属于开始时的 session。这同时验证「不同流可并发」和
「同流 caller 只发一次鉴权」，不会用上千请求在 live 环境测试容量上限。

```bash
./target/debug/atrust-probe --host atrust.xidian.edu.cn --insecure-tls \
  --log-file /tmp/e8.log \
  l3-session --session-file ~/.hermes/xidian-session.json \
  --node 61.150.43.94:441 --target 202.117.112.71:8081 \
  --probe tcp-syn --auth-only --src-port 42000 \
  --concurrent-flows 2 --callers-per-flow 2 \
  --experiment-timeout-seconds 15 --resource-refresh-seconds 3600 \
  --connect-timeout-seconds 20
```

**离线结果（2026-08-04）：** mock peer 等两个不同 `0x13` 都到达后才按反序返回 verdict；四个 caller
全部拿到正确结果，wire request=2、peak in-flight=2、conntrack=2。它证明客户端并发和 auth-id/waiter
关联正确，但服务端 live 仍需上述命令证实。

**live 尝试（2026-08-04 06:34 UTC）：不可判读。** 保存会话在 L3 建连前即返回
`75500002 / The session is invalid`，所以没有发出任何 `0x13`。需要新鲜 CAS 会话后连续跑 E8 和
E7 30 秒预检；日志保存在 `/tmp/e8.log`。这次失败只增加了一条控制面寿命观测，不能算 E8 失败。

**live 结果（L0，2026-08-04 06:51–06:52 UTC，新鲜会话）：通过。** VIP `10.210.29.188`，
flow 为源端口 `42000/42001` 到 `202.117.112.71:8081`；4/4 caller 成功，wire request=2、
verdict=2、timeout=0、peak in-flight=2、conntrack=2、same session=true，两条 connect token
长度均为 32。服务端返回顺序是 `42001` 后 `42000`，未造成 auth-id/waiter 串线。日志
`/tmp/e8-fresh.log`。**E8 的最小 live 判据已完成。** 容量上限和驱逐继续只做离线测试，不对
真实网关制造 8192-flow 压力。

**关于 `10.255.57.11`：它外网不可达是预期的，不构成阻塞。** 它是内网侧地址，
真正的问题不是「能不能直连它」，而是「Hermes 会不会默认选中它」——由 [E1](#e1) 回答。
只有当它被服务端标为 major 且排在前面时，才需要在配置层加显式的端点优选。
它作为**隧道内目的地**的可达性是另一回事，属于 E5 之后的验证。

### E11 — 无人值守 SID 续期 <a id="e11"></a>

**目标不是无人值守首次登录。** 第一次 CAS / IDS / 滑块 / SMS 仍由人完成；本实验只回答：
在已经完成一次 MFA 后，能否在不再发生任何人工交互的前提下，于旧 SID 到期前取得一份能跨过
旧到期点的新会话材料。

现有 [B7](#b7) 已排除「普通控制面或数据面活动自然续期」：`clientResource`、L3 heartbeat 和
真实数据流持续存在时，旧 SID 仍在约 3 小时 48 分失效。`ResourceCache` 目前只能发出
`SessionInvalidated` 并停止刷新，`AtrustClient` 的 `SessionMaterial` / SID 也不能在启动后替换。
因此顺序必须是：**先证明网关存在可用的无人值守续期原语，再设计运行时热切换**；不能先实现一套
没有服务端依据的自动重登状态机。

#### 待证伪模型

| 模型 | 操作 | 可观察结果 |
|---|---|---|
| R0：无续期能力 | 只做既有 `onlineInfo` / `clientResource` | 约 3.7 小时后旧 SID 失效；已有三批历史样本，可作基线 |
| R1：控制面调用续期 | 定期单独调用一个候选接口 | SID 不变但能稳定跨过历史到期点，或 cookie jar 出现新 SID |
| R2：CAS SSO 静默换票 | 复用首次 MFA 后仍存活的同一浏览器 profile，重新打开一个全新的 CAS challenge | 不出现 IDS/MFA 交互页，自动回到 aTrust portal，并取得新 gateway cookie/SID |
| R3：必须重新交互 | 同 R2 | 浏览器停在 IDS、滑块、SMS 或 `InteractionRequired`；当前部署无法无人值守续期 |

R1 的候选必须**每次新登录只测一个**，不能把多个调用绑在同一臂里，否则即使成功也无法归因：

1. `authConfig(modified=true, needTicket=false)`；它在过期 SID 下仍可能返回结构，因此只有后续
   `onlineInfo` / `clientResource` 跨过历史到期点才算成功；
2. `authCheck`；它可能推进认证状态，风险高于只读接口，只在第 1 项阴性后测试；
3. `reportEnv` 不列入 R1：它需要 portal ticket，而 ticket 已知单次使用，实际属于 R2 换票路径。

R2 是主实验，因为它同时保留两层可能的 SSO 状态：学校 IDS 浏览器 cookie 与 aTrust portal cookie。
实验探针必须区分「同一个仍存活的浏览器进程」与「关闭浏览器后只复用磁盘 profile」；后者不会自动
恢复所有 session cookie。两种生命周期不能合并成一个结论。

#### 主实验时间线

1. **T0 人工 bootstrap：** 使用专用持久 browser profile 完成一次 CAS + MFA；保存旧会话 `S0`，记录
   SID 和 cookie 集合的 SHA-256 指纹、DeviceID、ConnectionID、建立时间，只在 `0600` 会话文件中保存原值；
2. **T0 + 1h 静默续期：** 在同一 browser profile 中请求**新生成的** CAS challenge，全程不点击、
   不输入、不关闭窗口。最多等待 5 分钟；进入任何 IDS/MFA 页面即记为 `interaction_required` 并停止；
3. **隔离验证：** 将收割结果写为独立的 `S1.tmp`，不得覆盖 `S0`。使用独立 HTTP cookie jar 依次验证
   `authConfig`、`onlineInfo`、`clientResource`；全部通过后才原子落盘为 `S1`；
4. **数据面验证：** 保证此刻没有另一条 L3 会话，使用 `S1` 做一次 Get-IP 和一次 `--auth-only` flow；
   验证后立即关闭，不做并行长跑；
5. **跨旧到期点验证：** 先立即检查新会话是否使 `S0` 失效；否则从 T0 + 2h 起每 5 分钟验证 `S0`，
   最晚观察到 T0 + 4h15m。发现 `S0` 返回已知 session-invalid 后，立即验证 `S1` 的 `onlineInfo`、
   `clientResource`、Get-IP 和单次 flow auth。只有 `S0` 失败且 `S1` 成功才是决定性 PASS；
6. **续期可重复性：** 第一次 PASS 后再用同一方法从 `S1` 生成 `S2`。只成功一次不能证明能长期运行。

#### 判读矩阵

| 浏览器结果 | SID 指纹 | 跨 T0 + 4h | 结论 |
|---|---|---|---|
| 无交互完成 | 新 SID | S0 失败、S1 成功 | **R2 成立；具备实现无人值守续期与热切换的前提** |
| 无交互完成 | SID 不变 | S1 成功 | 可能是服务端延长同一 SID；再做一轮并记录新的到期边界后才能定论 |
| 无交互完成 | 任意 | S0/S1 同时失败 | 收割到的只是旧会话或无效 portal 状态，不构成续期 |
| 进入 IDS/MFA | 任意 | — | 该时间点和浏览器生命周期下需要交互；只有同进程短窗口与持久 profile 两路都失败，才支持 **R3** |
| 无交互完成 | 新 SID | 旧 SID 立即失效、S1 成功 | 后建会话替换旧会话；续期可用，但产品切换必须先建新 runtime 再停旧 runtime |

#### 实验纪律与停止条件

- 不并发启动 L3 会话；[B8](#b8) 已证明同设备后建者会顶掉前者。控制面验证也使用隔离 cookie jar，
  防止新旧 cookie 在同一 jar 中合并后失去归因；
- 不重放旧 portal ticket 或 service ticket。每次续期必须从新 CAS challenge 开始；
- `S0`、`S1` 和 browser trace 均视为实时凭据，文件权限固定 `0600`；browser profile 使用独立的
  `0700` 目录。实验结束后全部删除；普通摘要只记录指纹前 12 位、cookie 名称、时间、状态码和业务码，
  不记录值；
- 不改变现有日志内容或级别。本实验需要的新判据写入单独的 `0600` 结构化摘要；
- 遇到 `InteractionRequired`、会话业务拒绝或连续两次传输失败立即停止，不自动循环 CAS/MFA，避免锁号；
- 首轮只验证续期原语，不修改 `AtrustClient`。R2 连续两轮 PASS 后，下一阶段才设计
  `SessionMaterial` 原子替换、ResourceCache 重建、旧 L3 manager 排空及 VIP 变化通知。

**当前运行臂（2026-08-07）：R1 `authConfig`。** 凭证已由外部刷新，因此不再启动浏览器或尝试 CAS
换票。用户级 `hermes-e11-renewal.service` 只读 `~/.hermes/xidian-session.json`，在同一进程和 cookie
jar 中执行 `authConfig(modified=true)`，保持到会话文件年龄至少 4 小时 15 分后验证 `onlineInfo`、
`clientResource` 和 SID-only Get-IP。它不会创建、更新或覆盖任何会话文件。服务首次启动后发现外部
会话刚被再次更新，固定 5400 秒不足以跨过历史边界，因而在约 5 分钟内停止并按动态截止时间重启；
最终结果对应**两次同类 `authConfig` 调用**，不是严格单调用。跨过旧会话预计失效点仍成功才支持 R1；
失败必须同时检查「距候选调用的时间」，不能仅按会话文件总年龄否定候选。

**本轮结果（2026-08-07 18:37）：失败，但不可判定 R1。** 外部会话保存于 14:22:03；第二次
`authConfig` 在 14:40:24 返回 `LoggedIn`，随后的 `onlineInfo` 和 `clientResource` 都成功。最终检查在
18:37:42（会话文件年龄 15339 秒）执行，第一个 `onlineInfo` 即返回
`75500002 / The session is invalid`，因此没有继续到最终 `clientResource` 和 Get-IP；服务按预期以
状态 1 退出，凭证文件 mtime 和指纹未变化。

这次失败**不能证明 `authConfig` 不续期**：最终检查距候选调用约 3 小时 57 分，已经长于历史约
3 小时 48 分 TTL。即使候选在 14:40 重置了一次同长度 TTL，也可能在约 18:28 再次过期，而本轮直到
18:37 才检查。正确的下一臂应在会话年龄约 2 小时时调用候选、约 4 小时时验证：届时未续期模型已经
过期，而重置 TTL 模型中的候选年龄只有约 2 小时，两者有足够判读间隔。现有 runner 的“启动即调用、
等待到固定总年龄”时间模型不得直接复用。

**下一臂（17 小时、无人干预）的固定时间线：** 服务只接受 mtime 不超过 15 分钟的外部会话；启动时
为取得 CSRF 所需的 `authConfig` 只记为 candidate 0，不参与归因。之后所有检查点都严格执行“先用
上一轮 configuration 验证，再调用下一轮 candidate”，禁止先续期再验证：

| 会话启动后 | 操作 | 判读作用 |
|---:|---|---|
| 2:00 | candidate 1：`authConfig` + 即时 `onlineInfo` | 第一条可归因候选 |
| 4:00 | 验证 candidate 1；通过后 candidate 2 | 未续期模型应已过期；重置模型仅经过约 2 小时 |
| 7:15 | 验证 candidate 2；通过后 candidate 3 | 第一次接近 TTL 的重复续期 |
| 10:30 | 验证 candidate 3；通过后 candidate 4 | 第二次重复续期 |
| 13:45 | 验证 candidate 4；通过后 candidate 5 | 第三次重复续期 |
| 17:00 | 验证 candidate 5；最终 Get-IP | 第四次重复续期与数据面 SID 证明 |

每个验证点依次执行 `onlineInfo` 和 `clientResource`；非 session-invalid 的传输错误最多重试三次、间隔
30 秒，明确 session-invalid 立即失败。最终 Get-IP 同样最多尝试三次。服务通过 `systemd-inhibit` 阻止
系统睡眠，避免 monotonic timer 暂停而真实 SID 继续老化；会话文件始终只读。总预算 61200 秒（17 小时）
加少量网络请求时间，低于 20 小时限制。若 4 小时检查即失败，可以直接否定本部署当前配置下的 R1；
若 17 小时全部通过，则同时证明续期存在且至少可重复四轮。

**17 小时臂实际结果（2026-08-09）：在 candidate 1 处提前结束。** 外部会话文件保存于 11:52:33，
服务在 11:53:45 启动（会话文件年龄 72 秒）；candidate 0、即时 `onlineInfo` 和 1,324,933 字节
`clientResource` 均成功。13:54:10 到达计划中的 2 小时候，candidate 1 的 `authConfig` 请求本身返回，
但紧接的 `onlineInfo` 立即得到 `75500002 / The session is invalid`。服务在 elapsed=7225 秒、
会话文件年龄 7297 秒时以状态 1 退出，后续 4/7.25/10.5/13.75/17 小时检查均未执行；凭证文件未改变。

这说明本次样本的可用窗口只有约 2 小时，明显短于此前约 3.7 小时样本，而且再次确认
`authConfig` 即使在已过期状态下能返回结构，也**不能复活**会话。但 candidate 1 到达时会话已经失效，
所以本轮仍未测试到“过期前调用能否续期”。下一臂必须把第一条可归因候选提前到 1 小时，并在会话
总年龄约 2 小时 15 分先验证：未续期模型应已过期，而重置 2 小时 TTL 的模型中候选仅老化约 1 小时
15 分。后续重复周期也应缩到不超过 1 小时 30 分，不能再沿用 3 小时 15 分间隔。

**R2 runner（2026-08-10）：** `scripts/e11-r2-bootstrap.sh` 用全新 `0700` Chrome profile 完成唯一一次
人工登录并写出只读基线 `S0.json`。随后 `hermes-e11-r2.service` 在 S0 年龄 1 小时时发起静默 CAS，
先将候选写到 `S1.json.tmp`；控制面、Get-IP 和单次 flow auth 全部通过后才原子提交为 `S1.json`。
runner 不合并两份 cookie jar、不覆盖 S0，并通过 `systemd-inhibit` 保持墙钟与 monotonic 时间线一致。
外部 IDS 页面稳定停留 10 秒即归类为 `interaction_required`；未识别的 aTrust 交互页仍由 5 分钟总超时兜底。

#### R2 首轮结果：T+1h 的磁盘 profile 不足（2026-08-10）

T0 人工 bootstrap 于 10:45 完成。S0 基线的 `authConfig`、`onlineInfo`、1.32 MB `clientResource`、
Get-IP 和单次 L3 flow auth 全部通过；VIP 为 `10.210.29.217`，connect token 为 32 字节。T+1h
runner 正常创建新 CAS challenge，但浏览器随后停在 `https://ids.xidian.edu.cn/authserver/login`；稳定
10 秒后按设计以 `interaction_required`（退出码 2）停止。没有生成 `S1.json.tmp` 或 `S1.json`，S0
也没有被覆盖。事后在 S0 年龄约 3 小时 29 分时只读检查，`authConfig=LoggedOut`，`onlineInfo` 返回
`75500002 / The session is invalid`。

**可判定边界：** 本轮只否定「关闭 bootstrap Chrome，T+1h 仅复用同一磁盘 user-data-dir」这条路径，
不能据此宣布 R3。关闭浏览器后，profile 内没有继续保留 aTrust SID；IDS 只剩长期的 MFA browser
fingerprint、locale，以及一枚从 T0 起约 10 分钟过期的不透明 cookie。也就是说 profile 持久化本身
工作正常，但它没有保留一个能跨到 T+1h 的登录会话。尚未测试的是：

1. 同一个 Chrome/WebDriver 进程一直存活时，session cookie 能否支持静默换票；
2. 那枚约 10 分钟 cookie 尚未过期时，新 CAS challenge 能否刷新它或取得新 SID；
3. 官方客户端是否根本不走我们当前选择的 CAS URL，而是通过 portal 的本地 IPC 和另一条换票接口。

因此当前产品结论不是「只能运行约 3 小时且绝无续期机制」，而是「普通 API 活动不续期，T+1h
重启浏览器的 CAS 路径也不续期；官方客户端使用的续期/接管原语仍未定位」。

#### 路线 A：捕获 portal 唤醒官方客户端的本地 IPC

bootstrap trace 已经给出第一条直接证据。portal 在登录完成后分四轮向六个本地 HTTPS endpoint 发送
`POST /v1/detect`，本机未运行官方客户端，所以全部 connection refused：

| host | ports |
|---|---|
| `127.0.0.1` | `54630`, `54641`, `54652` |
| `localhost.sangfor.com.cn`（当前解析到 loopback） | `54631`, `54642`, `54653` |

同一轮加载了 `detect_client.*.js`、`client.*.js`、`utils_ipc.*.js`、`download_client_pc.*.js`、
`shortcut_api.js` 和 `shortcut_main.js`。对 portal JS 的静态检查进一步给出以下**推断路径**，但本轮
因 `/v1/detect` 未成功，尚未在 wire 上观察到后四步：

```text
portal -> POST https://<loopback>/v1/detect                 # 已观察
       -> /v1/service/init|status                           # JS 中存在
       -> gateway /passport/v1/public/ticketExchange        # JS 中存在
       -> POST /v1/service/start                             # 可能携带会话材料
       -> WSS /v1/service/events                            # JS 中存在
```

这比“猜一个自定义 URL scheme”更具体：当前没有发现桌面端 custom scheme，现有证据支持浏览器直接访问
本地 HTTPS/WSS agent。下一实验实现一个只绑定 loopback 的分阶段 listener，每一阶段单独运行：

1. **TCP-only：** 六端口 accept 后立即关闭，只记录端口、次数、时序和 TLS ClientHello 的 SNI/ALPN；
2. **TLS + 失败响应：** 使用仅供实验 profile 信任的临时 CA，固定返回 404/失败 JSON，只记录 method、
   去 query 的 path、长度和 digest；
3. **单端口 detect-success：** 每次只让一个 endpoint 返回从 JS 推导的最小成功结构，观察下一请求究竟是
   `init`、`status`、`start` 还是 WSS；
4. **WSS 能力：** 只完成 upgrade，记录 opcode/长度，不解释 payload；
5. **受控完整序列：** 只有前四步明确后才允许推进到 `service/start`。该请求可能含实时 ticket、SID 或
   设备材料，只能在内存中提取 JSON key/type，禁止落原始 body。

listener 必须拒绝非 loopback peer，不记录 Cookie、Authorization、query value、header value、POST 原文
或 WebSocket payload。没有官方客户端对照并不妨碍前两步；从 detect-success 开始属于主动模拟，必须把
「portal 实际发出」与「listener 伪造响应诱导出的后续行为」分别标记。

#### 路线 B：T+5m 短窗口换票

约 10 分钟的 IDS cookie 给出了可证伪窗口。第一臂不再关闭浏览器：T0 人工完成 CAS/MFA 后保持同一
Chrome 与 WebDriver session，在 T+5m 请求一个由当时 `authConfig(needTicket=true)` 新生成的 challenge；
全程不点击、不输入。现有 bootstrap/runner 是两个进程且会关闭 Chrome，不能直接复用，需先增加一个
单进程状态机。

判据保持与 R2 一致：新 challenge 自动回 portal 后，候选只写 `S1.tmp`；`onlineInfo`、
`clientResource`、Get-IP 和单次 flow auth 全通过才提交 S1。记录 IDS 短 cookie 的到期时间是否被刷新、
SID 是否变化，以及 S0 是否立即失效。若 T+5m 已停在 IDS/MFA，说明即使同进程短窗口也不能静默 CAS，
R3 得到强支持。

第二臂必须换一个登录日，只测试「T0 关闭 Chrome、T+5m 重开同一 profile」，用来区分 session cookie
与约 10 分钟持久 cookie 的作用。两臂不能在同一次登录中先后执行，否则第一条新 challenge 会改变
第二臂的状态。第一次成功只证明单次换票；随后再单独设计每 5 分钟连续两轮 S0 -> S1 -> S2，判断
短 cookie 是否会被每轮刷新。若短窗口 CAS 仍失败，路线 A 的 `/ticketExchange + service/start` 将成为
更可能的官方续期入口，也能回答“当前换票 URL 是否选错”。

**第一臂实现（2026-08-10）：** `atrust-probe e11-r2-short-window` 在一个进程和一个 WebDriver session
内执行两次 challenge。第一次允许人工完成 IDS/MFA，观察到 portal + SID 后自动收割 S0，但不关闭
Chrome；从 S0 验证完成时起等待 300 秒。第二次使用一个全新的 `ReqwestTransport`（空 HTTP cookie jar）
调用当时的 `authConfig(needTicket=true)`，确保 challenge 不是从 S0 控制面 jar 复用出来；随后让同一个
Chrome 导航到新 URL，进入该阶段后禁止任何点击或输入。

`scripts/e11-r2-5m-same-browser.sh` 负责完整判据：检测 S0 文件出现后，在浏览器仍保持期间串行验证
`onlineInfo`、`clientResource`、Get-IP 和一次 flow auth；第二次浏览器收割只写 `S1.json.tmp`，同样
全部验证后才改名为 `S1.json`。之后立即检查 S0，若仍有效则从 T0+2h 起每 5 分钟检查，直到 S0
session-invalid 后再次完整验证 S1。服务单元为 `scripts/hermes-e11-r2-5m.service`，通过
`systemd-inhibit` 同时保持浏览器进程和实验时间线。

操作纪律与上一轮不同：人工完成首次登录并进入 portal 后，**不要关闭 Chrome，不要点击 portal，
也不要手动触发第二次登录**。runner 会自动完成后续动作。独立运行目录为 `~/.hermes/e11-r2-5m/`；
为避免跨登录日混合状态，目录已存在时脚本会 fail-closed，绝不覆盖旧 S0、S1、profile 或 trace。

**第一臂首次启动结果：探针过早收割，不是 WebDriver 端口故障。** ChromeDriver 在指定的 `9518`
正常创建 session，人工 CAS 已经过 IDS callback 到达第一次 `portal/shortcut.html`，并观察到 10 个 gateway
cookie；但 `complete_cas_after_interaction` 把「第一次 portal + SID」错误当成最终完成，`portal_hits=0`
即返回。紧接的 `onlineInfo` 得到 `75500002`，所以没有写出 S0，runner 以
`bootstrap_or_S0_creation_failed` 停止。这次没有进入 T+5m，不能作为短窗口换票结果。由于下一实验改走
纯 HTTP，该 WebDriver 状态机缺陷暂不继续修复。

#### 路线 C：只依赖初次 gateway 凭证的无头双向换票

portal JS 暴露了两个方向相反的接口：

```text
已登录 gateway session
  -> POST /passport/v1/public/ticketExchange      body={}
  <- data.sidTicket

本地客户端提供的 sidTicket
  -> POST /passport/v1/public/sessionIdExchange   body={sidTicket}
  <- gateway session cookies（假设，待 live 验证）
```

静态契约确认 `ticketExchange` 不接收 local detect 结果或 portal ticket；它只依赖现有 gateway cookie、
`authConfig` 提供的 CSRF，以及公共 query/header。官方流程把返回的 `sidTicket` 立即交给本地
`/v1/service/start`；反方向的 `sessionIdExchange` 通常接收本地 `/v1/service/init` 返回的 ticket。因此把
两个 gateway API 直接串联**不是已知官方流程**，而是一个成本低、可明确证伪的无头候选：若同一
`sidTicket` 可直接换回新 gateway session，就找到了不需要浏览器和本地 agent 的续签原语；若第二步拒绝，
最可能说明 ticket 必须先经官方客户端消费或转换，不能据此否定路线 A。

`atrust-probe e11-headless-ticket-exchange` 和 `scripts/e11-headless-ticket-renewal.sh` 实现该候选：

1. 外部先生成 mtime 不超过 15 分钟的 `~/.hermes/xidian-session.json`；实验自身不启动 Chrome、
   ChromeDriver、WebDriver，也不读取 browser profile/trace；
2. runner 把源文件冻结为独立只读 S0，并完成控制面、Get-IP 和 flow auth 基线；
3. S0 年龄 5 分钟时，用 S0 jar 调一次 `ticketExchange`。`sidTicket` 只保存在进程内存，日志只记录存在性
   和长度，不落盘、不打印值或 digest；
4. 立即创建全新空 cookie jar，先取 CSRF，再用内存 ticket 调一次 `sessionIdExchange`；
5. 新 jar 的 `authConfig`、`onlineInfo`、`clientResource` 全通过才写 `S1.json.tmp`，数据面通过后才提交
   S1；之后仍要求 S0 失效而 S1 有效，才能最终 PASS。

判读分三层：`ticketExchange` 本身失败，说明保存的 gateway session 不能独立调用该原语；ticket 已取得但
`sessionIdExchange` 拒绝，说明直接闭环不成立、很可能缺本地客户端转换；S1 立即成立但不能跨 S0 到期点，
只说明一次 exchange 可登录，不证明续期。只有跨旧到期点的完整 S1 才支持产品实现。

**首次无头结果与恢复监测（2026-08-11）：** S0 年龄 5 分钟时 `ticketExchange` 成功返回 73 字节
`sidTicket`，同一 ticket 被全新空 jar 的 `sessionIdExchange` 接受。S1 的 `onlineInfo`、
`clientResource`、Get-IP 和 flow auth 全部通过并原子保存；SID 未变化，cookie 集合从 10 项变为 7 项。
意外关机发生在等待 S0 到期阶段，当时只确认 S0 在 522 秒仍有效。重启后 S0/S1 年龄约 1h40m/1h34m
时均通过 `onlineInfo`，说明 S1 可跨进程持久恢复，但尚未证明 TTL 被延长。

`scripts/e11-headless-resume-monitor.sh` 从现有文件恢复，不重新登录或换票。为捕获 S1 相对 S0 只有约
5m49s 的区分窗口，它每 60 秒只检查 S0；S0 session-invalid 后才立即完整验证 S1，避免每轮双倍请求。
原文件指纹必须保持不变，最长观察到 S0 年龄 4h15m。

**最终结果：无头恢复成立，但没有续期（2026-08-11）。** 重启后第一次检查时，S0/S1 分别在约
1h40m/1h34m 仍通过；约 14 分钟后 S1 已返回 `75500002`，紧接着 S0 也返回同一码。已知 S0 与 S1
的 SID 完全相同，而 S1 只晚创建约 5m49s；没有观察到「S0 失效、S1 仍有效」的窗口。当前证据支持：

1. `ticketExchange` 的 73 字节 ticket 可以被空 jar 的 `sessionIdExchange` 直接接受，无需浏览器或本地 agent；
2. 它能在另一进程/另一 cookie jar 中重建控制面和数据面均可用的会话；
3. 重建得到的仍是同一个后端 SID 和同一个绝对到期点，**不重置 TTL，不构成续签**。

因此该闭环可用于进程间会话接管或官方客户端启动，但不能解决长期无人值守。下一候选必须能产生新 SID、
刷新后端绝对期限，或让本地 agent 持有一个独立于 gateway SID 生命周期的数据面凭证。

**预计成本：** 一次 R2 主实验最长约 4 小时 15 分，其中只有 T0 需要人工；确认可重复性至少需要两个登录日。
R1 每个候选也必须独立占用一次登录，优先级低于 R2，不应为了穷举接口延迟主实验。

---

## 变更记录

- **2026-08-07（E11 设计）：** 基于 [B7](#b7) 的 SID 绝对 TTL 结果，新增无人值守续期实验。
  主路径是在一次人工 MFA 后复用持久 browser profile，发起新 CAS challenge 并尝试静默换取新 SID；
  先验证服务端原语和跨旧到期点，再考虑 `AtrustClient` 的运行时材料热替换。
- **2026-08-10（E11 R2 首轮）：** T+1h 复用关闭后的 Chrome profile 会停在 IDS 登录页，未生成 S1；
  该结果只否定重启浏览器路径，不足以证明 R3。新增两条并行路线：捕获 portal 对六个 loopback HTTPS
  endpoint 的官方客户端 IPC，以及在同一浏览器进程内执行 T+5m 短窗口 CAS 换票。
- **2026-07-31** 建档。收纳 A1–A7、B1–B5、C1–C4、D1–D3，实验 E1–E5。
  D1/D2 为当日新实测结果，推翻了架构文档中「外网 `:441` 不可达」的旧记录。
  同日为 [A1](#a1) 增加 `connect_token_len` / `data_resp layout` 两处埋点，
  在此之前 E5 不具备可观测性。
- **2026-07-31（同日，端点选择）** [D2](#d2) 的 SNI 抑制已实现（`enable_sni = false`）；
  端点选择由「取第一个」改为并行探测 + 时延排序（`atrust_auth::select_node`），
  显式 `--node` 按 [D3](#d3) fail-closed。
- **2026-07-31（同日，E3–E5 live）** 重登 CAS 后：
  - **E3：** good/bad SignKey 对 TCP 均握手成功 → [B1](#b1) 西电 TCP **不硬校验**；
  - **E4：** `addrType=1`，`vip=10.210.29.200`，`vip_data_hex=0ad21dc80000`（6 字节，尾 `00 00`），
    status `{"code":0,"data":{"deviceID":"644B123B"},"message":"OK"}` → [A2](#a2)/[A5](#a5) 首样本；
  - **E5：** L3 `tcp-syn` 鉴权 `ready=true`，`connect_token_len=32`（≥17，[A1](#a1) 安全），
    下行 `data_resp layout=length_prefixed` bytes=44，回环成功。
  注意：`icmp-echo` 对仅 `tcp:80` 资源会 `auth status 0x82`（见 [C2](#c2)）；E2 的 C1 目标
  `202.117.112.1:80` 在节点侧 TCP connect `0x03`（可达性/策略），换「新OA」后通。
- **2026-07-31（同日，E2 量化 + 掩码问题结案）**
  - **[C1](#c1)：** 2035 个采样点中 TCP 重叠 74%、**两种排序分歧 60%**；
    且 E3/E5 用过的三个目的地恰好都不分歧 → **live 至今对 C1 零证据**。新增 [E9](#e9) 作为
    决定性实验（同目的地、两个候选 `appId` 各拨一次，让服务端表态）；
  - **[A2](#a2)/[A8](#a8)：** VIP 尾 2 字节的掩码假说证伪后，查 zju-connect 确认
    **它根本不从 VIP 推导掩码**——VIP 恒 `/32`，MTU 硬编码 1400，路由完全由资源表逐条下发。
    掩码问题就此结案，不再是接 TUN 的阻塞项；
  - **[C2](#c2)：** `0x82` 确认服务端在 flow auth 阶段比较协议；
  - **代码：** 读循环改为满队列丢包（`try_send` + `dropped_packets` 计数），
    不再让慢消费者拖住 `0x93` 分发。
- **2026-08-03（E9 live）：** `202.117.112.71:8081` 的 specificity 与原始首条 appId 在
  TCP 地址阶段均通过、随后都因目标不可连接返回 `0x03`，L3 flow auth 均返回 connect token；
  无关 appId 在 TCP/L3 分别被 `0x02`/`0x82` 拒绝。西电网关验证 appId 是否属于匹配资源，
  但不强制重叠候选的唯一排序；Hermes 保持 specificity。TCP 默认 8 秒握手超时不足以等到
  本次约 15 秒后的 `0x03`，实验使用 20 秒。
