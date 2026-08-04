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
「隧道还在但所有流突然不通」。Get-IP 阶段的 body 已存入 `status_bodies` 可 trace；
会话中途的目前只计数。

### A6 — `0x95` 心跳应答体 <a id="a6"></a>

**依据：L1**。body 被完整消费但内容忽略。是否携带服务端侧的会话计时/配额信息未知。

### A7 — `0x16` / `0x96` second VIP <a id="a7"></a>

**依据：L3**。请求触发条件和用途均未确认。已知 `addrType = 5` 的 VIP 帧本身就同时带
IPv4 和 IPv6，与 second-VIP 是否互斥、还是分别服务不同场景，无依据。
Hermes 能解码 `0x96` 但从不主动发 `0x16`。

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

**实现后果（已处理）：** 同一个业务码会经由两个不同的错误类型到达调用方——`authConfig`
报 `AuthError::AuthenticationRejected`，`clientResource` 报 `AuthError::Resource(Rejected)`，
`AuthError::is_session_invalid()` 同时识别两者。`ResourceCache` 据此把它**升级**为
`HermesEvent::SessionInvalidated` 而不是计入连续失败计数：重试永远修不好它，而一个只会
反复 `warn` 的刷新循环会让整个运行时停在一张只会越来越旧的资源表上。

**对实验纪律的影响：** 任何需要正负对照的实验（[E3](#e3)、[E3b](#e3b)）必须在同一个会话里
连续跑完，中间不能夹一次重新登录。

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

**接 TUN 前还欠的三关**（尚未展开成实验条目）：

- **E6 — 大包 / MTU / token 分支。** E5 只证明了 44 字节；[A1](#a1) 的 `n > 4096` 区间和
  整个 token 分支**一次都没被触发过**。需要 `--payload-bytes` 与一个 UDP 探针
  （ICMP 走不通，见下方 C2 的 `0x82`）。上行受 MTU 1400 约束不会越界，**下行没有保证**；
- **E7 — 长会话存活。** 25 秒心跳是 zju-connect 的常量（[B4](#b4)），西电容忍窗口未知；
- **E8 — 并发多流。** conntrack 驱逐、并发授权去重、waiter map 目前**只有 mock 覆盖**。

**关于 `10.255.57.11`：它外网不可达是预期的，不构成阻塞。** 它是内网侧地址，
真正的问题不是「能不能直连它」，而是「Hermes 会不会默认选中它」——由 [E1](#e1) 回答。
只有当它被服务端标为 major 且排在前面时，才需要在配置层加显式的端点优选。
它作为**隧道内目的地**的可达性是另一回事，属于 E5 之后的验证。

---

## 变更记录

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
