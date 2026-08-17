# 外部 aTrust 二进制逆向材料评估

评估对象（2026-08-13 收到，不复制进仓库）：

- `<external-notes-dir>/atrust-tunnel-binary-paths.md`
- `<external-notes-dir>/atrust-protocol.md`

第一份给出 macOS `aTrustXTunnel` 与 Android `libsangforsdk.so` 的命名函数、地址和调用路径；
第二份将其中 TCP/QConn 结果整理为实现约束。它们不含本项目可复现的二进制 hash、版本号、
反编译数据库或原始抓包，因此在 Hermes 中记为**外部二进制逆向证据**：强于无来源推测，可用于
设计测试和解释实现，但不能覆盖西电 L0，也不能仅凭文档改变 live 已验证行为。

## 总体判定

**有用，且应保留其结论索引，但不应整体照搬。** 价值分三类：

1. 独立确认 Hermes 已实现的基础线协议：TCP 与 L3 是不同业务模块；TCP 应用数据使用 QConn
   framed profile；L3 初始鉴权与 `0x13..0x16` command 阶段分离；各 command 的头并不统一。
2. 给出 Hermes 之前缺少的官方客户端实现细节：QConn 独立读写状态与复用关闭；`0x84..0x87`
   flow-auth 状态；基于写活动的心跳；IPv6 事件触发的 second-VIP；大包分片。
3. 暴露版本/profile 差异。材料中的严格 parser、prefix-only close 与西电黑盒互操作已观测的
  兼容行为冲突，必须先做版本和线路实验，不能直接“修正”当前实现。

它们没有提供任何反证来扩张外部凭据集合。文档中的 tunnel auth 仍以 SID 为入口，也没有证明
DeviceID、ConnectionID、SignKey 或其他 Cookie 必须来自登录过程。因此当前
`sid + sid.sig` 最小外部凭据契约不变。

## 可直接采纳的确认

| 主张 | Hermes 状态 | 判定 |
|---|---|---|
| TCP tunnel 与 L3 tunnel 是独立业务路径，不按首个应用 payload 猜测 | 已分 crate/runtime 路径 | 独立确认，保留当前设计 |
| TCP 已确认 profile 为双向 `01 00 + u16-be len + payload` | `atrust-tcp` 已实现并 live | 一致 |
| TCP 是字节流，握手与数据必须支持任意拆包、粘包和预读保留 | 已使用有界、精确读取和缓冲 parser | 一致；可补边界测试 |
| L3 初始 SID/Get-IP 与后续 `0x13` flow auth 是两个阶段 | 已实现 | 一致 |
| `0x93/0x96` 为 5 字节状态头，`0x94/0x95` 为 4 字节长度头 | 已实现已知 command | 一致 |
| `0x14` 支持 token、保留字节、packet count 和逐包长度 | codec 支持批量，常规路径单包 | 一致；单包是合法子集 |
| 初始 VIP `addrType=1/4/5` 后续长度为 6/18/22 | Get-IP parser 与测试已覆盖 | 独立确认 |
| 不应由 HTTP/TLS/`01 00` 等 payload 特征猜 raw/framed | Hermes 不做此类探测 | 一致 |

## 有用但需新实验

### 1. `0x93` 的 `0x84..0x87` 状态

材料称 `0x84` 应立即回到待鉴权，`0x85..0x87` 应延迟重试，其他非零状态才是终态失败。
Hermes 当前把所有非零 outer status 作为 flow failure。这是最可能影响真实兼容性的新增事实，
但西电尚未出现这些状态，不能未经验证改变重试语义。

建议设立 `E12 flow-auth-status`：用受控 peer 对每个状态分别返回带/不带 conntrackHash 的 JSON，
记录官方客户端是否重发 `0x13`、延迟、hash 是否变化、原包是否重放及连接是否保留。完成 mock
状态机之前不连接真实目标。

### 2. QConn close 与复用状态

材料称 framed 读取端看到任意 `01 01 xx xx` 都结束，且只有 `isReuse=true` 时客户端
`CloseWrite` 才发送 `01 01 00 00`。Hermes 的 live 兼容 parser 只把 `01 01 30 30` 作为
server close，并曾把其他 marker 当作可跳过控制字节；Hermes 也不实现连接池复用。

建议设立 `E13 qconn-close-profile`：区分目标正常关闭、客户端 half-close、节点关闭和复用/非复用，
取得解密字节与官方客户端状态。没有这个实验，按 prefix-only 修改会回归当前 live 路径。

### 3. raw/framed 可达状态

QConn 数据结构可表达读写各自 raw/framed 四种组合，但材料只证明 zero-RTT 路径进入双向 framed。
这不构成实现 raw 模式的需求。只有取得非 zero-RTT 路径、明确状态映射和线路抓包后才增加
profile；禁止由 payload 内容自动探测。

### 4. 严格 L3 parser 与兼容 parser

材料中的特定 macOS/Android 版本只注册 `0x93..0x96`，遇到未知 command 或迟到 `53 00`
会重建连接。Hermes 依据既有互操作样本接受通用长度未知帧和迟到 `53 00`，并已支持材料中没有的
异步 `0x97` VIP 更新。这说明至少存在客户端版本或部署 profile 差异，而不是任一文档天然正确。

建议设立 `E14 l3-parser-profile`：向官方客户端的受控连接分别注入迟到 `53 00`、通用布局未知
command、状态布局未知 command 和 `0x97`，随后附合法 `0x95`，观察继续、报错或重连。
当前 live 兼容行为在实验前保持不变。

### 5. 心跳活动模型

材料称官方客户端仅在整个周期没有成功写 command 时发送 `0x15`；任意写入（包括心跳本身）
设置 `hasWrite`，未收到 `0x95` 并不直接累计“丢包”。Hermes 当前固定周期发送并单独统计 ACK。
现实现可用，但不能把 ACK 统计解释为官方超时算法。

建议设立 `E15 heartbeat-profile`：分别运行持续数据、完全空闲、丢弃 ACK 和写失败四臂，比较
官方客户端的发包和断线条件。若只影响额外流量，可维持 Hermes 更简单的 keepalive 策略并明确
记录差异。

### 6. MTU、分片与批量

材料称 macOS 路径对超过 1500 字节的包先做 IP 分片，再放进可批量的 `0x14`。Hermes codec
支持批量但不分片；既有兼容性样本采用 TUN MTU 1400。可能是版本、入口或层次差异。

建议设立 `E16 l3-mtu-fragmentation`：测试 1400/1401/1500/1501/4096/4097 字节，记录官方
客户端是在 TUN 前阻止、IP 分片、拆成多个 `0x14` entry，还是原样发送。TUN 实现前必须决定
MTU 和分片责任。

### 7. IPv6 second-VIP

材料将 `0x16/0x96` 限定为 IPv6 second-VIP 事件路径，并称失败后每秒重试、最多三次。这是
有用的新边界：不能实现成无条件周期刷新。Hermes 目前只观察 `0x96`，应等 IPv6/TUN 工作开始
后以真实 IPv6 resource、初始 addrType 和事件触发做 `E17 second-vip`。

## 暂不采纳为通用规则的冲突

| 外部材料主张 | 现有证据冲突 | 当前处理 |
|---|---|---|
| L3 数据期只接受 `0x93..0x96` | Hermes 互操作路径支持迟到 `53 00`、未知通用 frame、`0x97` | 视为版本/profile 差异，保持兼容 parser |
| 任意 `01 01 xx xx` 都是 QConn EOF | Hermes live 兼容路径区分特定 trailer/marker | 不改 parser，先做 E13 |
| 下行 `0x94` 始终为单包长度前缀 | 兼容性样本还包含 token-framed 分支；Hermes 已双格式测试 | 保留双格式；继续收集 L0 token 分支样本 |
| 官方 heartbeat 只按写活动工作 | Hermes 周期 heartbeat + ACK 统计已稳定运行 | 记录差异，先做 E15 |
| 超过 1500 字节由客户端分片 | 兼容性样本的 TUN MTU 为 1400，Hermes 尚无 TUN | 留给 E16 和 TUN 设计 |

## 验证层级与“未观察到”的含义

同一主张必须拆成三个不同问题，不能用一个层级替代另一个：

| 层级 | 能证明什么 | 不能证明什么 |
|---|---|---|
| P：静态路径 | 某版本官方二进制含有该函数、分支和状态转换 | 西电服务端会发送触发输入；其他版本相同 |
| M：受控 mock/fixture | Hermes 对精确 wire 输入的解析、状态和输出符合设计 | 官方客户端或真实网关行为相同 |
| L：live/受控官方客户端 | 特定客户端与 deployment 在线路上实际走到该路径 | 未测试版本、资源和部署也相同 |

因此每个实验分别记录 `P/M/L`。`P=通过、M=通过、L=未触发` 是有效的阶段性结果，不是失败；
也不能写成 L0。被动运行中没有出现某 command/status，仅说明该观察窗口和流量没有触发它。
尤其以下事件稀有或条件化，**零样本不构成反证**：`0x84..0x87`、token-framed `0x94`、
`0x97`、`0x16/0x96`、raw QConn、复用 close 和超 MTU 分片。

实验记录必须至少包含：客户端与二进制版本/hash、网关、SID 年龄、资源/目标、节点、TLS profile、
触发动作、完整 arm 顺序、每臂 wire 观测和结论层级。没有版本/hash 的外部逆向材料只能保持 P
候选，不提升为版本无关规则。

## 可立即执行的确定性验证

这些实验不等待真实网关发稀有包，可先闭合 Hermes 的实现质量。它们不产生新的 L0。

### V1 TCP 字节流边界

精确 harness、fixture、切分矩阵和错误注入设计见
[`v1-v2-e12m-design.md`](v1-v2-e12m-design.md#v1)。

**目的：** 验证当前已确认双向 framed profile 在任意 TCP 拆包、粘包和短写下不丢字节。

**受控 peer arms：**

1. `B0`：正常分段发送 address OK、connect OK、首个 app frame；
2. `F1`：上述每个字节单独发送；
3. `F2`：`05 00` 与首个 `01 00` app frame 一次写入；
4. `F3`：底层 writer 每次只接受 1、2、3 字节并交替 Pending；
5. `F4`：应用 payload 分别以 `01 01`、`01 00`、`05 81`、`53 00` 开头；
6. `F5`：应用写入 65535、65536 和 131071 字节；
7. `B0-final`：恢复正常 peer。

**硬判据：** 所有应用字节逐字节相同、消息边界不依赖一次 read、无 header/payload 交错；大写入
要么由流接口拆成合法帧，要么由明确标为 single-frame 的 API 拒绝，不能截断；F1-F5 后 B0-final
仍通过。另行注入 write/flush/shutdown 错误，确认公开 API 返回还是有意抑制错误，并把策略写成测试。

**状态：** 可立即做 M；无需 live。

### V2 L3 command 流边界

精确 command fixture、consumed 哨兵和端到端 peer 调度见
[`v1-v2-e12m-design.md`](v1-v2-e12m-design.md#v2)。

**目的：** 对每种已知头验证逐字节拆分、连续粘包和精确消费。

**fixture：** `0x93`/`0x96`/`0x97` 五字节状态头，`0x94`/`0x95` 四字节头，初始
`53 00` 与 VIP 6/18/22 字节。每个 fixture 后都追加合法 `05 95 00 00` 作为对齐哨兵。

**硬判据：** fixture 被解析为预期事件，哨兵仍被正确解析；截断、超长和错误 version fail closed；
parser 不扫描 payload 寻找伪 header。

**状态：** 大部分已有 M 测试；新增实验只补缺失组合，不需要等待 live。

## 主动可验证实验

这些实验理论上有明确触发路径，但要闭合 L 层通常需要受控官方客户端、可注入的 mock node、
TLS plaintext instrumentation 或授权代理。不能向生产节点注入伪服务端帧。

### E12 flow-auth-status

E12-M 的 status 分类、有限重试、虚拟时钟、并发 waiter 与取消语义见
[`v1-v2-e12m-design.md`](v1-v2-e12m-design.md#e12-m)。

**主张：** `0x84` 立即重鉴权，`0x85..0x87` 延迟重试。

**P 路径：** `authCmd.ResolveData -> conntrack.HandleAuthResp -> pending/delayed/failed`；外部材料已给出。

**arms：**

1. `B0`：`status=0` + 正常 token，要求单次授权成功；
2. `S84`：首次 `0x84`，第二次成功；
3. `S85/S86/S87`：首次对应 status，第二次成功；
4. 每个 status 分别使用正确 hash、缺失 hash、未知 hash 和 malformed JSON；
5. `Terminal`：`0x82` 或其他已知终态；
6. 每个候选后运行 `B0-check`。

**观测：** `0x13` 次数、第一次到第二次的延迟、conntrackHash、原 IP 包是否只发送一次、连接是否
重建、等待调用者最终结果。

**通过标准：** M 层先精确实现一份显式状态表，不允许无限重试；L 层只有在官方客户端受控 peer
复现同一次数和时间类别后，才可启用对应 production profile。西电被动日志首次出现这些 status
时只保存证据并停止自动推断，不能现场热改重试策略。

**状态：** P 可确认；M 可立即做；L 等受控官方客户端或服务端自然发包。当前西电尚未触发。

### E13 qconn-close-profile

**主张：** close trailer 是否 prefix-only，以及 `isReuse` 如何决定逻辑 close 或 TLS half-close。

**arms：**

1. `B0`：目标正常返回完整响应并主动 EOF；
2. server 依次发送 `01 01 00 00`、`01 01 30 30`、`01 01 12 34`、跨 read 拆分的同类帧；
3. close frame 后追加 app frame，验证 close 后数据绝不泄露；
4. client 分别在 reusable/non-reusable profile 调用 CloseWrite；
5. 节点 TLS 直接关闭作为 transport 对照；
6. `B0-final`。

**观测：** 应用 EOF、底层 half-close、实际发出的四字节、连接是否回池、后续 tunnel 是否复用同一
underlay、错误是否准确上报。

**通过标准：** M 层每种 trailer 有确定且有状态边界的结果；不能根据 app payload 猜 close。
L 层必须同时取得官方客户端状态与 plaintext bytes，才能改变 Hermes 当前 live-compatible 规则。

**状态：** Hermes mock 可立即做；普通目标 EOF 可 live；reuse 与替代 trailer 需要受控官方客户端。

### E14 l3-parser-profile

**主张：** 特定官方版本严格拒绝未知 command/迟到 `53 00`，而兼容 profile 可继续。

**arms：** 每臂先建立正常 L3，再注入一个候选 frame，随后发送对齐哨兵 `05 95 00 00`：

1. `B0`：只发送哨兵；
2. `Late53`：`53 00 <len> OK`；
3. `Unknown4`：`05 42 <u16 len> payload`；
4. `Unknown5`：`05 42 status <u16 len> payload`；
5. `Vip97`：合法和 malformed `0x97`；
6. 每臂后重新建立 `B0-check`。

**观测：** 哨兵是否到达 parser、连接继续/关闭/重建、close reason、是否发生 stream 错位。

**通过标准：** profile 必须显式选择 strict 或 compatible；unknown status-bearing frame 不能按通用
四字节头静默误吞。只有官方客户端版本化 L 结果才能决定该版本 profile，西电当前实现保持兼容。

**状态：** M 可立即做；L 需要可注入的官方客户端 mock node。生产线路被动等待几乎无法区分
“服务端从不发送”和“客户端会如何处理”。

### E15 heartbeat-profile

这是既有 [`E7`](open-questions.md#e7) 长会话结果的补充，不重跑“heartbeat 能否延长 SID/L3
空闲寿命”；它只比较官方 `hasWrite` 调度与 Hermes 固定周期调度。

**arms：**

1. `Idle`：两个周期无其他 write，正常 ACK；
2. `Active`：每个 tick 前发送一个成功 data/auth command；
3. `DropAck`：接受 `0x15` 但丢弃所有 `0x95`；
4. `WriteFail`：在普通 command 或 heartbeat 提交/flush 时断开；
5. `Recover`：恢复 peer 后重连。

**观测：** 每周期 `0x15` 数、任意 command write 数、ACK 数、lost counter（官方插桩）、断线条件、
重连结果。

**通过标准：** 先分别描述 Hermes 策略和官方策略，不要求强行相同。若 Active 中官方不发 heartbeat、
DropAck 中不因 ACK 缺失断线，则确认外部材料的 write-activity 模型；Hermes 是否复刻由流量和故障
收益另行决策。

**状态：** M 可立即做；P 已有；官方 L 需要 instrumentation。西电普通运行可提供被动计数，但
不能主动制造安全的 write failure。

### E16 l3-mtu-fragmentation

这是既有 [`E6`](open-questions.md#e6) 的官方客户端分片扩展。E6 负责 Hermes/gateway 的 1400
MTU、echo 和 `0x94` 边界；E16 额外回答外部材料所称 macOS “超过 1500 后先分片”是否在线路
可达，避免两组实验被误记成重复证据。

**arms：** IP 总长度 1399、1400、1401、1499、1500、1501、4096、4097；每个尺寸做 DF=0/1，
另加一组预先分片的 IPv4。每臂后发送小包 B0-check。优先使用授权 UDP echo 以校验完整 payload；
没有 echo target 时只能验证编码和 gateway 接受，不能声称 application round-trip。

**观测：** TUN 是否接受、ICMP fragmentation-needed、`0x14` 数量、每帧 packetCount、IP ID/offset/MF、
下行 `0x94` 形态、payload 完整性和后续小包对齐。

**通过标准：** 明确 fragmentation 责任属于 TUN/本地 IP 栈、Hermes L3 或 gateway 三者之一；DF=1
不得静默分片；任一大包失败后小包 B0-check 必须通过。TUN MTU 只能由可重复边界结果确定。

**状态：** codec/mock M 可立即做；当前没有已确认的授权 UDP echo target，完整 live 暂阻塞；
官方客户端是否在 1500 分片还需 TUN plaintext capture。

## 只能等待条件出现的实验

### E17 second-vip

**前置条件：** clientResource 出现 IPv6 资源，初始 VIP 支持 IPv6，且官方客户端产生可辨识的
IPv6 second-VIP 事件。当前西电样本不满足，不能人为向生产 gateway 发送未经授权的 `0x16`。

**触发后 arms：** 正常 `0x96`、首次失败后成功、连续失败；记录 `0x16` 触发时刻、1 秒重试间隔、
最多三次、地址是新增还是替换、IPv4 flow 是否保留。mock 可先验证 parser 和状态容器，但不能证明
真实触发条件。

**判定：** 长期未见 `0x16/0x96` 只记 `L=未触发`。只有满足前置条件仍重复不发送，才可对特定
客户端版本提出“路径不可达”的候选结论。

### E18 downstream-0x94-profile

这是既有 [`E5`](open-questions.md#e5)/[`E6`](open-questions.md#e6) 的被动观察项，不另行向生产
节点制造畸形或超 MTU 流量。

**前置/触发：** 服务端选择 token-framed 下行，或出现大于 4096 字节的下行 IP 包。当前西电多个
L0 样本均是短 length-prefixed，无法主动要求生产节点切换 profile。

**观测：** connect-token 长度与首字节、body 前两字节、IP total length、解码 branch、packetCount，
并用紧随的 `0x95` 证明对齐。受控 peer 应覆盖 token 长度 15/16/17/32、首字节 0/nonzero、
packet length 4096/4097/5000。

**判定：** M 双分支通过只证明兼容 decoder；西电长期只见 length-prefix 不否定 token 分支。
第一次真实 token 样本应保留脱敏结构和完整长度元数据，再提升 L0。

### E19 qconn-mode-reachability

**前置/触发：** 官方客户端进入非 zero-RTT 路径，或握手状态显示 read/write 任一方向未
handshaked。当前线路只确认双向 framed，QConn 类型“能够表达 raw”不等于 tunnel 可达 raw。

**观测：** zeroRTT 配置、SOCKS reply、SetRead/WriteShakeDone 调用、每方向首个 plaintext bytes、
reuse flag。禁止用 HTTP/TLS 特征或 `01 00` 开头猜模式。

**判定：** 未取得状态映射与线路 bytes 前保持 `L=未触发`，不实现自动探测。若未来确认可达，
新增显式、握手决定的 versioned profile，并保留当前双 framed B0。

## 实验执行顺序

1. 先完成 V1/V2，确保实验仪器本身在拆包、粘包和错误路径上可信。
2. 再完成 E12、E13、E14、E15 的 M 层；这些都不需要等待西电稀有包。
3. TUN 设计前完成 E16 的 mock/codec 层，并等待授权 echo target 做 live。
4. E17/E18/E19 保持被动 instrumentation；触发时保存证据，不在运行中自动改变 profile。
5. 任一 L 层候选结论都以同 profile 的已知成功 B0 前后夹层；基线失败则该轮不可归因。

## 近期优先级

1. **高、现在可做：** V1/V2；先证明实验 parser 和 stream 工具可信。
2. **高、现在可做 M：** E12 `0x84..0x87` mock 状态机，因为当前实现可能把可重试状态误报为终态失败。
3. **高、现在可做 M：** E13 close/profile、短写、大写入和 shutdown 错误传播。
4. **高、TUN 前做 M：** E16 MTU/分片责任；完整 L 等授权 echo target。
5. **中、现在可做 M：** E14 parser profile、E15 heartbeat profile；当前西电路径已通过，不应先改后测。
6. **被动等待：** E17 second-VIP、E18 token-framed/large `0x94`、E19 raw QConn。

## 审计规则

- 外部逆向材料用于增加候选事实，不自动提升为 L0 或全局协议规则。
- 与 live 证据一致的内容可记为独立确认；冲突内容必须按客户端版本/deployment profile 保存。
- 新增 wire 分支必须有 fixture/mock；改变已 live 路径还必须有对应 L0 回归。
- 新的外部凭据字段必须走独立最小覆盖实验，不能从二进制字段存在性推断“必须持久化”。
- 若后续取得二进制版本、hash、原始抓包或反编译片段，应补充来源元数据，再重新评定证据强度。
