# V1、V2 与 E12-M 可执行设计

本文把 [`external-binary-notes-assessment.md`](external-binary-notes-assessment.md) 中的 V1、V2 和
E12-M 细化为可直接实施的测试设计。三项均先闭合 M（Hermes mock）层，不声称目标 deployment
在线路上可达。生产 profile 在 L 层有证据前保持现状。

## 共同规则

1. 固定随机种子或使用穷举切分点；失败必须可重复。
2. 每个候选前后都有正常 B0；B0-final 失败则整组不可归因。
3. fixture 后追加一个已知合法 frame 作为对齐哨兵，不能只断言候选自身被接受。
4. 测试设置整体 timeout，防止 parser 或 waiter 挂死；不使用真实 sleep，延迟测试用 Tokio paused time。
5. wire fixture 不包含真实 SID、token、Cookie 或目标数据。
6. parser、状态机和 production policy 分层。能够解析一个状态不等于默认启用其行为。

## V1：TCP 字节流边界 <a id="v1"></a>

### 范围

目标文件：

- `crates/atrust-protocol/src/tcp_frame.rs`：单帧 codec；
- `crates/atrust-tcp/src/stream.rs`：framed AsyncRead/AsyncWrite；
- `crates/atrust-tcp/src/dial.rs`：握手精确消费与首个应用 frame 保留。

V1 只验证当前已确认的双向 framed profile，不决定 raw/framed 可达性，也不改变 `01 01` trailer
含义；后者属于 E13。

### Harness

在 `stream.rs` 测试模块增加 `ScriptedIo`：

```text
read_chunks: 预置下行 bytes 及每次最多返回长度
max_write: 每次底层 poll_write 最多接受长度
pending_every: 每 N 次 write/read 先返回一次 Pending
fail_write_after: 写到指定累计字节后返回错误
fail_flush / fail_shutdown: 对应阶段注入错误
written: 捕获全部上行 wire bytes
```

`ScriptedIo` 只模拟 AsyncRead/AsyncWrite，不解析协议。协议断言由测试端对 `written` 做严格 frame
解码，避免 peer 和被测代码共享同一个错误 parser。

在 `dial.rs` 继续使用 `tokio::io::duplex`，peer 可用 `write_partitioned(bytes, cuts)` 控制服务端
握手响应的拆分。所有任务置于 2 秒虚拟/测试 deadline。

### V1-A：纯 decoder 穷举切分

fixture：

```text
App0       = 01 00 00 00
App1       = 01 00 00 01 41
AppControl = 01 00 00 08 01 01 01 00 05 81 53 00
Marker     = 01 01 00 00
CloseKnown = 01 01 30 30
Chatter81  = 05 81
StatusOK   = 53 00 00 02 4f 4b
Sentinel   = 01 00 00 03 65 6e 64
```

对每个 fixture 长度 `n`，穷举 `0..n` 的所有单切分点；再对关键 fixture 穷举双切分点。每个前缀
在内容不足时必须返回 NeedMore，完整后必须只消费自身长度。候选与 Sentinel 粘接后，第二次 decode
必须准确得到 `end`。

硬判据：

- payload 中出现 `01 01`、`05 81`、`53 00` 不触发控制逻辑；
- App0 按当前工程策略作为 probe/no application bytes，不得产生 EOF；
- CloseKnown 后的任何 bytes 不交付应用层；
- 1024 字节 chatter 边界与 1025/1026 字节失败边界由测试固定，不能无限扫描。

### V1-B：AsyncRead

arms：

| Arm | 下行调度 | 调用者 ReadBuf | 断言 |
|---|---|---|---|
| B0 | 完整 App1 + Sentinel | 64 | 顺序返回 `A`、`end` |
| R1 | 每次底层只返回 1 byte | 64 | 与 B0 完全相同 |
| R2 | 两帧一次底层 read | 每次 1 byte | 应用 bytes 无丢失、无伪 EOF |
| R3 | Marker + App1 粘接 | 2 | marker 不泄露，返回 `A` |
| R4 | App0 + App1 粘接 | 2 | 空帧不让 AsyncRead 返回伪 EOF |
| R5 | Chatter81 + StatusOK + App1 | 1/2/64 | 当前 compatible profile 精确跳过后返回 `A` |
| R6 | CloseKnown + App1 | 64 | 立即 EOF，App1 不泄露 |
| B0-final | 同 B0 | 64 | 通过 |

每个 arm 分别用 `read_app()` 和 `AsyncReadExt::read_to_end/read_exact` 路径执行，确认 frame API 与
stream API 的差异是有意且稳定的。

### V1-C：AsyncWrite 与大写入

输入长度：`0`、`1`、`65535`、`65536`、`131071`。底层 `max_write` 分别为 1、2、3、4096，
并运行 Pending 交替版本。

预期策略：

- `poll_write` 遵循标准 partial-write 语义：单次最多接收 65535 application bytes，并准确返回已接收数；
- `AsyncWriteExt::write_all` 必须把 65536 编成 `65535 + 1` 两个完整 frame，把 131071 编成
  `65535 + 65535 + 1`；
- 显式空 AsyncWrite 保持 no-op，这是 Hermes 工程策略，不冒充官方 QConn 规则；
- `write_app` 应定义为 convenience `write_all`，支持自动分帧；单帧限制只留在
  `encode_tcp_app_data`。实施时先加失败测试，再做这个最小行为调整；
- 任意短写或 Pending 都不能让 frame header 与另一个写入的 payload 交错。

并发写不作为 `TcpTunnel<&mut S>` 的隐式能力测试；所有权模型允许共享写端后，另立 serialization
测试，不能用不安全共享构造假并发。

### V1-D：握手与预读

server logical stream：

```text
05 81
53 00 00 02 4f 4b
05 00
01 00 00 03 61 70 70
```

arms：每字节一次 write；按消息 write；全部一次 write；在每个 header/length/body 边界切分。

硬判据：

- `complete_handshake` 只消费到 `05 00`；
- 紧随其后的 `app` 仍由 `TcpTunnel` 完整读取；
- address/connect 任一截断得到 timeout/EOF，不被误判成功；
- 非 OK 或非零 connect status 返回可定位错误。

### V1-E：关闭错误传播

目标策略：显式 `close()` 返回首次 write/flush/shutdown 错误；`poll_shutdown` 也不把底层错误静默
改成成功。无论报错与否，本地 closed 状态都只转换一次，重复 close 幂等。

arms 在 close frame 第 1、2、4 字节、flush 和 shutdown 注入错误。断言错误种类、累计 wire bytes、
第二次 close 行为。这个调整只改善本地错误可见性，不改变 E13 尚未确认的 trailer 语义。

### V1 完成条件

- 所有 arm 与 B0-final 通过；
- 大输入重组后逐字节相同；
- Miri/fuzz 不是本轮门禁，但所有 deterministic partition 可进入默认 CI；
- `cargo test -p atrust-tcp --all-targets` 与 workspace clippy 通过。

## V2：L3 command 字节流边界 <a id="v2"></a>

### 范围与 Harness

目标文件：

- `crates/atrust-protocol/src/l3_frame.rs`：`0x94` body codec；
- `crates/atrust-l3/src/session.rs`：私有 `next_frame` 与 dispatch；
- `crates/atrust-l3/tests/mock_session.rs`：完整 reader task、waiter 和 packet channel。

纯边界测试留在 `session.rs` 内部测试模块，直接调用 `next_frame`。端到端测试扩展现有 mock peer，
只增加 `PeerWritePlan`：`Whole`、`OneByte`、`Cuts(Vec<usize>)`、`Coalesced`。不为测试公开 parser API。

### V2-A：标准 fixture

使用无秘密 JSON：

```text
Auth93    = 05 93 00 00 02 7b 7d
Second96  = 05 96 00 00 02 7b 7d
Update97  = 05 97 00 00 0f {"vip":"10.0.0.2"}
Heartbeat = 05 95 00 00
Protocol  = 53 00 00 02 4f 4b
Unknown   = 05 42 00 03 61 62 63
```

`Update97` 的长度必须由 fixture builder 计算，不手写常量。`0x94` 分别构造：

- 20 字节最小合法 IPv4 length-prefixed；
- 4096 字节 length-prefix 边界；
- 4097/5000 字节且 IP total length 匹配的大包；
- token-framed 单包与双包；
- 可判定 token 长度 17、32，以及长度 16 且首 token byte 非 0；
- 二义负例：token 长度 15，以及长度 16 且首 token byte 为 0。

每个 fixture 后追加 Heartbeat 哨兵。

### V2-B：prefix/consumed 穷举

对每个完整 fixture：

1. 每个严格前缀必须返回 `Ok(None)`，不能消费；
2. 完整 fixture 返回准确 Inbound variant 和 `consumed == fixture.len()`；
3. `fixture + Heartbeat` 第一次只消费 fixture，第二次消费 Heartbeat；
4. 所有两两已知 frame 粘接组合重复上述断言；
5. foreign version、非法 status/body length、超过 pending 上限 fail closed。

`0x94` 的断言还包括 layout、packet count、每包长度和 bytes。分类器的 M 结果只证明 decoder 自洽，
不把 token branch 提升为西电 L0。

二义负例不进入“完整 fixture 必须成功”的 pairwise 矩阵：其前两字节分别会落入 3840..4095 或
4096 的 length-prefix 区间，当前 decoder 会等待伪 packet length，无法可靠找到后续 Heartbeat。
测试必须固定并显式报告这个已知限制，不能假造成功。若未来真实 token 落入该区间，应先保存
证据并 fail closed，再另立有 expected-token 上下文的 decoder 实验。

### V2-C：dispatch 与端到端切分

arms：

| Arm | peer 下行序列 | 关键断言 |
|---|---|---|
| B0 | Auth93(success) + Heartbeat + Data94 | waiter ready、ACK+1、packet 到达 |
| D1 | 同 B0，每字节 write | 与 B0 状态完全相同 |
| D2 | Update97 + Heartbeat | VIP 原子替换、flow/waiter 清空、ACK 仍到达 |
| D3 | Protocol + Data94 | protocol_messages+1、packet 到达 |
| D4 | Unknown + Heartbeat | ignored event+1、连接保持、ACK 到达 |
| D5 | 两个 Data94 粘接 | 两包按序到达 |
| D6 | malformed recognized frame | session fail closed、close reason 精确、无后续 packet |
| B0-final | 同 B0 | 通过 |

端到端每臂使用 2 秒 deadline；任务结束后断言 reader/writer/heartbeat 均可 shutdown，不留后台任务。

### V2-D：兼容 profile 边界

当前 Hermes 对迟到 `53 00` 和通用四字节布局 unknown command 的接受是显式 compatible profile。
V2 固定当前行为但不扩张规则：

- unknown 五字节 status 布局不得被声称可安全跳过；
- malformed `0x97` 必须消费准确 frame 后记录 rejection，不能错位；
- unknown generic frame 的 payload 中含伪 `05 95` 不得被扫描成 heartbeat；
- strict/compatible 的版本选择留给 E14，不在 V2 中改变 production 默认值。

### V2 完成条件

- 所有 prefix、pairwise concatenation 和端到端 arms 通过；
- 每个成功候选后的 Heartbeat 哨兵可解析；
- malformed 输入得到有界失败而非 hang/错位；
- `cargo test -p atrust-protocol -p atrust-l3 --all-targets` 与 workspace clippy 通过。

## E12-M：`0x93` transient status 状态机 <a id="e12-m"></a>

### Wire 硬约束

`0x84..0x87` 是 `0x93` 的 **outer status 值**，不是 command：

```text
05 93 <status:u8> <jsonLen:u16-be> <JSON>
```

不得新增 `l3_cmd::0x84` 等常量，不得让它们进入 unknown-command parser。现有
`Inbound::Auth { status, json }` 和五字节 frame decoder 已足够；改动边界是 auth disposition、conntrack retry 状态和
调度，不是 command framing。

### 本轮目标与非目标

目标：

- 证明 status 分类准确；
- 证明 retry 有界、同流并发仍只发一条重试 wire request；
- 证明 waiter 在 transient 状态下不被错误失败/唤醒；
- 证明 malformed、未知 hash、late response fail closed；
- 用虚拟时钟验证 immediate 与 delayed 两类，而不宣称真实 delay 秒数。

非目标：

- 不默认启用生产重试；
- 不猜 `0x85/0x86/0x87` 各自真实延迟；
- 不声称西电会发送这些 status；
- 不在 M 层决定 retry 是否应换 conntrackHash。初始模型按外部调用路径保留同一 conntrack entry/hash，
  L 层若观察相反行为再修改。

### 纯分类层

在 `crates/atrust-l3/src/auth.rs` 设计：

```rust
enum AuthWireDisposition {
    Settled,
    RetryImmediate,
    RetryDelayed { status: u8 },
    Terminal { status: u8 },
}
```

固定表：

| status | disposition |
|---:|---|
| `0x00` | Settled，继续解析 token/code |
| `0x84` | RetryImmediate |
| `0x85..=0x87` | RetryDelayed，保留原 status 供 profile 选 delay |
| 其他非零 | Terminal |

分类是纯函数并穷举全部 256 个 status。retry status 仍必须从 JSON 取得非零、当前 in-flight 的
conntrackHash；malformed JSON、hash=0、未知/已淘汰 hash 返回 Unattributable，不允许猜“唯一 waiter”。

### 可注入 policy

在 L3 session 内部配置设计：

```text
enabled: bool
max_wire_retries_per_flow: usize
delayed_retry_delay(status) -> Duration
overall_auth_deadline: Duration
```

production 默认 `enabled=false` 或 retry budget 0，保持当前 live 行为。E12-M 测试 profile 使用：

```text
max_wire_retries_per_flow = 1
delayed_retry_delay(0x85..0x87) = 1 s（仅测试常量）
overall_auth_deadline = 8 s
```

测试常量不能进入协议常量或文档成为官方 delay。

### Conntrack 状态

将当前 `auth_started + Option<AuthOutcome>` 的隐式组合细化为内部状态，名称可在实施时最小化：

```text
New
InFlight { attempts, retries, reusable_frame }
RetryScheduled { attempts, retries, status, due, reusable_frame }
Ready { token }
Failed { message }
```

不把 TimedOut/Closed 永久存入 conntrack：沿用现有 eviction 和 session close。`reusable_frame` 是当前
`0x13` bytes 的内存副本，仅在 in-flight 生命周期存在，随 flow eviction/VIP update/close 清除。
该 frame 含 SID 和签名，必须放进 Debug 恒定脱敏、drop 时 zeroize 的专用 wrapper，不能直接让
`ConntrackEntry` 的派生 Debug 打印 `Vec<u8>`。这样 reader 收到 transient status 后无需持有或
重建 SignKey，也不会把 frame 或 SID 写入日志。

### 调度边界

reader/dispatch 不 sleep，也不直接在 conntrack mutex 下写 socket。建议增加有界 `auth_retry_tx`：

1. dispatch 在锁内完成 `InFlight -> RetryScheduled`，增加 retry 计数并取得 auth_id/status/due；
2. 锁外向 retry scheduler 发送不含秘密的 auth_id；frame 留在 conntrack；
3. scheduler 用 Tokio time 等到 due，再次锁表确认 entry 仍是同 auth_id、仍 scheduled、VIP/session 未变；
4. clone reusable frame，转换回 InFlight，锁外送入现有 writer queue并等待 flush；
5. write 失败走现有 session shutdown；成功才增加 auth request/retry stats；
6. status 重复且 budget 耗尽时转 Failed，通知全部 waiters一次。

通道满、scheduler 停止或 entry 已淘汰必须 fail closed，不能无限等待。session shutdown 必须停止
scheduler；`L3Session::close()` 后不再发送 retry frame。

### E12-M arms

统一成功 JSON：

```json
{"code":0,"message":"ok","data":{"conntrackHash":1,"connectToken":"token-32-bytes-or-more"}}
```

transient JSON 只保留可归因 hash。实际 auth_id 由 mock peer 从首个 `0x13` 解析后回填，不能写死 1。

| Arm | peer 响应 | 预期 wire/调用者结果 |
|---|---|---|
| B0 | success | 1 个 `0x13`，所有 waiter Ready |
| S84 | `0x84` 后 success | 2 个 `0x13`，无虚拟时间推进，所有 waiter 仅最终唤醒一次 |
| S85 | `0x85` 后 success | 1s 前仍 1 个，推进到 due 后第 2 个，最终 Ready |
| S86 | 同 S85 | 同上，stats 保留 status=0x86 |
| S87 | 同 S85 | 同上，stats 保留 status=0x87 |
| Exhaust84 | `0x84`、`0x84` | 总计 2 个请求，随后 Failed，不发第 3 个 |
| Exhaust85 | `0x85`、`0x85` | 同上，第二次 delay 不调度 |
| Terminal | `0x82` | 1 个请求，立即 Failed |
| BadJson | transient + malformed JSON | 不重试；unattributable；原 waiter 按既定 deadline timeout |
| MissingHash | transient + hash=0 | 同 BadJson |
| UnknownHash | transient + 未知 hash | 不影响当前 flow；当前 waiter timeout |
| Late | flow eviction 后旧 hash transient/success | 不复活、不重试、不通知新 flow |
| Concurrent | 32 callers，同一 flow，S84/S85 | 每 attempt 只有 1 个 `0x13`，32 callers 同一最终结果 |
| VipChange | scheduled delay 内 `0x97` | flow/frame/schedule 清除，不在新 VIP 上发送旧 retry |
| Close | scheduled delay 内 session close | scheduler 停止，零额外 write |
| B0-final | success | 通过 |

### Stats 与日志

扩展 `FlowAuthStats` 的候选字段：

```text
transient_statuses_received
wire_retries_scheduled
wire_retries_sent
wire_retries_exhausted
wire_retries_cancelled
```

结构化日志只含 status、auth_id、attempt、delay_ms、结果和 flow key；不含 JSON、connect token、
SignKey 或 reusable frame。`auth_id` 不是外部凭据，可用于归因。

### E12-M 完成条件

- 256 status 分类测试通过；
- 全部 arms 在 paused time 下确定性通过；
- 每个 attempt 的 wire 次数、flush 完成、stats、waiter 唤醒次数精确匹配；
- retry budget、overall deadline、VIP update 和 close 均能取消；
- production 默认 profile 的现有非零 status 行为保持回归测试；
- 只有取得 E12-L 后，才讨论将 budget 和真实 delay 设为非零 production 默认值。

## 实施顺序

1. V1-A/V1-B/V1-D：先锁定读取与握手边界。
2. V1-C/V1-E：再处理大写入和错误传播，避免测试 harness 隐藏短写。
3. V2-A/V2-B：锁定 pure parser consumed 语义。
4. V2-C/V2-D：扩展现有 mock peer，闭合 reader task 与 dispatch。
5. E12-M 纯 status classifier。
6. E12-M 可注入 policy、conntrack 状态和 scheduler。
7. E12-M 端到端 arms；production profile 保持 disabled。
8. 最终运行 workspace fmt、test、clippy 和 `git diff --check`。

## 启动实验

三组实验都是离线、确定性的 Rust 测试，不读取 SID、Cookie 或线路配置。测试名使用稳定前缀，
可从仓库根目录随时独立启动：

```bash
# V1：TCP framed stream、短读写、大写入、握手预读和关闭错误
cargo test -p atrust-tcp v1_ -- --nocapture

# V2：L3 frame 前缀、粘包、双格式 0x94 和端到端 dispatch
cargo test -p atrust-protocol -p atrust-l3 v2_ -- --nocapture

# E12-M：0x93 transient status、有限重试、并发去重和取消
cargo test -p atrust-l3 e12_m_ -- --nocapture

# 三组连续执行
cargo test -p atrust-tcp v1_ -- --nocapture && \
  cargo test -p atrust-protocol -p atrust-l3 v2_ -- --nocapture && \
  cargo test -p atrust-l3 e12_m_ -- --nocapture
```

`E12-M` 只通过测试显式调用 `L3Session::start_with_config` 启用实验 policy；生产入口
`L3Session::start` 和 `L3Session::establish` 始终使用 `L3AuthRetryConfig::disabled()`。

## 执行记录

### 2026-08-14：M 层人工复核

用户从仓库根目录手动执行了上述三组稳定前缀命令：

| 实验 | 结果 | 备注 |
|---|---:|---|
| V1 | 13 passed、0 failed | 16 个非 V1 测试被过滤；总耗时 1.58 s |
| V2 | 10 passed、0 failed | L3 unit 3、L3 integration 3、protocol unit 4 |
| V2 consistency rerun | 10 passed、0 failed | 不带 `--nocapture` 再次通过 |
| E12-M | 12 passed、0 failed | 256-status classifier 1、mock session arms 11 |

该记录闭合的是 Hermes fixture/mock 的 M 层。它证明稳定启动命令和确定性 harness 在用户环境中
可复现，不证明西电网关会发送 transient status、token-framed `0x94` 或其他条件化 wire 输入。
