# aTrust 隧道建立规划

本文描述在控制面（会话 + `clientResource` + 节点解析）就绪后，如何分阶段建立
数据面。**当前代码禁止在未确认会话材料前拨号。**

## 前置条件（已有 / 待补）

| 材料 | 状态 | 说明 |
| --- | --- | --- |
| 网关 Cookie 会话 | **已实测（Xidian 2026-07-27）** | 浏览器关窗后收割 10 cookies |
| `onlineInfo` | **已实测** | ~27ms，`username_present=true` |
| `clientResource` | **已实测** | 200，~1.3MB / 12.5s；1361 IP / 523 域名 |
| 节点地址解析 | **已实测** | 1 major 组、2 endpoints、0 sdpc placeholder |
| 节点可达性探测 | 代码有 TLS 冒烟；**西电未 live** | TCP connect / 时延选优（对照 Go `getBestNodes`） |
| SID | **已导出并实测** | Cookie `sid` + `sid.sig`；是否即 init SID 仍待对照 |
| DeviceID | 已生成 | 客户端随机；持久化与 `reportEnv` 对齐仍待做 |
| ConnectionID | 已生成 | `UPPER(MD5(deviceId)) + "-" + unix_micros` |
| SignKey | **临时客户端随机** | `SignKey` 32 字节随机，`sign_key_provisional=true`；服务端注册未确认 |
| Username | 可选 | `onlineInfo` 可提供；进签名 JSON |

未解决「SID / SignKey 来源」前，**不得**把 TCP/L3 当作稳定 API 向上封装。

## 阶段划分

### Phase A — 材料与节点表（当前 → 下一迭代）

1. Cookie 会话后拉 `clientResource`（`cas-login` 已同进程触发）。
2. `resolve_node_groups(gateway)` 得到每组 `host:port` 列表。
3. `all_nodes` 提供每组全部地址用于探测；`primary_nodes` 仅供显式首节点选择。
   节点地址不是会话秘密，诊断探测会记录组 ID 和完整 `host:port`。
4. **已完成（代码）：**
   - Cookie 路径 SID 导出（`extract_sid_from_cookies` / `sid` > `sid-legacy` + `*.sig` 存在性）；
   - `SessionMaterial { sid, device_id, connection_id, sign_key, username, … }`；
   - 导入 Cookie 值可按名回读（仅 jar 内，不进日志）。
5. **仍待：**
   - 确认 Cookie SID 是否即隧道 init JSON 的 SID（抓包对照）；
   - SignKey 服务端注册/绑定。
6. **已完成（2026-07-30）：** 跨进程会话持久化 `--session-file`（`atrust_auth::StoredSession`，
   `0600`）。`cas-login` / `password` 写入，`tcp-dial` / `node-probe` / `client-resource` 读取，
   DeviceID / ConnectionID / SignKey 原样恢复而非重新随机。

### Phase B — 单节点 TLS 冒烟（无业务隧道）

目标：证明「节点 host:port + 严格 TLS」可连，**不发送** init JSON。

1. `atrust-probe node-probe`，或 `cas-login --probe-nodes`，默认探测每组全部端点；
   `node-probe --primary` 可显式缩减为每组第一个端点。同进程路径免去会话持久化。
2. 对每个候选：`TcpStream` + `rustls`（默认 Verify；仅私有网关显式 insecure）
3. 记录：成功/超时/证书错误；**不**发送 `05 01 81...`（`probe_nodes_tls` 共享实现）
4. 后续再加 3 次短 TCP 时延选优（对齐 Go `pingNum=3`）

**状态（2026-07-28）：** 已接线，外网跑出 `:441` TCP 超时（网络层不可达）。代码正确，
待校内网络位置复跑取 `Ok`。

### Phase C — 最小 TCP 隧道（单一受控目标）

前置：Phase A 材料齐备 + Phase B 至少一节点可连。

对照 Go `DialTCP` / `docs/atrust-protocol-analysis.md` §4：

```text
TLS 到节点
  -> 05 01 81 53 03 <u16-be len> <signed JSON>
  -> 目标地址帧（IPv4 或域名）
  -> 等待 53 00 ... OK（可忽略中间 05 81）
  -> 01 00 00 00 探测
  -> 05 00 成功
  -> 应用数据：01 00 <u16> <payload>
  -> 关闭：01 01 00 00
```

实现约束：

1. ~~新 crate~~ **已落地 `atrust-tcp`**：`dial_tcp` / `complete_handshake` / `TcpTunnel`（AsyncRead+Write 帧）。
2. JSON 必须用 `atrust_protocol::to_wire_json` 固定字段顺序；签名用
   `calculate_request_signature`（HMAC-SHA256 大写 hex）。
3. **禁止** `fmt::sprintf` 拼签名 JSON（Go 现网有此模式，Rust 重写必须强类型）。
4. 首个联调目标：校内已知 HTTP 端口或用户指定 `host:port`，只验证读写回环。
5. 超时、取消、半关闭、short-write：本地 mock duplex 握手 + 应用帧回环已单测；live 仍 ignored。

**状态（2026-07-29）：已 live 打通（公网参考服务端）。** `atrust-probe tcp-dial` 对
`Hermes-aTrust-Server`（`103.99.178.36`，control `:8443` / data `:8444`）完成：
psw 登录 → jar 导出 SID → `SessionMaterial`（`sign_key_provisional=true`）→ `clientResource`
200 → 拨号 `:8444` → **握手成功**（init+HMAC 签名帧被接受 → 目标帧 → `53 00 OK` → `01 00 00 00`
探测 → `05 00`）→ 应用数据回环（`GET /` → 381B，`looks_like_http=true`，服务端侧代拨
`1.1.1.1:80`）→ 干净关闭。证实：客户端临时随机 SignKey 模型正确（服务端 UnboundAccepted
兼容放行）、帧与状态机逐字节互通。节点 `--node` 覆盖为必需（`policy.json` 广告的是
服务端本机 `127.0.0.1:8444`）。拨号 TLS connect+handshake 约 6.3s（链路较慢），超时预算宜放宽。

### Phase D — L3（Get-IP 探针已落地）

在 TCP 路径稳定后：

1. Get-IP 使用实际 SID JSON 长度编码；典型 73 字节 SID 对应 `0x0053`，待 Xidian
   原生 live 确认服务端不依赖固定长度；
2. 确认 SignKey 绑定；`0x94` 双格式已编码在 `atrust-protocol::l3_frame`；
3. SID 总连接认证 + VIP；
4. 五元组鉴权 / conntrack / connectToken；
5. 再谈 TUN / DNS / 路由。

EasyConnect 不在本规划内。

#### 进入 L3 前的闸门（2026-07-30 评估）

**必须先在西电真机确认**（否则 L3 代码形状会猜错）：

1. **SignKey 是否真被校验 —— 1 号闸门。** 目前 `sign_key_provisional=true`，唯一通过的
   握手来自参考服务端 `sign_key_hex=None → UnboundAccepted`。§3.3 的 `0x13` 逐流鉴权
   同样以 HMAC-SHA256 覆盖整段 JSON 字节串，若西电真校验，第一个五元组即失败。
   最便宜的判定：西电 `tcp-dial` 各跑一次正常 key 与改 1 bit 的 key——都通过=不校验；
   都拒=key 另有来源；一通一拒=必须先解决绑定。
2. **西电原生 `tcp-dial` live**（Phase C 只对公网参考服务端通过）。带两个未知进 L3
   无法二分定位。会话持久化落地后此条已无阻塞。
3. **Get-IP 西电 live 复跑**，并保留 `53 00` 响应 JSON：`atrust-l3` 目前读完即丢，
   而该 JSON 可能带 VIP / 掩码 / second VIP 线索，应落 trace。
4. **`0x94` 下行双格式**：已落地为 body 首 `u16-be n`，`0 < n ≤ 4096` 为长度前缀、否则 token 帧（见 `atrust-protocol::l3_frame`）。
5. **`tcp:` vs `tcp://`**：TCP init 用 `tcp://`（`tcp_init.rs`），§3.3 的 L3 鉴权写
   `tcp:10.0.0.1:443`。~~L3 独立 wire DTO~~（`build_signed_l3_auth_json`）；真机 `url` 形态仍待抓包。

**可离线先做完、不被校内网络阻塞：**

1. ~~**资源匹配器（最大一块前置代码）**~~ **已完成（2026-07-30）：**
   `atrust_auth::ResourceIndex`（`routing.rs`）。`(dstIP, protocol, dstPort)` → `appId` +
   `nodeGroupId`，未命中返回 `None`（即不得进 VPN）；域名目标走域名表且**不**本地先解析，
   避免丢失域名资源语义（§6.4）。重叠表按「地址范围最窄 → 端口最窄 → 精确协议先于 `all`
   → 服务端原始顺序」定序，`match_ip_all` / `match_domain_all` 暴露全部候选供抓包对照
   （服务端真实优先级仍未确认，见架构文档未决项 7）。17 个单测含一条从真实 JSON body
   解析到匹配的端到端用例。诊断入口：
   `atrust-probe resource-match --resource-file <body.json> --target <host:port> [--protocol udp|icmp] [--show-all]`，
   配合 `client-resource --save-body` 可完全离线迭代。`tcp-dial` 会在拨号前记录匹配结果，
   并在与 `--app-id` 不一致时打 WARN（仅观测，不改变拨号行为）。
2. ~~会话持久化~~（已完成，见执行清单第 8 项）。
3. ~~L3 帧 codec~~：`encode_l3_data_req` / `encode_l3_auth_req` / `encode_l3_heartbeat_req` /
   `0x94` 双格式解码 / `05 95` 头判定（`atrust-protocol::l3_frame`）。property/fuzz 仍待。
4. ~~conntrack + connectToken 状态机骨架~~：`FlowKey` / `auth_id` / `try_start_auth` /
   `mark_auth` / `L3_AUTH_TIMEOUT=8s`（`atrust-l3::conntrack`）。**未**接读循环、驱逐、
   重试一次、超时丢包。
5. IPv4 包解析（atype / protocol / 五元组），只做 IPv4，与 Go `processIPV4` 一致。
6. 节点时延选优（`pingNum=3`）：L3 每个 node group 缓存一条长连接，选错代价大于 Phase C。
7. 超时预算复核：实测 TLS connect+handshake 约 6.3s，而鉴权超时 8s，叠加会误判为鉴权失败。
8. 全双工 L3 会话：TLS 长连接 + 读循环分发 `0x93`/`0x94`/`0x95` + 心跳任务 + 手工 IP 包往返。

**范围边界：** L3 里程碑止于「总连接认证 + VIP + 一条五元组鉴权 + 一个数据包往返」，
用手工构造 IP 包验证，**不接 TUN / DNS / 路由**——TUN 一旦接上，故障域从协议扩到内核
路由表，无法二分。

## 建议 crate / 模块边界

```text
atrust-auth          会话、会话存储、clientResource、节点解析、资源匹配（无拨号）
atrust-protocol      帧编解码、签名、wire DTO
hermes-transport     HTTP + `connect_tls` / `NodeTlsStream`
atrust-tcp           DialTCP 状态机 + 帧化 TcpTunnel（无默认 live）
atrust-l3           Get-IP + conntrack/auth；后续全双工 L3 会话（无 TUN）
atrust-probe         人工诊断子命令：auth / cas-login / client-resource / resource-match
                     / node-probe / tcp-dial
```

## 测试门禁（按阶段加）

| 阶段 | 必测 |
| --- | --- |
| A | 节点解析单测（已有）；资源 golden；资源匹配单测（已有，17 项）；可选 live 仅计数 |
| B | mock TCP 可连；TLS 策略默认 Verify；超时 |
| C | init 帧 golden（与 Go 逐字节或固定 fixture）；握手状态机；应用帧；ignored live |
| D | codec property / fuzz；L3 模拟对端拆包 |

真实登录、真实拨号：**永不**进入默认 CI。

## 风险与未确认关卡

1. **SID 获取路径**：Cookie-only 登录后 SID 是否在 Cookie 值、onlineInfo 扩展字段或其它 controller API。
2. **SignKey**：纯客户端随机 vs 服务端下发/注册。
3. **URL 形式**：TCP JSON 中 `tcp://` vs `tcp:`（架构文档列为关卡）。
4. **私有节点证书**：默认 Verify；失败时诊断，不默认 insecure。
5. **签名字段顺序**：任何 map 序列化都会破坏 HMAC。

## 近期执行清单

1. ~~西电人工 `cas-login`，确认 `probe.client_resource` + `probe.nodes_summary` 非零。~~
   **已完成（2026-07-27 完整复测）：** 1361 IP / 523 域名 / 1 组 2 节点；
   `clientResource` body ~1.3MB / 12.5s；`probe.session_material` 全字段 present（SignKey provisional）。
2. ~~从网关 Cookie 导出 SID + 落地 `SessionMaterial`（含 DeviceID / ConnectionID / 临时 SignKey）。~~
3. ~~`node-probe` TLS-only 冒烟（`probe_node_tls` + CLI，默认 Verify；支持 `--address`）。~~
4. ~~TCP init / target / app 帧 codec（`atrust-protocol`）。~~
5. ~~TCP 握手状态机 + 应用帧 I/O（`atrust-tcp`，mock duplex 单测）。~~
6. ~~西电 `node-probe --primary` live（TLS only，不发 init）。~~
   **已接线并 live（2026-07-28，外网）：** `cas-login --probe-nodes` 同进程收割后
   探测 primary 节点；`:441` **TCP connect 超时**（外网网络层不可达，非 TLS/证书）。
   `node-probe --address` 独立路径同样因外网超时。**待校内复跑**取 `outcome=Ok` 与时延基线。
7. Cookie SID ↔ init JSON SID 抓包对照；SignKey 服务端策略确认。
   **参考服务端已确认（2026-07-29）：** SID 即 psw 响应 `Set-Cookie: sid=`，`session_cookie_value`
   从 jar 导出后原样进 init JSON；服务端 `sign_key_hex=None` → UnboundAccepted 放行。西电真机仍待抓包。
8. ~~可选：gitignored 会话持久化，支撑跨进程 node-probe / tcp-dial。~~
   **已完成（2026-07-30）：** `--session-file`（`StoredSession`，`0600`）。`cas-login` /
   `password` 写，`tcp-dial` / `node-probe` / `client-resource` 读。这也解开了 `tcp-dial`
   写死密码登录的限制：CAS + MFA 网关现在可以直接复用浏览器收割的会话拨号。
   DeviceID / ConnectionID / SignKey 恢复时原样使用——若服务端把 DeviceID 绑到会话，
   同进程路径会掩盖问题，持久化后才会暴露。
9. ~~单一目标 `tcp-dial` live（ignored；需 CLI 接线）。~~
   **已完成（2026-07-29）：** `tcp-dial` 子命令已接线，对公网参考服务端 live 打通（见 Phase C 状态）。
10. SID-only Get-IP 原生探针。
    **代码已完成（2026-07-29）：** `atrust-l3` 使用动态 JSON 长度和有界响应读取；
    `cas-login --get-ip-node <host:port>` 可在同一 Cookie 会话中执行一次 Get-IP，不启动
    L3 总连接、TUN、DNS 或路由。mock 对端测试已通过。
    **解析对齐（2026-07-30）：** Xidian live 返回前导 `05 d0` method ack 时不再
    `UnexpectedHeader`；循环接受 `05 d0` / `53 00` / `05 00`。失败写 trace
    `get_ip_failed`。数据节点自签 `CN=sdp` 需 `--insecure-tls` 或 pin。
    Xidian Get-IP live 成功（`probe.get_ip.succeeded`）仍待人工复跑确认。
