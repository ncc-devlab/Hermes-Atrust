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
3. `primary_nodes` 取每组首地址（无探测）；日志只计数量/标志，不打印敏感值。
4. **已完成（代码）：**
   - Cookie 路径 SID 导出（`extract_sid_from_cookies` / `sid` > `sid-legacy` + `*.sig` 存在性）；
   - `SessionMaterial { sid, device_id, connection_id, sign_key, username, … }`；
   - 导入 Cookie 值可按名回读（仅 jar 内，不进日志）。
5. **仍待：**
   - 确认 Cookie SID 是否即隧道 init JSON 的 SID（抓包对照）；
   - SignKey 服务端注册/绑定；
   - 可选：gitignored 会话持久化。

### Phase B — 单节点 TLS 冒烟（无业务隧道）

目标：证明「节点 host:port + 严格 TLS」可连，**不发送** init JSON。

1. `atrust-probe node-probe --group <id>|--primary`
2. 对每个候选：`TcpStream` + `rustls`（默认 Verify；仅私有网关显式 insecure）
3. 记录：成功/超时/证书错误；**不**发送 `05 01 81...`
4. 后续再加 3 次短 TCP 时延选优（对齐 Go `pingNum=3`）

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

### Phase D — L3（延后）

在 TCP 路径稳定后：

1. 确认 Get-IP `0x0053` 长度语义、SignKey 绑定、下行 `0x94` 双格式判别；
2. SID 总连接认证 + VIP；
3. 五元组鉴权 / conntrack / connectToken；
4. 再谈 TUN / DNS / 路由。

EasyConnect 不在本规划内。

## 建议 crate / 模块边界

```text
atrust-auth          会话、clientResource、节点解析（无拨号）
atrust-protocol      帧编解码、签名、wire DTO
hermes-transport     HTTP + `connect_tls` / `NodeTlsStream`
atrust-tcp           DialTCP 状态机 + 帧化 TcpTunnel（无默认 live）
atrust-l3（更后）    L3 总连接与数据帧
atrust-probe         人工诊断子命令：auth / cas-login / client-resource / node-probe /（tcp-dial 待加）
```

## 测试门禁（按阶段加）

| 阶段 | 必测 |
| --- | --- |
| A | 节点解析单测（已有）；资源 golden；可选 live 仅计数 |
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
6. **下一步：** 西电 `node-probe --primary` live（TLS only，不发 init）。
7. Cookie SID ↔ init JSON SID 抓包对照；SignKey 服务端策略确认。
8. 可选：gitignored 会话持久化，支撑跨进程 node-probe / tcp-dial。
9. 单一目标 `tcp-dial` live（ignored；需 CLI 接线）。
