# 代理运行时与验证边界

状态日期：2026-11-03。

## 本轮实现

以本地 `zju-connect` 的 client/stack/dial/resolve/service 分层为参考，保留 Hermes 的协议、认证和资源边界，新增 `atrust-net` 与 `hermes-proxy`。没有引入 Go FFI，也没有从兼容客户端直接推断西电网关的续期行为。

| 参考能力 | Hermes 实现 |
|---|---|
| client、网络栈、服务分层 | `AtrustClient` → `NetworkStack` / `ProxyConnector` → SOCKS5、HTTP、DNS |
| 当前凭据与生命周期 | `replace_session` 先验证后切换；独立控制面 jar、资源、L3 managers 和后台任务；旧状态永久退休 |
| 独立底层出口 | 可注入 `UnderlayDialer`；`SystemUnderlay` 支持显式源地址和 Linux 接口；HTTP 使用对应出口设置 |
| DNS 与域名身份 | 静态策略地址、远端 A 查询、UDP 超时/截断后 TCP 回退、TTL 缓存、同名查询合并 |
| Fake IP / 地址策略 | 保留 `AddrPretend`；Fake IP 反向还原域名；真实共享 IP 有二义时拒绝错误归属 |
| TCP 路径策略 | 保留 `EnableTCPPrefL3`；原生隧道或宿主提供的 L3 TCP 栈 |
| 节点维护 | 首次使用及周期性 TLS-only 探测、有限并发、结果缓存、失败候选回退、L3 重连退避 |
| 资源索引 | IP 区间树、域名后缀树；保留 Hermes 的 specificity 和原始顺序兜底 |

## 修复与生命周期

1. L3 writer 在写入和 flush 中监听关闭；写入有 20 秒期限，关闭加入任务有时间上限。
2. 至少三次已实际写出的心跳未获 ACK，且达到三个心跳周期的接收期限后关闭连接；排队中的探针不计入漏 ACK。保留已有 25 秒默认节奏；这属于客户端失联策略，不是新测得的网关协议常量。
3. 在读取端口前拒绝所有 IPv4 分片，包括 MF 首片。
4. 相同五元组的 `appId`/node group 变化会退休旧授权；迟到的回复和旧超时不得删除新授权。进行中的旧鉴权收到单流失败，不触发整组隧道重连。
5. SID 被网关拒绝后阻止新的核心、代理和 DNS 操作；需要验证过的新会话才能恢复。
6. 关闭、会话切换、资源删除会退休旧 L3 owner；外部保留旧 manager 也无法重连。关闭请求同步发出，后续任务回收可异步完成。
7. 会话文件使用同目录临时文件、`0600`、flush/fsync 和 rename 替换；已打开的读取者继续看到完整旧版本。
8. conntrack 清理在包路径上摊销，避免每个包扫描整表，也避免满表时淘汰仍在使用的现有 flow。

每个 UDP 连接分配独立源端口和有界回包队列。订阅在发送前建立，按反向五元组分发，不与其他连接或原始包消费者竞争。VIP/会话变更会关闭订阅；已建立的数据报对象返回错误，调用方重新拨号。接收侧校验 IP/UDP 长度、地址、端口和 checksum。

## DNS 与 Fake IP

缓存以 `(session_epoch, resource_generation, hostname)` 分键，使用响应 TTL 并受配置上限约束。只接受请求 ID、问题名、类型和 class 匹配的回复；跟踪回答区中的有界 CNAME 链，不缓存无关 additional 地址。错误和截断响应不写入正向缓存。

Fake IP 使用 `198.18.0.0/15`，同时受 TTL、会话和资源代际约束。一个池生命周期内不把已使用的地址重新分配给另一个域名；过期或未知的 Fake IP 会被拒绝。池有容量上限，耗尽时报错。

`AddrPretend=false` 返回真实地址并保留域名关联。共享地址涉及多个可用域名资源且没有独立 IP 授权时，IP 本身无法确定原域名，拨号会拒绝该二义输入；可通过显式域名调用。

原生 aTrust TCP 的域名目的地直接进入隧道握手，不强制提前 DNS。UDP 和宿主 L3 TCP 使用真实 IPv4，同时在授权中携带保留的域名。

本地 DNS 当前只回答 A；其他类型返回 NODATA。它不是 DNSSEC 验证器，不实现 DoH/DoT 或完整递归解析。默认使用资源表的 DNS，或显式配置的服务器；服务器目的地仍经过资源校验。

## 宿主接口与限制

`AtrustStack::new(client)` 提供原生 TCP 和 L3 UDP。`with_l3_tcp(Arc<dyn NetworkStack>)` 接入宿主已有的 TCP/IP 栈。未提供时，要求 L3 的 TCP 资源返回 `Unsupported`，不忽略服务端路径偏好。

`SystemUnderlay::update` 对下一次连接生效，已有连接保留旧绑定；宿主可在出口变化后请求重连。默认系统 DNS 仍由操作系统管理。接入 TUN 的宿主需保证自己的控制面、数据节点和主机名解析绕过 TUN，或注入带独立解析/路由能力的拨号器。当前没有自动网卡探测、TUN 安装或系统路由回滚。

工作区当前仍包含 Unix 专属会话文件与 CLI 代码；本轮仅在当前 Linux 环境验证，不宣称 Windows 全工作区可构建。

## 验证

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

本地代理集成测试需要监听回环 TCP/UDP 端口。真实网关测试继续保持 ignore 和显式启用门槛，不会自动登录、重复短信或执行 MFA。

新增回归覆盖阻塞写入、心跳丢失、分片、资源变更重鉴权、会话替换/拒绝/退休、原子文件、出口注入、节点缓存/退避、索引与线性结果一致性、UDP 校验、DNS 合并/TTL/代际失效、Fake IP，以及代理认证、半关闭、HTTP 粘连数据、UDP ASSOCIATE 和 DNS 双协议监听。

2026-11-03 最终离线验证：323 项测试通过、0 失败、1 项真实网关测试保持忽略；工作区 Clippy（`-D warnings`）、格式检查和 `serve --help` 冒烟通过。

历史 L0 证据仍只覆盖当时的西电部署及样本。新增 `serve` 整体、域名 L3 授权、真实网关异常恢复及跨 SID 到期的运行仍需独立 live 验收；MTU/分片/大包、token-framed 下行等边界仍见 [未决问题](open-questions.md)。
