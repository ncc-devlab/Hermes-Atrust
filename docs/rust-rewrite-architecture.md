# Hermes Rust 重写架构

本文记录 aTrust 重写期间必须保持的依赖边界、测试门禁和协议验证关卡。当前阶段
只实现 aTrust；EasyConnect 不参与现阶段 API 设计，也不添加未经需要证明的兼容层。

## 依赖方向

```text
application
  -> atrust-client
      -> auth / resource / discovery / tcp / l3
          -> atrust-protocol
          -> hermes-transport
          -> hermes-model
```

当前已经落地：

- `hermes-model`：经过校验的公共强类型和敏感值封装；
- `atrust-protocol`：纯线协议 JSON 和签名基础，不包含网络、配置、日志或异步运行时。
- `hermes-logging`：应用入口使用的统一 `tracing` 订阅器，支持 compact 与 JSON 输出；
- `hermes-transport`：可替换的异步 HTTP 接口、受限响应读取和显式 TLS 策略；
- `atrust-auth`：`authConfig`、RSA 密码主认证、CAS challenge 和严格回调校验；
  `clientResource` 解析、节点解析、跨进程会话存储，以及纯离线的资源匹配器
  （五元组 → `appId` / `nodeGroupId`，不拨号）；
- `atrust-browser`：可复用的 WebDriver/BiDi 复杂 CAS/MFA 人工登录、网关 Cookie
  收割和全保真 trace（`0600`，见强制边界 12）；
- `atrust-tcp`：单连接 TCP 隧道握手和帧化 I/O；
- `atrust-l3`：SID-only Get-IP 实验探针；尚不包含总连接、单流授权或数据转发；
- `atrust-probe`：组合上述库进行真实对端诊断，不再拥有浏览器协议实现。

只有存在实际实现时才新增 crate，禁止先创建无职责的空壳模块。

## 强制边界

1. 高层可以控制网关、目标地址、TLS 策略、网卡、超时、重试、节点选择和分流策略。
2. 帧版本、命令字、字段顺序、长度编码和签名算法不能成为普通运行参数。
3. 随服务端版本变化的线协议差异必须进入经过测试的 `ProtocolProfile`，不能使用任意
   字节配置。
4. 协议 DTO 与领域模型分开。外部 JSON 先进入 wire DTO，再通过受校验构造器转成
   领域类型。
5. 强类型不直接派生可绕过构造器的 `Deserialize`。空 SID、非法 endpoint 等输入
   必须在边界被拒绝。
6. 协议签名基于确定的 JSON 字节。禁止把待签名对象转换为无序 map 后再序列化。
7. 密码、Cookie、SID、SignKey 和连接 token 不得出现在 `Debug` 或普通日志中。
8. 所有异步网络状态机必须支持超时、取消和确定性关闭。
9. 业务模块统一通过 `tracing` 发出结构化事件；只有应用入口可以初始化 logger。
10. transport 日志只记录方法、主机、状态、耗时和长度，不记录 query、Header 或正文。
11. 分发应用默认使用 `warn` 过滤器；需要详细诊断时由操作者通过 `HERMES_LOG`
    显式启用 `info`/`debug`。
12. **日志流与 trace 文件是两类产物，保护方式不同。** 日志流（stderr / `--log-file`）
    只记录存在性、计数、状态码和耗时，永远不含凭据，因此在任何过滤级别下都安全。
    `--browser-trace-file` 指向的 trace 则**不做脱敏**：Cookie 值、SID、SignKey、
    DeviceID、完整 URL、请求正文（含 CAS 凭据 POST）一律原样写入，用途是与抓包逐字节
    对照。该文件强制 `0600`，由目录权限保护，启用时打一条 `warn` 提示；它是凭据材料，
    不得随报告分发。脱敏会让协议联调无法定位字段级差异，这一权衡是刻意的。

## 测试层次

每个协议模块至少需要：

1. 纯单元测试；
2. 与 Go 实现或脱敏抓包逐字节一致的 golden test；
3. 本地模拟对端测试，包括拆包、粘包、截断、超长、超时和未知状态；
4. 显式启用的真实对端测试。

工作区基础门禁：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

真实测试必须同时满足 `#[ignore]` 和显式环境开关。独立的 `atrust-probe` 用于人工
诊断和抓包，测试代码不得自动重复密码、验证码或短信请求。

学校认证中的验证码、滑块、MFA 和二次认证属于人工交互边界。协议核心不得识别、
代填或绕过这些认证因子。部署专属约束和联调进度见
[`xidian-atrust-integration.md`](xidian-atrust-integration.md)。

## 未确认协议关卡

以下事实未经真实对端和抓包确认前，不得当作稳定协议继续向上封装：

1. Go Get-IP 请求中的 `0x0053` 是否为固定值，还是应由 SID JSON 长度动态计算；
2. L3 `0x94` 下行数据两种格式应通过哪个明确字段区分，不能沿用数值区间猜测；
3. SignKey 是客户端生成、服务端下发还是经其它接口注册，以及它与 SID 的绑定关系；
4. second VIP 的请求条件和用途；
5. L3 flow key 是否必须包含协议号；
6. L3 授权 URL 应使用 `tcp:` 还是 `tcp://`；
7. **资源表重叠时服务端的优先级规则**。Hermes 的 `ResourceIndex` 目前按「地址范围最窄
   → 端口范围最窄 → 精确协议先于 `all` → 服务端原始顺序」排序取第一名，并通过
   `match_ip_all` / `match_domain_all` 暴露全部候选供抓包对照。若证实服务端是
   first-match-wins，只需改 `ResourceIndex::build` 的排序；
8. **ICMP 如何命中资源**。资源表只有 `tcp` / `udp` / `all` 三种协议值，Hermes 现规定
   ICMP 只能命中 `all` 且不做端口比较，这一条尚未经真机验证；
9. **域名通配符语义**。现按 `*.example.edu` 覆盖任意子域但不含 apex 实现，
   服务端是否同此仍待确认。

## 当前里程碑

第一个真实联调里程碑只包含：

```text
authConfig                              [已完成]
→ 浏览器完成 IDS + aTrust 多步 MFA      [Xidian 2026-07-27 完整实测]
→ 人工关窗后收割网关 Cookie 会话        [10 cookies；portal_hits=2]
→ onlineInfo 会话确认                   [~27ms；LoggedIn]
→ SessionMaterial                       [sid/device/conn/sign_key/user present；SignKey provisional]
→ clientResource                        [200；~1.3MB/12.5s；1361 IP / 523 域名 / 1 节点组]
→ 节点地址解析（无探测）               [2 endpoints，major 存在]
→ node-probe TLS-only                   [已接线并 live；外网 :441 TCP 超时，待校内复跑]
→ TCP 帧 codec                          [已实现]
→ TCP DialTCP 握手 + 应用帧             [已实现；对公网参考服务端 live 打通]
```

**控制面里程碑已闭环（2026-07-27）。数据面探测已接上（2026-07-28）。数据面 TCP 隧道已 live
打通（2026-07-29，公网参考服务端）。** Phase B 已 live（`cas-login --probe-nodes` 同进程），
外网因网络层不可达超时；节点 `:441` 待校内复跑。Phase C 已用 `atrust-probe tcp-dial` 对
`Hermes-aTrust-Server` 完成 psw 登录 → SID 导出 → 握手 → 应用数据回环 → 关闭的端到端验证；
证实临时随机 SignKey 模型正确、帧逐字节互通。**西电真机数据面仍待校内抓包对照**（SID/SignKey
绑定、`0x0053` 长度语义、`0x94` 双格式）。隧道分阶段规划见 [`tunnel-plan.md`](tunnel-plan.md)。

学校差异（IDS 表单、滑块、SMS UI）只存在于浏览器/UI 适配层。协议层只接受：

- 网关 origin 的 Cookie 会话（主路径）；
- 可选的、尚未被浏览器消费的 service/portal ticket（辅路径，Xidian 交互登录默认不用）。

## 联调记录

当前 aTrust 联调目标为 `atrust.xidian.edu.cn:443`。地址只存在于联调命令和部署
配置中，不进入协议 crate 的常量。

### 2026-07-25：西电 authConfig 只读探测

使用默认的严格证书校验执行：

```bash
cargo run -p atrust-probe -- \
  --host atrust.xidian.edu.cn \
  auth-config
```

请求成功，服务端处于未登录状态并返回两个认证入口：

| 登录域 | 认证类型 | 名称 |
| --- | --- | --- |
| `cas42187` | `auth/cas` | 统一身份认证 |
| `local` | `auth/psw` | Local Password Auth |

该网关的证书可通过当前系统/Web PKI 校验，后续联调默认禁止使用 `--insecure-tls`。
本次请求未携带账号、Cookie 或验证码，未建立隧道。

### 2026-07-25：西电主认证探测

- `local` 密码端点可达，初次请求返回图形验证码挑战；
- 对照客户端完成验证码后，服务端报告凭据不正确并提示剩余 9 次尝试；
- 为避免账户锁定，未继续重试，也未将账号、密码、验证码或响应正文写入项目；
- Rust 将非零业务码与 `graphCheckCodeEnable` 组合建模为挑战，不自动重试；
- `cas42187` 已确认跳转至 `ids.xidian.edu.cn/authserver/login`，其 `service` 指回
  aTrust 的 `/passport/v1/auth/cas?sfDomain=cas42187`；
- Xidian 统一认证包含必须人工参与的两步认证，第二步需要输入验证码；
- 独立 Chrome 联调已跑通 IDS + aTrust SMS，并在人工关窗后建立 Cookie 会话；
- `onlineInfo` 在导入网关 Cookie 后成功；`clientResource` 已在浏览器侧观察到调用；
- 首次 CAS/portal 不得提前收割；portal ticket 被浏览器消费后不可再 `reportEnv`。

### 2026-07-27：控制面闭环（完整 cas-login）

人工完成 IDS + SMS 后关窗，同进程：

- WebDriver：每次新 Chrome profile，避免 SingletonLock → 500；
- 收割 10 个网关 Cookie；`authConfig` → `LoggedIn`；`onlineInfo` 成功；
- `probe.session_material` 全字段 present（`sign_key_provisional=true`）；
- `clientResource` **200**，约 1.3MB / 12.5s → 1361 IP / 523 域名 / 1 组 2 节点；
- 此前 `clientResource` “超时”在完整会话下未复现。

详细证据与下一阶段任务见
[`xidian-atrust-integration.md`](xidian-atrust-integration.md)。

## 未完成部分

### 认证控制面

- Cookie jar 的导出、过期、持久化与更可审计的会话生命周期；
- 网关 Cookie 受限导入已实现；需补充导入后的 jar 可观测与隔离测试；
- 回调参数绑定与严格校验已有单元测试，仍需脱敏 golden fixture；
- 产品级 `authCheck`/SMS 状态机（Xidian 当前把 MFA 全部留在浏览器内完成）；
- `reportEnv`/`onlineInfo`/ `clientResource` API 与西电实测已完成；隧道未建；
- 设备查询、授信和取消授信；
- SID ↔ 隧道 init 对照、SignKey 服务端绑定、材料跨进程持久化。

### 资源和节点

- ~~IP/CIDR/范围、端口范围、协议和域名资源的严格解析~~（已实现并西电实测）；
- 确定性的资源冲突优先级和无匹配拒绝策略；
- ~~DNS 配置、major node group 和节点地址解析~~（解析已实现；西电 DNS option 为空）；
- 节点 TCP/TLS **live 探测**、评分、健康缓存和周期更新（TLS 冒烟代码就绪）；
- IPv6 节点地址及服务端资源能力判定。

### 底层传输

- Tokio TCP/TLS connector 抽象；
- Linux、macOS、Windows 的指定网卡绑定；
- 自动探测底层网卡及网络切换后的重新探测；
- VPN 服务端和虚拟 IP 的路由排除；
- TCP/TLS 分阶段超时、取消、重试和退避；
- 自定义 CA、证书固定及更细粒度 TLS 诊断。

### TCP 隧道

- ~~初始化 JSON DTO、确定性签名~~（已实现）；golden vector 仍待补（与脱敏抓包逐字节）；
- ~~IPv4/域名目标地址帧~~（已实现）；
- ~~`05 81`、`53 00` 和 connect status 状态机~~（已实现并 live 验证）；
- ~~应用数据帧~~（已实现并 live 回环）；半关闭、服务端关闭、short-write 的对端行为测试仍待补；
- ~~受控 HTTP 目标的真实联调~~（已对公网参考服务端完成；西电真机仍待）。

### L3 隧道

- Get-IP codec 已落地并按实际 SID JSON 动态编码长度；Xidian 原生 live 待执行；
- SID 总连接认证和虚拟 IP 解析；
- 按五元组鉴权、conntrack 和 connect token 生命周期；
- L3 数据帧、心跳、多节点组连接和确定性关闭；
- 下行 `0x94` 两种格式的明确判别；
- ICMP、UDP、TCP 的逐阶段真实联调；
- second VIP 和 IPv6 能力确认。

### 上层接入

- DNS resolver、域名资源、Fake IP 和 DNS 劫持；
- SOCKS5、HTTP 代理和端口转发；
- 用户态网络栈与 TUN 适配；
- 路由添加、MTU 和回环保护；
- 主程序配置合并、生命周期管理和优雅退出。

### 测试和诊断

- 本地 HTTP/TLS 模拟服务器及拆包、超限和超时测试；
- Go/Rust 认证请求逐字节 golden fixture；
- codec property test 和 fuzz target；
- ticket 后认证和资源获取的 ignored live tests；
- `atrust-probe` 的认证续接、资源、节点、TCP 和 L3 子命令；
- 日志事件命名规范、敏感字段审计和可选诊断抓包层。

EasyConnect 的全部认证和数据面仍按计划暂缓，不属于当前 aTrust 里程碑。
