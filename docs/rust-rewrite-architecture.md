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
- `atrust-l3`：Get-IP、conntrack/`connectToken`、每流 `0x13` 帧组装；全双工读循环 / TUN 未做；
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

**完整登记（含二义区间、误判症状、判定实验和命令）见
[`open-questions.md`](open-questions.md)。** 本节只保留结论条目。

以下事实未经真实对端和抓包确认前，不得当作稳定协议继续向上封装：

1. ~~Go Get-IP 请求中的 `0x0053` 是否为固定值，还是应由 SID JSON 长度动态计算~~
   **已决（2026-07-31，zju-connect 对照）：动态。** `authTunnel::wrapAuthReqData` 动态计算，
   `getIP` 写死的 `0x0053`=83 只是 73 字符 SID 的巧合。Hermes 的动态实现正确；
2. ~~L3 `0x94` 下行双格式判别~~（已决：body 首 `u16-be n`，`0 < n ≤ 4096` → 长度前缀，否则 token 帧；见 `atrust-protocol::l3_frame`）；
3. SignKey 是客户端生成、服务端下发还是经其它接口注册，以及它与 SID 的绑定关系；
4. second VIP 的请求条件和用途。addrType=5 的 VIP 帧同时带 IPv4 与 IPv6，
   `0x16`/`0x96` 是独立的 second-VIP 请求/响应对——两者关系仍未确认；
5. ~~L3 flow key 是否必须包含协议号~~ **已决：不含。** zju-connect `connTrackKey` =
   `{atype}:{src}:{sport}-{dst}:{dport}`，与 Hermes `FlowKey` 逐字符一致；
6. ~~L3 授权 URL 应使用 `tcp:` 还是 `tcp://`~~ **已决：`tcp:`（无 `//`）。**
   zju-connect `buildAuthRequest` 用 `protoName(proto):dstIP:dstPort`，Hermes 一致；
7. ~~资源表重叠时服务端的优先级规则~~ **西电已决（2026-08-03，E9）：任一匹配候选均可授权。**
   zju-connect 没有统一策略：L3 `processIPV4` 按服务端原始顺序 first-match；TCP tunnel
   的 IP 循环不 `break`，实际由 last-match 覆盖；域名资源使用 Go `map`，重复与重叠选择
   也不稳定。Hermes 的 `ResourceIndex` 按「地址范围最窄 → 端口范围最窄 →
   精确协议先于 `all` → 原始顺序」排序取第一名。表存在重叠时两者会选出不同的
   `appId`/`nodeGroupId`。E9 对同一目标测试 specificity、原始首条和无关 appId：前两者在
   TCP/L3 均通过 app 授权，无关项分别被 TCP `0x02`、L3 `0x82` 拒绝。故西电验证 appId
   是否属于匹配资源，但不强制唯一排序；Hermes 保持确定性的 specificity。该结论尚不能外推
   到其他网关或跨 node-group 的重叠项；
8. **ICMP 如何命中资源**。zju-connect 的判据是 `resource.Protocol == "icmp" || == "all"`
   且不比较端口，但其 aTrust parser 当前会提前过滤显式 `icmp` 条目。Hermes 同时解析并匹配
   显式 `icmp` 与 `all`，不复制这个 parser/matcher 不一致；
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
→ node-probe TLS-only                   [已接线并 live；61.150.43.94:441 外网可达，81ms]
→ TCP 帧 codec                          [已实现]
→ TCP DialTCP 握手 + 应用帧             [已实现；对公网参考服务端 live 打通]
→ L3 帧 codec + IPv4 包解析             [已实现]
→ L3 全双工会话（Get-IP→鉴权→数据）    [已实现；仅 mock 对端验证，无任何 live]
```

**控制面里程碑已闭环（2026-07-27）。数据面探测已接上（2026-07-28）。数据面 TCP 隧道已 live
打通（2026-07-29，公网参考服务端）。** Phase B 已 live（`cas-login --probe-nodes` 同进程）。

**2026-07-31 更正：此前记录的「外网 `:441` 不可达 / 待校内复跑」是误判。** 真实数据面节点是
`61.150.43.94:441`（自签 `CN=sdp`，TLS 握手 81 ms，公网当前可达）；DNS 里的 `.99:441` 才是死端口，
且**任何 SNI 都会让节点静默不响应**。这两条见 [`open-questions.md`](open-questions.md) D1/D2。
后果是**西电 live 验证不再需要进校**，实验序列 E1–E5 见同一文档。Phase C 已用 `atrust-probe tcp-dial` 对
`Hermes-aTrust-Server` 完成 psw 登录 → SID 导出 → 握手 → 应用数据回环 → 关闭的端到端验证；
证实帧与该服务端逐字节互通。注意「临时随机 SignKey 模型成立」只在那个**重建**服务端上成立，
属于循环论证，西电是否硬校验由实验 E3 判定。**西电真机数据面仍待实测对照**（SID/SignKey
绑定、`0x0053` 长度语义；`0x94` 双格式见 `atrust-protocol::l3_frame` 与 open-questions A1）。

**L3 离线件已到里程碑边界（2026-07-31）：** `atrust-l3::L3Session` 打通「Get-IP → 五元组鉴权 →
IPv4 包往返 → 关闭」，诊断入口 `atrust-probe l3-session`。**但它一次真实对端都没跑过**——
覆盖它的 `mock_session.rs` 是照着参考服务端源码写的，因此只能证明实现自洽，不能证伪
对帧格式的理解。下一步的 live 顺序不变，但**已不再被地理位置阻塞**：资源表重叠量化（E2，离线）
→ SignKey 是否真被校验（E3，1 号闸门）→ Get-IP 复跑（E4）→ 才谈 L3 live（E5）。
实验命令见 [`open-questions.md`](open-questions.md)，隧道分阶段规划见 [`tunnel-plan.md`](tunnel-plan.md)。

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
- ~~TCP/TLS 分阶段超时与瞬时建连重试~~（连接与握手各 15s；应用数据发送前最多重试 1 次）；
  多节点退避仍待上层连接池；
- 自定义 CA、证书固定及更细粒度 TLS 诊断。

### TCP 隧道

- ~~初始化 JSON DTO、确定性签名~~（已实现）；golden vector 仍待补（与脱敏抓包逐字节）；
- ~~IPv4/域名目标地址帧~~（已实现）；
- ~~`05 81`、`53 00` 和 connect status 状态机~~（已实现并 live 验证）；
- ~~应用数据帧~~（已实现并 live 回环）；半关闭、服务端关闭、short-write 的对端行为测试仍待补；
- ~~受控 HTTP 目标的真实联调~~（已对公网参考服务端完成；西电真机仍待）。

### L3 隧道

- ~~Get-IP codec（动态 SID JSON 长度；`05 d0` / `53 00` / 地址循环）~~；`53 00` body 已保留进
  `GetIpv4Response::status_bodies` 并落 trace；Xidian live 待复跑（`atrust-probe get-ip --session-file`）；
- ~~SID 总连接（Get-IP 之后）长连接保持与重连~~（`atrust-l3::L3Session` 驱动读/写/心跳，
  `L3SessionManager` 按节点组拥有会话；closed 最多重连 5 次，auth timeout 作废连接后重试 1 次）；
  多节点组的全局 manager cache 仍待上层按需组合；
- ~~按五元组鉴权 JSON（`tcp:` 无 `//`）、conntrack 表、connectToken 状态机~~
  （`atrust-protocol::l3_auth` + `atrust-l3::{conntrack,auth,session,manager}`；8s 超时后由 manager
  重建连接并自动重试一次；并发同流合并为一次 `0x13`）；
- ~~`0x14` 编码 / 下行 `0x94` 双格式 / 心跳请求常量~~；~~读循环与心跳任务~~（已接，25s）；
- ~~IPv4 包五元组解析~~（`atrust-l3::parse_ipv4_flow`，按 IHL 定位传输层）；
- ICMP、UDP、TCP 的逐阶段真实联调（`atrust-probe l3-session --probe icmp-echo|tcp-syn`）；
- second VIP（`0x96` 已能解出并记录，未主动请求）和 IPv6 能力确认。

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
