# Xidian aTrust 联调状态

本文只记录 Xidian 部署的运行约束和真实联调结论。学校登录页面、认证因子和部署地址
不得进入 aTrust 协议 crate；其它学校应由各自的浏览器或身份提供方适配层处理。

## 人工认证约束

Xidian 的完整登录必须有人工参与，不能作为无人值守流程运行。至少包含：

1. 学校 IDS 登录（账号、密码、滑块等）；
2. aTrust 侧二次认证（当前实测为 SMS 验证码）。

联调工具和后续产品实现必须遵守：

1. 使用真实浏览器或 WebView 展示服务端/学校提供的页面；
2. 用户自行输入账号、密码、滑块、SMS 验证码及后续可能增加的因子；
3. Hermes **不**实现验证码识别、滑块破解、代填或绕过二次认证；
4. 不自动重复密码提交、验证码发送或校验，避免账户锁定和发送频率限制；
5. **日志流**（stderr / `--log-file`）不得包含密码、验证码、Cookie 值、ticket 值、
   完整回调 URL、敏感 Header 或响应正文；最多记录路径、业务码、Cookie **名**、布尔标志。
   `--browser-trace-file` 指向的调试 trace 是例外：它刻意不脱敏（见架构文档强制边界
   12），文件强制 `0600`，属于凭据材料，不得随报告或 issue 分发；
6. 自动化只负责打开入口、观察导航/Cookie 名，并在**用户确认流程结束后**收割
   网关 Cookie 会话。

本地凭据只能放在被 git 忽略的 `.env` 中，禁止提交。

## 已确认链路

### 认证方式发现（2026-07-25 / 2026-07-26）

对 `atrust.xidian.edu.cn:443` 使用严格 TLS：

| 登录域 | 认证类型 | 名称 |
| --- | --- | --- |
| `cas42187` | `auth/cas` | 统一身份认证 |
| `local` | `auth/psw` | Local Password Auth |

证书可通过系统信任链校验，联调默认禁止 `--insecure-tls`。

### IDS 对应关系

```text
https://atrust.xidian.edu.cn/passport/v1/public/casLogin?sfDomain=cas42187
  -> https://ids.xidian.edu.cn/authserver/login?service=...

service:
https://atrust.xidian.edu.cn/passport/v1/auth/cas?sfDomain=cas42187
```

### 完整浏览器登录与会话建立（2026-07-26 / 2026-07-27，独立 Chrome）

使用：

- 独立 Chrome + **每次 session 新 profile**（`/tmp/hermes-chrome-profile-{pid}-{ts}`；
  固定 `/tmp/hermes-chrome-profile` 会因 SingletonLock 导致 Chrome 退出、WebDriver 500）；
- 匹配的 ChromeDriver 150；二进制自动探测（优先 `/opt/google/chrome/chrome`）；
- `atrust-probe cas-login --browser chrome`；
- **人工关窗后才收割**（不因首次 portal / 首次 `sid` 提前退出）。

实测导航顺序（仅路径与接口名，无敏感值）：

```text
casLogin
  -> IDS /authserver/login
  -> /passport/v1/auth/cas                 # 中间 CAS，不收割
  -> /portal/shortcut.html                 # 首次 portal，常对应进入 aTrust 二步
  -> 浏览器侧 reportEnv / authCheck
  -> /portal/ + phoneNumber / auth/sms     # aTrust SMS MFA（人工输入）
  -> onlineInfo / clientResource           # MFA 完成后
  -> 用户关闭 probe 浏览器
  -> Hermes 导入网关 Cookie 并校验会话
```

关窗后客户端结果（**2026-07-27 完整跑通**）：

| 观察项 | 结果 |
| --- | --- |
| `portal_hits` | 2 |
| 网关 Cookie 名 | `sid`, `sid.sig`, `sid-legacy`, `sid-legacy.sig`, `straceid`, `straceid.sig`, `lang`, `language`, `sdp_limit_auth_tag`, `sdp_limit_auth_tag.sig` |
| `authConfig` 登录态 | `LoggedIn`（`csrf_present=true`） |
| `onlineInfo` | 成功（约 27ms，`username_present=true`，用户名不入库） |
| 会话事件 | `probe.session_established sid_present=true` |
| `probe.session_material` | `sid` / `device_id` / `connection_id` / `sign_key` / `username` 均 present；`sign_key_provisional=true`；`sid_cookie_name=sid`；`sid_sig_present=true` |

### 会话后 clientResource / 节点（2026-07-27 同进程实测）

同一 `cas-login` 进程在关窗收割后继续（日志 `/tmp/hermes-probe.log`）：

| 观察项 | 结果 |
| --- | --- |
| `clientResource` HTTP | **200**；headers ~78ms；body **1 325 105 B / ~12.5s**（此前“超时”实为未登录/材料不全或旧超时，非协议本身不可达） |
| `ip_resource_count` | **1361** |
| `domain_resource_count` | **523** |
| `node_group_count` | **1**（`major` 存在） |
| `resolved_endpoint_count` | **2**（`primary_node_count=1`） |
| `sdpc_placeholder_count` | 0（西电节点为显式地址，非 `{{sdpcHost}}`） |
| DNS option | 主/备均未出现在解析结果中 |
| 浏览器侧路径 | `phoneNumber` → `auth/sms` → `onlineInfo` → **`clientResource`** |

**里程碑结论（控制面）：** 已闭环验证

```text
authConfig → 浏览器 IDS+SMS MFA → 关窗收割 Cookie
  → LoggedIn + onlineInfo → SessionMaterial
  → clientResource 严格解析 → 节点表（无拨号）
```

TLS `node-probe` 与 TCP 帧 codec 已落地。Phase B 已接线（`cas-login --probe-nodes`
同进程收割后对 primary 节点 TLS-only 冒烟，不发 init）。

### Phase B 首次 live（2026-07-28，外网）

`cas-login --probe-nodes` 在收割 + `clientResource` 后同进程探测 primary 节点：

| 观察项 | 结果 |
| --- | --- |
| `node_tls_probed` | `port=441`、`outcome=timeout`、`elapsed_ms=5001`、`success=false`、`from_sdpc_placeholder=false` |
| `node_tls_summary` | `attempted=1 / succeeded=0 / failed=1` |
| 判读 | 卡在 **TCP connect**（非 TLS 握手/证书），即**网络层不可达**；根因为**探测方在外网**，节点 `:441` 为校内地址 |
| 对照 | 控制面 `:443` 外网可通，数据节点 `:441` 外网不可达 |

**尚未**对西电节点成功 TLS、发 init 或建隧道。

> 注（2026-07-30）：此前 trace 做过字段级脱敏（只留长度 + sha256 + 字段名）。该策略已
> 撤销——脱敏后无法定位字段级差异，反而拖慢协议联调。现在 trace 全保真 + `0600`，
> 凭据保护交给日志默认 `warn` 级别与目录权限。

### 已证伪或应避免的策略

1. **不要在第一次 `/passport/v1/auth/cas` 或首次 portal 收割。**  
   该跳转通常只是进入 aTrust 二步验证页，而非登录完成。
2. **不要对已由浏览器打开过的 portal ticket 再跑 `reportEnv`。**  
   ticket 倾向于一次性；浏览器已消费后客户端重放会得到超时/页签冲突类错误。
3. **不要因出现 `sid` 就立即退出。**  
   二步页阶段也可能已有 Cookie；必须等用户走完 SMS 并手动关窗（或未来明确的
   “流程完成”信号）后再收割。
4. **不要把 IDS Cookie 导入 aTrust transport。**  
   仅导入网关 origin 的 Cookie；学校差异留在浏览器/UI 适配层。

## 当前代码边界

### 解耦原则

```text
任意学校网页登录（浏览器 / WebView）
  -> 仅交付：网关 Cookie 会话（+ 可选 portal 观察）
  -> atrust-auth / transport：会话校验、后续控制面
```

- 学校表单、滑块、SMS UI **不**进入 `atrust-auth` / `atrust-protocol`；
- `browser.rs` 只使用通用 WebDriver/BiDi，不解析 Xidian 表单字段；
- 其它学校应复用同一「浏览器完成交互 + 关窗/完成信号后收割网关 Cookie」模型。

### 已实现能力

| 组件 | 能力 |
| --- | --- |
| `hermes-transport` | 无自动重定向、脱敏 Debug、网关 Cookie 受限导入 |
| `atrust-auth` | authConfig、密码主认证、CAS challenge、portal ticket 解析、reportEnv/authCheck/onlineInfo、clientResource 严格解析、会话进度模型 |
| `atrust-probe` | auth-config / password / cas-start / cas-login（成功后同进程 clientResource）/ client-resource；Chrome/Firefox；人工关窗收割 |

### cas-login 行为（协作约定）

1. 打开独立浏览器到服务端 CAS 入口；
2. **只观察** URL 路径变化与 Cookie **名**（不记录值）；
3. 中间 CAS / 首次 portal / MFA 页面全部放行；
4. **用户手动关闭 probe 浏览器后**再导入网关 Cookie；
5. 刷新 `authConfig`，优先 `onlineInfo` 确认会话；
6. portal ticket / `reportEnv` 仅作可选回退，Xidian 实测路径以 Cookie 会话为准；
7. 会话建立成功后同进程调用 `clientResource`，只记录资源/节点计数（无隧道）。

### 推荐联调命令

```bash
# 先启动与 Chrome 版本匹配的 ChromeDriver；默认监听 127.0.0.1:9515
chromedriver --host 127.0.0.1 --port 9515

# 本地 .env（已 gitignore），至少包含：
# HERMES_ATRUST_HOST=atrust.xidian.edu.cn
# HERMES_ATRUST_CAS_DOMAIN=cas42187

# 独立 Chrome + chromedriver（示例端口 9515）
cargo run -p atrust-probe -- \
  --host atrust.xidian.edu.cn \
  cas-login \
  --login-domain cas42187 \
  --browser chrome \
  --webdriver-url http://127.0.0.1:9515 \
  --timeout-seconds 1800
```

流程：在 probe Chrome 中完成 IDS + SMS → 确认 portal 业务页可用 → **关闭该窗口** →
查看是否出现 `probe.session_established`。

## 里程碑状态

| 里程碑 | 状态 | 日期 / 证据 |
| --- | --- | --- |
| authConfig 只读 | 完成 | 2026-07-25 |
| 浏览器 IDS + SMS 关窗收割 | 完成 | 2026-07-26 / **2026-07-27** |
| 浏览器认证抽取为 `atrust-browser` | 完成 | 2026-07-29；`atrust-probe` 改为库调用方 |
| Cookie → LoggedIn + onlineInfo | 完成 | 2026-07-27 |
| SessionMaterial 导出 | 完成（SignKey provisional） | 2026-07-27 `probe.session_material` |
| clientResource + 节点解析 | 完成 | 2026-07-27：1361/523/1 组 2 节点，~1.3MB/12.5s |
| node-probe TLS 冒烟 | **已接线并 live 跑过（外网）** | 2026-07-28：`cas-login --probe-nodes` 同进程触发；primary 节点 `:441` **TCP connect 超时**（外网网络层不可达，非 TLS/证书失败）；待校内复跑 |
| TCP Dial / init | codec、拨号状态机和参考对端 live 已完成；Xidian 待校内验证 | Phase C |
| L3 / TUN / DNS 路由 | 未做 | Phase D |

## 尚未闭环

1. ~~`clientResource` 客户端请求与严格解析 + 西电实测计数~~
2. SID / DeviceID / ConnectionID / SignKey 的**服务端绑定确认**
   （Cookie SID 与隧道 init JSON 是否同一值仍待抓包；SignKey 仍 provisional）；
3. 节点 TLS 可达性 live、TCP/L3 隧道、代理与 TUN；
4. 将 SMS/MFA 建模为可恢复的 `SessionProgress::InteractionRequired` 产品状态机
   （当前 Xidian 路径把 MFA 全部留在浏览器内完成）；
5. golden fixture 与更多 ignored live tests；
6. ~~会话 Cookie 跨进程持久化~~ **已完成（2026-07-30）：** `--session-file` 会话存储，
   见下节；
7. BiDi `browser_url_change` 噪音过大（静态资源也记入），可改为仅 document 导航。

## 会话存储与登录方式一致性（2026-07-30）

网关 Cookie jar 原先只存在于进程内，`tcp-dial` 因此写死了密码登录路径——而西电必须走
CAS + MFA，密码登录根本拿不到会话。现在登录方式由**会话来源**决定，不再由子命令决定：

```bash
# 一次 CAS + MFA，把会话落到 0600 文件
cargo run -p atrust-probe -- --host atrust.xidian.edu.cn \
  cas-login --login-domain cas42187 --session-file ~/.cache/hermes/xidian.json

# 之后任意进程复用同一会话，无需重做 MFA
cargo run -p atrust-probe -- --host atrust.xidian.edu.cn \
  tcp-dial --session-file ~/.cache/hermes/xidian.json --node '<node>:441' --target '<host>:80'
cargo run -p atrust-probe -- --host atrust.xidian.edu.cn \
  node-probe --session-file ~/.cache/hermes/xidian.json
cargo run -p atrust-probe -- --host atrust.xidian.edu.cn \
  client-resource --session-file ~/.cache/hermes/xidian.json
```

`password --session-file` 走同样的写入路径，因此 `tcp-dial` 对两种登录方式只有一套消费代码。

存储内容与约束：

- 全部网关 Cookie（值原样）、SID、DeviceID、ConnectionID、SignKey、用户名、登录方式与
  登录域；文件强制 `0600`。
- **DeviceID / ConnectionID / SignKey 一并持久化，恢复时原样使用**，不重新随机。
  `ConnectionId = UPPER(MD5(deviceId)) + "-" + micros`，若服务端把 DeviceID 绑到会话或
  `reportEnv`，跨进程换 ID 会被拒；同进程路径会掩盖这个问题，持久化后才会暴露。
- 恢复时校验存储的网关 host:port 与 `--host/--port` 一致，避免把一处会话发往另一处；
  随后用 `onlineInfo` 验活，过期会话在控制面失败，而不是拖到数据面握手才报错。

## 资源匹配器（2026-07-30）

`atrust_auth::ResourceIndex` 回答「这条流该不该进隧道、进哪个 `appId` / 节点组」。
西电资源表约 1361 条 IP + 523 条域名，重叠不可避免（`/16` 套 `/32`、端口区间套精确端口），
匹配器按「地址范围最窄 → 端口最窄 → 精确协议先于 `all` → 服务端原始顺序」取第一名，
并保留全部候选供抓包对照。**服务端真实优先级规则尚未确认**，若证实是 first-match-wins，
只需改 `ResourceIndex::build` 的排序。

先存一份 body，之后完全离线迭代：

```bash
# 存一次（server policy，非凭据）
cargo run -p atrust-probe -- --host atrust.xidian.edu.cn \
  client-resource --session-file ~/.cache/hermes/xidian.json \
  --save-body /tmp/xidian-clientresource.json

# 之后不需要会话、不需要网络
cargo run -p atrust-probe -- --host atrust.xidian.edu.cn resource-match \
  --resource-file /tmp/xidian-clientresource.json \
  --target 202.117.x.y:443 --show-all
```

`matched=false` 是有效结果：数据面对未命中资源的目标**必须不发**。域名目标走域名表，
不在本地先解析——域名资源与 IP 资源可能是不同的 `appId` 和节点组（§6.4）。

两条待真机确认的规则已写入架构文档未决项：ICMP 只能命中 `all` 且不比较端口（未决项 8）、
`*.example.edu` 覆盖任意子域但不含 apex（未决项 9）。

`tcp-dial` 现在会在拨号前记录该目标的匹配结果；若与 `--app-id` 不一致会打一条
`probe.tcp_dial.app_id_mismatch` WARN，但**仍按 `--app-id` 拨号**——排序规则未经真机确认前
不改变数据面行为，这条日志正是用来收集确认证据的。

## 下一阶段任务（建议顺序）

对照 [`tunnel-plan.md`](tunnel-plan.md)：

1. **Phase B live：** `node-probe --primary`（或 `--address`）对西电解析出的节点做
   TLS-only 冒烟；记录成功/超时/证书错误，**不发** init。
2. **Phase A 收尾：** 抓包/对照确认 Cookie `sid` ≡ 隧道 init SID；查 SignKey 注册路径。
   ~~可选 gitignored 会话落盘~~ 已由 `--session-file` 完成。
3. **Phase C：** mock TLS 对端 + TCP 握手状态机；再 `tcp-dial` 单一受控目标（ignored live）。
4. 产品化：~~跨进程 session store~~（已完成）、MFA 状态机、日志降噪（document-only URL）。
5. Phase D（延后）：L3 / VIP / TUN / DNS。

## 双轨实验计划

### 实验一：浏览器会话交给 zju-connect 数据面

`atrust-browser` 是复杂 CAS/MFA 浏览器生命周期的唯一实现。实验桥接只交付 HTTPS
网关 origin 及完整网关 Cookie 属性，不交付 IDS Cookie、CAS/portal ticket、密码或短信码。
zju-connect 导入 Cookie 后只能执行 `authConfig(mod=1, needTicket=false)`、`onlineInfo` 和
`clientResource`，不得再次消费 CAS callback，也不得再次执行 `reportEnv` 或 MFA。

验收顺序：

1. 人工完成 IDS/CAS、滑块和 aTrust SMS，关窗后获得含 `sid` 的网关 Cookie；
2. zju-connect 导入会话并通过 `onlineInfo`，随后解析 `clientResource`；
3. 校内网络对 major 组的每个端点执行 TCP/TLS-only 探测，不发送 init；
4. 调用只依赖 SID 的 Get-IP，确认 Cookie SID 与数据面会话一致；
5. 对一个明确授权的目标建立单 TCP 隧道；L3/TUN 不在本实验中启用。

正式桥接应使用继承文件描述符或权限受限的本地 IPC，在内存中传递 Cookie。受限权限的
临时文件只用于一次性概念验证，不作为稳定会话格式。

#### 首次实测（2026-07-29）

ChromeDriver 使用 `--ignore-explicit-port` 自动选择高端口，Hermes 将实际端口传给
`cas-login --webdriver-url`。人工完成 CAS/MFA 并关窗后收割 10 个网关 Cookie，`sid`
存在，`onlineInfo` 成功；会话以 `0600` 的一次性 zju-connect `client_data` 文件交接。

zju-connect 未指定认证类型，导入后直接报告 `Already logged in`，随后成功执行
`onlineInfo`、`clientResource` 和资源解析。两个数据端点的 TLS-only 结果为：

- 私网端点 `:441` TCP connect 5 秒超时；
- 公网端点 `:441` TCP 成功，TLS handshake 成功（约 68 ms）；
- 汇总：`attempted=2 / tcp_succeeded=1 / tls_succeeded=1`。

探测后进程在 Get-IP、L3、TUN 和路由初始化前退出。该结果证明浏览器 Cookie 会话可以由
zju-connect 接管，也证明当前网络至少存在一个可达的 Xidian aTrust 数据节点；尚未发送
aTrust init 或验证 SID 数据面认证。

#### SID-only Get-IP（2026-07-29）

复用同一 `0600` 会话文件再次执行 Cookie adoption，`authConfig` 仍报告已登录；zju-connect
重新获取资源并选择上一步可达的公网 `:441` 节点。随后只发送 SID 初始化和 Get-IP 请求，
服务端返回 `OK` 并分配有效的 `10.x` 客户端 IPv4。

进程在收到地址后立即退出，没有创建 L3、TUN、DNS 或路由。该结果确认：

1. 浏览器 Cookie 中的 `sid` 可直接用于 Xidian 数据面认证；
2. 控制面 Cookie 会话与公网数据节点会话一致；
3. Get-IP 阶段不依赖浏览器 DeviceID、ConnectionID 或 SignKey；
4. 下一关可以隔离验证单 TCP init，随后才进入 L3 SID 认证与单流授权。

Hermes 原生等价探针现已接入同进程 CAS 路径。使用前先从上一轮 TLS-only 结果中选择
明确可达的公网节点，避免把私网节点超时误判成 SID 拒绝。

数据节点证书常见为深信服私有自签（`CN=sdp`）；默认证书校验会在 TLS 握手失败。
联调时可加 `--insecure-tls` 做诊断，生产路径应改为固定 CA / 指纹，而非常态 insecure。

响应侧：Xidian 可能先回 L3 method ack `05 d0`，再 `53 00 …OK` 与 `05 00` IPv4；
`atrust-l3` 按帧循环读取，与 zju-connect Get-IP / L3 auth 行为对齐。

```bash
HERMES_LOG=info cargo run -p atrust-probe -- \
  --host atrust.xidian.edu.cn \
  --insecure-tls \
  --browser-trace-file /tmp/hermes-browser-trace.jsonl \
  cas-login \
  --login-domain cas42187 \
  --webdriver-url http://127.0.0.1:9515 \
  --timeout-seconds 1800 \
  --get-ip-node '<reachable-node>:441' \
  --get-ip-timeout-seconds 8
```

该动作只建立一条临时 TLS 连接并发送 SID-only Get-IP。成功日志不会输出分配的 VIP，
只记录 IPv4 和是否为私网地址；失败写入 trace `get_ip_failed`。没有自动重试，
也不会创建 TUN、DNS 或路由。

### 实验二：Hermes 原生数据面与 L3

Hermes 使用同一 `atrust-browser` 会话列出资源和节点，并以 zju-connect 的已授权协议行为
作为对照，不共享其运行时会话。验收顺序固定为：节点解析、TLS-only、Get-IP、单 TCP、
L3 SID 认证、单流授权、心跳与关闭，最后才是 TUN/DNS/路由。

每一阶段必须有本地 mock/golden test，并将真实失败区分为 DNS、TCP、TLS、SID、设备绑定、
签名、策略和目标错误。DeviceID、ConnectionID、SignKey 只在服务端证据要求时逐项纳入，
不预先假定它们与浏览器会话的绑定方式。

## 测试门禁

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

已覆盖的会话路径单测（默认 CI 运行）：

- `reportEnv` / `authCheck` / `onlineInfo` / `establish_session_from_portal` mock；
- 网关 Cookie 受限导入与名称可观测（不暴露值）；
- `AuthStep` 边界与 `BusinessEnvelope` 脱敏解析；
- 首次 portal 不收割 portal ticket 的策略；
- `clientResource` 请求体 golden 与 IP/CIDR/域名/节点组/DNS 严格解析。

真实 Xidian 登录只能由人工显式启动，不进入默认测试、CI 或自动重试任务。
`.env` 仅保留主机/域/WebDriver 等非密钥设置；不需要也不应存放账号密码。
