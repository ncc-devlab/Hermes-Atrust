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
5. 日志和测试产物不得包含密码、验证码、Cookie 值、ticket 值、完整回调 URL、
   敏感 Header 或响应正文；最多记录路径、业务码、Cookie **名**、布尔标志；
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

### 完整浏览器登录与会话建立（2026-07-26，独立 Chrome）

使用：

- 独立 Chrome：`user-data-dir=/tmp/hermes-chrome-profile`（与日常浏览器隔离）；
- 匹配的 ChromeDriver 150；
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

关窗后客户端结果：

| 观察项 | 结果 |
| --- | --- |
| `portal_hits` | 2 |
| 网关 Cookie 名 | `sid`, `sid.sig`, `sid-legacy`, `sid-legacy.sig`, `straceid`, `straceid.sig`, `lang`, `language`, `sdp_limit_auth_tag`, `sdp_limit_auth_tag.sig` |
| `authConfig` 登录态 | `LoggedIn` |
| `onlineInfo` | 成功（`username_present=true`，用户名不入库） |
| 会话事件 | `probe.session_established sid_present=true` |

### 会话后 clientResource / 节点（2026-07-26 再次实测）

同一 `cas-login` 进程在关窗收割后继续：

| 观察项 | 结果 |
| --- | --- |
| `ip_resource_count` | **1361** |
| `domain_resource_count` | **523** |
| `node_group_count` | **1**（`major` 存在） |
| `resolved_endpoint_count` | **2**（`primary_node_count=1`） |
| `sdpc_placeholder_count` | 0（西电节点为显式地址，非 `{{sdpcHost}}`） |
| DNS option | 主/备均未出现在解析结果中 |
| 浏览器侧路径 | `phoneNumber` → `auth/sms` → `onlineInfo` → **`clientResource`** |

**结论：** 控制面已验证到「Cookie 会话 + onlineInfo + clientResource 严格解析 +
节点地址解析」。`SessionMaterial` 可从 Cookie `sid` 导出（代码路径就绪；需下一轮
`cas-login` 确认 `probe.session_material`）。TLS `node-probe` 与 TCP 帧 codec 已落地，
**尚未**对西电节点发 init 或建隧道。

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

## 尚未闭环

1. ~~`clientResource` 客户端请求与严格解析~~（已实现；待西电 Cookie 会话后实测计数）
2. SID / DeviceID / ConnectionID / SignKey 的完整生命周期与持久化；
3. 节点发现、TCP/L3 隧道、代理与 TUN；
4. 将 SMS/MFA 建模为可恢复的 `SessionProgress::InteractionRequired` 产品状态机
   （当前 Xidian 路径把 MFA 全部留在浏览器内完成）；
5. 脱敏 golden fixture 与更多 ignored live tests；
6. 会话 Cookie 跨进程持久化（当前 jar 仅进程内；`cas-login` 成功后同进程会尝试 `clientResource`）。

## 下一阶段任务（建议顺序）

1. 西电 `cas-login` 后确认 `probe.client_resource` / `probe.nodes_summary` 非空；
2. ~~节点地址解析 / `{{sdpcHost}}` 替换~~（已实现，默认端口 441，无拨号探测）；
3. 定位 SID / SignKey 来源并落地 `SessionMaterial`（见 `tunnel-plan.md` Phase A）；
4. 节点 TLS 冒烟 → 最小 TCP 隧道 → 再考虑 L3 / TUN / DNS。

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
