# Xidian aTrust 联调状态

本文只记录 Xidian 部署的运行约束和真实联调结论。学校登录页面、认证因子和部署地址
不得进入 aTrust 协议 crate；其它学校应由各自的浏览器或身份提供方适配层处理。

## 人工认证约束

Xidian 的 aTrust 统一身份认证包含两步认证，第二步需要用户输入验证码。因此完整登录
必须有人工参与，不能作为无人值守流程运行。

联调工具和后续产品实现必须遵守以下约束：

1. 使用真实浏览器或 WebView 展示学校提供的登录页面；
2. 用户自行输入账号、密码、滑块结果、验证码及后续可能增加的认证因子；
3. Hermes 不实现验证码识别、滑块破解、验证码代填或绕过二次认证；
4. 不自动重复密码提交、验证码发送或验证码校验，避免账户锁定和发送频率限制；
5. 日志和测试产物不得包含密码、验证码、Cookie、ticket、完整回调 URL、Header 或
   响应正文；
6. 自动化只负责打开服务端提供的入口、等待回调以及把未受信任的回调交给
   `atrust-auth` 校验。

`adapters_tests/XIDIAN/ids` 中的脚本可用于理解 IDS 页面和 CAS 跳转，但其中的密码
加密和滑块处理不能成为 Hermes 的生产登录方案。

## 已确认链路

2026-07-25 使用严格 TLS 校验对 `atrust.xidian.edu.cn:443` 进行了真实联调。

### 认证方式发现

`authConfig` 正常返回：

| 登录域 | 认证类型 | 名称 |
| --- | --- | --- |
| `cas42187` | `auth/cas` | 统一身份认证 |
| `local` | `auth/psw` | Local Password Auth |

网关证书可由当前系统信任链验证，Xidian 联调不得使用 `--insecure-tls`。

### IDS 对应关系

无凭据探测确认了以下重定向关系：

```text
https://atrust.xidian.edu.cn/passport/v1/public/casLogin?sfDomain=cas42187
  -> https://ids.xidian.edu.cn/authserver/login?service=...

service:
https://atrust.xidian.edu.cn/passport/v1/auth/cas?sfDomain=cas42187
```

IDS 登录页包含动态 `pwdEncryptSalt`、`lt`、`execution` 和 `userNameLogin`，与现有
Xidian IDS 参考脚本属于同一身份系统。

### 浏览器回调实测

`atrust-probe cas-login` 通过 Firefox WebDriver 打开服务端提供的登录入口。用户人工
完成学校登录、滑块和验证码后，Firefox WebDriver BiDi 在请求发出前捕获到返回
aTrust 的 HTTPS 回调。`CasChallenge` 成功完成以下校验：

- 回调使用 HTTPS；
- 回调 authority 与配置的 aTrust 网关一致；
- 回调路径为 `/passport/v1/auth/cas`；
- 回调包含非空 ticket，且 ticket 未进入日志。

这证明以下控制面链路可用：

```text
aTrust authConfig
  -> aTrust CAS 入口
  -> Xidian IDS
  -> 人工两步认证
  -> aTrust CAS 回调
  -> ticket 校验
```

该结果不能证明 aTrust 会话、资源获取或 VPN 数据面已经可用。

## 当前代码边界

- `atrust-auth` 负责认证方式发现、aTrust 密码主认证、CAS challenge 和回调校验；
- `atrust-probe` 负责 WebDriver 生命周期和人工联调编排；
- `browser.rs` 使用通用 WebDriver/BiDi 接口，不包含 Xidian 表单字段、IDS 密码算法
  或验证码逻辑；
- 浏览器返回的 URL 始终是不受信任输入，只有 `CasChallenge::validate_callback` 可以
  把它转换为受保护的 ticket；
- 当前没有代码消费该 ticket 以建立 aTrust 已认证会话。

## 尚未闭环

当前已经完成“学校登录到 aTrust 回调”的闭环，尚未完成：

1. 确认回调 ticket 的后续消费方式以及浏览器 Cookie 是否必须转交 HTTP transport；
2. 执行回调后的 aTrust 会话建立；
3. 实现 `authCheck` 和服务端要求的后续认证状态机；
4. 获取并严格解析 `clientResource`；
5. 建模 SID、DeviceID、ConnectionID 和 SignKey 生命周期；
6. 选择资源与节点并建立最小 TCP 隧道；
7. 通过 VPN 隧道访问受控目标并校验实际响应。

因此当前结论是：Xidian IDS 和 aTrust CAS 认证对端响应正常，认证控制面到 ticket
回调已验证；aTrust 已认证会话和 VPN 数据面仍未验证。

## 下一阶段任务

下一阶段仍以认证控制面为唯一范围，不提前实现 L3、TUN、DNS 或系统路由。

1. 获取一次授权且脱敏的回调后网络记录，只保留方法、路径、状态码、字段名和 Cookie
   名，删除所有值、Header 和正文；
2. 确认 CAS service ticket 是由浏览器访问回调消费，还是由客户端提交到其它端点；
3. 为浏览器 Cookie 与 `ReqwestTransport` 设计最小、可审计的会话交接，若协议无需
   Cookie 则不增加导入导出能力；
4. 实现 ticket 后的认证状态机，并把“需要人工验证码”建模为显式暂停状态，由 UI
   提交用户输入后继续，禁止后台自动重试；
5. 为每个新端点补充脱敏 golden fixture、本地模拟测试和显式启用的 ignored live
   test；
6. 认证成功后实现最小 `clientResource` 请求，完成第一个控制面里程碑；
7. 控制面稳定后再实现单一 TCP 资源的隧道握手和受控目标响应测试。

## 测试门禁

每次相关变更至少执行：

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

真实 Xidian 登录只能由人工显式启动，不进入默认测试、CI 或自动重试任务。
