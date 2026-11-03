# Hermes aTrust

Rust aTrust 协议核心及本地代理。支持原生 TCP 隧道、IPv4 L3、UDP 数据报、资源分流、远端 DNS、Fake IP，以及已认证会话的运行时接管。

## 构建与运行

```sh
cargo build --release --locked
```

先通过现有登录流程保存会话，详见 [西电认证联调说明](docs/xidian-atrust-integration.md)。已有有效会话时：

```sh
./target/release/atrust-probe --host atrust.xidian.edu.cn serve \
  --session-file ~/.hermes/xidian-session.json \
  --insecure-node-tls
```

默认监听 SOCKS5 `127.0.0.1:1080`、HTTP `127.0.0.1:1081`。SOCKS5 支持 CONNECT 和 UDP ASSOCIATE，HTTP 支持 CONNECT 及普通 HTTP 请求。未命中服务端资源的目的地会被拒绝。

`--insecure-node-tls` 仅用于西电数据节点的自签证书；网关控制面仍验证 TLS。其他部署按其证书情况选择是否启用。

可选参数：

- `--dns-bind 127.0.0.1:5353`：在同一端口提供 UDP/TCP DNS；域名资源可返回 Fake IP。
- `--remote-dns 202.117.112.3:53`：覆盖策略提供的 DNS。DNS 目标仍需服务端资源授权，TCP 回退也需对应的 TCP 授权。
- `--no-http`：只启动 SOCKS5。
- `--bind-interface eth0`、`--bind-address 192.0.2.10`：显式指定底层出口；接口名和地址应替换为本机实际值。原生数据面接口绑定目前支持 Linux/Android；其他平台应提供自定义底层拨号器。
- `--proxy-auth`：从 `HERMES_PROXY_USERNAME`、`HERMES_PROXY_PASSWORD` 读取本地代理凭据。

新登录保存到同一个会话文件后，运行中的代理默认每 5 秒检查一次变更。它先用独立 Cookie jar 验证新会话和资源表，再替换运行时；验证失败保留原会话。`SIGINT`/`SIGTERM` 会关闭监听、活动代理连接和 L3 任务。

## 集成边界

- `atrust-client`：资源快照、节点健康、鉴权、TCP/L3、会话接管、事件和统计。
- `atrust-net`：统一 `NetworkStack`/`ProxyConnector`、UDP 数据报适配、DNS 和 Fake IP。
- `hermes-proxy`：本地 SOCKS5、HTTP、DNS 服务。
- `hermes-transport`：可注入 `UnderlayDialer`，以及明确的 HTTP/节点 TLS 策略。

资源要求 TCP over L3 时，宿主需通过 `AtrustStack::with_l3_tcp` 提供 TCP/IP 网络栈。当前命令行没有内置该网络栈，会明确拒绝此类连接。TUN 设备和系统路由尚未实现。IPv4 分片被拒绝，内置 UDP 适配限制 payload 为 1372 字节。

会话文件接管不延长网关 SID 的寿命，不自动执行 MFA。已有 TCP 隧道由调用方持有；接管后新拨号使用新会话，旧 L3 会话及其数据报连接被关闭，数据报调用方需要重新拨号。

本轮新增的运行时和代理服务通过离线协议测试及本地模拟测试，尚未重新进行真实网关端到端验收。历史西电实验、当前限制和测试入口见 [运行时说明](docs/proxy-runtime.md)。
