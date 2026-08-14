# Hermes TUN 设计草案（待评议）

状态：设计草案，尚未实现。本文记录当前证据支持的边界，不代表已经完成 TUN、DNS 或系统路由集成。

## 目标

为已建立的 Hermes L3 session 提供一个本地三层 TUN 接口，使普通应用产生的 IPv4 数据包能够经过资源匹配、flow authorization 和 aTrust 数据节点转发。

## 地址与 MTU

- TUN 接口地址使用 Get-IP 返回的 VIP，按 `<vip>/32` 配置。
- VIP 是隧道内 IPv4 源地址，但不提供子网、网关或广播语义。
- 初始 MTU 使用 1400；这是参考客户端的保守常量，不是西电服务端已声明的协商结果。
- 当前西电没有非空 IPv6 资源，因此第一阶段只实现 IPv4。
- 收到 `L3VipChanged` 时，暂停发送，更新接口地址和相关路由，再恢复流量。

## 数据路径

```text
应用 -> Linux 路由 -> Hermes TUN -> IP/五元组解析
     -> ResourceIndex -> appId/nodeGroupId -> 0x13 flow auth
     -> L3 0x14 data frame -> 数据节点 -> 目标服务
```

返回数据经 `0x94` 解帧后写回 TUN，由 Linux TCP/IP 栈交给应用。L3 session 是设备级长连接；每个不同五元组的 flow 独立鉴权，但同一 flow 的并发调用应去重。

## 路由策略

1. `clientResource` 成功后生成期望的 IP 路由集合。
2. 单 IP、CIDR 和 IP 区间转换为可安装的 CIDR 路由；重叠路由去重或保留最长前缀语义。
3. 路由只负责把候选 IP 包送入 TUN；端口、协议、`appId` 和 node group 仍由 Hermes 的 `ResourceIndex` 再匹配。
4. 没有匹配资源的包必须 fail-closed，不应静默回落到隧道或错误的 appId。
5. 资源刷新采用增量更新，只修改 Hermes 自己安装和标记的路由；退出时清理这些路由。
6. 控制面网关、数据节点、CAS/IDS 等 Hermes 自身连接必须通过物理出口或独立 policy-routing 绕过 TUN，防止路由回环。

## 域名资源

系统路由表不能直接表达域名资源。待评议方案有两种：

- DNS 解析后按当前地址动态安装 `/32` 路由；
- DNS 劫持/Fake IP，使 Hermes 保留原始域名并按域名资源匹配。

第一阶段不得把一次 DNS 解析永久当作域名路由；必须处理 TTL、地址变化、共享 CDN 地址和资源删除。

## 资源匹配与重叠

系统路由最长前缀匹配和 Hermes 的业务资源匹配是两层不同机制。Hermes 继续使用：地址范围最窄、端口范围最窄、精确协议优先、原始顺序兜底。当前西电 L0 证据表明多个覆盖目标的候选 appId 都可能被接受，但其他部署不一定如此。

## 安全与回滚

- 创建 TUN、安装路由、切换 VIP 和删除路由必须有阶段化回滚。
- 不覆盖非 Hermes 路由，不修改默认路由，默认不接管未授权目的地。
- TUN 启用前完成 E6/E16 的 MTU、分片和大包边界验证。
- 首版先支持 IPv4，先不主动启用 IPv6 或 second VIP。

## 待评议问题

- 第一版采用动态真实 IP 路由还是 Fake IP/DNS 方案。
- IP 区间转换和重叠路由的安装粒度。
- Linux、macOS、Windows 的路由回滚和底层连接排除机制。
- MTU 1400 是否足够，以及分片责任属于 TUN、本地 IP 栈、Hermes L3 还是网关。
- 资源刷新和 VIP 更新期间是否短暂阻断新 flow。
