# 西电 DNS live 实验

## 目的

验证资源表中显式授权的 UDP/53 目标是否能完成真实 DNS 查询，而不是把 DNS 响应错误地当成 UDP echo 失败。

## 目标与请求

- `202.117.112.3:53`
- `202.117.112.9-202.117.112.14:53`
- `ANY xidian.edu.cn`：作为较大响应候选，优先执行；响应可能合法地设置 TC（截断）位。
- `A www.xidian.edu.cn`
- `A gsoft.xidian.edu.cn`
- `A w.xidian.edu.cn`
- `A zfw.xidian.edu.cn`

实验只发送标准 DNS 查询，不发送任意 payload，不使用 `1-65535` UDP 资源去盲探未知端口。

## 判据

成功返回时只记录：

- flow authorization 是否成功；
- 返回包是否反向匹配目标 IP/端口和 VIP/源端口；
- IPv4/UDP 长度是否合法；
- DNS transaction ID 是否匹配；
- QR 是否为响应；
- QDCOUNT 是否为 1；
- 响应是否有合法 DNS question section。

不记录 DNS 响应正文、Cookie、SID、VIP 或其他凭据材料。`ANY` 响应即使带 TC 也不应直接判为协议失败；它需要单独记录为“合法但截断”，因为现代 DNS 服务可能限制 ANY 响应。

## 运行

```bash
scripts/dns-live-observation.sh
```

脚本要求外部提供一个权限为 `0600` 且年龄不超过 15 分钟的 session 文件。每次查询独立启动一个 Hermes runtime，避免同一设备并发 L3 session 互相淘汰。输出目录为 `debug_logs/<timestamp>-dns-live/`，目录权限为 `0700`。

## 边界

通过只证明该 DNS 目标在当前 session、节点和资源代际下可完成 DNS 数据包往返，不证明：

- 所有 UDP 端口都有服务；
- UDP echo 可用；
- MTU 1400 已被 live 证明；
- `0x94` token-framed 分支已被触发；
- ANY 响应一定完整返回。

## 2026-08-14 live 结果

使用新鲜 CAS session、数据节点 `61.150.43.94:441` 和 VIP `10.210.29.44` 串行执行。全部请求匹配显式 UDP/53 资源，使用同一 `appId`，flow authorization 均返回 32 字节 connect token。所有下行均为 length-prefixed `0x94`，没有触发 token-framed 分支。

`202.117.112.3:53` 结果：

| 查询 | DNS body | IPv4 包 | RCODE | AA | RA | TC | Answer | Authority | Additional |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ANY xidian.edu.cn` | 342 B | 370 B | 0 | true | true | false | 5 | 0 | 5 |
| `A www.xidian.edu.cn` | 51 B | 79 B | 0 | true | true | false | 1 | 0 | 0 |
| `A gsoft.xidian.edu.cn` | 53 B | 81 B | 0 | true | true | false | 1 | 0 | 0 |
| `A w.xidian.edu.cn` | 49 B | 77 B | 0 | true | true | false | 1 | 0 | 0 |
| `A zfw.xidian.edu.cn` | 51 B | 79 B | 0 | true | true | false | 1 | 0 | 0 |

对 `202.117.112.9` 至 `202.117.112.14` 分别发送 `A www.xidian.edu.cn`，六个目标均通过 flow auth 和 DNS wire 校验，均返回 79 字节 IPv4/UDP 包。由此得到当前部署下的 L0 结论：

1. Hermes 的 UDP 路由、鉴权、上行 `0x14`、下行 length-prefixed `0x94` 和 DNS 请求/响应链已经端到端通过；
2. 七个广告 DNS 地址都实际响应 UDP/53，不只是资源表中存在静态授权；
3. `ANY xidian.edu.cn` 返回完整、未截断的 342 字节 DNS body，但仍远低于 MTU 1400，不能代替 E6 大包实验；
4. 这些结果不证明 DNS-over-TCP、EDNS0、分片、DNSSEC 大响应或 Fake IP 路由方案。

完整日志位于：

```text
debug_logs/2026-08-14-181854-dns-live/
debug_logs/2026-08-14-dns-metadata/
```
