# aTrust 私有 VPN 协议分析

本文目标是说明 aTrust 客户端实际执行了哪些运算、发送了哪些协议字段，以及这些实现的边界。
这里的“协议”不是一份厂商公开的 RFC：它是对 Sangfor EasyConnect 和 aTrust
客户端行为的兼容实现，部分字段来自逆向分析，服务端升级后可能改变。

## 1. 总览

程序支持两套互不相同的接入方式：

| 模式 | 登录/控制面 | 数据面 | TCP 隧道 |
| --- | --- | --- | --- |
| `easyconnect` | `/por/*.csp` HTTPS、TWFID、RSA 密码加密 | 特制 TLS L3 双连接（发送和接收分离） | 不支持 |
| `atrust` | `/passport/v1/*`、`/controller/v1/*` HTTPS、SID/设备/资源 | TLS 上的版本 `0x05` L3 帧 | 支持 |

两者都使用 TCP 外层和 TLS。源码中的 TLS 配置普遍设置了
`InsecureSkipVerify: true`，所以“使用 TLS”不等于“校验了服务端身份”，这一点
见本文的安全风险章节。

典型的数据路径如下：

```text
应用或 TUN
  -> 路由/资源匹配
  -> 构造 IP 元数据
  -> 登录后按连接获得授权 token（aTrust）
  -> 数据帧
  -> TLS/TCP
  -> VPN 网关
```

## 2. EasyConnect 协议

### 2.1 登录和密码运算

实现位于 `client/easyconnect/request.go`。

1. 客户端 GET `https://server/por/login_auth.csp?apiversion=1`。
2. 从 XML 响应读取 `TwfID`、RSA 模数 `RSA_ENCRYPT_KEY`、指数
   `RSA_ENCRYPT_EXP`，以及可选的 `CSRF_RAND_CODE`。
3. 若有 CSRF 随机码，实际待加密密码为：

   ```text
   password' = password + "_" + CSRF_RAND_CODE
   ```

4. 用服务端下发的 RSA 公钥执行 RSA PKCS#1 v1.5 加密：

   ```text
   ciphertext = RSAES-PKCS1-v1_5(public_key, UTF-8(password'))
   svpn_password = lowercase(hex(ciphertext))
   ```

5. POST `/por/login_psw.csp?anti_replay=1&encrypt=1&type=cs`，表单中携带用户名、
   十六进制密文、验证码和 `TWFID` Cookie。
6. 服务端可能继续要求短信验证码、TOTP 或客户端证书。源码支持：
   `auth/sms`、`auth/token` 和 PKCS#12 证书登录；图形验证码则下载图片后由用户
   输入。
7. 登录成功后保存新的 TWFID，并继续请求服务端配置、线路、资源和虚拟 IP。

RSA 只用于保护登录密码，不是后续 IP 数据的独立加密层。后续数据依赖 TLS 会话
保护。

### 2.2 特制 TLS ClientHello

实现位于 `client/easyconnect/protocol.go` 的 `tlsConn`。连接到 VPN 服务器的
443 端口后，客户端不使用普通的 Go TLS ClientHello，而是用 uTLS 手工设置字段，
以便网关在同一端口区分 Web/HTTP 和 VPN 流量：

```text
TLS 版本：TLS 1.1
随机数：32 字节随机数
密码套件：TLS_RSA_WITH_RC4_128_SHA
压缩：none
SessionID："L3IP" + 其余填充到 32 字节
扩展：自定义 5 字节 heartbeat 扩展
```

源码还允许跳过服务端证书验证。SessionID 的 `L3IP`、TLS 1.1、RC4 和自定义
heartbeat 都是兼容私有网关的识别信号，不应理解为新的密码学设计。

### 2.3 发送和接收握手

登录产生的 token 在 `Client` 中是 48 字节数组，客户端虚拟 IP 的字节逆序值为
`ipReverse`。每条 TLS 连接建立后先发送一个固定结构：

```text
offset  size  含义
0       4     命令：发送为 05 00 00 00，接收为 06 00 00 00
4       48    登录 token
52      8     保留字段，当前全为 00
60      ?     ipReverse
```

服务端对发送连接返回的首字节 `0x02` 表示源码接受的成功状态。已知其它状态
包括 `0x05/0x06/0x07/0x09`（稍后重连）、`0x08`（关闭会话）、`0x0a`
（IP 有效）和 `0x0e/0x0f`（心跳相关）。接收连接要求首字节为 `0x01`。

一个 `L3Conn` 同时维护：

```text
sendConn：写入客户端发出的 IP 数据
recvConn：读取服务端返回的 IP 数据
```

这不是一个普通的双向单连接协议。读写失败时，代码分别重新执行对应握手，最多
尝试数次。

### 2.4 EasyConnect 支持范围

- 主要数据面是 L3 原始 IP，通常由 TUN 或内部协议栈提供。
- TCP、UDP、ICMP 的分流和代理路径由上层资源配置决定。
- 源码明确 `CanUseTCPTunnel() == false`，因此不提供 aTrust 那种面向单个
  TCP 连接的隧道。
- 支持服务端下发的 IP 资源、域名资源、DNS 资源和线路列表；线路探测使用多次
  TCP ping，选择平均延迟最低且全部探测成功的线路。

## 3. aTrust 协议

### 3.1 门户登录和会话材料

aTrust 的认证代码位于 `client/atrust/auth`。整体顺序是：

1. 访问 `/passport/v1/public/authConfig`，读取认证方式列表、CSRF token、RSA
   公钥/指数和 anti-replay 随机值。
2. 根据登录域和认证类型选择认证流程。
3. 支持的认证类型包括：
   - `auth/psw`：密码认证；
   - `auth/cas`：CAS ticket 认证；
   - `auth/smsCheckCode`：短信验证码认证。
4. 根据服务端的 `authCheck`/`nextService` 响应继续短信或其它二次认证。
5. 登录后获取 SID、设备 ID、连接 ID、签名密钥、节点组和 IP/域名资源。
6. 这些材料可序列化为 `client-data.json`，以后复用登录状态；也可以调用授信
   设备接口把当前设备加入或移除信任列表。

aTrust 的密码登录同样会使用服务端提供的 RSA/反重放参数，但它与 EasyConnect
   的 `/por/login_*.csp` XML 流程不是同一个协议，不能混用 TWFID 和 SID。

### 3.1b 基准来源说明（2026-07-31）

本文的 L3 部分现以 **zju-connect**（`/home/nancunchild/projects/zju-connect`，
`client/atrust/`）为对照基准。它是已被证实在真实 aTrust 网关上可用的客户端，
优先级高于 `Hermes-aTrust-Server`——后者是依据抓包和控制台表现重建的服务端推测，
用它验证客户端属于循环论证。

已逐行核对且**一致**的部分：`connTrackKey` 格式 `{atype}:{src}:{sport}-{dst}:{dport}`、
鉴权 JSON 字段顺序与 `atype=0x0800`/`protocol=IANA号`、HMAC-SHA256 大写 hex 签名覆盖
`xRequestSig=""` 的字节串、`0x13`/`0x14` 编码、`0x93`/`0x96` 的 status-在-长度-之前布局、
`0x94` 的 `0 < n ≤ 4096` 双格式判别、25s 心跳、8s 鉴权超时、CAS 式单次发起鉴权。

### 3.2 L3 隧道总连接认证

每个节点组缓存一个 L3 TLS 连接。建立 TLS 后，客户端先发送：

```text
05 01 D0
53 00 <u16-be: JSON长度>
<JSON: {"sid":"..."}>
05 04 00 <addrType> 00 00 00 00 00 00
```

服务端返回：

```text
05 D0
53 <status> <u16-be: JSON长度>
<JSON响应>
<虚拟IP头和定长虚拟IP数据>
```

`53 00` 是一个嵌套的长度包。源码还会忽略或跳过部分 `53 00` 协议消息，因此
抓包分析时不能只按 `05 <cmd> <len>` 一种格式解析。

**虚拟 IP 帧的长度由 addrType 决定（2026-07-31 由 zju-connect 订正）：**

```text
05 <status> <reserved> <addrType>        4 字节头
<vipData>                                长度 = vipPayloadLength(addrType)
    addrType=1 → 6 字节（前 4 为 IPv4，尾 2 字节用途未知）
    addrType=4 → 18 字节（IPv6）
    addrType=5 → 22 字节（IPv4 4 字节 + IPv6 16 字节）
    其它       → 4 字节
```

即 addrType=1 时整帧 **10 字节，不是 8 字节**。zju-connect 自身两处不一致：
`ip.go::getIP` 只读 8 字节（少读 2），`l3tunnelconn.go::authTunnel` 读满 10 字节。
前者读完即关连接，少读不可见；后者连接要继续用，必须读满。**以 authTunnel 为准。**
Hermes 原先按 8 字节读，在独立 Get-IP 下无害，但会让保持长连接的 L3 会话从第一帧起错位。

另注：`getIP` 的 `05 01 d0 53 00 00 53` 把长度写死为 `0x0053`=83，恰好等于 73 字符 SID 的
`{"sid":"..."}` 长度；而 `authTunnel::wrapAuthReqData` 是**动态**计算长度的。
这解决了架构文档未决项 1——动态才是正确形态，`0x0053` 只是对 73 字符 SID 成立的巧合。

### 3.3 按连接授权：JSON、conntrack 和 HMAC

L3 数据不是拿到 SID 后即可直接发送。首次出现一个五元组时，源码先创建
conntrack 项并发送 `0x13` 鉴权请求。请求 JSON 中包含：

```text
sid, appId, url, deviceId, connectionId,
env, conntrackHash, lang,
ip: {atype, protocol, destAddr, destPort, srcAddr, srcPort},
procHash, xRequestSig
```

其中 `conntrackHash` 是该连接的随机/唯一标识，`url` 的形式类似
`tcp:10.0.0.1:443`，环境字段会伪装或描述进程、平台、路径和信任状态。

签名计算是源码中最明确的自定义运算：

```text
unsigned = JSON.Marshal(request with xRequestSig = "")
digest = HMAC-SHA256(signKey, unsigned)
xRequestSig = UPPERCASE(hex(digest))
```

注意签名覆盖的是 JSON 字节串，因此字段顺序、空字段、大小写和 JSON 编码变化
都会影响结果。服务端响应中返回 `connectToken`（缺失时兼容读取 `token`），
客户端把它绑定到 conntrack 项。鉴权等待 8 秒超时；成功后数据包才会带这个 token。

### 3.4 L3 数据帧

请求帧使用版本 `0x05` 和命令 `0x14`：

```text
05 14
<u8 tokenLen>
<token: tokenLen字节>
<reserved: 2字节>
<u8 packetCount>
重复 packetCount 次：
    <u16-be packetLen>
    <原始IP包: packetLen字节>
```

服务端响应命令为 `0x94`。`05 94` 之后的 body 按首 2 字节 `n = u16-be` 分帧
（与 zju-connect `readDataRespPayload` / Hermes `atrust-protocol::l3_frame` 一致）：

- `0 < n ≤ 4096`：**长度前缀** — 随后 `n` 字节为一整包原始 IP；
- 否则：**token 帧** — 与 `0x14` 相同的 `tokenLen | token | reserved | count | 包…`。

该阈值为 wire 判别字段，不是对 IP 内容的扫描。服务端返回的 IP 包进入
`dataChan`，再由 TUN 或内部栈处理。

客户端在发送前从 IPv4 包提取：

```text
atype = 4
protocol = 6(TCP) / 17(UDP) / 1(ICMP)
srcIP, dstIP, srcPort, dstPort
```

然后按服务端 IP 资源的地址范围、协议和端口范围选择 `appId` 与 `nodeGroupId`。
无匹配资源时，包不会被发送到 VPN。

### 3.5 心跳和重连

每条 L3 TLS 连接每 25 秒发送：

```text
05 15 00 00
```

服务端心跳响应是 `05 95`。底层连接关闭时，节点组缓存会被驱逐并重新建连；鉴权
超时会驱逐连接并重试一次，仍失败时当前包被丢弃。

## 4. aTrust TCP 隧道

TCP 隧道由 `DialTCP` 使用，适合代理单个 TCP 连接，和 L3 TUN 是两条路径。

1. 按目标 IP/端口或域名资源选择 `appId`、节点组和最佳节点。
2. 与节点建立 TLS，发送初始化消息：

   ```text
   05 01 81 53 03 <u16-be: JSON长度> <JSON>
   ```

3. JSON 内容与 L3 鉴权类似，也包含进程环境、目标地址、SID、设备 ID、连接 ID
   和 `xRequestSig`。签名仍是对 `xRequestSig` 为空的 JSON 做 HMAC-SHA256。
4. 发送目标地址：IPv4 使用 `05 01 01 01 <4字节IP> <u16端口>`；域名使用
   `05 01 01 03 <u8域名长度> <域名> <u16端口>`。
5. 等待服务端返回 `53 00 <u16长度> OK`，再发送连接探测
   `01 00 00 00`。
6. 服务端返回 `05 00` 表示成功；其它状态映射为拒绝、不可达、连接拒绝、TTL
   超时、命令不支持或地址类型不支持。

应用数据帧是：

```text
写入：01 00 <u16-be长度> <数据>
读取：01 00 <u16-be长度> <数据>
关闭：01 01 00 00
```

单个应用数据帧最大为 65535 字节。当前 TCP 隧道的地址发送实现主要按 IPv4
目标处理；域名模式是把域名交给服务端解析，而不是本地先解析。

## 5. 支持矩阵和实际边界

### 已实现

- EasyConnect 登录：密码、可选图形验证码、短信、TOTP、客户端证书。
- aTrust 登录：密码、CAS、短信验证码，以及登录状态文件和授信设备操作。
- EasyConnect L3 数据面。
- aTrust L3 数据面和单连接 TCP 隧道。
- TCP、UDP、ICMP 的 IPv4 元数据识别。
- TUN、SOCKS5、HTTP 代理、端口转发和 DNS 相关的上层功能。

### 不应误认为已实现

- EasyConnect 没有独立的 TCP 隧道模式。
- L3 路径的 `processIPV4` 只处理 IPv4 包；虽然元数据编码器包含 IPv6 分支，
  这不代表端到端 IPv6 已打通。
- `icmp6` 等协议名称在辅助函数中存在，不等价于实际分流和服务端授权支持。
- 这是客户端兼容协议，不是通用的 IPsec、WireGuard、OpenVPN 或 SOCKS 加密
  协议。

## 6. 潜在的坑和风险

### 6.1 服务端身份没有被验证

EasyConnect 的 HTTP 客户端、特制 TLS 和 aTrust L3/TCP TLS 都设置了
`InsecureSkipVerify: true`。攻击者若能劫持网络流量，可以冒充 VPN 服务器，窃取
登录会话、SID、token 或转发数据。生产环境至少应考虑固定 CA、证书指纹或其它
可验证的服务端身份机制；直接打开校验可能因私有网关证书不受系统信任而无法连接，
需要先确认网关证书链。

### 6.2 兼容性依赖老旧 TLS 特征

EasyConnect 主动伪造 TLS 1.1、RC4 和自定义扩展。现代 TLS 库或中间设备可能拒绝
这些特征；反过来，替换成现代 TLS ClientHello 也可能让 Sangfor 网关把连接当成
普通 HTTPS。不能在不抓包验证的情况下随意升级版本或密码套件。

### 6.3 私有字段和响应解析存在版本耦合

成功码、`0x05` 帧格式、aTrust 的双数据响应格式、虚拟 IP 长度和 `OK` 文本判断都
是经验兼容逻辑。服务端返回新字段通常没问题，但改变字段顺序、长度编码、状态码
或 token 位置就可能导致连接看似建立、数据却全部丢失。

### 6.4 分流、DNS 和 Fake IP 的相互影响

- L3 发送前必须命中服务端 IP 资源的地址、协议和端口范围。
- 域名资源与 IP 资源可能使用不同的 `appId` 和节点组，先在本地解析可能丢失
  域名资源语义。
- aTrust TUN 模式下，域名 TCP 流量通常需要 DNS 劫持和 Fake IP 配合，否则包的
  目标地址可能无法匹配服务端资源。
- 与其它 TUN/Fake-IP 代理同时使用时，路由环路、DNS 回流和底层 VPN 连接被再次
  接管是常见故障。VPN 的底层拨号应明确绑定正确网卡，并为 VPN 服务端地址设置
  直连/排除规则。

### 6.5 日志和调试转储可能泄露敏感材料

源码在调试路径会十六进制转储握手、JSON、数据包和协议帧；aTrust 初始化日志还
会输出 SID、DeviceID、ConnectionID 和 SignKey。EasyConnect 登录流程也会记录
服务端 RSA 信息。不要在共享环境开启 `debug-dump`，也不要把日志、抓包或
`client-data.json` 上传到公开 issue。IP 包本身可能包含 DNS、Cookie、账号和应用
数据。

### 6.6 凭据与会话文件的生命周期

密码、TOTP secret、客户端证书和 aTrust 客户端数据都是高价值材料。权限过宽、备份
同步或容器挂载可能使他人直接复用会话。应限制文件权限、避免命令行暴露密码，并在
怀疑泄露时主动注销/撤销设备信任，而不是只删除本地文件。

### 6.7 MTU、长度和丢包行为

数据包长度字段只有 16 位，TCP 应用帧不能超过 65535 字节。L3 鉴权有 8 秒超时，
发送侧遇到认证失败时可能直接丢包；网络抖动期间首次连接的包也可能经历重试或丢失。
如果 TUN MTU、路径 MTU 和服务端允许的封装大小不一致，表现可能是小包正常、TLS
或网页大包卡住。

## 7. 复现和验证建议

若需要继续逆向或排查服务端升级，建议按以下顺序记录，不要先修改协议字段：

1. 在隔离测试账号上抓取登录后的 TLS 连接元数据，确认每个连接的方向和
   `SessionID`/版本特征。
2. 记录 EasyConnect 的发送/接收握手及首字节状态码。
3. 对 aTrust 分别记录总连接认证、首次五元组鉴权、首个数据包和心跳。
4. 用源码中的大端序长度、token 长度和逐包长度逐层解码，不要把 TLS 明文内容
   当作可以直接在公网读取的协议。
5. 验证四类流量：IPv4 TCP、IPv4 UDP、ICMP，以及域名资源下的 TCP；再单独验证
   TUN、SOCKS/HTTP 和 TCP 隧道。
6. 测试服务端重启、节点切换、鉴权超时和 DNS 劫持关闭后的行为，因为这些路径
   暴露了最多的实现假设。

## 8. 源码索引

- EasyConnect 登录和 RSA：`client/easyconnect/request.go`
- EasyConnect 特制 TLS、发送/接收握手：`client/easyconnect/protocol.go`
- EasyConnect 双 L3 连接：`client/easyconnect/l3conn.go`
- aTrust L3 帧、鉴权、HMAC、心跳：`client/atrust/l3tunnelconn.go`
- aTrust IPv4 资源匹配和重试：`client/atrust/l3tunnelpacket.go`
- aTrust TCP 隧道和 HMAC：`client/atrust/tcptunnel.go`
- aTrust 节点组连接缓存：`client/atrust/l3tunnel.go`
- 命令行支持矩阵和运行注意事项：`README.md`
