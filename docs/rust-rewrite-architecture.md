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
- `atrust-auth`：认证控制面状态和请求，当前实现只读 `authConfig`。

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

## 未确认协议关卡

以下事实未经真实对端和抓包确认前，不得当作稳定协议继续向上封装：

1. Go Get-IP 请求中的 `0x0053` 是否为固定值，还是应由 SID JSON 长度动态计算；
2. L3 `0x94` 下行数据两种格式应通过哪个明确字段区分，不能沿用数值区间猜测；
3. SignKey 是客户端生成、服务端下发还是经其它接口注册，以及它与 SID 的绑定关系；
4. second VIP 的请求条件和用途；
5. L3 flow key 是否必须包含协议号；
6. L3 授权 URL 应使用 `tcp:` 还是 `tcp://`。

## 当前里程碑

第一个真实联调里程碑只包含：

```text
authConfig
→ 一条明确选择的登录流程
→ authCheck/必要二次认证
→ clientResource
→ 严格资源解析
```

此里程碑不连接节点、不建立 TCP/L3 隧道，也不接管系统 DNS 或路由。

## 联调记录
