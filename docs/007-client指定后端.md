# Client 指定后端

创建日期：2026-09-27

server 显式开启此功能后，认证成功的 client 可以指定任意 server 可达的 `host:port`。无需在 server 上逐个定义目标地址，也无需为新增目标发送 reload 信号。所有 client 继续使用共享 secret。

每个 client 进程固定一个目标，它的所有持久隧道和业务连接都使用这个目标。需要多个目标时启动多个 client 进程。

## 命令行启动

在 server 上开启功能，默认关闭：

```bash
./bin/gotunnel -listen=:8001 -secret="your-secret" -allow-client-backend
```

client 指定由 server 访问的数据库地址：

```bash
./bin/gotunnel -listen=127.0.0.1:13306 -backend=server:8001 \
  -tunnels=4 -target=10.0.0.5:3306 -secret="your-secret"
```

业务应用连接 client 的 `127.0.0.1:13306`，数据经过隧道到达 server，再由 server 连接 `10.0.0.5:3306`。

| 参数 | 含义 |
|---|---|
| client 的 `-backend` | gotunnel server 的地址，沿用原有含义 |
| client 的 `-target` | server 要连接的业务后端地址 |
| client 的 `-listen` | 业务应用连接的本地监听地址 |
| server 的 `-allow-client-backend` | 允许已认证 client 自行指定后端，默认 `false` |

`-target` 支持域名、IPv4 和带方括号的 IPv6，例如 `db.internal:5432`、`10.0.0.5:3306`、`[::1]:9001`。地址总长度为 1–1024 字节，端口必须是 1–65535 的数字。域名由 server 在建立业务连接时解析，`127.0.0.1` 和 `::1` 也指 server 所在机器。

目标地址不要求在 client 启动时就可达；后端不可达时，对应业务连接关闭，持久隧道仍可用于之后的连接。

## YAML 配置与 tag 混用

也可以在 server 的 YAML 中开启：

```yaml
listen: ":8001"
secret: "your-secret"
allow_client_backend: true

routes:
  A: "127.0.0.1:9001"
```

```bash
./bin/gotunnel -config=server.yaml
```

这个 server 同时接受 `-tag=A` 和 `-target=host:port` 的 client。tag client 使用 server 配置的映射；target client 使用自己指定的地址。只使用 target client 时可以省略 `routes`。

命令行也能混用：

```bash
./bin/gotunnel -listen=:8001 -secret="your-secret" \
  -allow-client-backend -route=A=127.0.0.1:9001
```

参数约束：

- client 的 `-target` 与 `-tag` 互斥，且需要 `-tunnels > 0`。
- `-allow-client-backend` 仅用于 server，不能与 server 的 `-backend` 同时指定。
- 使用 `-config` 时，连接、路由和开关都从 YAML 读取，不能再通过相应命令行参数覆盖。

开启功能后，持有共享 secret 的 client 可以访问任意 server 可达的目标，包括 server 本机服务；`routes` 不限制 target client 的地址范围。

## Reload 与兼容性

`SIGHUP` 仍只追加 YAML 中的新 tag。修改 `allow_client_backend`、监听地址或 secret 需要重启；运行中修改开关会被忽略并记录 `restart required`，合法的新 tag 仍会被加入。

修改 client 的目标需要重启该 client。target 保存在每条已认证隧道中，不会被 server 后续加载的 tag 映射覆盖。

| Server 模式 | 普通 client | tag client | target client |
|---|---|---|---|
| 单后端 server | 支持 | 拒绝 | 拒绝 |
| tag 路由 server，未开启此功能 | 拒绝 | 支持已配置 tag | 拒绝 |
| 开启此功能的 server | 拒绝 | 支持已配置 tag | 支持指定目标 |

普通 client 指既不带 `-tag`、也不带 `-target` 的 client。已有的单后端协议和 tag 协议保持兼容；target client 需要两端均支持此功能。旧 server 或未开启功能的 server 会拒绝 target 请求，不会将其转到默认后端。

目标地址及 server 的接受或拒绝结果绑定到本次认证并校验签名；目标地址被篡改或 secret 不匹配时，隧道建立失败。

## 排查与验证

| 现象 | 检查项 |
|---|---|
| `client-specified backend is disabled on server` | server 是否已通过命令行或 YAML 开启功能，修改开关后是否已重启 |
| `route ... handshake failed` | 两端是否支持目标地址模式、secret 是否一致、server 是否开启功能 |
| `backend must be host:port` 或端口校验失败 | 目标需要非空主机名和数字端口，IPv6 用方括号 |
| 隧道建立成功但业务连接断开 | 检查 server 到目标的连通性、域名解析和后端日志 |

- [目标路由测试](../tunnel/target_test.go)：不同 client 指定不同目标、与 tag 混用、默认拒绝、认证、地址校验和 reload 保持启动开关。
- [握手测试](../tunnel/tag_test.go)：tag/target 认证与篡改拒绝。
- [命令行测试](../options_test.go)：新旧模式和参数冲突。

```bash
go test -race -cover ./...
go vet ./...
```
