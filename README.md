# gotunnel

Secure TCP tunnel with ChaCha20 encryption and persistent connections.

Forked from [xjdrew/gotunnel](https://github.com/xjdrew/gotunnel) with modern security and Go optimizations.

## Architecture

```
client <-> gotunnel <--------------> gotunnel <-> server
         (encrypted, persistent tunnels)
```

## Features

- **ChaCha20 encryption** (upgraded from deprecated RC4)
- **SHA-256 authentication** (upgraded from MD5)
- **Cryptographically secure random** via `crypto/rand`
- **Persistent tunnel connections** — no per-request TCP handshake overhead
- **Multiplexed links** — multiple application connections over few tunnels
- **Tag routing** — one backend per client tag, with add-only YAML reload on SIGHUP
- **Client-selected backend** — authenticated clients can choose a target when the server explicitly enables it
- **Heartbeat monitoring** with automatic reconnection and exponential backoff
- **Graceful shutdown** via SIGTERM/SIGINT

## Build

```bash
./build.sh
# or
go build -o bin/gotunnel .
```

For OpenWRT builds, see [docs/build_openwrt](docs/build_openwrt/).

## Usage

```
usage: bin/gotunnel
  -allow-client-backend  allow clients to choose backend addresses (server only)
  -backend string     backend address (default "127.0.0.1:1234")
  -config string      server YAML file; SIGHUP loads new tags
  -heartbeat int      tunnel heartbeat interval in seconds (default 10)
  -listen string      listen address (default ":8001")
  -log uint           log level (default 1)
  -route value        server route TAG=host:port (repeatable)
  -secret string      tunnel secret
  -tag string         route tag for this client
  -target string      backend host:port chosen by this client (exclusive with -tag)
  -timeout int        tunnel read/write timeout in seconds (default 30)
  -tunnels uint       low-level tunnel count (0 = server mode)
```

**Server mode** (`-tunnels 0`): listens for tunnel connections, forwards to backend.
**Client mode** (`-tunnels > 0`): creates persistent tunnels to server, listens locally.

## Example

Server side (encrypt traffic to local squid):
```bash
./gotunnel -listen=:8001 -backend=127.0.0.1:3128 -secret="your secret"
```

Client side (local proxy with encryption):
```bash
./gotunnel -tunnels=100 -listen="127.0.0.1:8080" -backend="server:8001" -secret="your secret"
```

Then use `curl --proxy 127.0.0.1:8080 http://example.com` — all traffic is encrypted.

## 按 tag 分流

server 支持通过重复的 `-route=TAG=host:port` 或 `-config=server.yaml` 定义路由。
每个 client 进程使用一个 `-tag`，所有 tag 共用 secret。
保存 YAML 后，向 server 进程发送 `SIGHUP`（`kill -HUP <PID>`）才会重新读取配置，运行期间只追加新 tag。修改或删除已有映射需要重启 server。
原有单后端模式和旧版 client/server 的互通方式保持兼容。

启动示例、reload 规则、兼容关系及排查方法见 [Tag 路由与配置热加载](docs/006-tag路由与配置热加载.md)，配置样例见 [examples/server.yaml](examples/server.yaml)。

## 由 client 指定后端

server 使用 `-allow-client-backend` 或 YAML 的 `allow_client_backend: true` 显式开启后，认证成功的 client 可以用 `-target=host:port` 指定任意 server 可达的后端。client 的 `-backend` 仍填写 gotunnel server 地址；`-target` 与 `-tag` 二选一。

启动命令、与 tag 混用的配置和兼容关系见 [Client 指定后端](docs/007-client指定后端.md)。

## Upgrades from Original

| Feature | Original | This Fork |
|---------|----------|-----------|
| Encryption | RC4 (deprecated) | ChaCha20 |
| Auth signature | MD5 | SHA-256 |
| Random source | `math/rand` | `crypto/rand` |
| Signal handling | SIGHUP only | SIGHUP + SIGTERM + SIGINT |
| Deprecated APIs | `net.Error.Temporary()` | `net.Error.Timeout()` |
| Go style | `interface{}` | `any` (Go 1.18+) |
| Panic messages | `"!!"` | descriptive error |
| Memory pool | strict `cap == sz` check | relaxed `cap >= sz` |

See [CHANGELOG.md](CHANGELOG.md) for details.

## License

MIT — Copyright (c) 2015 xjdrew, 2026 RaindyRoye
