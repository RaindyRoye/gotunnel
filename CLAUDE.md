# gotunnel

安全 TCP 隧道 — ChaCha20 加密、多路复用、持久连接。
Fork 自 xjdrew/gotunnel，升级了加密算法和 Go 代码风格。

## 构建与运行

```bash
./build.sh                          # CGO_ENABLED=0 go build
go build -o bin/gotunnel .          # 另一种方式
```

服务端：`./gotunnel -listen=:8001 -backend=127.0.0.1:3128 -secret="key"`
客户端：`./gotunnel -tunnels=100 -listen=127.0.0.1:8080 -backend=server:8001 -secret="key"`

## 测试

```bash
go test -race -cover ./tunnel/
```

不使用第三方测试框架，仅用标准库 `testing`。

## 架构

- `main.go` — CLI 入口、参数解析、信号处理
- `tunnel/` — 核心逻辑，单一 package
  - `server.go` / `client.go` — 服务端与客户端（隧道生命周期管理）
  - `hub.go` — 多路复用：分发控制命令和数据到各 link
  - `link.go` — 单条多路复用连接（双向转发）
  - `conn.go` — TunnelConn（ChaCha20 加解密）+ Tunnel（数据包帧封装）
  - `auth.go` — 双向认证：AES-128 + HMAC-SHA256
  - `buffer.go` — 线程安全环形缓冲区（sync.Cond）
  - `mpool.go` — 固定大小 byte 切片的 sync.Pool
  - `id_allocator.go` — uint16 ID 空闲列表（buffered channel 实现）
  - `tcp.go` / `listener.go` — TCP 连接工具（keep-alive 配置）

## 代码约定

- Go 1.25+，使用 `any` 不用 `interface{}`
- 全局状态（`Heartbeat`、`Timeout`、`LogLevel`）由 main 中 CLI 参数设置，tunnel 包中读取
- 日志：使用包级 `Log/Info/Debug/Error/Trace` 函数，不用 `log` 或 `fmt`
- Panic 恢复：使用 `safe_go.go` 中的 `Recover()`，不用裸 `recover()`
- 内存：使用 `mpool.Get()` / `mpool.Put()` 管理数据包大小的缓冲区，不要临时分配
- 隧道数据包头：小端序 `header{Linkid uint16, Len uint16}`
- 并发写由 `sync.Mutex` 保护；每个 tunnel 的读操作为单 goroutine

## 关键不变量

- 每条隧道使用独立的 ChaCha20 cipher 实例（每连接固定零 nonce 是安全的）
- `WritePacket` 会 defer `mpool.Put(data)` — 调用方必须传入 mpool 分配的切片
- `link.aclose/rclose/wclose` 使用 `sync.Once` — 可安全重复调用
- `Hub.Start()` 是主分发循环；退出时会重置所有 link
