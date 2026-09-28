可以，当前代码的 goroutine 拓扑其实很清楚，分成 `main`、`client`、`server`、`link` 四层来看最好。

**总入口**

程序启动后，主 goroutine 在 [main.go](e:/myproject/gotunnel/main.go#L46) 里做两件事：

- 起一个信号处理 goroutine：[`go handleSignal(app)`](e:/myproject/gotunnel/main.go#L85)
- 主 goroutine 自己阻塞在 [`app.Start()`](e:/myproject/gotunnel/main.go#L89)

所以最顶层永远是这样：

```text
main goroutine
├─ signal goroutine
└─ app.Start()        // server 或 client
```

**Server 模式**

当 `-tunnels=0` 时走 [NewServer](e:/myproject/gotunnel/tunnel/server.go#L165)，主 goroutine 进入 [Server.Start()](e:/myproject/gotunnel/tunnel/server.go#L131) 的 accept 循环。

每来一个 tunnel TCP 连接，就起一个 goroutine 跑 [`handleConn`](e:/myproject/gotunnel/tunnel/server.go#L85)：

```text
main goroutine -> Server.Start accept loop
├─ conn goroutine #1   // s.handleConn(conn)
├─ conn goroutine #2
└─ ...
```

每个 `handleConn` 在认证通过后会创建一个 `ServerHub`，然后直接在当前 goroutine 里跑 [`h.Start()`](e:/myproject/gotunnel/tunnel/server.go#L124)。也就是说：

- “每条 tunnel 连接”对应“一个 hub goroutine”
- 这个 hub goroutine 本质上就是那个 `handleConn` goroutine，本身不再额外起一层

而在 hub 内部，收到一个 `LINK_CREATE` 时，会再起一个 goroutine 处理这个逻辑链路：[`go h.handleLink(l)`](e:/myproject/gotunnel/tunnel/server.go#L49)

```text
one tunnel conn goroutine
└─ Hub.Start read loop
   ├─ link handler goroutine #id=1
   ├─ link handler goroutine #id=2
   └─ ...
```

每个 `link handler goroutine` 在 [`startLink`](e:/myproject/gotunnel/tunnel/link.go#L141) 里又会再拆成两个 goroutine：

- 一个负责从本地 TCP 读，再写进 tunnel
- 一个负责从 tunnel 取数据，再写回本地 TCP

见 [link.go](e:/myproject/gotunnel/tunnel/link.go#L149) 和 [link.go](e:/myproject/gotunnel/tunnel/link.go#L167)

```text
link handler goroutine
└─ startLink()
   ├─ read side goroutine
   └─ write side goroutine
```

所以 server 端完整拓扑大致是：

```text
main
├─ signal
└─ Server.Start accept loop
   ├─ tunnel conn goroutine A
   │  └─ Hub.Start loop
   │     ├─ link goroutine 100
   │     │  ├─ read goroutine
   │     │  └─ write goroutine
   │     └─ link goroutine 101
   │        ├─ read goroutine
   │        └─ write goroutine
   └─ tunnel conn goroutine B
      └─ Hub.Start loop
         └─ ...
```

**Client 模式**

当 `-tunnels>0` 时走 [NewClient](e:/myproject/gotunnel/tunnel/client.go#L381)，主 goroutine 进入 [Client.Start()](e:/myproject/gotunnel/tunnel/client.go#L332)。

这里会先起 `tunnels` 个“隧道维护 goroutine”：

- 见 [`go func(index int) { ... }`](e:/myproject/gotunnel/tunnel/client.go#L336)
- 每个 goroutine 负责维持一条底层 tunnel，断了就重连

然后主 goroutine 自己进入本地监听循环 [`cli.listen()`](e:/myproject/gotunnel/tunnel/client.go#L363)

```text
main goroutine -> Client.Start
├─ signal goroutine
├─ tunnel maintainer #0
├─ tunnel maintainer #1
├─ ...
└─ local listen loop
```

每个 maintainer 成功建 tunnel 后，会创建一个 `ClientHub`。这里还有一个额外 goroutine：[`go h.heartbeat()`](e:/myproject/gotunnel/tunnel/client.go#L82)

所以每条底层 tunnel 在 client 侧是：

```text
tunnel maintainer goroutine
├─ heartbeat goroutine
└─ hub.Start() read loop   // maintainer 自己阻塞在这里
```

本地监听每 accept 到一个用户连接，会起一个 goroutine 处理：[`go cli.handleConn(hub, conn)`](e:/myproject/gotunnel/tunnel/client.go#L308)

而每个 `handleConn` 最后也会进入同一个 [`startLink`](e:/myproject/gotunnel/tunnel/link.go#L141)，再拆成两个 goroutine。

所以 client 端完整拓扑是：

```text
main
├─ signal
├─ local listen loop
│  ├─ local conn goroutine A
│  │  └─ startLink()
│  │     ├─ read goroutine
│  │     └─ write goroutine
│  ├─ local conn goroutine B
│  └─ ...
├─ tunnel maintainer #0
│  ├─ heartbeat goroutine
│  └─ Hub.Start loop
├─ tunnel maintainer #1
│  ├─ heartbeat goroutine
│  └─ Hub.Start loop
└─ ...
```

**几个关键关系**

- `Hub.Start()` 只有一个读循环 goroutine，不会并发读 tunnel，见 [hub.go](e:/myproject/gotunnel/tunnel/hub.go#L108)
- 每个 link 一定是 “1 个管理 goroutine + 2 个 I/O goroutine”
- client 比 server 多出来两类 goroutine：
  - `tunnel maintainer`
  - `heartbeat`
- server 比 client 多出来一类 goroutine：
  - 每条 tunnel TCP 连接的 `handleConn` 接入 goroutine

**为什么这跟你前面的问题有关**

你前面遇到的“timeout 后像卡死”，本质上就发生在最底下这层 `startLink()`：

- 一个 link 的读写 goroutine 没有被真正唤醒退出
- 上面的 `handleConn`/`hub.Start`/maintainer 就会看到“逻辑上该结束，物理上却还挂着”
- 于是出现 link 表和堆状态的竞态收尾

如果你愿意，我下一条可以直接给你画一张“从本地连接进入，到 server backend 连接建立”的时序图，把 `LINK_CREATE / LINK_CLOSE / LINK_CLOSE_RECV / LINK_CLOSE_SEND` 也串起来。