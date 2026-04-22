# [P1] aclose 不关闭底层 TCP 连接

## 描述

`link.aclose()` 在移除 `closeConn()` 后，只调用 `rclose()` + `wclose()`，不再关闭底层 `conn`。

当前依赖 `startLink` 中两个 goroutine 的 `defer` 来关闭连接：

- 读 goroutine：`defer l.conn.CloseRead()`
- 写 goroutine：`defer l.conn.CloseWrite()`

但如果一个 goroutine 提前退出，另一个可能仍在阻塞，导致连接无法及时关闭。

## 触发路径

1. 对端异常关闭连接，`read()` 返回错误
2. 读 goroutine 退出，调用 `CloseRead()`
3. `_write()` 仍在 `wbuf.Pop()` 阻塞（因为 `wclose` 尚未调用）
4. `wg.Wait()` 未返回，`startLink` 未结束
5. 写 goroutine 无法被 `CloseWrite()` 唤醒

## 受影响场景

- `Hub.resetAllLink()` 调用 `l.aclose()`
- `Hub.onCtrl(LINK_CLOSE)` 调用 `l.aclose()`

## 建议修复

在 `Hub.Start()` 循环退出后（`break` 后），显式清理所有 link 的底层连接，或在 `aclose` 中添加独立清理机制。

## 相关文件

- `tunnel/link.go` - aclose 实现变更
- `tunnel/hub.go` - resetAllLink/onCtrl 调用链

## 发现时间

2026-04-22
