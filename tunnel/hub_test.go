package tunnel

import (
	"bytes"
	"net"
	"testing"
)

// hub_test Tier 1 — 直接方法调用（无 goroutine，最简单）
//
// 直接构造 Hub，调用方法，检查 link 内部状态（同包可访问 l.rerr、l.wbuf）。
// 不调用 Start()/Send()/SendCmd()，因此不需要 tunnel I/O。
//
// 关键点：
//   - createLink 创建的 link 没有 conn，但 onCtrl/onData 只操作
//     link 的 close 状态和 wbuf，不需要活跃 TCP 连接
//   - onData 的 data 参数必须是 mpool 分配的切片（内部会 mpool.Put 回收）

// ---- helpers ----

// newTestHub 创建一个用于 Tier 1 测试的 Hub。
// tunnel 仅作占位，不进行 I/O。
func newTestHub() *Hub {
	ca, _ := net.Pipe()
	tun := newTunnel(ca)
	return newHub(tun)
}

// ---- 1. link CRUD ----

func TestHubCreateGetDeleteLink(t *testing.T) {
	h := newTestHub()

	l := h.createLink(1)
	if l == nil {
		t.Fatal("createLink(1) should return a link")
	}
	if l.id != 1 {
		t.Fatalf("link.id: got %d, want 1", l.id)
	}

	if h.getLink(1) != l {
		t.Fatal("getLink(1) should return the same link")
	}

	if h.getLink(2) != nil {
		t.Fatal("getLink(2) should return nil for non-existent link")
	}

	h.deleteLink(1)
	if h.getLink(1) != nil {
		t.Fatal("getLink(1) should return nil after delete")
	}
}

// ---- 2. createLink 重复 ID ----

func TestHubCreateLinkDuplicateID(t *testing.T) {
	h := newTestHub()

	l1 := h.createLink(1)
	if l1 == nil {
		t.Fatal("first createLink(1) should succeed")
	}

	l2 := h.createLink(1)
	if l2 != nil {
		t.Fatal("duplicate createLink(1) should return nil")
	}

	// 原始 link 应仍在 map 中
	if h.getLink(1) != l1 {
		t.Fatal("original link should still be accessible")
	}
}

// ---- 3. onCtrl(LINK_CLOSE) → aclose 全关闭 ----

func TestHubOnCtrlLinkClose(t *testing.T) {
	h := newTestHub()
	l := h.createLink(1)

	h.onCtrl(Cmd{Cmd: LINK_CLOSE, Id: 1})

	if l.rerr == nil {
		t.Fatal("link should be read-closed after LINK_CLOSE")
	}
	if l.write([]byte("x")) {
		t.Fatal("write should fail after LINK_CLOSE (wbuf closed)")
	}
}

// ---- 4. onCtrl(LINK_CLOSE_RECV) → rclose 读侧关闭 ----

func TestHubOnCtrlLinkCloseRecv(t *testing.T) {
	h := newTestHub()
	l := h.createLink(1)

	h.onCtrl(Cmd{Cmd: LINK_CLOSE_RECV, Id: 1})

	if l.rerr == nil {
		t.Fatal("link should be read-closed after LINK_CLOSE_RECV")
	}
	// 写侧仍可工作
	if !l.write([]byte("x")) {
		t.Fatal("write should still work after LINK_CLOSE_RECV")
	}
}

// ---- 5. onCtrl(LINK_CLOSE_SEND) → wclose 写侧关闭 ----

func TestHubOnCtrlLinkCloseSend(t *testing.T) {
	h := newTestHub()
	l := h.createLink(1)

	h.onCtrl(Cmd{Cmd: LINK_CLOSE_SEND, Id: 1})

	// 读侧不受影响
	if l.rerr != nil {
		t.Fatal("link should NOT be read-closed after LINK_CLOSE_SEND")
	}
	// 写侧应关闭
	if l.write([]byte("x")) {
		t.Fatal("write should fail after LINK_CLOSE_SEND")
	}
}

// ---- 6. onCtrlFilter 返回 true → 拦截 ----

func TestHubOnCtrlFilterIntercept(t *testing.T) {
	h := newTestHub()
	l := h.createLink(1)

	var receivedCmd Cmd
	h.onCtrlFilter = func(cmd Cmd) bool {
		receivedCmd = cmd
		return true // 拦截，不执行默认逻辑
	}

	h.onCtrl(Cmd{Cmd: LINK_CLOSE, Id: 1})

	// filter 拦截后 link 不应被关闭
	if l.rerr != nil {
		t.Fatal("link should NOT be closed when filter intercepts")
	}
	if receivedCmd.Cmd != LINK_CLOSE || receivedCmd.Id != 1 {
		t.Fatalf("filter received: Cmd=%d Id=%d, want Cmd=LINK_CLOSE Id=1",
			receivedCmd.Cmd, receivedCmd.Id)
	}
}

// ---- 7. onCtrlFilter 返回 false → passthrough ----

func TestHubOnCtrlFilterPassthrough(t *testing.T) {
	h := newTestHub()
	l := h.createLink(1)

	var called bool
	h.onCtrlFilter = func(cmd Cmd) bool {
		called = true
		return false // passthrough，执行默认逻辑
	}

	h.onCtrl(Cmd{Cmd: LINK_CLOSE, Id: 1})

	if !called {
		t.Fatal("filter should have been called")
	}
	// passthrough 后默认逻辑应执行
	if l.rerr == nil {
		t.Fatal("link should be closed after passthrough")
	}
}

// ---- 8. onCtrl 不存在的 link → 不 panic ----

func TestHubOnCtrlNoLink(t *testing.T) {
	h := newTestHub()

	h.onCtrl(Cmd{Cmd: LINK_CLOSE, Id: 99})
	h.onCtrl(Cmd{Cmd: LINK_CLOSE_RECV, Id: 99})
	h.onCtrl(Cmd{Cmd: LINK_CLOSE_SEND, Id: 99})
}

// ---- 9. onCtrl 未知命令 → 不影响 link ----

func TestHubOnCtrlUnknownCmd(t *testing.T) {
	h := newTestHub()
	l := h.createLink(1)

	h.onCtrl(Cmd{Cmd: 0xFF, Id: 1})

	if l.rerr != nil {
		t.Fatal("link rerr should be nil after unknown cmd")
	}
	if !l.write([]byte("x")) {
		t.Fatal("link write should still work after unknown cmd")
	}
}

// ---- 10. onData 路由到 link → wbuf.Pop() 得到数据 ----

func TestHubOnDataRouteToLink(t *testing.T) {
	h := newTestHub()
	l := h.createLink(1)

	data := mpool.Get()
	copy(data, []byte("hello"))
	h.onData(1, data[:5])

	got, ok := l.wbuf.Pop()
	if !ok {
		t.Fatal("wbuf.Pop should succeed")
	}
	if !bytes.Equal(got, []byte("hello")) {
		t.Fatalf("got %q, want 'hello'", got)
	}
	mpool.Put(got)
}

// ---- 11. onData 无 link → mpool.Put 回收，不泄漏 ----

func TestHubOnDataNoLink(t *testing.T) {
	h := newTestHub()

	data := mpool.Get()
	copy(data, []byte("orphan"))

	// 不应 panic，data 被 mpool.Put 回收
	h.onData(99, data[:6])
}

// ---- 12. onData link 已 wclose → mpool.Put 回收，不泄漏 ----

func TestHubOnDataLinkWclose(t *testing.T) {
	h := newTestHub()
	l := h.createLink(1)
	l.wclose()

	data := mpool.Get()
	copy(data, []byte("dropped"))

	// 不应 panic，data 被 mpool.Put 回收
	h.onData(1, data[:7])

	_ = l // suppress unused warning
}

// ---- 13. resetAllLink 关闭所有 link ----

func TestHubResetAllLink(t *testing.T) {
	h := newTestHub()
	l1 := h.createLink(1)
	l2 := h.createLink(2)
	l3 := h.createLink(3)

	h.resetAllLink()

	for _, l := range []*link{l1, l2, l3} {
		if l.rerr == nil {
			t.Fatalf("link(%d) should be read-closed after reset", l.id)
		}
		if l.write([]byte("x")) {
			t.Fatalf("link(%d) write should fail after reset", l.id)
		}
	}

	// link 仍在 map 中（resetAllLink 只关闭不删除）
	if h.getLink(1) == nil || h.getLink(2) == nil || h.getLink(3) == nil {
		t.Fatal("links should still exist in map after resetAllLink")
	}
}
