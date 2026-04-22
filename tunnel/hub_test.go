package tunnel

import (
	"bytes"
	"encoding/binary"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
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

// ---- Tier 2: 通过 pipe tunnel 测试调度（需要 goroutine）----
//
// 使用 newPipeTunnels() 创建连接对，一端 Hub.Start() 在 goroutine 中运行，
// 另一端作为 peer 注入/验证数据包。
// 通过 onCtrlFilter 的 channel 回调实现同步等待。

// ---- 14. SendCmd ----

func TestHubSendCmd(t *testing.T) {
	a, b := newPipeTunnels()
	h := newHub(a)

	var sendOk bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		sendOk = h.SendCmd(1, LINK_CLOSE)
	}()

	// peer 应收到 control packet（linkid=0）
	linkid, data, err := b.ReadPacket()
	wg.Wait()

	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	defer mpool.Put(data)

	if !sendOk {
		t.Fatal("SendCmd should succeed")
	}
	if linkid != 0 {
		t.Fatalf("linkid: got %d, want 0 (control)", linkid)
	}

	var cmd Cmd
	buf := bytes.NewBuffer(data)
	if err := binary.Read(buf, binary.LittleEndian, &cmd); err != nil {
		t.Fatalf("parse cmd: %v", err)
	}
	if cmd.Cmd != LINK_CLOSE || cmd.Id != 1 {
		t.Fatalf("cmd: got {Cmd=%d, Id=%d}, want {LINK_CLOSE, 1}", cmd.Cmd, cmd.Id)
	}
}

// ---- 15. Send ----

func TestHubSend(t *testing.T) {
	a, b := newPipeTunnels()
	h := newHub(a)

	payload := []byte("hello from send")

	var sendOk bool
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		data := mpool.Get()
		copy(data, payload)
		sendOk = h.Send(42, data[:len(payload)])
	}()

	linkid, gotData, err := b.ReadPacket()
	wg.Wait()

	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	defer mpool.Put(gotData)

	if !sendOk {
		t.Fatal("Send should succeed")
	}
	if linkid != 42 {
		t.Fatalf("linkid: got %d, want 42", linkid)
	}
	if !bytes.Equal(gotData, payload) {
		t.Fatalf("data: got %q, want %q", gotData, payload)
	}
}

// ---- 16. Start 调度 ctrl packet ----

func TestHubStartCtrlDispatch(t *testing.T) {
	a, b := newPipeTunnels()
	h := newHub(b)
	l := h.createLink(1)

	ctrlCh := make(chan Cmd, 1)
	h.onCtrlFilter = func(cmd Cmd) bool {
		ctrlCh <- cmd
		return false // passthrough，让默认逻辑也执行
	}

	startDone := make(chan struct{})
	go func() {
		h.Start()
		close(startDone)
	}()

	// 通过 peer tunnel 发送 control packet（linkid=0）
	ctrlData := mpool.Get()[0:0]
	ctrlBuf := bytes.NewBuffer(ctrlData)
	binary.Write(ctrlBuf, binary.LittleEndian, &Cmd{Cmd: LINK_CLOSE, Id: 1})
	if err := a.WritePacket(0, ctrlBuf.Bytes()); err != nil {
		t.Fatal(err)
	}

	// 验证 onCtrlFilter 收到命令
	select {
	case cmd := <-ctrlCh:
		if cmd.Cmd != LINK_CLOSE || cmd.Id != 1 {
			t.Fatalf("got {Cmd=%d, Id=%d}, want {LINK_CLOSE, 1}", cmd.Cmd, cmd.Id)
		}
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for ctrl dispatch")
	}

	// 1. Start() goroutine：onCtrlFilter 写入 channel → 返回 false
	// 2. 测试 goroutine：从 channel 收到命令 → 立刻检查 l.write()
	// 3. 但此时 onCtrl 还没来得及调用 l.aclose()
	// onCtrlFilter 返回 false 后，onCtrl 还要执行 h.getLink(id) → l.aclose()。测试 goroutine 可能在 aclose 之前就检查了状态，所以 write
	// 还能成功，断言失败。

	// 用轮询等待 aclose 生效后才判定。goto closed 跳过 t.Fatal，避免用 break 跳出两层嵌套。
	// onCtrlFilter 返回 false 后，onCtrl 继续执行 aclose()。
	// 轮询等待 aclose 生效（跨 goroutine 无内存屏障，不能假设即时可见）。
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if !l.write([]byte("x")) {
			goto closed
		}
		runtime.Gosched()
	}
	t.Fatal("link write should fail after LINK_CLOSE passthrough")
closed:

	a.Close()
	<-startDone
}

// ---- 17. Start 调度 data packet ----

func TestHubStartDataDispatch(t *testing.T) {
	a, b := newPipeTunnels()
	h := newHub(b)
	l := h.createLink(1)

	startDone := make(chan struct{})
	go func() {
		h.Start()
		close(startDone)
	}()

	// 通过 peer tunnel 发送 data packet（linkid=1）
	payload := []byte("routed data")
	data := mpool.Get()
	copy(data, payload)
	if err := a.WritePacket(1, data[:len(payload)]); err != nil {
		t.Fatal(err)
	}

	// 用 goroutine + timeout 防止 Pop 永久阻塞
	popCh := make(chan []byte, 1)
	go func() {
		got, ok := l.wbuf.Pop()
		if ok {
			popCh <- got
		}
	}()

	select {
	case got := <-popCh:
		if !bytes.Equal(got, payload) {
			t.Fatalf("got %q, want %q", got, payload)
		}
		mpool.Put(got)
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for wbuf.Pop")
	}

	a.Close()
	<-startDone
}

// ---- 18. Start 退出 → resetAllLink ----

func TestHubStartExitResetsLinks(t *testing.T) {
	a, b := newPipeTunnels()
	h := newHub(b)
	l1 := h.createLink(1)
	l2 := h.createLink(2)

	startDone := make(chan struct{})
	go func() {
		h.Start()
		close(startDone)
	}()

	// 关闭 peer tunnel → Start() 读到 EOF → 退出 → resetAllLink
	a.Close()

	select {
	case <-startDone:
	case <-time.After(time.Second):
		t.Fatal("Start() didn't exit after peer close")
	}

	// 所有 link 应被重置
	for _, l := range []*link{l1, l2} {
		if l.rerr == nil {
			t.Fatalf("link(%d) should be read-closed after Start exits", l.id)
		}
		if l.write([]byte("x")) {
			t.Fatalf("link(%d) write should fail after Start exits", l.id)
		}
	}
}
