package tunnel

import (
	"bytes"
	"container/heap"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// client_test 测试矩阵：
//
// Tier 1 — 纯函数/数据结构（零依赖）
//   1. HubQueue Push+Pop 优先级排序
//   2. HubQueue Remove 按索引删除
//   3. HubQueue 空 queue Len
//   4. backoff 指数增长 + jitter + maxDelay cap
//   5. ClientHub.onCtrl TUN_HEARTBEAT → rcvd 更新
//   6. ClientHub.onCtrl 非 TUN_HEARTBEAT → passthrough

// ---- helpers ----

// newTestHubItem creates a HubItem with nil ClientHub for heap-only tests.
// Heap operations only access priority and index, never ClientHub.
func newTestHubItem(priority int) *HubItem {
	return &HubItem{
		priority: priority,
		index:    -1,
	}
}

// ---- HubQueue heap operations ----

// 1. Push + Pop 优先级排序 — priority 最小的先弹出

func TestHubQueuePushPopPriority(t *testing.T) {
	var hq HubQueue
	heap.Init(&hq)

	heap.Push(&hq, newTestHubItem(5))
	heap.Push(&hq, newTestHubItem(1))
	heap.Push(&hq, newTestHubItem(3))

	item := heap.Pop(&hq).(*HubItem)
	if item.priority != 1 {
		t.Fatalf("first pop: got %d, want 1", item.priority)
	}

	item = heap.Pop(&hq).(*HubItem)
	if item.priority != 3 {
		t.Fatalf("second pop: got %d, want 3", item.priority)
	}

	item = heap.Pop(&hq).(*HubItem)
	if item.priority != 5 {
		t.Fatalf("third pop: got %d, want 5", item.priority)
	}

	if hq.Len() != 0 {
		t.Fatalf("queue should be empty, got len %d", hq.Len())
	}
}

// 2. Remove 按索引删除 — 删除后堆性质正确，剩余 item.index 正确

func TestHubQueueRemoveByIndex(t *testing.T) {
	var hq HubQueue
	heap.Init(&hq)

	a := newTestHubItem(1)
	b := newTestHubItem(2)
	c := newTestHubItem(3)

	heap.Push(&hq, a)
	heap.Push(&hq, b)
	heap.Push(&hq, c)

	// 删除 b（priority=2）
	heap.Remove(&hq, b.index)

	if hq.Len() != 2 {
		t.Fatalf("len: got %d, want 2", hq.Len())
	}
	if b.index != -1 {
		t.Fatalf("removed item index: got %d, want -1", b.index)
	}

	// 剩余 item 的 index 应与实际位置一致
	for i, item := range hq {
		if item.index != i {
			t.Fatalf("hq[%d].index: got %d, want %d", i, item.index, i)
		}
		if hq[item.index] != item {
			t.Fatalf("hq[%d] != item with priority %d", item.index, item.priority)
		}
	}

	// Pop 顺序：a(1), c(3)
	first := heap.Pop(&hq).(*HubItem)
	if first != a {
		t.Fatalf("first pop: got priority %d, want a(1)", first.priority)
	}
	second := heap.Pop(&hq).(*HubItem)
	if second != c {
		t.Fatalf("second pop: got priority %d, want c(3)", second.priority)
	}
}

// 3. 空 queue Len — Len=0

func TestHubQueueEmpty(t *testing.T) {
	var hq HubQueue
	heap.Init(&hq)

	if hq.Len() != 0 {
		t.Fatalf("empty queue len: got %d, want 0", hq.Len())
	}

	// heap.Pop on empty slice panics — 这是 heap.Interface 的契约，
	// 调用方必须先检查 Len() > 0。此处只验证 Len() 返回 0。
}

// ---- backoff() 纯函数 ----

// 4. 指数增长 + jitter 范围 + maxDelay cap

func TestBackoffExponentialGrowth(t *testing.T) {
	base := time.Second
	max := 4 * time.Second // 小 max，attempt≥2 就触发 cap

	for attempt := 0; attempt <= 10; attempt++ {
		// 计算 attempt 对应的理论 delay（无 jitter）
		delay := base
		for i := 0; i < attempt; i++ {
			delay *= 2
			if delay >= max {
				delay = max
				break
			}
		}

		lo := delay / 2
		hi := delay

		for i := 0; i < 50; i++ {
			d := backoff(attempt, base, max)
			if d < lo || d >= hi {
				t.Fatalf("attempt=%d: got %v, want [%v, %v)", attempt, d, lo, hi)
			}
		}
	}
}

// ---- ClientHub.onCtrl() 过滤 ----

// 5. TUN_HEARTBEAT → rcvd 更新，返回 true

func TestClientHubOnCtrlHeartbeat(t *testing.T) {
	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()
	tun := newTunnel(ca)

	ch := &ClientHub{
		Hub: newHub(tun),
	}

	result := ch.onCtrl(Cmd{Cmd: TUN_HEARTBEAT, Id: 42})

	if !result {
		t.Fatal("onCtrl should return true for TUN_HEARTBEAT")
	}
	if ch.rcvd.Load() != 42 {
		t.Fatalf("rcvd: got %d, want 42", ch.rcvd.Load())
	}
}

// 6. 非 TUN_HEARTBEAT → passthrough，返回 false，rcvd 不变

func TestClientHubOnCtrlPassthrough(t *testing.T) {
	ca, cb := net.Pipe()
	defer ca.Close()
	defer cb.Close()
	tun := newTunnel(ca)

	ch := &ClientHub{
		Hub: newHub(tun),
	}
	ch.sent.Store(10)
	ch.rcvd.Store(5)

	result := ch.onCtrl(Cmd{Cmd: LINK_CLOSE, Id: 1})

	if result {
		t.Fatal("onCtrl should return false for non-TUN_HEARTBEAT")
	}
	if ch.rcvd.Load() != 5 {
		t.Fatalf("rcvd should be unchanged: got %d, want 5", ch.rcvd.Load())
	}
	if ch.sent.Load() != 10 {
		t.Fatalf("sent should be unchanged: got %d, want 10", ch.sent.Load())
	}
}

// ---- Tier 2: Client hub 状态管理（零 I/O，只操作堆）----

// newTestClient creates a Client with an empty HubQueue for state management tests.
func newTestClient() *Client {
	cli := &Client{
		alloc: newAllocator(),
		cq:    make(HubQueue, 0),
	}
	heap.Init(&cli.cq)
	return cli
}

// 7. addHub + fetchHub 轮转均衡性
//
// 3 个 priority=0 的 item，fetchHub 300 次。
// fetchHub 选中 min-priority item 并 priority++，因此严格轮转，各 100 次。

func TestClientFetchHubRoundRobin(t *testing.T) {
	cli := newTestClient()
	items := []*HubItem{newTestHubItem(0), newTestHubItem(0), newTestHubItem(0)}

	for _, item := range items {
		cli.addHub(item)
	}

	if cli.cq.Len() != 3 {
		t.Fatalf("queue len: got %d, want 3", cli.cq.Len())
	}

	counts := make(map[*HubItem]int)
	const rounds = 300

	for i := 0; i < rounds; i++ {
		item := cli.fetchHub()
		if item == nil {
			t.Fatal("fetchHub should not return nil")
		}
		counts[item]++
	}

	expected := rounds / len(items)
	for _, item := range items {
		c := counts[item]
		if c != expected {
			t.Errorf("item got %d selections, want %d", c, expected)
		}
	}
}

// 8. dropHub → priority 恢复
//
// a(pri=3) 不如 b(pri=0) 受青睐。反复 dropHub(a) 使 priority 降到 0，
// fetchHub 时 a 重新成为最优先。

func TestClientDropHubRestoresPriority(t *testing.T) {
	cli := newTestClient()
	a := newTestHubItem(3)
	b := newTestHubItem(0)

	cli.addHub(a)
	cli.addHub(b)

	// b(0) 优先于 a(3)
	item := cli.fetchHub()
	if item != b {
		t.Fatal("should pick b (lowest priority)")
	}
	// b.priority: 0→1, a still 3

	// dropHub(a) 三次：3→2→1→0
	cli.dropHub(a)
	cli.dropHub(a)
	cli.dropHub(a)

	// a(0) 优先于 b(1)
	item = cli.fetchHub()
	if item != a {
		t.Fatal("after dropHub, a should be most preferred")
	}
}

// 9. removeHub → 从堆中删除

func TestClientRemoveHub(t *testing.T) {
	cli := newTestClient()
	a := newTestHubItem(0)
	b := newTestHubItem(0)
	c := newTestHubItem(0)

	cli.addHub(a)
	cli.addHub(b)
	cli.addHub(c)

	cli.removeHub(b)

	if cli.cq.Len() != 2 {
		t.Fatalf("queue len: got %d, want 2", cli.cq.Len())
	}
	if b.index != -1 {
		t.Fatalf("removed item index: got %d, want -1", b.index)
	}

	seen := map[*HubItem]bool{}
	for i := 0; i < 2; i++ {
		item := cli.fetchHub()
		if item == b {
			t.Fatal("removed item should not be fetchable")
		}
		seen[item] = true
	}
	if !seen[a] || !seen[c] {
		t.Fatal("a and c should both be fetchable after removing b")
	}
}

// 10. 边界情况：空队列 + 无效 item

func TestClientHubManagementEdgeCases(t *testing.T) {
	cli := newTestClient()

	// 空 queue → fetchHub 返回 nil
	if item := cli.fetchHub(); item != nil {
		t.Fatal("fetchHub on empty queue should return nil")
	}

	// 无效 item（index=-1，从未入堆）
	orphan := newTestHubItem(0)
	cli.removeHub(orphan) // 不 panic
	cli.dropHub(orphan)   // 不 panic

	// 已删除的 item
	a := newTestHubItem(0)
	cli.addHub(a)
	cli.removeHub(a)
	cli.removeHub(a) // 重复删除不 panic
	cli.dropHub(a)   // 已删除 item 的 dropHub 不 panic
}

// ---- Tier 3: heartbeat 逻辑 ----
//
// heartbeat() goroutine 周期发送 TUN_HEARTBEAT，收到 echo 后更新 rcvd，
// 连续 maxSpan 次无 echo 则 Hub.Close() 超时断开。
//
// 11. 收到 echo → rcvd 更新 — Hub.Start() + onCtrlFilter 端到端

func TestClientHubHeartbeatEcho(t *testing.T) {
	origTO := Timeout
	Timeout = 30
	defer func() { Timeout = origTO }()

	a, b := newPipeTunnels()
	ch := &ClientHub{
		Hub: newHub(a),
	}

	// 用 channel hook 检测 echo 回传，避免直接读取 ch.rcvd（data race）
	echoCh := make(chan uint16, 10)
	ch.Hub.onCtrlFilter = func(cmd Cmd) bool {
		if ch.onCtrl(cmd) {
			echoCh <- cmd.Id
			return true
		}
		return false
	}

	// Hub.Start() 处理入站包
	startDone := make(chan struct{})
	go func() {
		ch.Hub.Start()
		close(startDone)
	}()

	// heartbeat() 发送心跳
	hbDone := make(chan struct{})
	go func() {
		ch.heartbeat()
		close(hbDone)
	}()

	// peer echo: 收到 TUN_HEARTBEAT 后回传
	echoDone := make(chan struct{})
	go func() {
		defer close(echoDone)
		for {
			linkid, data, err := b.ReadPacket()
			if err != nil {
				return
			}
			if linkid != 0 {
				t.Errorf("unexpected data packet: linkid=%d", linkid)
				mpool.Put(data)
				continue
			}
			var cmd Cmd
			if binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &cmd) == nil && cmd.Cmd == TUN_HEARTBEAT {
				resp := mpool.Get()[0:0]
				respBuf := bytes.NewBuffer(resp)
				binary.Write(respBuf, binary.LittleEndian, &Cmd{Cmd: TUN_HEARTBEAT, Id: cmd.Id})
				b.WritePacket(0, respBuf.Bytes())
			}
			mpool.Put(data)
		}
	}()

	// 等待 3 个 echo 回传，验证 Id 递增
	for i := 1; i <= 3; i++ {
		select {
		case id := <-echoCh:
			if id != uint16(i) {
				t.Fatalf("echo %d: got Id=%d, want %d", i, id, i)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for echo %d", i)
		}
	}

	a.Close()
	<-hbDone
	<-startDone
	<-echoDone
}

// 12. 连续未收到 echo → 超时断开 — Hub.Close() 被调用
func TestClientHubHeartbeatTimeout(t *testing.T) {
	// Heartbeat=1s, Timeout=0 → maxSpan=tunnelMinSpan=3
	// 3 ticks 无 echo → Hub.Close()
	origHB := Heartbeat
	Heartbeat = 1
	defer func() { Heartbeat = origHB }()

	a, b := newPipeTunnels()
	ch := &ClientHub{
		Hub: newHub(a),
	}

	hbDone := make(chan struct{})
	go func() {
		ch.heartbeat()
		close(hbDone)
	}()

	// peer 消费心跳但不回传（使 span 累积）
	peerDone := make(chan struct{})
	go func() {
		defer close(peerDone)
		for {
			_, data, err := b.ReadPacket()
			if err != nil {
				return
			}
			mpool.Put(data)
		}
	}()

	// heartbeat 应在 ~3 秒后因超时退出
	select {
	case <-hbDone:
		// heartbeat 已退出 — 隧道被 Close()
	case <-time.After(5 * time.Second):
		t.Fatal("heartbeat should have timed out within 5 seconds")
	}

	// peer 也应退出（tunnel 关闭后 ReadPacket 返回 error）
	select {
	case <-peerDone:
	case <-time.After(time.Second):
		t.Fatal("peer should have exited after tunnel close")
	}
}
