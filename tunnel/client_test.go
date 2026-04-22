package tunnel

import (
	"container/heap"
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
	ca, _ := net.Pipe()
	defer ca.Close()
	tun := newTunnel(ca)

	ch := &ClientHub{
		Hub:  newHub(tun),
		sent: 0,
		rcvd: 0,
	}

	result := ch.onCtrl(Cmd{Cmd: TUN_HEARTBEAT, Id: 42})

	if !result {
		t.Fatal("onCtrl should return true for TUN_HEARTBEAT")
	}
	if ch.rcvd != 42 {
		t.Fatalf("rcvd: got %d, want 42", ch.rcvd)
	}
}

// 6. 非 TUN_HEARTBEAT → passthrough，返回 false，rcvd 不变

func TestClientHubOnCtrlPassthrough(t *testing.T) {
	ca, _ := net.Pipe()
	defer ca.Close()
	tun := newTunnel(ca)

	ch := &ClientHub{
		Hub:  newHub(tun),
		sent: 10,
		rcvd: 5,
	}

	result := ch.onCtrl(Cmd{Cmd: LINK_CLOSE, Id: 1})

	if result {
		t.Fatal("onCtrl should return false for non-TUN_HEARTBEAT")
	}
	if ch.rcvd != 5 {
		t.Fatalf("rcvd should be unchanged: got %d, want 5", ch.rcvd)
	}
	if ch.sent != 10 {
		t.Fatalf("sent should be unchanged: got %d, want 10", ch.sent)
	}
}
