package tunnel

import (
	"sync"
	"testing"
)

// IdAllocator 测试思路
//
// IdAllocator 用 buffered channel (容量 65534) 做空闲 ID 队列，
// Acquire 从 channel 取、Release 放回。测试覆盖以下维度：
//
// 1. 基本正确性
//   - AcquireRelease: 验证初始分配递增 (1..10)；耗尽后 Release(id) 再 Acquire 拿到同一 id
//
// 2. 容量边界
//   - Exhaust: 耗尽全部 65534 个 ID 后 Acquire 阻塞，Release 解除阻塞
//
// 3. 唯一性
//   - NoDuplicate: 连续 Acquire 500 次无重复
//
// 4. 并发安全
//   - Concurrent: 16 个 goroutine 各 Acquire 500 个再全部 Release，
//     验证无竞态 (-race) 且所有 ID 可完整回收
//
// 5. 阻塞语义
//   - ReleaseUnblocks: 耗尽后 Acquire 阻塞，Release 唤醒并拿到精确值

func TestIdAllocatorAcquireRelease(t *testing.T) {
	alloc := newAllocator()

	// 连续 Acquire 几个 ID，验证递增且不为 0
	for want := uint16(1); want <= 10; want++ {
		got := alloc.Acquire()
		if got != want {
			t.Fatalf("Acquire: got %d, want %d", got, want)
		}
	}

	// 耗尽所有 ID，然后 Release 一个，验证能再次 Acquire 到
	const total = int(TunnelMaxId) - 1
	for i := 10; i < total; i++ {
		alloc.Acquire()
	}

	alloc.Release(42)
	if got := alloc.Acquire(); got != 42 {
		t.Fatalf("Acquire after Release(42): got %d, want 42", got)
	}
}

func TestIdAllocatorExhaust(t *testing.T) {
	alloc := newAllocator()

	// 耗尽所有 ID
	held := make([]uint16, 0, TunnelMaxId-1)
	for i := 0; i < int(TunnelMaxId)-1; i++ {
		held = append(held, alloc.Acquire())
	}

	// Acquire 应阻塞；在另一个 goroutine 中释放一个 ID
	go func() {
		alloc.Release(held[0])
	}()

	got := alloc.Acquire()
	if got != held[0] {
		t.Fatalf("Acquire after exhaust: got %d, want %d", got, held[0])
	}

	// 清理：释放其余 ID 避免泄漏（不影响测试结果）
	for _, id := range held[1:] {
		alloc.Release(id)
	}
}

func TestIdAllocatorNoDuplicate(t *testing.T) {
	alloc := newAllocator()

	const n = 500
	seen := make(map[uint16]bool, n)
	for i := 0; i < n; i++ {
		id := alloc.Acquire()
		if seen[id] {
			t.Fatalf("duplicate ID acquired: %d", id)
		}
		seen[id] = true
	}

	// 归还
	for id := range seen {
		alloc.Release(id)
	}
}

func TestIdAllocatorConcurrent(t *testing.T) {
	alloc := newAllocator()

	const workers = 16
	const perWorker = 500
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			held := make([]uint16, 0, perWorker)
			for i := 0; i < perWorker; i++ {
				id := alloc.Acquire()
				held = append(held, id)
			}
			for _, id := range held {
				alloc.Release(id)
			}
		}()
	}

	wg.Wait()

	// 验证所有 ID 已归还：能再次 Acquire workers*perWorker 个不重复的 ID
	total := workers * perWorker
	seen := make(map[uint16]struct{}, total)
	for i := 0; i < total; i++ {
		id := alloc.Acquire()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate ID after concurrent round: %d", id)
		}
		seen[id] = struct{}{}
	}

	for id := range seen {
		alloc.Release(id)
	}
}

func TestIdAllocatorReleaseUnblocks(t *testing.T) {
	alloc := newAllocator()

	// 耗尽所有 ID
	for i := 0; i < int(TunnelMaxId)-1; i++ {
		alloc.Acquire()
	}

	// 启动 goroutine 尝试 Acquire，会阻塞在空 freeList 上
	acquired := make(chan uint16, 1)
	go func() {
		acquired <- alloc.Acquire()
	}()

	// 释放一个 ID，应解除阻塞
	const released = uint16(999)
	alloc.Release(released)

	got := <-acquired
	if got != released {
		t.Fatalf("blocked Acquire got %d, want %d", got, released)
	}
}
