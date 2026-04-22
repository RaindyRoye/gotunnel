package tunnel

import (
	"sync"
	"testing"
)

// MPool 测试思路：
// 1. Get 契约：返回的切片 len/cap 符合 NewMPool 指定大小
// 2. Put 后 Get 可复用：Put 归还后再次 Get 能拿到合法切片（reslice 场景同理）
// 3. 边界值：sz=0 不 panic
// 4. 并发安全：多 goroutine 同时 Get/Put，-race 检测数据竞争
//
// 注：Put 无返回值，容量过滤是静默行为，无法从外部断言，仅保证不 panic。

func TestMPoolGetReturnsCorrectSize(t *testing.T) {
	const sz = 256
	p := NewMPool(sz)
	b := p.Get()
	if len(b) != sz {
		t.Fatalf("got len %d, want %d", len(b), sz)
	}
	if cap(b) < sz {
		t.Fatalf("got cap %d, want >= %d", cap(b), sz)
	}
}

func TestMPoolPutAndGetReuse(t *testing.T) {
	const sz = 128
	p := NewMPool(sz)

	b := p.Get()
	// 写入标记数据
	copy(b, "hello")
	p.Put(b)

	// Get 应该复用同一块内存（sync.Pool 不保证，但单 goroutine 下大概率命中）
	b2 := p.Get()
	if cap(b2) < sz {
		t.Fatalf("reused slice cap %d, want >= %d", cap(b2), sz)
	}
}

func TestMPoolPutResliced(t *testing.T) {
	const sz = 128
	p := NewMPool(sz)

	b := p.Get()
	// 模拟 reslice：[:0]，cap 不变
	sliced := b[:0]
	p.Put(sliced) // cap 仍为 128，应接受

	b2 := p.Get()
	if cap(b2) < sz {
		t.Fatalf("after reslice put, got cap %d, want >= %d", cap(b2), sz)
	}
}

func TestMPoolConcurrent(t *testing.T) {
	const sz = 512
	const workers = 8
	const iterations = 2000

	p := NewMPool(sz)
	var wg sync.WaitGroup

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				b := p.Get()
				if len(b) != sz {
					t.Errorf("worker %d iter %d: len %d, want %d", id, i, len(b), sz)
					return
				}
				// 写入标记
				b[0] = byte(id)
				b[sz-1] = byte(i)
				p.Put(b)
			}
		}(w)
	}
	wg.Wait()
}

func TestMPoolNewWithZeroSize(t *testing.T) {
	p := NewMPool(0)
	b := p.Get()
	if len(b) != 1 {
		t.Fatalf("got len %d, want 1", len(b))
	}
}
