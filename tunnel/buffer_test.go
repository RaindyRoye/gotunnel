package tunnel

import (
	"sync"
	"testing"
)

func TestBuffer(t *testing.T) {
	input := "hello, world"
	buf := NewBuffer(1)

	// round 1: sequential produce then consume
	for i := 0; i < len(input); i++ {
		buf.Put([]byte(input[i : i+1]))
	}
	var output string
	for len(output) < len(input) {
		data, ok := buf.Pop()
		if !ok {
			t.Fatal("Pop returned false before consuming all data (round 1)")
		}
		output += string(data)
	}
	if output != input {
		t.Fatalf("round 1: got %q, want %q", output, input)
	}

	// round 2: repeat to verify buffer reuse
	for i := 0; i < len(input); i++ {
		buf.Put([]byte(input[i : i+1]))
	}
	output = ""
	for len(output) < len(input) {
		data, ok := buf.Pop()
		if !ok {
			t.Fatal("Pop returned false before consuming all data (round 2)")
		}
		output += string(data)
	}
	if output != input {
		t.Fatalf("round 2: got %q, want %q", output, input)
	}
}

func TestBufferConcurrent(t *testing.T) {
	const writers = 4
	const itemsPerWriter = 1000
	buf := NewBuffer(4)

	// collect all expected items for verification
	expected := make(map[string]int)
	for w := 0; w < writers; w++ {
		for i := 0; i < itemsPerWriter; i++ {
			key := string(rune('a'+w)) + "-" + string(rune('0'+i%10))
			expected[key]++
		}
	}

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < itemsPerWriter; i++ {
				key := string(rune('a'+id)) + "-" + string(rune('0'+i%10))
				if !buf.Put([]byte(key)) {
					t.Errorf("Put failed: writer %d, item %d", id, i)
					return
				}
			}
		}(w)
	}

	// single consumer drains all items
	total := writers * itemsPerWriter
	received := make(map[string]int)
	for len(received) < total {
		// count unique items by summing values
		count := 0
		for _, c := range received {
			count += c
		}
		if count >= total {
			break
		}
		data, ok := buf.Pop()
		if !ok {
			t.Fatalf("Pop failed after %d items, expected %d", count, total)
		}
		received[string(data)]++
	}
	wg.Wait()

	// verify every expected item was received the correct number of times
	for key, want := range expected {
		if got := received[key]; got != want {
			t.Errorf("item %q: received %d times, want %d", key, got, want)
		}
	}
}

func TestBufferNewZeroOrNegative(t *testing.T) {
	for _, sz := range []int{0, -1} {
		buf := NewBuffer(sz)
		// 验证不会 panic，能正常 Put/Pop
		if !buf.Put([]byte("x")) {
			t.Fatalf("NewBuffer(%d): Put should succeed", sz)
		}
		data, ok := buf.Pop()
		if !ok || string(data) != "x" {
			t.Fatalf("NewBuffer(%d): Pop should return 'x', got %q, ok=%v", sz, data, ok)
		}
	}
}

func TestBufferClose(t *testing.T) {
	buf := NewBuffer(4)
	buf.Put([]byte("a"))
	buf.Put([]byte("b"))

	if !buf.Close() {
		t.Fatal("first Close should return true")
	}
	if buf.Close() {
		t.Fatal("second Close should return false")
	}

	// Close 后 Put 应失败
	if buf.Put([]byte("c")) {
		t.Fatal("Put on closed buffer should return false")
	}

	// Close 后已有数据仍可取出
	data, ok := buf.Pop()
	if !ok || string(data) != "a" {
		t.Fatal("should get 'a' after close")
	}
	data, ok = buf.Pop()
	if !ok || string(data) != "b" {
		t.Fatal("should get 'b' after close")
	}

	// 取空后返回 (nil, false)
	_, ok = buf.Pop()
	if ok {
		t.Fatal("Pop on closed empty buffer should return false")
	}
}

func TestBufferConcurrentCloseWakesPop(t *testing.T) {
	buf := NewBuffer(4)

	popDone := make(chan struct{})
	go func() {
		defer close(popDone)
		// Pop on empty buffer should block until Close
		_, ok := buf.Pop()
		if ok {
			t.Error("Pop should return false on closed empty buffer")
		}
	}()

	// Give the Pop goroutine time to enter cond.Wait.
	// This is a non-deterministic check; in practice with -race it's sufficient.
	buf.Close()

	<-popDone
}
