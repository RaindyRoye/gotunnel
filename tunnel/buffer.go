// Package tunnel contains a thread-safe buffer for queuing byte slices.
package tunnel

import (
	"sync"
)

// Buffer is a thread-safe circular buffer for storing byte slices ([]byte).
// It uses sync.Cond for efficient waiting when the buffer is empty or full.
type Buffer struct {
	start  int       // Index of the first element in the buffer
	end    int       // Index where the next element will be placed
	buf    [][]byte  // The underlying slice acting as the circular buffer
	cond   *sync.Cond // Condition variable for blocking Pop on empty and signaling on Put
	closed bool      // Flag indicating if the buffer is closed
}

// bufferLen calculates the current number of elements in the buffer.
// This helper function is called while holding the mutex lock.
func (b *Buffer) bufferLen() int {
	// Calculate length considering the circular nature of the buffer.
	// Adding cap(b.buf) before modulo handles potential negative results from subtraction.
	return (b.end + cap(b.buf) - b.start) % cap(b.buf)
}

// Len returns the current number of elements in the buffer.
// It blocks briefly to acquire the internal lock.
func (b *Buffer) Len() int {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()
	return b.bufferLen()
}

// Close marks the buffer as closed.
// Any subsequent Puts will fail, and ongoing or future Pops will eventually return (nil, false).
// Returns true if the buffer was successfully closed (was not already closed), false otherwise.
func (b *Buffer) Close() bool {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()

	if b.closed {
		return false // Already closed
	}

	b.closed = true
	// Signal all goroutines waiting on the condition variable.
	// This wakes up any Poppers waiting for data, allowing them to check the 'closed' flag.
	b.cond.Broadcast()
	return true
}

// Put attempts to add a byte slice to the buffer.
// It blocks if the buffer is full until space becomes available or the buffer is closed.
// Returns true if the data was successfully added, false if the buffer was closed.
func (b *Buffer) Put(data []byte) bool {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()

	// Check if the buffer is closed before attempting to add data.
	if b.closed {
		return false
	}

	// Check if the buffer is full (next position is the start index).
	// This also handles the initial case where start == end == 0 and capacity > 0.
	oldCap := cap(b.buf)
	if (b.end+1)%oldCap == b.start {
		// Buffer is full, need to grow it.
		newCapacity := oldCap * 2
		if newCapacity == 0 {
			// Handle initial capacity of 0, ensure growth starts properly.
			// NewBuffer guarantees sz >= 1, so this line should theoretically not be reached
			// unless someone manually creates a Buffer with 0 capacity.
			newCapacity = 2
		}
		newBuf := make([][]byte, newCapacity)

		// Copy existing elements from the old buffer to the new one in order.
		currentLen := b.bufferLen()
		if currentLen > 0 {
			// If the buffer wraps around (end < start), copy in two parts.
			// Otherwise (start <= end), copy in one contiguous part.
			if b.end > b.start {
				// ... [start ... end) ... -> ... [0 ... currentLen) ...
				copy(newBuf, b.buf[b.start:b.end])
			} else { // b.end < b.start (wrap-around case)
				// ... [start ... N) [0 ... end) ... -> ... [0 ... part1) [part1 ... part1+part2) ...
				part1Len := oldCap - b.start
				copy(newBuf, b.buf[b.start:oldCap])           // Copy from start to end of old buffer
				copy(newBuf[part1Len:], b.buf[0:b.end])       // Copy from start of old buffer to end
			}
		}

		// Update buffer internals to use the new buffer and reset indices.
		b.buf = newBuf
		b.start = 0
		b.end = currentLen // The new end index is the number of elements copied
	}

	// Add the new data element at the current 'end' position.
	b.buf[b.end] = data
	b.end = (b.end + 1) % cap(b.buf) // Move end pointer, wrap around if necessary

	// Signal one goroutine waiting in Pop that new data is available.
	b.cond.Signal()
	return true
}

// Pop retrieves and removes the oldest byte slice from the buffer.
// It blocks if the buffer is empty until an element is added or the buffer is closed.
// Returns the oldest byte slice and true on success, or (nil, false) if the buffer is closed
// and no more elements are available.
func (b *Buffer) Pop() ([]byte, bool) {
	b.cond.L.Lock()
	defer b.cond.L.Unlock()

	// Loop to handle spurious wakeups from b.cond.Wait().
	for {
		// Check if there's data available.
		if b.bufferLen() > 0 {
			// Retrieve the data at the 'start' index.
			data := b.buf[b.start]
			// Clear the reference to the data in the old slice to help GC if needed.
			// b.buf[b.start] = nil // Optional: Uncomment if slices hold pointers and you want to hint at GC
			b.start = (b.start + 1) % cap(b.buf) // Move start pointer, wrap around if necessary
			return data, true
		}

		// Check if the buffer is closed and empty.
		if b.closed {
			// No more data will ever arrive. Exit the loop and return failure.
			return nil, false
		}

		// Buffer is empty and not closed. Wait for a signal (from Put or Close).
		b.cond.Wait()
		// After Wait(), the lock is held again, and we loop back to re-check conditions.
	}
}

// NewBuffer creates a new thread-safe Buffer with an initial capacity for sz elements.
// sz must be greater than 0.
func NewBuffer(sz int) *Buffer {
	// Use sync.Mutex as the Locker for sync.Cond.
	var mu sync.Mutex
	return &Buffer{
		buf:   make([][]byte, sz), // Create the initial underlying slice
		start: 0,                  // Initially, start and end point to the beginning
		end:   0,
		cond:  sync.NewCond(&mu), // Create the condition variable
	}
}
