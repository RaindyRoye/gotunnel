// Package tunnel contains utilities, including an ID allocator.
package tunnel

// IdAllocator efficiently manages and distributes unique IDs in a thread-safe manner.
// It uses a buffered channel as a free-list to recycle IDs.
type IdAllocator struct {
	freeList chan uint16 // Channel acting as a queue for available IDs
}

// Acquire retrieves the next available unique ID.
// It blocks if no IDs are currently available in the free-list.
func (alloc *IdAllocator) Acquire() uint16 {
	return <-alloc.freeList
}

// Release returns an ID to the allocator, making it available for future acquisition.
// It blocks if the free-list's buffer is full.
func (alloc *IdAllocator) Release(id uint16) {
	alloc.freeList <- id
}

// newAllocator creates and initializes a new IdAllocator.
// It pre-populates the internal free-list with all valid IDs from 1 to TunnelMaxId - 1.
// Note: This assumes TunnelMaxId is ^uint16(0) (65535). If TunnelMaxId is different,
// the loop range might need adjustment.
func newAllocator() *IdAllocator {
	// Determine the channel capacity based on the range of IDs to be pre-populated.
	// The loop `for id = 1; id != TunnelMaxId; id++` adds IDs from 1 up to (but not including) TunnelMaxId.
	// So, the number of IDs added is TunnelMaxId - 1.
	// Example: TunnelMaxId = 65535 (MaxUint16). Loop adds 1..65534. Count = 65534 = 65535 - 1.
	// Ensure the channel capacity matches this count.
	capacity := int(TunnelMaxId - 1) // Subtract as uint16, then convert to int for make()
	// Note: If TunnelMaxId were 0, this would underflow uint16 (become MaxUint16) and then cast to a very large int,
	// which would cause make() to panic. However, the original code's loop `id != TunnelMaxId` would also fail
	// if TunnelMaxId were 0 (it would never run). The assumption here is TunnelMaxId > 0 (which it is, as ^uint16(0)).

	freeList := make(chan uint16, capacity)

	// Populate the free-list channel with initial IDs.
	// Iterates from 1 up to (but not including) TunnelMaxId.
	// Example: If TunnelMaxId is 65535, adds 1, 2, ..., 65534.
	var id uint16
	for id = 1; id != TunnelMaxId; id++ {
		freeList <- id
	}

	// Create and return the initialized allocator.
	return &IdAllocator{
		freeList: freeList,
	}
}
