//
//   date  : 2014-12-04
//   author: xjdrew
//

package tunnel

import (
	"sync"
)

// MPool is a specialized sync.Pool for fixed-size byte slices.
type MPool struct {
	*sync.Pool
	sz int
}

// Get retrieves a byte slice from the pool.
func (p *MPool) Get() []byte {
	return p.Pool.Get().([]byte)
}

// Put returns a byte slice to the pool if it matches the expected capacity.
func (p *MPool) Put(x []byte) {
	// Allow slices with capacity >= sz (handles cases where the slice was resliced)
	if cap(x) >= p.sz {
		p.Pool.Put(x[:p.sz])
	}
}

// NewMPool creates a new memory pool for byte slices of the given size.
func NewMPool(sz int) *MPool {
	p := &MPool{sz: sz}
	p.Pool = &sync.Pool{
		New: func() interface{} {
			return make([]byte, p.sz)
		},
	}
	return p
}
