package tunnel

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
)

// conn_test 测试思路：
// 使用 net.Pipe() 创建全双工连接对，测试 TunnelConn 和 Tunnel 的完整行为。
//
// 测试矩阵：
// 1. TunnelConn 读写往返（无加密 / 有加密）
// 2. Tunnel WritePacket/ReadPacket 往返
// 3. SetCipherKey 密钥扩展/截断
// 4. 并发 WritePacket 安全性
// 5. 写入错误传播（werr 缓存）
// 6. ReadPacket 过大包拒绝
// 7. 读 EOF 传播
//
// ---- helpers ----

// newPipeTunnels 返回一对通过 net.Pipe 互连的 Tunnel。
func newPipeTunnels() (a, b *Tunnel) {
	ca, cb := net.Pipe()
	a = newTunnel(ca)
	b = newTunnel(cb)
	return
}

// newPipeTunnelsWithKey 返回一对启用 ChaCha20 加密的 Tunnel。
func newPipeTunnelsWithKey(key []byte) (a, b *Tunnel) {
	a, b = newPipeTunnels()
	a.SetCipherKey(key)
	b.SetCipherKey(key)
	return
}

// ---- TunnelConn 测试 ----

func TestTunnelConnReadWritePlain(t *testing.T) {
	a, b := newPipeTunnels()

	msg := []byte("hello, tunnel!")
	orig := make([]byte, len(msg))
	copy(orig, msg) // Write 会修改底层 slice（加密场景），这里虽无加密但保持习惯

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		n, err := a.Write(msg)
		if err != nil {
			t.Errorf("write: %v", err)
			return
		}
		if n != len(msg) {
			t.Errorf("write len: got %d, want %d", n, len(msg))
		}
		a.Flush()
	}()

	buf := make([]byte, len(orig))
	n, err := io.ReadFull(b, buf)
	wg.Wait()

	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if n != len(orig) {
		t.Fatalf("read len: got %d, want %d", n, len(orig))
	}
	if !bytes.Equal(buf, orig) {
		t.Fatalf("content mismatch: got %q, want %q", buf, orig)
	}
}

func TestTunnelConnReadWriteEncrypted(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	a, b := newPipeTunnelsWithKey(key)

	msg := []byte("secret data through chacha20")
	orig := make([]byte, len(msg))
	copy(orig, msg) // TunnelConn.Write 原地加密，必须先保存原文

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.Write(msg)
		a.Flush()
	}()

	buf := make([]byte, len(orig))
	_, err := io.ReadFull(b, buf)
	wg.Wait()

	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(buf, orig) {
		t.Fatalf("decrypted mismatch: got %q, want %q", buf, orig)
	}
}

func TestTunnelConnEncryptionActuallyEncrypts(t *testing.T) {
	// 验证加密确实生效：同一明文写入，线路上不应该是明文
	key := make([]byte, 32)
	rand.Read(key)

	ca, _ := net.Pipe()
	tc := newTunnel(ca).TunnelConn
	tc.SetCipherKey(key)

	msg := []byte("plaintext should not appear on wire")
	enc := make([]byte, len(msg))
	copy(enc, msg)
	tc.enc.XORKeyStream(enc, enc)

	if bytes.Equal(enc, msg) {
		t.Fatal("encrypted data should differ from plaintext")
	}
}

func TestSetCipherKeyShortKey(t *testing.T) {
	key := []byte("short")
	ca, _ := net.Pipe()
	tc := newTunnel(ca).TunnelConn
	tc.SetCipherKey(key)

	if tc.enc == nil || tc.dec == nil {
		t.Fatal("cipher should be initialized")
	}
}

func TestSetCipherKeyLongKey(t *testing.T) {
	key := make([]byte, 64)
	rand.Read(key)
	ca, _ := net.Pipe()
	tc := newTunnel(ca).TunnelConn
	tc.SetCipherKey(key)

	if tc.enc == nil || tc.dec == nil {
		t.Fatal("cipher should be initialized")
	}
}

// ---- Tunnel WritePacket/ReadPacket 往返 ----

func TestTunnelPacketRoundTrip(t *testing.T) {
	a, b := newPipeTunnels()

	payload := []byte("hello packet")
	data := mpool.Get()
	copy(data, payload)
	sendData := data[:len(payload)]

	linkid := uint16(42)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.WritePacket(linkid, sendData); err != nil {
			t.Errorf("WritePacket: %v", err)
		}
	}()

	gotLinkid, gotData, err := b.ReadPacket()
	wg.Wait()

	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if gotLinkid != linkid {
		t.Errorf("linkid: got %d, want %d", gotLinkid, linkid)
	}
	if !bytes.Equal(gotData, payload) {
		t.Errorf("data: got %q, want %q", gotData, payload)
	}
	mpool.Put(gotData)
}

func TestTunnelPacketRoundTripEncrypted(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)
	a, b := newPipeTunnelsWithKey(key)

	payload := []byte("encrypted packet payload")
	data := mpool.Get()
	copy(data, payload)
	sendData := data[:len(payload)]

	linkid := uint16(1234)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.WritePacket(linkid, sendData); err != nil {
			t.Errorf("WritePacket: %v", err)
		}
	}()

	gotLinkid, gotData, err := b.ReadPacket()
	wg.Wait()

	if err != nil {
		t.Fatalf("ReadPacket: %v", err)
	}
	if gotLinkid != linkid {
		t.Errorf("linkid: got %d, want %d", gotLinkid, linkid)
	}
	if !bytes.Equal(gotData, payload) {
		t.Errorf("data: got %q, want %q", gotData, payload)
	}
	mpool.Put(gotData)
}

func TestTunnelMultiplePackets(t *testing.T) {
	a, b := newPipeTunnels()

	packets := []struct {
		linkid uint16
		data   string
	}{
		{1, "first"},
		{2, "second packet"},
		{65535, "max linkid"},
		{0, "zero linkid"},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, pkt := range packets {
			data := mpool.Get()
			copy(data, pkt.data)
			if err := a.WritePacket(pkt.linkid, data[:len(pkt.data)]); err != nil {
				t.Errorf("WritePacket linkid=%d: %v", pkt.linkid, err)
				return
			}
		}
	}()

	for _, pkt := range packets {
		gotLinkid, gotData, err := b.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket: %v", err)
		}
		if gotLinkid != pkt.linkid {
			t.Errorf("linkid: got %d, want %d", gotLinkid, pkt.linkid)
		}
		if string(gotData) != pkt.data {
			t.Errorf("data: got %q, want %q", gotData, pkt.data)
		}
		mpool.Put(gotData)
	}
	<-done
}

func TestTunnelEmptyPacket(t *testing.T) {
	a, b := newPipeTunnels()

	data := mpool.Get()[:0]

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := a.WritePacket(99, data); err != nil {
			t.Errorf("WritePacket empty: %v", err)
		}
	}()

	gotLinkid, gotData, err := b.ReadPacket()
	wg.Wait()

	if err != nil {
		t.Fatalf("ReadPacket empty: %v", err)
	}
	if gotLinkid != 99 {
		t.Errorf("linkid: got %d, want 99", gotLinkid)
	}
	if len(gotData) != 0 {
		t.Errorf("data: got len %d, want 0", len(gotData))
	}
}

// ---- 并发 WritePacket ----

func TestTunnelConcurrentWrite(t *testing.T) {
	a, b := newPipeTunnels()

	const writers = 4
	const packetsPerWriter = 50

	// 用 map[linkid]map[byte]bool 收集每个 writer 发送的 data[1] 值，
	// 验证数据完整性：所有包都到达，且 data[0] 与 linkid 一致。
	received := make([]map[byte]bool, writers)
	for w := 0; w < writers; w++ {
		received[w] = make(map[byte]bool)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < writers*packetsPerWriter; i++ {
			linkid, data, err := b.ReadPacket()
			if err != nil {
				t.Errorf("ReadPacket: %v", err)
				return
			}
			if int(linkid) >= writers {
				t.Errorf("unexpected linkid %d", linkid)
				continue
			}
			if len(data) != 2 {
				t.Errorf("linkid %d: data len %d, want 2", linkid, len(data))
				mpool.Put(data)
				continue
			}
			// data[0] 必须等于 linkid（即 writer id）
			if data[0] != byte(linkid) {
				t.Errorf("linkid %d: data[0]=%d, want %d", linkid, data[0], linkid)
			}
			received[linkid][data[1]] = true
			mpool.Put(data)
		}
	}()

	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < packetsPerWriter; i++ {
				data := mpool.Get()
				data[0] = byte(id)
				data[1] = byte(i)
				if err := a.WritePacket(uint16(id), data[:2]); err != nil {
					t.Errorf("writer %d pkt %d: %v", id, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	<-done

	// 验证每个 writer 的 50 个包全部到达
	for w := 0; w < writers; w++ {
		if len(received[w]) != packetsPerWriter {
			t.Errorf("writer %d: received %d packets, want %d", w, len(received[w]), packetsPerWriter)
		}
	}
}

// ---- 错误场景 ----

func TestTunnelReadPacketEOF(t *testing.T) {
	a, b := newPipeTunnels()

	a.Close()

	_, _, err := b.ReadPacket()
	if err == nil {
		t.Fatal("expected error on closed connection")
	}
}

func TestTunnelWritePacketErrorPropagation(t *testing.T) {
	a, _ := newPipeTunnels()
	a.Close()

	data := mpool.Get()[:4]
	err := a.WritePacket(1, data)
	if err == nil {
		t.Fatal("expected error writing to closed tunnel")
	}

	// 第二次写入应立即失败（werr 缓存）
	data2 := mpool.Get()[:4]
	err = a.WritePacket(2, data2)
	if err == nil {
		t.Fatal("expected cached error on second write")
	}
}

func TestTunnelReadPacketTooLarge(t *testing.T) {
	ca, cb := net.Pipe()
	b := newTunnel(cb)

	go func() {
		h := header{Linkid: 1, Len: TunnelPacketSize + 1}
		binary.Write(ca, binary.LittleEndian, &h)
		ca.Close()
	}()

	_, _, err := b.ReadPacket()
	if err != errTooLarge {
		t.Fatalf("expected errTooLarge, got: %v", err)
	}
}

// ---- Tunnel.String() ----

func TestTunnelString(t *testing.T) {
	a, _ := newPipeTunnels()
	s := a.String()
	if s == "" {
		t.Fatal("String() should not be empty")
	}
	t.Logf("Tunnel.String() = %s", s)
}
