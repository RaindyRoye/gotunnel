package tunnel

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

// link_test 测试思路：
// 使用本地 TCP 连接对模拟双向数据转发，测试 link 的 close 语义（半关闭/全关闭）。
//
// 注：net.Pipe() 返回 *net.PipeConn，不满足 link.conn 的 *net.TCPConn 类型约束，
// 因此用本地 TCP 监听器建立真实连接对，效果等价。
//
// 测试矩阵：
// 1. setRerr / rclose 单次语义
// 2. wclose 关闭写缓冲
// 3. aclose 全关闭 + 多次/并发调用安全
// 4. read 从连接读数据 + rclose / 连接关闭后返回错误
// 5. write / _write 数据经 Buffer 转发到连接
// 6. 半关闭：rclose 不影响写、wclose 不影响读
// 7. 双向转发

// ---- helpers ----

// newTCPConnPair 创建一对本地 TCP 连接。
func newTCPConnPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	acceptCh := make(chan *net.TCPConn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			close(acceptCh)
			return
		}
		acceptCh <- c.(*net.TCPConn)
	}()

	client, err = net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}

	server, ok := <-acceptCh
	if !ok || server == nil {
		client.Close()
		t.Fatal("accept failed")
	}
	return
}

// newTestLink 创建一个指定 id 和连接的 link。
// conn 传 nil 表示不设置连接（用于纯 close 语义测试）。
func newTestLink(id uint16, conn *net.TCPConn) *link {
	return &link{
		id:   id,
		conn: conn,
		wbuf: NewBuffer(16),
	}
}

// ---- 1. setRerr / rclose 单次语义 ----

func TestLinkSetRerrOnce(t *testing.T) {
	l := newTestLink(1, nil)

	if !l.setRerr(errPeerClosed) {
		t.Fatal("first setRerr should return true")
	}
	if l.setRerr(io.EOF) {
		t.Fatal("second setRerr should return false")
	}
	if l.rerr != errPeerClosed {
		t.Fatalf("rerr: got %v, want %v", l.rerr, errPeerClosed)
	}
}

func TestLinkRclose(t *testing.T) {
	l := newTestLink(1, nil)

	if !l.rclose() {
		t.Fatal("first rclose should return true")
	}
	if l.rclose() {
		t.Fatal("second rclose should return false")
	}
}

// ---- 2. wclose 关闭写缓冲 ----

func TestLinkWclose(t *testing.T) {
	l := newTestLink(1, nil)

	if !l.wclose() {
		t.Fatal("first wclose should return true")
	}
	if l.wclose() {
		t.Fatal("second wclose should return false")
	}
	if l.write([]byte("x")) {
		t.Fatal("write after wclose should return false")
	}
}

// ---- 3. aclose 全关闭 + 多次/并发安全 ----

func TestLinkAcloseIdempotent(t *testing.T) {
	_, conn := newTCPConnPair(t)
	defer conn.Close()

	l := newTestLink(1, conn)

	l.aclose()
	l.aclose()
	l.aclose()
}

func TestLinkAcloseConcurrent(t *testing.T) {
	_, conn := newTCPConnPair(t)
	defer conn.Close()

	l := newTestLink(1, conn)

	const n = 10
	var wg sync.WaitGroup
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			l.aclose()
		}()
	}
	wg.Wait()
}

// ---- 4. read ----

func TestLinkReadData(t *testing.T) {
	peer, conn := newTCPConnPair(t)
	defer peer.Close()
	defer conn.Close()

	l := newTestLink(1, conn)

	msg := []byte("hello link")
	if _, err := peer.Write(msg); err != nil {
		t.Fatal(err)
	}

	data, err := l.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(data, msg) {
		t.Fatalf("got %q, want %q", data, msg)
	}
}

func TestLinkReadAfterRclose(t *testing.T) {
	_, conn := newTCPConnPair(t)
	defer conn.Close()

	l := newTestLink(1, conn)
	l.rclose()

	_, err := l.read()
	if err != errPeerClosed {
		t.Fatalf("got %v, want %v", err, errPeerClosed)
	}
}

func TestLinkReadPeerClosed(t *testing.T) {
	peer, conn := newTCPConnPair(t)
	defer conn.Close()

	l := newTestLink(1, conn)
	peer.Close()

	_, err := l.read()
	if err == nil {
		t.Fatal("expected error when peer closed")
	}
}

// ---- 5. write / _write 数据转发 ----

func TestLinkWriteDrain(t *testing.T) {
	peer, conn := newTCPConnPair(t)
	defer peer.Close()
	defer conn.Close()

	l := newTestLink(1, conn)

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- l._write()
	}()

	msg := []byte("drained")
	l.write(msg)
	l.wclose() // 触发 _write 退出

	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if !bytes.Equal(buf, msg) {
		t.Fatalf("peer got %q, want %q", buf, msg)
	}

	if err := <-writeDone; err != errPeerClosed {
		t.Fatalf("_write exit: got %v, want %v", err, errPeerClosed)
	}
}

func TestLinkWriteMultiple(t *testing.T) {
	peer, conn := newTCPConnPair(t)
	defer peer.Close()
	defer conn.Close()

	l := newTestLink(1, conn)

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- l._write()
	}()

	msgs := []string{"aaa", "bbbb", "ccccc"}
	for _, m := range msgs {
		l.write([]byte(m))
	}
	l.wclose()

	for _, m := range msgs {
		buf := make([]byte, len(m))
		if _, err := io.ReadFull(peer, buf); err != nil {
			t.Fatalf("peer read %q: %v", m, err)
		}
		if string(buf) != m {
			t.Fatalf("peer got %q, want %q", buf, m)
		}
	}

	if err := <-writeDone; err != errPeerClosed {
		t.Fatalf("_write exit: got %v, want %v", err, errPeerClosed)
	}
}

func TestLinkWriteConnError(t *testing.T) {
	_, conn := newTCPConnPair(t)
	l := newTestLink(1, conn)

	// 关闭底层连接，_write 应返回错误
	conn.Close()

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- l._write()
	}()

	l.write([]byte("will fail"))

	err := <-writeDone
	if err == nil {
		t.Fatal("_write should return error when conn is closed")
	}
	t.Logf("_write error (expected): %v", err)
}

// ---- 6. 半关闭语义 ----

func TestLinkHalfCloseReadSide(t *testing.T) {
	// rclose 关闭读侧，写侧仍可工作
	peer, conn := newTCPConnPair(t)
	defer peer.Close()
	defer conn.Close()

	l := newTestLink(1, conn)
	l.rclose()

	// read 应立即返回错误
	_, err := l.read()
	if err != errPeerClosed {
		t.Fatalf("read: got %v, want %v", err, errPeerClosed)
	}

	// write 仍可正常工作
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- l._write()
	}()

	l.write([]byte("still writing"))
	l.wclose()

	buf := make([]byte, 13)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if string(buf) != "still writing" {
		t.Fatalf("peer got %q, want 'still writing'", buf)
	}
	<-writeDone
}

func TestLinkHalfCloseWriteSide(t *testing.T) {
	// wclose 关闭写侧，读侧仍可工作
	peer, conn := newTCPConnPair(t)
	defer peer.Close()
	defer conn.Close()

	l := newTestLink(1, conn)
	l.wclose()

	// write 应失败
	if l.write([]byte("x")) {
		t.Fatal("write after wclose should return false")
	}

	// read 仍可正常工作
	peer.Write([]byte("still reading"))
	data, err := l.read()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(data) != "still reading" {
		t.Fatalf("got %q, want 'still reading'", data)
	}
}

// ---- 7. 双向转发 ----

func TestLinkBidirectional(t *testing.T) {
	peer, conn := newTCPConnPair(t)
	defer peer.Close()
	defer conn.Close()

	l := newTestLink(42, conn)

	// 启动写排空
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- l._write()
	}()

	// link -> peer
	l.write([]byte("outgoing"))
	buf := make([]byte, 8)
	if _, err := io.ReadFull(peer, buf); err != nil {
		t.Fatalf("peer read: %v", err)
	}
	if string(buf) != "outgoing" {
		t.Fatalf("peer got %q, want 'outgoing'", buf)
	}

	// peer -> link
	peer.Write([]byte("incoming"))
	data, err := l.read()
	if err != nil {
		t.Fatalf("link read: %v", err)
	}
	if string(data) != "incoming" {
		t.Fatalf("link got %q, want 'incoming'", data)
	}

	l.aclose()
	peer.Close()
	<-writeDone
}
