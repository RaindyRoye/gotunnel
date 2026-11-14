package tunnel

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"
)

type proxyTestResult struct {
	target string
	err    error
}

// localTestProxy handles one real CONNECT/SOCKS5 connection, forwarding its
// bytes to the local server. The synthetic target lets the test detect a
// client that accidentally bypasses the proxy.
type localTestProxy struct {
	listener net.Listener
	upstream string
	results  chan proxyTestResult
	done     chan struct{}

	mu     sync.Mutex
	closed bool
	conns  []net.Conn
}

func startLocalTestProxy(t *testing.T, protocol, upstream string) *localTestProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &localTestProxy{
		listener: ln,
		upstream: upstream,
		results:  make(chan proxyTestResult, 1),
		done:     make(chan struct{}),
	}
	go func() {
		defer close(p.done)
		client, err := ln.Accept()
		if err != nil {
			return
		}
		if !p.track(client) {
			return
		}
		defer client.Close()
		if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			p.results <- proxyTestResult{err: err}
			return
		}
		var target string
		var input io.Reader = client
		switch protocol {
		case "http":
			reader := bufio.NewReader(client)
			input = reader
			target, err = readConnectRequest(reader)
		case "socks5":
			target, err = readSOCKS5Request(client)
		}
		if err != nil {
			p.results <- proxyTestResult{err: err}
			return
		}
		server, err := net.DialTimeout("tcp", p.upstream, 5*time.Second)
		if err != nil {
			p.results <- proxyTestResult{err: err}
			return
		}
		if !p.track(server) {
			return
		}
		defer server.Close()

		if protocol == "http" {
			// Combine CONNECT's response and the server's first authentication
			// packet in one write. A client that discards the buffered bytes hangs.
			header := make([]byte, 4)
			if _, err = io.ReadFull(server, header); err == nil {
				challenge := make([]byte, binary.LittleEndian.Uint16(header[2:]))
				if _, err = io.ReadFull(server, challenge); err == nil {
					response := append([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"), header...)
					response = append(response, challenge...)
					_, err = client.Write(response)
				}
			}
		} else {
			_, err = client.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		}
		if err != nil {
			p.results <- proxyTestResult{err: err}
			return
		}
		if err := client.SetDeadline(time.Time{}); err != nil {
			p.results <- proxyTestResult{err: err}
			return
		}
		p.results <- proxyTestResult{target: target}
		copyDone := make(chan struct{})
		go func() {
			io.Copy(client, server)
			client.Close()
			close(copyDone)
		}()
		io.Copy(server, input)
		server.Close()
		<-copyDone
	}()
	t.Cleanup(func() {
		p.mu.Lock()
		p.closed = true
		p.listener.Close()
		for _, conn := range p.conns {
			conn.Close()
		}
		p.mu.Unlock()
		select {
		case <-p.done:
		case <-time.After(3 * time.Second):
			t.Error("proxy did not stop")
		}
	})
	return p
}

func (p *localTestProxy) track(conn net.Conn) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		conn.Close()
		return false
	}
	p.conns = append(p.conns, conn)
	return true
}

func readConnectRequest(reader *bufio.Reader) (string, error) {
	req, err := http.ReadRequest(reader)
	if err != nil {
		return "", err
	}
	if req.Method != http.MethodConnect {
		return "", fmt.Errorf("method = %q, want CONNECT", req.Method)
	}
	if req.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
		return "", fmt.Errorf("wrong proxy authorization")
	}
	return req.Host, nil
}

func readSOCKS5Request(conn net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	if header[0] != 5 || !bytes.Contains(methods, []byte{2}) {
		return "", fmt.Errorf("SOCKS client did not offer username/password authentication")
	}
	if _, err := conn.Write([]byte{5, 2}); err != nil {
		return "", err
	}
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	user := make([]byte, header[1])
	if _, err := io.ReadFull(conn, user); err != nil {
		return "", err
	}
	var length [1]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return "", err
	}
	password := make([]byte, length[0])
	if _, err := io.ReadFull(conn, password); err != nil {
		return "", err
	}
	if header[0] != 1 || string(user) != "user" || string(password) != "pass" {
		return "", fmt.Errorf("wrong SOCKS authentication")
	}
	if _, err := conn.Write([]byte{1, 0}); err != nil {
		return "", err
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return "", err
	}
	if request[0] != 5 || request[1] != 1 || request[3] != 3 {
		return "", fmt.Errorf("unexpected SOCKS CONNECT request %v", request)
	}
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return "", err
	}
	host := make([]byte, length[0])
	if _, err := io.ReadFull(conn, host); err != nil {
		return "", err
	}
	var port [2]byte
	if _, err := io.ReadFull(conn, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(string(host), strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func TestTargetClientThroughProxy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		protocol    string
		env         string
		servicePort bool
	}{
		{name: "http flag", protocol: "http"},
		{name: "socks5 flag", protocol: "socks5"},
		{name: "http_proxy environment", protocol: "http", env: "http_proxy"},
		{name: "https_proxy environment with socks5", protocol: "socks5", env: "https_proxy"},
		{name: "http service port", protocol: "http", servicePort: true},
		{name: "socks5 service port", protocol: "socks5", servicePort: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
				t.Setenv(key, "")
			}
			backend := startNamedBackend(t, "echo")
			server, err := NewTargetServer("127.0.0.1:0", "shared", nil)
			if err != nil {
				t.Fatal(err)
			}
			startRoutingTestServer(t, server)
			proxy := startLocalTestProxy(t, tc.protocol, server.ln.Addr().String())
			proxyURL := fmt.Sprintf("%s://user:pass@%s", tc.protocol, proxy.listener.Addr())
			proxyOption := proxyURL
			if tc.env != "" {
				t.Setenv(tc.env, proxyURL)
				proxyOption = ""
			}
			destination := "gotunnel.invalid:8001"
			wantTarget := destination
			if tc.servicePort {
				destination = "gotunnel.invalid:https"
				wantTarget = "gotunnel.invalid:443"
			}
			cli, err := NewTargetClient("127.0.0.1:0", destination, "shared", 1, backend.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			if err := cli.ConfigureProxy(proxyOption); err != nil {
				t.Fatal(err)
			}
			connectTestClient(t, cli)
			select {
			case result := <-proxy.results:
				if result.err != nil {
					t.Fatal(result.err)
				}
				if result.target != wantTarget {
					t.Fatalf("proxy target = %q, want %q", result.target, wantTarget)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("proxy did not receive the tunnel connection")
			}
			echoThenClose(t, openRoutedLink(t, cli, "echo"), []byte("through proxy"))
		})
	}
}
