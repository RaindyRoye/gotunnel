package tunnel

import (
	"fmt"
	"io"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestConfigReloadAddsOnly(t *testing.T) {
	s := &Server{secret: "shared", configListen: ":8001", routes: map[string]string{
		"A": "host-a:9001", "kept": "host-a:9001",
	}}
	err := s.reloadConfig([]byte("listen: ':8001'\nsecret: shared\nroutes:\n  A: changed:9002\n  B: host-b:9002\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "host-a:9001", "kept": "host-a:9001", "B": "host-b:9002"}
	if !maps.Equal(s.routes, want) {
		t.Fatalf("routes = %v, want %v", s.routes, want)
	}
	err = s.reloadConfig([]byte("listen: ':8002'\nsecret: changed\nallow_client_backend: true\nroutes:\n  C: host-c:9003\n"))
	want["C"] = "host-c:9003"
	if err != nil || s.configListen != ":8001" || s.secret != "shared" || s.allowClientBackend || !maps.Equal(s.routes, want) {
		t.Fatalf("reload changed startup options or failed to add C: err=%v routes=%v", err, s.routes)
	}
	// No partial additions from a file containing an invalid route.
	err = s.reloadConfig([]byte("listen: ':8001'\nsecret: shared\nroutes:\n  D: host-d:9004\n  broken: no-port\n"))
	if err == nil || !maps.Equal(s.routes, want) {
		t.Fatalf("invalid config changed routes: err=%v routes=%v", err, s.routes)
	}
}

func TestConfigReloadReadsCurrentFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "server.yaml")
	initial := "listen: ':8001'\nsecret: shared\nroutes:\n  A: host-a:9001\n"
	if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		secret: "shared", configListen: ":8001", configPath: path,
		routes: map[string]string{"A": "host-a:9001"},
	}
	// Explicit reload must read the file even when all tracked metadata is unchanged.
	updated := strings.Replace(initial, "A:", "B:", 1)
	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "host-a:9001", "B": "host-a:9001"}
	if !maps.Equal(s.routes, want) {
		t.Fatalf("routes = %v, want %v", s.routes, want)
	}
	if err := os.Rename(path, path+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil || !maps.Equal(s.routes, want) {
		t.Fatalf("missing file changed routes: err=%v routes=%v", err, s.routes)
	}
	invalid := updated + "  C: host-c:9003\n  broken: no-port\n"
	if err := os.WriteFile(path, []byte(invalid), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err == nil || !maps.Equal(s.routes, want) {
		t.Fatalf("invalid file changed routes: err=%v routes=%v", err, s.routes)
	}
	if err := os.WriteFile(path, []byte(updated+"  C: host-c:9003\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	want["C"] = "host-c:9003"
	if !maps.Equal(s.routes, want) {
		t.Fatalf("reload after correction: routes = %v, want %v", s.routes, want)
	}
}

func startNamedBackend(t *testing.T, name string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if _, err := io.WriteString(conn, name); err != nil {
					return
				}
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln
}

func startRoutingTestServer(t *testing.T, s *Server) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Start()
	}()
	t.Cleanup(func() {
		s.ln.Close()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("server did not stop")
		}
	})
}

func connectTaggedClient(t *testing.T, s *Server, tag string) *Client {
	t.Helper()
	cli, err := NewTaggedClient("127.0.0.1:0", s.ln.Addr().String(), "shared", 1, tag)
	if err != nil {
		t.Fatal(err)
	}
	return connectTestClient(t, cli)
}

func connectTestClient(t *testing.T, cli *Client) *Client {
	t.Helper()
	hub, err := cli.createHub()
	if err != nil {
		t.Fatal(err)
	}
	cli.addHub(hub)
	done := make(chan struct{})
	go func() {
		hub.Start()
		close(done)
	}()
	t.Cleanup(func() {
		hub.Close()
		<-done
	})
	return cli
}

func openRoutedLink(t *testing.T, cli *Client, backendName string) net.Conn {
	t.Helper()
	peer, conn := newTCPConnPair(t)
	done := make(chan struct{})
	go func() {
		cli.handleConn(cli.fetchHub(), conn)
		close(done)
	}()
	t.Cleanup(func() {
		peer.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("routed link did not stop")
		}
	})
	if err := peer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	name := make([]byte, len(backendName))
	if _, err := io.ReadFull(peer, name); err != nil {
		t.Fatal(err)
	}
	if string(name) != backendName {
		t.Fatalf("routed to %q, want %q", name, backendName)
	}
	return peer
}

func TestTaggedRoutingAndExplicitReload(t *testing.T) {
	a := startNamedBackend(t, "A")
	b := startNamedBackend(t, "B")
	path := filepath.Join(t.TempDir(), "server.yaml")
	initial := fmt.Sprintf("listen: '127.0.0.1:0'\nsecret: shared\nroutes:\n  A: %s\n  kept: %s\n", a.Addr(), a.Addr())
	if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServerFromConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	startRoutingTestServer(t, s)
	cliA := connectTaggedClient(t, s, "A")
	existing := openRoutedLink(t, cliA, "A")
	cliA2 := connectTaggedClient(t, s, "A")
	openRoutedLink(t, cliA2, "A").Close()

	cliB, err := NewTaggedClient("127.0.0.1:0", s.ln.Addr().String(), "shared", 1, "B")
	if err != nil {
		t.Fatal(err)
	}
	if hub, err := cliB.createHub(); err == nil {
		hub.Close()
		t.Fatal("accepted unknown tag B")
	} else if !strings.Contains(err.Error(), "unknown tag") {
		t.Fatalf("unexpected rejection: %v", err)
	}

	// An editor-style replacement adds B while also changing A and removing kept.
	updated := fmt.Sprintf("listen: '127.0.0.1:0'\nsecret: shared\nroutes:\n  A: %s\n  B: %s\n", b.Addr(), b.Addr())
	replacement := filepath.Join(filepath.Dir(path), "replacement.yaml")
	if err := os.WriteFile(replacement, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.routeBackend("B"); ok {
		t.Fatal("tag B loaded before explicit reload")
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	connectB := connectTaggedClient(t, s, "B")
	echoThenClose(t, openRoutedLink(t, connectB, "B"), []byte("payload B"))
	// Both an existing link and new links on the existing tunnel keep A's backend.
	echoThenClose(t, existing, []byte("existing A"))
	echoThenClose(t, openRoutedLink(t, cliA, "A"), []byte("new A"))
	connectA := connectTaggedClient(t, s, "A")
	openRoutedLink(t, connectA, "A").Close()
	connectKept := connectTaggedClient(t, s, "kept")
	openRoutedLink(t, connectKept, "A").Close()
}

func TestTaggedClientRejectsLegacyServer(t *testing.T) {
	s, err := NewServer("127.0.0.1:0", "127.0.0.1:1", "shared")
	if err != nil {
		t.Fatal(err)
	}
	startRoutingTestServer(t, s)
	cli, err := NewTaggedClient("127.0.0.1:0", s.ln.Addr().String(), "shared", 1, "A")
	if err != nil {
		t.Fatal(err)
	}
	if hub, err := cli.createHub(); err == nil {
		hub.Close()
		t.Fatal("tagged client silently connected to the legacy backend")
	}
}
