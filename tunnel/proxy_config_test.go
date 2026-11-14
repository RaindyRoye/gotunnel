package tunnel

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func clearProxyConfigEnvironment(t *testing.T) {
	t.Helper()
	for _, name := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"} {
		t.Setenv(name, "")
	}
}

// Each listener records which proxy was selected and rejects the CONNECT.
func startRejectingProxy(t *testing.T, name string, selected chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		selected <- name
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
	}()
	t.Cleanup(func() {
		ln.Close()
		<-done
	})
	return ln.Addr().String()
}

func newProxyConfigClient(t *testing.T, backend string) *Client {
	t.Helper()
	cli, err := NewTargetClient("127.0.0.1:0", backend, "shared", 1, "127.0.0.1:9001")
	if err != nil {
		t.Fatal(err)
	}
	return cli
}

func assertProxySelected(t *testing.T, cli *Client, selected <-chan string, want string) {
	t.Helper()
	hub, err := cli.createHub()
	if err == nil {
		hub.Close()
		t.Fatal("a rejecting proxy must not fall back to a direct connection")
	}
	select {
	case got := <-selected:
		if got != want {
			t.Fatalf("proxy selected = %s, want %s", got, want)
		}
	case <-time.After(time.Second):
		t.Fatalf("proxy %s did not receive a connection: %v", want, err)
	}
}

func TestProxyEnvironmentPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name string
		vars []string
	}{
		{"uppercase HTTPS first", []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"}},
		{"lowercase HTTPS before HTTP", []string{"https_proxy", "HTTP_PROXY", "http_proxy"}},
		{"uppercase HTTP first", []string{"HTTP_PROXY", "http_proxy"}},
		{"lowercase HTTP", []string{"http_proxy"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearProxyConfigEnvironment(t)
			selected := make(chan string, len(tc.vars))
			for _, name := range tc.vars {
				address := startRejectingProxy(t, name, selected)
				// A scheme-less environment value is an HTTP proxy as well.
				if name != "http_proxy" {
					address = "http://" + address
				}
				t.Setenv(name, address)
			}
			cli := newProxyConfigClient(t, "service.invalid:8001")
			if err := cli.ConfigureProxy(""); err != nil {
				t.Fatal(err)
			}
			assertProxySelected(t, cli, selected, tc.vars[0])
		})
	}
}

func TestProxyExplicitSelectionOverridesEnvironment(t *testing.T) {
	t.Run("direct overrides invalid environment", func(t *testing.T) {
		clearProxyConfigEnvironment(t)
		t.Setenv("HTTPS_PROXY", "https://unsupported.example:443")
		s, err := NewTargetServer("127.0.0.1:0", "shared", nil)
		if err != nil {
			t.Fatal(err)
		}
		startRoutingTestServer(t, s)
		cli := newProxyConfigClient(t, s.ln.Addr().String())
		if err := cli.ConfigureProxy("direct"); err != nil {
			t.Fatal(err)
		}
		hub, err := cli.createHub()
		if err != nil {
			t.Fatalf("direct connection failed: %v", err)
		}
		hub.Close()
	})

	t.Run("explicit proxy overrides no proxy", func(t *testing.T) {
		clearProxyConfigEnvironment(t)
		t.Setenv("NO_PROXY", "*")
		selected := make(chan string, 1)
		address := startRejectingProxy(t, "explicit", selected)
		s, err := NewTargetServer("127.0.0.1:0", "shared", nil)
		if err != nil {
			t.Fatal(err)
		}
		startRoutingTestServer(t, s)
		cli := newProxyConfigClient(t, s.ln.Addr().String())
		if err := cli.ConfigureProxy("http://" + address); err != nil {
			t.Fatal(err)
		}
		assertProxySelected(t, cli, selected, "explicit")
	})
}

func TestProxyEnvironmentNoProxy(t *testing.T) {
	clearProxyConfigEnvironment(t)
	selected := make(chan string, 1)
	address := startRejectingProxy(t, "environment", selected)
	t.Setenv("http_proxy", "http://"+address)

	s, err := NewTargetServer("127.0.0.1:0", "shared", nil)
	if err != nil {
		t.Fatal(err)
	}
	startRoutingTestServer(t, s)
	loopbackClient := newProxyConfigClient(t, s.ln.Addr().String())
	if err := loopbackClient.ConfigureProxy(""); err != nil {
		t.Fatal(err)
	}
	loopbackHub, err := loopbackClient.createHub()
	if err != nil {
		t.Fatalf("loopback should bypass an environment proxy: %v", err)
	}
	loopbackHub.Close()

	_, port, err := net.SplitHostPort(s.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	// Unlike loopback addresses, this IP is bypassed only when NO_PROXY matches.
	backend := net.JoinHostPort("0.0.0.0", port)
	probe, err := net.DialTimeout("tcp", backend, time.Second)
	if err != nil {
		t.Skipf("this platform cannot connect to the local unspecified address: %v", err)
	}
	probe.Close()

	cli := newProxyConfigClient(t, backend)
	if err := cli.ConfigureProxy(""); err != nil {
		t.Fatal(err)
	}
	assertProxySelected(t, cli, selected, "environment")

	t.Setenv("NO_PROXY", "0.0.0.0")
	cli = newProxyConfigClient(t, backend)
	if err := cli.ConfigureProxy(""); err != nil {
		t.Fatal(err)
	}
	hub, err := cli.createHub()
	if err != nil {
		t.Fatalf("NO_PROXY should connect directly: %v", err)
	}
	hub.Close()
}

func TestProxyInvalidConfiguration(t *testing.T) {
	clearProxyConfigEnvironment(t)
	cli := newProxyConfigClient(t, "service.invalid:8001")
	for _, value := range []string{"https://proxy.example:443", "http://user:secret@[broken"} {
		if err := cli.ConfigureProxy(value); err == nil {
			t.Errorf("accepted invalid proxy %q", value)
		} else if strings.Contains(err.Error(), "secret") {
			t.Errorf("proxy error exposed credentials: %v", err)
		}
	}

	t.Setenv("HTTPS_PROXY", "https://proxy.example:443")
	if err := cli.ConfigureProxy(""); err == nil {
		t.Error("invalid environment proxy must fail instead of silently using a direct connection")
	}
}
