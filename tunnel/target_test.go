package tunnel

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func connectTargetClient(t *testing.T, s *Server, target string) *Client {
	t.Helper()
	cli, err := NewTargetClient("127.0.0.1:0", s.ln.Addr().String(), "shared", 1, target)
	if err != nil {
		t.Fatal(err)
	}
	return connectTestClient(t, cli)
}

func TestClientTargetRouting(t *testing.T) {
	a, b := startNamedBackend(t, "A"), startNamedBackend(t, "B")
	path := filepath.Join(t.TempDir(), "server.yaml")
	// No tag table is needed when clients provide their own targets.
	initial := "listen: '127.0.0.1:0'\nsecret: shared\nallow_client_backend: true\n"
	if err := os.WriteFile(path, []byte(initial), 0600); err != nil {
		t.Fatal(err)
	}
	s, err := NewServerFromConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	startRoutingTestServer(t, s)
	cliA := connectTargetClient(t, s, a.Addr().String())
	cliB := connectTargetClient(t, s, b.Addr().String())
	existing := openRoutedLink(t, cliA, "A")
	echoThenClose(t, openRoutedLink(t, cliB, "B"), []byte("client chose B"))

	// Reload adds tags but cannot change the startup permission for targets.
	updated := fmt.Sprintf("listen: '127.0.0.1:0'\nsecret: shared\nallow_client_backend: false\nroutes:\n  A: %s\n", a.Addr())
	if err := os.WriteFile(path, []byte(updated), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.Reload(); err != nil {
		t.Fatal(err)
	}
	tagged := connectTaggedClient(t, s, "A")
	echoThenClose(t, openRoutedLink(t, tagged, "A"), []byte("tag still works"))
	reconnected := connectTargetClient(t, s, b.Addr().String())
	echoThenClose(t, openRoutedLink(t, reconnected, "B"), []byte("permission unchanged"))
	echoThenClose(t, existing, []byte("existing target A"))
	echoThenClose(t, openRoutedLink(t, cliA, "A"), []byte("new link target A"))
}

func TestClientTargetRequiresOptInAndAuthentication(t *testing.T) {
	for _, mode := range []string{"tag-only server", "legacy server", "wrong secret"} {
		t.Run(mode, func(t *testing.T) {
			var s *Server
			var err error
			secret := "shared"
			switch mode {
			case "tag-only server":
				s, err = NewRoutingServer("127.0.0.1:0", secret, map[string]string{})
			case "legacy server":
				s, err = NewServer("127.0.0.1:0", "127.0.0.1:1", secret)
			case "wrong secret":
				s, err = NewTargetServer("127.0.0.1:0", secret, nil)
				secret = "wrong"
			}
			if err != nil {
				t.Fatal(err)
			}
			startRoutingTestServer(t, s)
			cli, err := NewTargetClient("127.0.0.1:0", s.ln.Addr().String(), secret, 1, "127.0.0.1:9001")
			if err != nil {
				t.Fatal(err)
			}
			hub, err := cli.createHub()
			if err == nil {
				hub.Close()
				t.Fatal("target client connected without permission or authentication")
			}
			if mode == "tag-only server" && !strings.Contains(err.Error(), "disabled") {
				t.Fatalf("expected an explicit denial, got %v", err)
			}
		})
	}
}

func TestClientTargetValidation(t *testing.T) {
	for _, target := range []string{"localhost:80", "127.0.0.1:9001", "[::1]:443"} {
		if _, err := NewTargetClient(":0", "server:8001", "shared", 1, target); err != nil {
			t.Fatalf("rejected target %q: %v", target, err)
		}
	}
	server, client := NewTaa("shared"), NewTaa("shared")
	server.GenToken()
	response, ok := client.ExchangeCipherBlock(server.GenCipherBlock(nil))
	if !ok {
		t.Fatal("challenge exchange failed")
	}
	for _, target := range []string{"", ":80", "host", "host:0", "host:65536", "host:http", strings.Repeat("x", maxTargetLength) + ":80"} {
		if _, err := NewTargetClient(":0", "server:8001", "shared", 1, target); err == nil {
			t.Errorf("client accepted invalid target %q", target)
		}
		request := client.routingResponse(response, routingRequest{targetVersion, target})
		_, err := server.verifyRoutingResponse(request)
		mpool.Put(request)
		if err == nil {
			t.Errorf("server accepted invalid target %q", target)
		}
	}
}
