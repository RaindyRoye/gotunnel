package tunnel

import "testing"

func TestServerConfigValidation(t *testing.T) {
	for _, body := range []string{
		"routes:\n  A: host:9001\n  A: other:9002\n",
		"routes: {}\nunknown: true\n",
		"routes: {}\nreload_interval: 1s\n",
		"routes: [\n",
		"routes:\n  'bad tag': host:9001\n",
		"routes: {}\n---\nroutes: {}\n",
		"allow_client_backend: false\n",
	} {
		if _, err := parseServerConfig([]byte("listen: ':8001'\nsecret: shared\n" + body)); err == nil {
			t.Errorf("accepted invalid config: %q", body)
		}
	}
	if _, err := parseServerConfig([]byte("listen: ':8001'\nsecret: shared\nroutes: {}\n")); err != nil {
		t.Fatalf("empty initial route table: %v", err)
	}
}
