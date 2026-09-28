package main

import (
	"flag"
	"io"
	"strings"
	"testing"
)

func TestRoutingOptions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		command string
		ok      bool
	}{
		// 成对的 server/client 命令可在构建后从项目根目录分别运行。
		{"legacy server", "./bin/gotunnel -listen=:8001 -backend=127.0.0.1:9001 -secret=example-secret", true},
		{"legacy client", "./bin/gotunnel -listen=127.0.0.1:18080 -backend=127.0.0.1:8001 -tunnels=4 -secret=example-secret", true},
		{"tag server", "./bin/gotunnel -listen=:8001 -route=A=127.0.0.1:9001 -route=B=127.0.0.1:9002 -secret=example-secret", true},
		{"tag client", "./bin/gotunnel -listen=127.0.0.1:18080 -backend=127.0.0.1:8001 -tunnels=4 -tag=A -secret=example-secret", true},
		{"target server", "./bin/gotunnel -listen=:8001 -allow-client-backend -secret=example-secret", true},
		{"target client", "./bin/gotunnel -listen=127.0.0.1:18080 -backend=127.0.0.1:8001 -tunnels=4 -target=127.0.0.1:9001 -secret=example-secret", true},
		{"YAML server", "./bin/gotunnel -config=examples/server.yaml", true},

		// 只保留两种最容易混用的参数冲突。
		{"config conflict", "./bin/gotunnel -config=examples/server.yaml -secret=override", false},
		{"tag and target", "./bin/gotunnel -tunnels=4 -tag=A -target=127.0.0.1:9001", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags := flag.NewFlagSet(tc.name, flag.ContinueOnError)
			flags.SetOutput(io.Discard)
			flags.String("listen", ":8001", "")
			flags.String("backend", "127.0.0.1:1234", "")
			flags.String("secret", "shared", "")
			tunnels := flags.Uint("tunnels", 0, "")
			tag := flags.String("tag", "", "")
			target := flags.String("target", "", "")
			allowClientBackend := flags.Bool("allow-client-backend", false, "")
			config := flags.String("config", "", "")
			var routes routeFlags
			flags.Var(&routes, "route", "")
			err := flags.Parse(strings.Fields(tc.command)[1:])
			if err == nil {
				err = validateModes(flags, *tunnels, *tag, *target, *config, *allowClientBackend, routes)
			}
			if (err == nil) != tc.ok {
				t.Fatalf("err=%v, want success=%v", err, tc.ok)
			}
		})
	}
}
