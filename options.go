package main

import (
	"flag"
	"fmt"
	"maps"
	"slices"
	"strings"
)

type routeFlags map[string]string

func (r *routeFlags) String() string {
	var entries []string
	for _, tag := range slices.Sorted(maps.Keys(*r)) {
		entries = append(entries, tag+"="+(*r)[tag])
	}
	return strings.Join(entries, ",")
}

func (r *routeFlags) Set(value string) error {
	tag, backend, ok := strings.Cut(value, "=")
	if !ok || tag == "" || backend == "" {
		return fmt.Errorf("route must be TAG=host:port")
	}
	if _, exists := (*r)[tag]; exists {
		return fmt.Errorf("duplicate route tag %q", tag)
	}
	if *r == nil {
		*r = make(routeFlags)
	}
	(*r)[tag] = backend
	return nil
}

func validateModes(flags *flag.FlagSet, tunnels uint, tag, target, config string, allowClientBackend bool, routes routeFlags) error {
	explicit := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { explicit[f.Name] = true })
	if config != "" {
		for _, name := range []string{"listen", "backend", "secret", "tunnels", "tag", "target", "route", "allow-client-backend"} {
			if explicit[name] {
				return fmt.Errorf("-config cannot be combined with -%s", name)
			}
		}
	}
	if explicit["tag"] && (tag == "" || tunnels == 0) {
		return fmt.Errorf("-tag requires a nonempty tag and client mode (-tunnels > 0)")
	}
	if explicit["target"] && (target == "" || tunnels == 0) {
		return fmt.Errorf("-target requires a nonempty backend host:port and client mode (-tunnels > 0)")
	}
	if tag != "" && target != "" {
		return fmt.Errorf("-tag and -target are mutually exclusive")
	}
	if explicit["allow-client-backend"] && tunnels > 0 {
		return fmt.Errorf("-allow-client-backend requires server mode")
	}
	if allowClientBackend && explicit["backend"] {
		return fmt.Errorf("-allow-client-backend cannot be combined with -backend")
	}
	if len(routes) > 0 && (tunnels > 0 || explicit["backend"]) {
		return fmt.Errorf("-route requires server mode and cannot be combined with -backend")
	}
	return nil
}
