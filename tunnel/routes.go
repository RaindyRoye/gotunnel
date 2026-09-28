package tunnel

import (
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
)

func validateBackend(backend string) error {
	host, port, err := net.SplitHostPort(backend)
	if err != nil || host == "" {
		return fmt.Errorf("backend must be host:port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("backend port must be 1..65535")
	}
	return nil
}

func validateRoutes(routes map[string]string) error {
	for tag, backend := range routes {
		if err := validateTag(tag); err != nil {
			return err
		}
		if err := validateBackend(backend); err != nil {
			return fmt.Errorf("route %q: %w", tag, err)
		}
	}
	return nil
}

// NewRoutingServer accepts only tagged clients. Each tag's backend is immutable
// for the lifetime of the server, including across configuration reloads.
func NewRoutingServer(listen, secret string, routes map[string]string) (*Server, error) {
	if routes == nil {
		return nil, fmt.Errorf("routes must be provided")
	}
	if err := validateRoutes(routes); err != nil {
		return nil, err
	}
	ln, err := newListener(listen)
	if err != nil {
		return nil, err
	}
	return &Server{ln: ln, secret: secret, routes: maps.Clone(routes)}, nil
}

// NewTargetServer accepts client-specified backend addresses as well as any
// configured tags. A nil routes map starts with no tags.
func NewTargetServer(listen, secret string, routes map[string]string) (*Server, error) {
	if routes == nil {
		routes = map[string]string{}
	}
	s, err := NewRoutingServer(listen, secret, routes)
	if err != nil {
		return nil, err
	}
	s.allowClientBackend = true
	return s, nil
}

// NewServerFromConfig loads a routing server. Reload reads the same path for
// additions, including after an editor replaces the file.
func NewServerFromConfig(path string) (*Server, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	config, err := parseServerConfig(data)
	if err != nil {
		return nil, err
	}
	var s *Server
	if config.AllowClientBackend {
		s, err = NewTargetServer(config.Listen, config.Secret, config.Routes)
	} else {
		s, err = NewRoutingServer(config.Listen, config.Secret, config.Routes)
	}
	if err != nil {
		return nil, err
	}
	s.configPath, s.configListen = path, config.Listen
	return s, nil
}

func (s *Server) routeBackend(tag string) (string, bool) {
	s.routesLock.RLock()
	defer s.routesLock.RUnlock()
	backend, ok := s.routes[tag]
	return backend, ok
}

func (s *Server) reloadConfig(data []byte) error {
	config, err := parseServerConfig(data)
	if err != nil {
		return err
	}
	if config.Listen != s.configListen || config.Secret != s.secret {
		Log("config reload: listen/secret changes ignored; restart required")
	}
	if config.AllowClientBackend != s.allowClientBackend {
		Log("config reload: allow_client_backend change ignored; restart required")
	}

	s.routesLock.Lock()
	defer s.routesLock.Unlock()
	// Validate the whole file before applying any additions.
	for _, tag := range slices.Sorted(maps.Keys(config.Routes)) {
		backend := config.Routes[tag]
		if old, ok := s.routes[tag]; ok {
			if old != backend {
				Log("config reload: tag %q backend change ignored; restart required", tag)
			}
			continue
		}
		s.routes[tag] = backend
		Log("config reload: added tag %q -> %s", tag, backend)
	}
	for _, tag := range slices.Sorted(maps.Keys(s.routes)) {
		if _, ok := config.Routes[tag]; !ok {
			Log("config reload: tag %q removal ignored; restart required", tag)
		}
	}
	return nil
}

// Reload reads the YAML file and adds new tags. Servers configured through
// command-line routes or a single backend have no file to reload.
func (s *Server) Reload() error {
	if s.configPath == "" {
		return nil
	}
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return err
	}
	if err := s.reloadConfig(data); err != nil {
		return err
	}
	Log("config reload: completed")
	return nil
}
