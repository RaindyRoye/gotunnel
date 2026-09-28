package tunnel

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"go.yaml.in/yaml/v3"
)

type serverConfig struct {
	Listen             string            `yaml:"listen"`
	Secret             string            `yaml:"secret"`
	Routes             map[string]string `yaml:"routes"`
	AllowClientBackend bool              `yaml:"allow_client_backend"`
}

func parseServerConfig(data []byte) (serverConfig, error) {
	var config serverConfig
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("decode server config: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return config, fmt.Errorf("server config must contain exactly one YAML document")
	}
	if config.Listen == "" || config.Secret == "" || (config.Routes == nil && !config.AllowClientBackend) {
		return config, fmt.Errorf("server config requires listen, secret and routes (or allow_client_backend: true)")
	}
	if _, _, err := net.SplitHostPort(config.Listen); err != nil {
		return config, fmt.Errorf("invalid listen address: %w", err)
	}
	return config, validateRoutes(config.Routes)
}
