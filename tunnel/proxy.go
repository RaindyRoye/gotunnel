package tunnel

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
	"golang.org/x/net/proxy"
)

const proxyDialTimeout = 5 * time.Second

// ConfigureProxy sets the client's backend proxy. Call it before Start.
// An empty value reads the proxy environment variables; direct disables them.
func (cli *Client) ConfigureProxy(value string) error {
	fromEnvironment := value == ""
	if fromEnvironment {
		value = firstEnv("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
	}
	if value == "" || (!fromEnvironment && value == "direct") {
		cli.dialBackend = cli.dialDirect
		return nil
	}

	proxyURL, address, err := parseProxyURL(value)
	if err != nil {
		return err
	}
	backend, err := proxyBackendAddress(cli.backend)
	if err != nil {
		return err
	}
	if fromEnvironment {
		// Use the Go HTTP proxy matcher for NO_PROXY, including loopback handling.
		cfg := httpproxy.Config{
			HTTPSProxy: "http://proxy.invalid:80",
			NoProxy:    firstEnv("NO_PROXY", "no_proxy"),
		}
		selected, err := cfg.ProxyFunc()(&url.URL{Scheme: "https", Host: backend})
		if err != nil {
			return fmt.Errorf("evaluate NO_PROXY: %w", err)
		}
		if selected == nil {
			cli.dialBackend = cli.dialDirect
			return nil
		}
	}

	switch proxyURL.Scheme {
	case "http":
		cli.dialBackend = func() (net.Conn, error) {
			return dialHTTPProxy(address, proxyURL.User, backend)
		}
	case "socks5", "socks5h":
		forward := &net.Dialer{KeepAlive: TunnelKeepAlivePeriod}
		proxyURL.Host = address
		dialer, err := proxy.FromURL(proxyURL, forward)
		if err != nil {
			return fmt.Errorf("configure SOCKS5 proxy: %w", err)
		}
		contextDialer := dialer.(proxy.ContextDialer)
		cli.dialBackend = func() (net.Conn, error) {
			ctx, cancel := context.WithTimeout(context.Background(), proxyDialTimeout)
			defer cancel()
			return contextDialer.DialContext(ctx, "tcp", backend)
		}
	}
	return nil
}

func proxyBackendAddress(address string) (string, error) {
	host, service, err := net.SplitHostPort(address)
	if err != nil {
		return "", fmt.Errorf("invalid proxy backend address: %w", err)
	}
	port, err := net.LookupPort("tcp", service)
	if err != nil {
		return "", fmt.Errorf("resolve proxy backend port: %w", err)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

func firstEnv(names ...string) string {
	for _, name := range names {
		if value := os.Getenv(name); value != "" {
			return value
		}
	}
	return ""
}

func parseProxyURL(value string) (*url.URL, string, error) {
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, "", fmt.Errorf("invalid proxy URL")
	}
	u.Scheme = strings.ToLower(u.Scheme)
	var defaultPort string
	switch u.Scheme {
	case "http":
		defaultPort = "80"
	case "socks5", "socks5h":
		defaultPort = "1080"
	default:
		return nil, "", fmt.Errorf("unsupported proxy scheme %q", u.Scheme)
	}
	port := u.Port()
	if port == "" {
		port = defaultPort
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, "", fmt.Errorf("invalid proxy port")
	}
	return u, net.JoinHostPort(u.Hostname(), port), nil
}

// bufferedProxyConn preserves bytes read beyond the CONNECT response headers.
type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (conn *bufferedProxyConn) Read(p []byte) (int, error) {
	return conn.reader.Read(p)
}

func dialHTTPProxy(address string, user *url.Userinfo, backend string) (_ net.Conn, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), proxyDialTimeout)
	defer cancel()
	forward := &net.Dialer{KeepAlive: TunnelKeepAlivePeriod}
	conn, err := forward.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("connect to HTTP proxy %s: %w", address, err)
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return nil, fmt.Errorf("set HTTP proxy deadline: %w", err)
	}
	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: backend},
		Host:   backend,
		Header: make(http.Header),
	}
	if user != nil {
		password, _ := user.Password()
		credentials := base64.StdEncoding.EncodeToString([]byte(user.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+credentials)
	}
	if err = req.Write(conn); err != nil {
		return nil, fmt.Errorf("write HTTP CONNECT: %w", err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, req)
	if err != nil {
		return nil, fmt.Errorf("read HTTP CONNECT response: %w", err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP CONNECT failed with status %d", response.StatusCode)
	}
	if err = conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear HTTP proxy deadline: %w", err)
	}
	return &bufferedProxyConn{Conn: conn, reader: reader}, nil
}
