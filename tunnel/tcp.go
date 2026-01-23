// Package tunnel contains utilities for establishing TCP connections with tunnel-specific configurations.
package tunnel

import (
	"net"
	"time"
)

// TcpListener wraps a *net.TCPListener to automatically configure accepted connections
// with keep-alive settings suitable for tunneling.
type TcpListener struct {
	*net.TCPListener // Embedding allows TcpListener to inherit all methods from net.TCPListener
}

// Accept waits for and returns the next connection to the listener.
// It automatically configures the accepted TCP connection with keep-alive settings.
func (l *TcpListener) Accept() (net.Conn, error) {
	conn, err := l.TCPListener.AcceptTCP()
	if err != nil {
		return nil, err
	}

	// Configure the newly accepted connection with keep-alive parameters.
	// This helps maintain long-lived connections through NATs and firewalls.
	conn.SetKeepAlive(true)
	conn.SetKeepAlivePeriod(TunnelKeepAlivePeriod)

	// Return the configured connection. The caller receives a net.Conn interface,
	// which is satisfied by *net.TCPConn.
	return conn, nil
}

// newTcpListener creates a new TCP listener bound to the specified address.
// The returned listener automatically configures accepted connections with tunnel-appropriate settings.
func newTcpListener(laddr string) (net.Listener, error) {
	// Use the standard library to listen on the given address.
	ln, err := net.Listen("tcp", laddr)
	if err != nil {
		// Propagate the error if listening fails (e.g., address in use, permission denied).
		return nil, err
	}

	// Type assert the result to *net.TCPListener, which is what net.Listen("tcp", ...) returns.
	// This conversion is safe because we explicitly requested a "tcp" listener.
	tcpLn := ln.(*net.TCPListener)

	// Wrap the TCP listener in our custom TcpListener which handles configuration.
	wrappedLn := &TcpListener{TCPListener: tcpLn}

	return wrappedLn, nil
}

// dialTcp establishes a TCP connection to the specified remote address with a timeout.
// It configures the established connection with keep-alive settings suitable for tunneling.
func dialTcp(raddr string) (net.Conn, error) {
	// Dial the remote address with a fixed timeout of 5 seconds.
	// This prevents indefinite blocking if the remote host is unreachable.
	conn, err := net.DialTimeout("tcp", raddr, 5*time.Second)
	if err != nil {
		// Propagate the error if dialing fails (e.g., host unreachable, connection refused, timeout).
		return nil, err
	}

	// Type assert the result to *net.TCPConn, which is what net.DialTimeout("tcp", ...) returns.
	// This conversion is safe because we explicitly requested a "tcp" connection.
	tcpConn := conn.(*net.TCPConn)

	// Configure the newly established connection with keep-alive parameters.
	tcpConn.SetKeepAlive(true)
	tcpConn.SetKeepAlivePeriod(TunnelKeepAlivePeriod)

	// Return the configured connection. The caller receives a net.Conn interface,
	// which is satisfied by *net.TCPConn.
	return tcpConn, nil
}
