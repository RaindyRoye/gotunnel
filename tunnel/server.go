// Package tunnel contains the server-side implementation for creating tunnel endpoints.
package tunnel

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// ServerHub extends Hub to manage links specifically for a tunnel server.
// It handles incoming link requests and connects them to a backend server.
type ServerHub struct {
	*Hub         // Embedding Hub provides all its methods and fields
	baddr string // Address of the backend server to which links are forwarded
}

// handleLink manages the lifecycle of a single tunnel link on the server side.
// It dials the backend, then starts the bidirectional data transfer.
func (h *ServerHub) handleLink(l *link) {
	// Ensure the link is cleaned up from the hub's management upon function exit.
	defer h.deleteLink(l.id)
	// Ensure any panics in this goroutine are recovered and logged.
	defer Recover()

	// Establish a connection to the backend server with a timeout.
	conn, err := net.DialTimeout("tcp", h.baddr, 10*time.Second)
	if err != nil {
		Error("link(%d) connect to backend %v failed: %v", l.id, h.baddr, err)
		// Inform the client that the link creation failed.
		h.SendCmd(l.id, LINK_CLOSE)
		return
	}

	tcpConn := conn.(*net.TCPConn)
	defer conn.Close() // Ensure fd is released after startLink (CloseRead+CloseWrite don't release fd)
	// Successfully connected to the backend. Start the link's I/O routines.
	h.startLink(l, tcpConn)
}

// onCtrl acts as a filter and dispatcher for control commands received by the server hub.
// It handles LINK_CREATE and TUN_HEARTBEAT, returning true if the command was handled
// and should not be processed by the base Hub logic.
func (h *ServerHub) onCtrl(cmd Cmd) bool {
	id := cmd.Id
	switch cmd.Cmd {
	case LINK_CREATE:
		// Attempt to create a new link for the given ID.
		l := h.createLink(id)
		if l != nil {
			// Successfully created link. Spawn a goroutine to handle its backend connection.
			go h.handleLink(l)
		} else {
			// Link creation failed (e.g., ID collision). Tell the client to close.
			h.SendCmd(id, LINK_CLOSE)
		}
		return true // Command handled by us
	case TUN_HEARTBEAT:
		// Echo the heartbeat back to the client to confirm tunnel health.
		h.SendCmd(id, TUN_HEARTBEAT)
		return true // Command handled by us
	}
	// Unknown command, let the base Hub logic handle it or discard it.
	return false
}

// newServerHub creates a new ServerHub instance.
// It initializes the underlying Hub and sets up the control command filter.
func newServerHub(tunnel *Tunnel, baddr string) *ServerHub {
	h := &ServerHub{
		Hub:   newHub(tunnel), // Initialize the embedded Hub
		baddr: baddr,          // Store the backend address
	}
	// Assign the custom control filter to handle server-specific commands.
	h.Hub.onCtrlFilter = h.onCtrl
	return h
}

// Server represents the tunnel server itself, managing incoming connections.
type Server struct {
	ln     net.Listener // Listener for incoming tunnel connections
	baddr  *net.TCPAddr // Backend server address
	secret string       // Shared secret for authentication

	routesLock         sync.RWMutex
	routes             map[string]string // nil selects the legacy single-backend protocol
	allowClientBackend bool              // Fixed at startup; reload only adds tags

	configPath   string
	configListen string
}

// handleConn manages the lifecycle of a single incoming tunnel connection.
// It performs authentication and then starts the hub for that connection.
func (s *Server) handleConn(conn net.Conn) {
	// Always close the connection when this function exits.
	defer conn.Close()
	// Recover from panics in this connection's goroutine.
	defer Recover()

	// Wrap the raw connection with tunnel logic.
	tunnel := newTunnel(conn)
	if s.routes != nil {
		if err := conn.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
			Error("set routing handshake deadline: %v", err)
			return
		}
	}
	backend, err := s.authenticate(tunnel)
	if err != nil {
		Error("server authentication failed for %v: %v", tunnel, err)
		return
	}
	if s.routes != nil {
		if err := conn.SetDeadline(time.Time{}); err != nil {
			Error("clear routing handshake deadline: %v", err)
			return
		}
	}
	newServerHub(tunnel, backend).Start()
}

func (s *Server) authenticate(tunnel *Tunnel) (string, error) {
	// Initialize the authentication algorithm with the shared secret.
	a := NewTaa(s.secret)
	// Generate the server's initial challenge token.
	a.GenToken()

	// Create the initial challenge block and send it to the client.
	challengeBlock := a.GenCipherBlock(nil)
	if err := tunnel.WritePacket(0, challengeBlock); err != nil {
		return "", fmt.Errorf("write challenge: %w", err)
	}

	// Read the response block (expected to contain the client's signed token) from the client.
	_, responseBlock, err := tunnel.ReadPacket()
	defer mpool.Put(responseBlock)
	if err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	var backend string
	if s.routes == nil {
		if !a.VerifyCipherBlock(responseBlock) {
			return "", fmt.Errorf("invalid token response (single-backend mode requires an untagged client)")
		}
		backend = s.baddr.String()
	} else {
		request, err := a.verifyRoutingResponse(responseBlock)
		if err != nil {
			return "", err
		}
		status := byte(routeAccepted)
		switch request.version {
		case tagVersion:
			var ok bool
			backend, ok = s.routeBackend(request.destination)
			if !ok {
				status = tagUnknown
			}
		case targetVersion:
			if !s.allowClientBackend {
				status = targetDisabled
			} else {
				backend = request.destination
			}
		}
		if err := tunnel.WritePacket(0, a.routingAck(request, status)); err != nil {
			return "", fmt.Errorf("write routing acknowledgement: %w", err)
		}
		if err := request.statusError(status); err != nil {
			return "", err
		}
		Log("%s authenticated route %q -> %s", tunnel, request.destination, backend)
	}

	// Authentication successful. Set up the encryption key for the tunnel session.
	// Note: RC4 is cryptographically deprecated, but this is preserved as per API requirements.
	tunnel.SetCipherKey(a.GetChacha20key())

	return backend, nil
}

// Start begins listening for incoming connections and spawns a handler goroutine for each.
// It blocks until an error occurs that prevents accepting new connections.
func (s *Server) Start() error {
	// Close the listener when the server stops.
	defer s.ln.Close()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			// Check if the listener was closed
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				Log("accept timeout on %v: %s", s.ln.Addr(), netErr.Error())
				continue
			}
			return err
		}

		Log("new tunnel connection accepted from %v", conn.RemoteAddr())
		go s.handleConn(conn)
	}
}

// Status prints the current status of the server.
// Currently, it does nothing, but the interface is reserved for future use.
func (s *Server) Status() {
	// Future implementation might print listener stats, active connections, etc.
}

// NewServer creates a new tunnel server instance.
// It resolves the listen and backend addresses and prepares the server.
func NewServer(listen, backend, secret string) (*Server, error) {
	// Create a listener socket bound to the listen address.
	ln, err := newListener(listen)
	if err != nil {
		return nil, err
	}

	// Resolve the backend address string to a TCP address structure.
	baddr, err := net.ResolveTCPAddr("tcp", backend)
	if err != nil {
		// Close the listener if backend resolution fails.
		ln.Close()
		return nil, err
	}

	// Create and populate the Server struct.
	s := &Server{
		ln:     ln,
		baddr:  baddr,
		secret: secret,
	}
	return s, nil
}
