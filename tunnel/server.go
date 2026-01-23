// Package tunnel contains the server-side implementation for creating tunnel endpoints.
package tunnel

import (
	"net"
)

// ServerHub extends Hub to manage links specifically for a tunnel server.
// It handles incoming link requests and connects them to a backend server.
type ServerHub struct {
	*Hub      // Embedding Hub provides all its methods and fields
	baddr *net.TCPAddr // Address of the backend server to which links are forwarded
}

// handleLink manages the lifecycle of a single tunnel link on the server side.
// It dials the backend, then starts the bidirectional data transfer.
func (h *ServerHub) handleLink(l *link) {
	// Ensure the link is cleaned up from the hub's management upon function exit.
	defer h.deleteLink(l.id)
	// Ensure any panics in this goroutine are recovered and logged.
	defer Recover()

	// Establish a connection to the backend server.
	conn, err := net.DialTCP("tcp", nil, h.baddr)
	if err != nil {
		Error("link(%d) connect to backend %v failed: %v", l.id, h.baddr, err)
		// Inform the client that the link creation failed.
		h.SendCmd(l.id, LINK_CLOSE)
		// Note: deleteLink is deferred, so it will run after this function ends.
		return
	}

	// Successfully connected to the backend. Start the link's I/O routines.
	h.startLink(l, conn)
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
func newServerHub(tunnel *Tunnel, baddr *net.TCPAddr) *ServerHub {
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

	// Initialize the authentication algorithm with the shared secret.
	a := NewTaa(s.secret)
	// Generate the server's initial challenge token.
	a.GenToken()

	// Create the initial challenge block and send it to the client.
	challengeBlock := a.GenCipherBlock(nil)
	if err := tunnel.WritePacket(0, challengeBlock); err != nil {
		Error("server failed to write challenge to %v: %s", tunnel, err)
		return
	}

	// Read the response block (expected to contain the client's signed token) from the client.
	_, responseBlock, err := tunnel.ReadPacket()
	if err != nil {
		Error("server failed to read token response from %v: %s", tunnel, err)
		return
	}

	// Verify the client's response block against the server's token.
	if !a.VerifyCipherBlock(responseBlock) {
		Error("server authentication failed for %v: invalid token response", tunnel)
		return
	}

	// Authentication successful. Set up the encryption key for the tunnel session.
	// Note: RC4 is cryptographically deprecated, but this is preserved as per API requirements.
	tunnel.SetCipherKey(a.GetChacha20key())

	// Create the server hub for this authenticated tunnel connection.
	h := newServerHub(tunnel, s.baddr)
	// Start the hub's main loop to handle multiplexed links over this connection.
	h.Start()
}

// Start begins listening for incoming connections and spawns a handler goroutine for each.
// It blocks until an error occurs that prevents accepting new connections.
func (s *Server) Start() error {
	// Close the listener when the server stops.
	defer s.ln.Close()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			// Check if the error is temporary (e.g., too many open files).
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				// Log the temporary failure and continue trying to accept.
				Log("accept failed temporarily on %v: %s", s.ln.Addr(), netErr.Error())
				continue
			} else {
				// A permanent error occurred (e.g., listener closed, network down).
				// Return the error to signal the server should stop.
				return err
			}
		}

		// Successfully accepted a new connection.
		Log("new tunnel connection accepted from %v", conn.RemoteAddr())
		// Spawn a new goroutine to handle this connection concurrently.
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
