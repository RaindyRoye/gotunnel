// Package tunnel contains the client-side implementation for establishing tunnel connections.
package tunnel

import (
	"container/heap"
	"errors"
	"net"
	"sync"
	"time"
)

// ClientHub extends Hub to manage client-side links and implement heartbeat logic.
type ClientHub struct {
	*Hub      // Embedding Hub provides all its methods and fields
	sent uint16 // Counter for the last heartbeat ID sent
	rcvd uint16 // Counter for the last heartbeat ID received from the server
}

// heartbeat runs in a separate goroutine and manages tunnel liveness checks.
// It sends periodic heartbeat commands and monitors for responses.
func (h *ClientHub) heartbeat() {
	heartbeatInterval := getHeartbeat()
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	// Calculate the maximum allowed span between sent and received heartbeats.
	// This determines how many heartbeats can be missed before the tunnel is considered dead.
	timeoutDuration := getTimeout()
	maxSpan := int(timeoutDuration / heartbeatInterval)
	if maxSpan <= tunnelMinSpan {
		maxSpan = tunnelMinSpan
	}
	Debug("ClientHub heartbeat maxSpan: %d (interval: %v, timeout: %v)", maxSpan, heartbeatInterval, timeoutDuration)

	for range ticker.C {
		// Calculate the current span (number of heartbeats sent since last received ack).
		// Handle potential uint16 wraparound (0xFFFF -> 0).
		// Formula: (sent + 1) - rcvd, accounting for wraparound.
		// Example: sent=65535, rcvd=65533 => span = (65535 - 65533) + 1 = 3.
		// Example: sent=2, rcvd=65535 => span = (2 + 65536 - 65535) + 1 = 4.
		span := (h.sent + 1 - h.rcvd) & 0xFFFF // Bitwise AND masks to 16 bits effectively

		if int(span) >= maxSpan {
			Error("tunnel(%v) heartbeat timeout. Sent: %d, Last Received Ack: %d, Calculated Span: %d", 
			      h.Hub.tunnel, h.sent, h.rcvd, span)
			h.Hub.Close() // Close the tunnel connection if timeout occurs
			break         // Exit the heartbeat loop
		}

		h.sent++
		if !h.SendCmd(h.sent, TUN_HEARTBEAT) {
			// If sending the heartbeat fails, the tunnel is likely broken.
			// Break the loop to stop the heartbeat goroutine.
			Debug("ClientHub failed to send heartbeat %d, stopping.", h.sent)
			break
		}
	}
}

// onCtrl acts as a filter for control commands received by the client hub.
// It handles TUN_HEARTBEAT by updating the received counter.
func (h *ClientHub) onCtrl(cmd Cmd) bool {
	if cmd.Cmd == TUN_HEARTBEAT {
		// Update the last received heartbeat ID
		h.rcvd = cmd.Id
		return true // Command handled, don't pass to base Hub
	}
	// Pass other commands to the base Hub logic
	return false
}

// newClientHub creates and starts a new ClientHub instance.
// It initializes the base Hub and starts the heartbeat goroutine.
func newClientHub(tunnel *Tunnel) *ClientHub {
	h := &ClientHub{
		Hub:  newHub(tunnel), // Initialize the embedded Hub
		sent: 0,              // Initialize counters
		rcvd: 0,
	}
	h.Hub.onCtrlFilter = h.onCtrl // Set the control filter
	go h.heartbeat()              // Start the heartbeat loop in the background
	return h
}

// HubItem represents a single tunnel connection managed by the client.
type HubItem struct {
	*ClientHub        // Embedding ClientHub provides access to its methods and fields
	priority int       // Priority for the heap (lower is higher priority)
	index    int       // Index in the heap (required by container/heap)
}

// HubQueue implements container/heap.Interface for HubItem.
type HubQueue []*HubItem

func (hq HubQueue) Len() int { return len(hq) }

// Less defines the min-heap property based on priority (lower number is higher priority).
func (hq HubQueue) Less(i, j int) bool { return hq[i].priority < hq[j].priority }

func (hq HubQueue) Swap(i, j int) {
	hq[i], hq[j] = hq[j], hq[i]
	hq[i].index = i
	hq[j].index = j
}

func (hq *HubQueue) Push(x interface{}) {
	n := len(*hq)
	item := x.(*HubItem)
	item.index = n
	*hq = append(*hq, item)
}

func (hq *HubQueue) Pop() interface{} {
	old := *hq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil  // Avoid memory leak
	item.index = -1 // for safety
	*hq = old[0 : n-1]
	return item
}

// Client manages multiple tunnel connections and listens for local connections to forward.
type Client struct {
	laddr   string  // Local address to listen for incoming connections
	backend string  // Remote address of the tunnel server
	secret  string  // Shared secret for authentication
	tunnels uint    // Number of concurrent tunnel connections to maintain

	alloc *IdAllocator // Allocator for unique link IDs
	cq    HubQueue     // Concurrent queue (min-heap) of active hubs
	lock  sync.Mutex   // Mutex protecting access to the hub queue
}

// createHub establishes a new tunnel connection to the backend server.
// It performs the authentication handshake and returns a new HubItem.
func (cli *Client) createHub() (hub *HubItem, err error) {
	// Dial the backend server
	conn, err := dial(cli.backend)
	if err != nil {
		return nil, err
	}

	// Wrap the connection with tunnel logic
	tunnel := newTunnel(conn)

	// Read the initial challenge block from the server
	_, challenge, err := tunnel.ReadPacket()
	if err != nil {
		Error("client failed to read challenge from %v: %s", tunnel, err)
		conn.Close() // Clean up the failed connection
		return nil, err
	}

	// Initialize the authentication algorithm with the shared secret
	a := NewTaa(cli.secret)

	// Exchange the challenge block with the server to authenticate
	token, ok := a.ExchangeCipherBlock(challenge)
	if !ok {
		err = errors.New("client authentication (challenge exchange) failed")
		Error("client authentication failed for %v", tunnel)
		conn.Close()
		return nil, err
	}

	// Send the response token back to the server
	if err = tunnel.WritePacket(0, token); err != nil {
		Error("client failed to write token response to %v: %s", tunnel, err)
		conn.Close()
		return nil, err
	}

	// Authentication successful. Set up the encryption key for the tunnel session.
	// Note: RC4 is cryptographically deprecated, but this is preserved as per API requirements.
	tunnel.SetCipherKey(a.GetChacha20key())

	// Create the client hub for this authenticated tunnel connection.
	hub = &HubItem{
		ClientHub: newClientHub(tunnel),
	}
	return hub, nil
}

// addHub adds a newly created HubItem to the client's managed queue.
func (cli *Client) addHub(item *HubItem) {
	cli.lock.Lock()
	heap.Push(&cli.cq, item)
	cli.lock.Unlock()
}

// removeHub removes a HubItem from the client's managed queue.
func (cli *Client) removeHub(item *HubItem) {
	cli.lock.Lock()
	heap.Remove(&cli.cq, item.index) // Remove by index
	cli.lock.Unlock()
}

// fetchHub retrieves the highest priority (lowest number) HubItem from the queue.
// It increments its priority to reduce its likelihood of being picked again immediately.
func (cli *Client) fetchHub() *HubItem {
	cli.lock.Lock()
	defer cli.lock.Unlock() // Unlock happens after the function returns

	if len(cli.cq) == 0 {
		return nil // No hubs available
	}

	item := cli.cq[0] // Get the root (highest priority) item
	item.priority++   // Increase its priority (make it less preferred next time)
	heap.Fix(&cli.cq, 0) // Restore the heap property after priority change
	return item
}

// dropHub decrements the priority of a HubItem, making it more likely to be chosen again soon.
// This is used when a connection attempt using the hub fails.
func (cli *Client) dropHub(item *HubItem) {
	cli.lock.Lock()
	item.priority--            // Decrease its priority (make it more preferred)
	heap.Fix(&cli.cq, item.index) // Restore the heap property after priority change
	cli.lock.Unlock()
}

// handleConn manages the lifecycle of a single local connection forwarded through a tunnel hub.
func (cli *Client) handleConn(hub *HubItem, conn *net.TCPConn) {
	// Ensure resources are cleaned up on function exit.
	defer conn.Close()
	defer cli.dropHub(hub) // Decrement priority on exit (failure or success path)
	defer Recover()        // Recover from panics in this goroutine

	// Acquire a unique ID for this link from the global allocator.
	id := cli.alloc.Acquire()
	defer cli.alloc.Release(id) // Always release the ID back to the pool

	// Get the base Hub instance from the ClientHub wrapper.
	h := hub.Hub

	// Create a new link instance within the hub for this connection.
	l := h.createLink(id)
	defer h.deleteLink(id) // Ensure the link is removed from the hub on exit

	// Request the server to create the corresponding link.
	h.SendCmd(id, LINK_CREATE)

	// Start the bidirectional data forwarding between the local connection and the tunnel.
	h.startLink(l, conn)
}

// listen starts the local TCP server to accept incoming connections.
// It fetches a hub for each connection and starts forwarding.
func (cli *Client) listen() error {
	// Listen on the local address
	ln, err := net.Listen("tcp", cli.laddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	// Cast to TCPListener to get access to specific TCP methods if needed (though AcceptTCP is already available via net.Listener).
	// Using the generic net.Listener interface is generally preferred for flexibility.
	tcpListener, ok := ln.(*net.TCPListener)
	if !ok {
		// If the listener is not a *TCPListener, we cannot call specific TCP methods on it.
		// This should not happen with net.Listen("tcp", ...), but handle generically.
		// We can still call Accept() which returns net.Conn.
		// For this specific code, AcceptTCP is called anyway, which is fine as *TCPConn implements net.Conn.
		// Proceed with the original logic assuming ln is effectively a TCPListener.
		// The original code was: tcpListener := ln.(*net.TCPListener)
		// Let's keep the cast but add a comment.
		tcpListener = ln.(*net.TCPListener) // Safe cast for net.Listen("tcp", ...)
	}

	for {
		conn, err := tcpListener.AcceptTCP()
		if err != nil {
			// Check if the error is temporary (e.g., too many open files).
			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				// Log the temporary failure and continue trying to accept.
				Log("client listen accept failed temporarily on %v: %s", ln.Addr(), netErr.Error())
				continue
			} else {
				// A permanent error occurred (e.g., listener closed, network down).
				// Return the error to signal the listener loop should stop.
				return err
			}
		}

		Info("client accepted new local connection from %v", conn.RemoteAddr())

		// Fetch an available hub from the client's queue.
		hub := cli.fetchHub()
		if hub == nil {
			Error("client has no active hubs available, dropping local connection from %v", conn.RemoteAddr())
			conn.Close() // Close the local connection if no tunnel is available
			continue
		}

		// Configure keep-alive for the local connection.
		conn.SetKeepAlive(true)
		conn.SetKeepAlivePeriod(time.Second * 60)

		// Start handling the connection in a new goroutine.
		go cli.handleConn(hub, conn)
	}
}

// Start initializes the client.
// It spawns goroutines to maintain the desired number of tunnel connections
// and starts the local listener to forward connections.
func (cli *Client) Start() error {
	// Determine the number of tunnel maintenance goroutines to spawn.
	numTunnels := int(cli.tunnels)
	for i := 0; i < numTunnels; i++ {
		go func(index int) {
			defer Recover() // Recover from panics in this maintenance goroutine

			for {
				// Attempt to create a new tunnel connection
				hub, err := cli.createHub()
				if err != nil {
					Error("client tunnel %d failed to connect or authenticate: %v", index, err)
					time.Sleep(time.Second * 3) // Wait before retrying
					continue                    // Retry the connection loop
				}

				Info("client tunnel %d connected and authenticated successfully", index)
				cli.addHub(hub) // Add the new hub to the managed queue
				hub.Start()     // Start the hub's main loop (this blocks until the tunnel breaks)
				cli.removeHub(hub) // Remove the hub from the queue when it stops/disconnects
				Error("client tunnel %d disconnected", index)
				// Loop continues, attempting to reconnect
			}
		}(i)
	}

	// Start the local listener loop. This call blocks.
	return cli.listen()
}

// Status prints the current status of all managed hubs.
func (cli *Client) Status() {
	cli.lock.Lock()
	hubsToCheck := make([]*HubItem, len(cli.cq))
	copy(hubsToCheck, cli.cq)
	cli.lock.Unlock()

	// Call Status on each hub outside the critical section to avoid blocking other operations.
	for _, hub := range hubsToCheck {
		hub.Status()
	}
}

// NewClient creates a new tunnel client instance.
// It initializes the client structure and prepares the hub queue.
func NewClient(listen, backend, secret string, tunnels uint) (*Client, error) {
	client := &Client{
		laddr:   listen,
		backend: backend,
		secret:  secret,
		tunnels: tunnels,

		alloc: newAllocator(),                   // Initialize the ID allocator
		cq:    make(HubQueue, tunnels)[:0:tunnels], // Initialize the hub queue slice with correct capacity and length
	}
	// Initialize the heap structure on the slice
	heap.Init(&client.cq)

	return client, nil
}
