// Package tunnel contains the client-side implementation for establishing tunnel connections.
package tunnel

import (
	"container/heap"
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"net"
	"sync"
	"time"
)

// ClientHub extends Hub to manage client-side links and implement heartbeat logic.
type ClientHub struct {
	*Hub // Embedding Hub provides all its methods and fields
	ctx  context.Context
	sent uint16 // Counter for the last heartbeat ID sent
	rcvd uint16 // Counter for the last heartbeat ID received from the server
}

// heartbeat runs in a separate goroutine and manages tunnel liveness checks.
// It sends periodic heartbeat commands and monitors for responses.
func (h *ClientHub) heartbeat() {
	heartbeatInterval := getHeartbeat()
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()

	timeoutDuration := getTimeout()
	maxSpan := int(timeoutDuration / heartbeatInterval)
	if maxSpan <= tunnelMinSpan {
		maxSpan = tunnelMinSpan
	}
	Debug("ClientHub heartbeat maxSpan: %d (interval: %v, timeout: %v)", maxSpan, heartbeatInterval, timeoutDuration)

	for {
		select {
		case <-h.ctx.Done():
			Debug("ClientHub heartbeat stopped: %v", h.ctx.Err())
			return
		case <-ticker.C:
			span := (h.sent + 1 - h.rcvd) & 0xFFFF

			if int(span) >= maxSpan {
				Error("tunnel(%v) heartbeat timeout. Sent: %d, Last Received Ack: %d, Calculated Span: %d",
					h.Hub.tunnel, h.sent, h.rcvd, span)
				h.Hub.Close()
				return
			}

			h.sent++
			if !h.SendCmd(h.sent, TUN_HEARTBEAT) {
				Debug("ClientHub failed to send heartbeat %d, stopping.", h.sent)
				return
			}
		}
	}
}

// onCtrl acts as a filter for control commands received by the client hub.
func (h *ClientHub) onCtrl(cmd Cmd) bool {
	if cmd.Cmd == TUN_HEARTBEAT {
		h.rcvd = cmd.Id
		return true
	}
	return false
}

// newClientHub creates and starts a new ClientHub instance.
func newClientHub(ctx context.Context, tunnel *Tunnel) *ClientHub {
	h := &ClientHub{
		Hub:  newHub(tunnel),
		ctx:  ctx,
		sent: 0,
		rcvd: 0,
	}
	h.Hub.onCtrlFilter = h.onCtrl
	go h.heartbeat()
	return h
}

// HubItem represents a single tunnel connection managed by the client.
type HubItem struct {
	*ClientHub
	priority int
	index    int
}

// HubQueue implements container/heap.Interface for HubItem.
type HubQueue []*HubItem

func (hq HubQueue) Len() int           { return len(hq) }
func (hq HubQueue) Less(i, j int) bool { return hq[i].priority < hq[j].priority }
func (hq HubQueue) Swap(i, j int) {
	hq[i], hq[j] = hq[j], hq[i]
	hq[i].index = i
	hq[j].index = j
}
func (hq *HubQueue) Push(x any) {
	item := x.(*HubItem)
	item.index = len(*hq)
	*hq = append(*hq, item)
}
func (hq *HubQueue) Pop() any {
	old := *hq
	n := len(old)
	item := old[n-1]
	old[n-1] = nil
	item.index = -1
	*hq = old[0 : n-1]
	return item
}

// Client manages multiple tunnel connections and listens for local connections to forward.
type Client struct {
	ctx     context.Context // context for graceful shutdown
	cancel  context.CancelFunc
	laddr   string // Local address to listen for incoming connections
	backend string // Remote address of the tunnel server
	secret  string // Shared secret for authentication
	tunnels uint   // Number of concurrent tunnel connections to maintain

	alloc *IdAllocator // Allocator for unique link IDs
	cq    HubQueue     // Concurrent queue (min-heap) of active hubs
	lock  sync.Mutex   // Mutex protecting access to the hub queue
}

// createHub establishes a new tunnel connection to the backend server.
// It performs the authentication handshake and returns a new HubItem.
func (cli *Client) createHub(ctx context.Context) (hub *HubItem, err error) {
	// Check context before dialing
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

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
	tunnel.SetCipherKey(a.GetChacha20key())

	// Create the client hub for this authenticated tunnel connection.
	hub = &HubItem{
		ClientHub: newClientHub(ctx, tunnel),
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
	if item.index >= 0 && item.index < len(cli.cq) && cli.cq[item.index] == item {
		heap.Remove(&cli.cq, item.index) // Remove by index
	}
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

	item := cli.cq[0]    // Get the root (highest priority) item
	item.priority++      // Increase its priority (make it less preferred next time)
	heap.Fix(&cli.cq, 0) // Restore the heap property after priority change
	return item
}

// dropHub decrements the priority of a HubItem, making it more likely to be chosen again soon.
// This is used when a connection attempt using the hub fails.
func (cli *Client) dropHub(item *HubItem) {
	cli.lock.Lock()
	if item.index >= 0 && item.index < len(cli.cq) && cli.cq[item.index] == item {
		item.priority--               // Decrease its priority (make it more preferred)
		heap.Fix(&cli.cq, item.index) // Restore the heap property after priority change
	}
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

func (cli *Client) listen() error {
	ln, err := net.Listen("tcp", cli.laddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	tcpListener := ln.(*net.TCPListener)

	for {
		conn, err := tcpListener.AcceptTCP()
		if err != nil {
			// Check context cancellation
			select {
			case <-cli.ctx.Done():
				Log("client listener shutting down: %v", cli.ctx.Err())
				return nil
			default:
			}

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				Log("client listen accept timeout on %v: %s", ln.Addr(), netErr.Error())
				continue
			}
			return err
		}

		Info("client accepted new local connection from %v", conn.RemoteAddr())

		hub := cli.fetchHub()
		if hub == nil {
			Error("client has no active hubs available, dropping local connection from %v", conn.RemoteAddr())
			conn.Close()
			continue
		}

		conn.SetKeepAlive(true)
		conn.SetKeepAlivePeriod(time.Second * 60)

		go cli.handleConn(hub, conn)
	}
}

// secureBackoff returns a duration for exponential backoff with cryptographically secure jitter.
// attempt is 0-based. The delay grows from baseDelay up to maxDelay,
// with random jitter to prevent thundering herd.
func secureBackoff(attempt int, baseDelay, maxDelay time.Duration) time.Duration {
	delay := baseDelay
	for i := 0; i < attempt; i++ {
		delay *= 2
		if delay >= maxDelay {
			delay = maxDelay
			break
		}
	}
	// Add jitter: 50% ~ 100% of delay using crypto/rand
	halfDelay := delay / 2
	if halfDelay > 0 {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(halfDelay)))
		if err == nil {
			return halfDelay + time.Duration(n.Int64())
		}
	}
	return delay
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

			failures := 0 // consecutive failure count for backoff
			for {
				// Check context before attempting to connect
				select {
				case <-cli.ctx.Done():
					Log("client tunnel %d shutting down: %v", index, cli.ctx.Err())
					return
				default:
				}

				// Attempt to create a new tunnel connection
				hub, err := cli.createHub(cli.ctx)
				if err != nil {
					// If context was cancelled, don't retry
					if cli.ctx.Err() != nil {
						return
					}
					failures++
					wait := secureBackoff(failures, 3*time.Second, 60*time.Second)
					Error("client tunnel %d failed to connect or authenticate: %v (retry in %v)", index, err, wait)

					// Wait with context awareness
					select {
					case <-cli.ctx.Done():
						return
					case <-time.After(wait):
					}
					continue
				}

				failures = 0 // reset on successful connection
				Info("client tunnel %d connected and authenticated successfully", index)
				cli.addHub(hub)    // Add the new hub to the managed queue
				hub.Start()        // Start the hub's main loop (this blocks until the tunnel breaks)
				cli.removeHub(hub) // Remove the hub from the queue when it stops/disconnects

				// Check context before reconnecting
				select {
				case <-cli.ctx.Done():
					return
				case <-time.After(time.Second): // Brief delay before reconnect to avoid tight loop
				}
				Error("client tunnel %d disconnected, reconnecting", index)
			}
		}(i)
	}

	// Start the local listener loop. This call blocks.
	return cli.listen()
}

// Close gracefully shuts down the client.
func (cli *Client) Close() {
	if cli.cancel != nil {
		cli.cancel()
	}
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
	ctx, cancel := context.WithCancel(context.Background())

	client := &Client{
		ctx:     ctx,
		cancel:  cancel,
		laddr:   listen,
		backend: backend,
		secret:  secret,
		tunnels: tunnels,

		alloc: newAllocator(),                      // Initialize the ID allocator
		cq:    make(HubQueue, tunnels)[:0:tunnels], // Initialize the hub queue slice with correct capacity and length
	}
	// Initialize the heap structure on the slice
	heap.Init(&client.cq)

	return client, nil
}
