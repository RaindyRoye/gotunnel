// Package main provides the entry point for the gotunnel application.
// It parses command-line flags and starts either a tunnel server or client.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"gotunnel/tunnel"
)

// Service defines the common interface for starting and checking the status of the application.
type Service interface {
	Start() error // Start begins the service's main loop and blocks until an error occurs or the service stops.
	Status()      // Status prints the current status of the service.
}

// handleSignal sets up a signal handler to listen for SIGHUP.
// On receiving SIGHUP, it prints the application status and the number of goroutines.
// On receiving any other signal, it logs the event and exits.
func handleSignal(app Service) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT) // Listen for more common termination signals

	for sig := range sigChan {
		switch sig {
		case syscall.SIGHUP:
			app.Status()
			tunnel.Log("total goroutines: %d", runtime.NumGoroutine())
		case syscall.SIGTERM, syscall.SIGINT: // Handle standard termination signals
			tunnel.Log("received signal: %v, initiating shutdown...", sig)
			os.Exit(0) // Exit gracefully
		default:
			tunnel.Log("caught unexpected signal: %v, exiting", sig)
			os.Exit(1) // Exit with error code
		}
	}
}

// usage prints the command-line usage information and exits with status 1.
func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
	os.Exit(1)
}

func main() {
	// Define command-line flags
	laddr := flag.String("listen", ":8001", "Address to listen on for incoming connections")
	baddr := flag.String("backend", "127.0.0.1:1234", "Backend server address to connect to")
	secret := flag.String("secret", "the answer to life, the universe and everything", "Shared secret for tunnel authentication")
	tunnels := flag.Uint("tunnels", 0, "Number of low-level tunnels to create (0 for server mode)")

	// Bind flags directly to the global variables in the tunnel package
	flag.IntVar(&tunnel.Heartbeat, "heartbeat", 10, "Tunnel heartbeat interval in seconds")
	flag.IntVar(&tunnel.Timeout, "timeout", 30, "Tunnel read/write timeout in seconds")
	flag.UintVar(&tunnel.LogLevel, "log", 1, "Log level (higher number means more verbose)")

	// Set custom usage function
	flag.Usage = usage
	// Parse command-line arguments
	flag.Parse()

	var app Service
	var err error

	// Determine whether to start as a server or client based on the 'tunnels' flag.
	if *tunnels == 0 {
		// Server mode: accepts incoming connections and forwards them to the backend.
		app, err = tunnel.NewServer(*laddr, *baddr, *secret)
	} else {
		// Client mode: connects to the server and creates persistent tunnels.
		app, err = tunnel.NewClient(*laddr, *baddr, *secret, *tunnels)
	}

	if err != nil {
		// Log the error and exit if the application (server/client) creation fails.
		fmt.Fprintf(os.Stderr, "Failed to create service: %s\n", err.Error())
		os.Exit(1) // Exit with error code
	}

	// Start the signal handler goroutine to manage OS signals.
	go handleSignal(app)

	// Start the main application logic. This call blocks.
	// The application's Start() method is expected to return an error when it stops.
	tunnel.Log("Application exited with error: %v", app.Start())
}
