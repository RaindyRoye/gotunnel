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
	Close()       // Close gracefully shuts down the service.
}

// handleSignal sets up a signal handler to listen for SIGHUP, SIGTERM, and SIGINT.
// On receiving SIGHUP, it prints the application status and the number of goroutines.
// On receiving SIGTERM or SIGINT, it initiates graceful shutdown.
func handleSignal(app Service) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)

	for sig := range sigChan {
		switch sig {
		case syscall.SIGHUP:
			app.Status()
			tunnel.Log("total goroutines: %d", runtime.NumGoroutine())
		case syscall.SIGTERM, syscall.SIGINT:
			tunnel.Log("received signal: %v, initiating graceful shutdown...", sig)
			app.Close()
			return
		default:
			tunnel.Log("caught unexpected signal: %v, initiating shutdown", sig)
			app.Close()
			return
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

	// Bind flags to setter functions for thread-safe updates
	hb := flag.Int("heartbeat", 10, "Tunnel heartbeat interval in seconds")
	to := flag.Int("timeout", 30, "Tunnel read/write timeout in seconds")
	ll := flag.Uint("log", 1, "Log level (higher number means more verbose)")

	// Set custom usage function
	flag.Usage = usage
	// Parse command-line arguments
	flag.Parse()

	// Apply configuration using thread-safe setters
	tunnel.SetHeartbeat(*hb)
	tunnel.SetTimeout(*to)
	tunnel.SetLogLevel(*ll)

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
		fmt.Fprintf(os.Stderr, "Failed to create service: %s\n", err.Error())
		os.Exit(1)
	}

	// Start the signal handler goroutine to manage OS signals.
	go handleSignal(app)

	// Start the main application logic. This call blocks until shutdown.
	if err := app.Start(); err != nil {
		tunnel.Log("Application exited with error: %v", err)
		os.Exit(1)
	}
	tunnel.Log("Application shut down gracefully")
}
