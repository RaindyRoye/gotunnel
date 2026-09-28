package main

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

type statusService struct {
	statuses int
}

func (s *statusService) Start() error { return nil }
func (s *statusService) Status()      { s.statuses++ }

type reloadService struct {
	statusService
	reloads int
}

func (s *reloadService) Reload() error {
	s.reloads++
	if s.reloads == 1 {
		return errors.New("invalid config")
	}
	return nil
}

func TestSIGHUPReload(t *testing.T) {
	app := &reloadService{}
	signals := make(chan os.Signal, 2)
	signals <- syscall.SIGHUP
	signals <- syscall.SIGHUP
	close(signals)
	handleSignal(app, signals)
	if app.reloads != 2 || app.statuses != 2 {
		t.Fatalf("reloads=%d statuses=%d, want two reload attempts and status reports", app.reloads, app.statuses)
	}
}

func TestSIGHUPLegacyStatus(t *testing.T) {
	app := &statusService{}
	signals := make(chan os.Signal, 1)
	signals <- syscall.SIGHUP
	close(signals)
	handleSignal(app, signals)
	if app.statuses != 1 {
		t.Fatalf("statuses=%d, want 1", app.statuses)
	}
}
