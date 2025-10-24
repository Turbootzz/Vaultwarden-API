package vaultwarden

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

type SessionManager struct {
	mu            sync.RWMutex
	sessionToken  string
	serverURL     string
	email         string
	password      string
	refreshTicker *time.Ticker
	stopChan      chan bool
}

func NewSessionManager(serverURL, email, password string) *SessionManager {
	sm := &SessionManager{
		serverURL: serverURL,
		email:     email,
		password:  password,
		stopChan:  make(chan bool),
	}

	if err := sm.login(); err != nil {
		logger.Warn.Printf("Initial login failed: %v - will retry", err)
	}

	sm.startAutoRefresh()
	return sm
}

func (sm *SessionManager) GetToken() string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return sm.sessionToken
}

func (sm *SessionManager) login() error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	cmd := exec.Command("bw", "config", "server", sm.serverURL)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("config server failed: %w", err)
	}

	if sm.password != "" {
		cmd = exec.Command("bw", "login", sm.email, "--passwordenv", "BW_PASSWORD")
		cmd.Env = append(os.Environ(), fmt.Sprintf("BW_PASSWORD=%s", sm.password))
		output, err := cmd.CombinedOutput()
		if err != nil && string(output) != "" && !contains(string(output), "already logged in") {
			return fmt.Errorf("login failed: %w - %s", err, output)
		}
	}

	cmd = exec.Command("bw", "unlock", "--passwordenv", "BW_PASSWORD", "--raw")
	cmd.Env = append(os.Environ(), fmt.Sprintf("BW_PASSWORD=%s", sm.password))
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("unlock failed: %w", err)
	}

	sm.sessionToken = string(output)
	logger.Info.Println("Successfully obtained Bitwarden session token")
	return nil
}

func (sm *SessionManager) startAutoRefresh() {
	sm.refreshTicker = time.NewTicker(6 * time.Hour)

	go func() {
		for {
			select {
			case <-sm.refreshTicker.C:
				logger.Info.Println("Refreshing Bitwarden session...")
				if err := sm.login(); err != nil {
					logger.Error.Printf("Session refresh failed: %v", err)
				}
			case <-sm.stopChan:
				return
			}
		}
	}()
}

func (sm *SessionManager) Stop() {
	sm.refreshTicker.Stop()
	sm.stopChan <- true
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}
