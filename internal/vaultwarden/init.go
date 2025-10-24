package vaultwarden

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

var bitwardenInitMutex sync.Mutex

func InitializeBitwardenCLI(serverURL, clientID, clientSecret, password string) (string, error) {
	bitwardenInitMutex.Lock()
	defer bitwardenInitMutex.Unlock()

	logger.Info.Println("Initializing Bitwarden CLI...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	cmd := exec.CommandContext(ctx, "bw", "config", "server", serverURL)
	if output, err := cmd.CombinedOutput(); err != nil {
		cancel()
		return "", fmt.Errorf("config server failed: %w - %s", err, output)
	}
	cancel()

	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
	cmd = exec.CommandContext(ctx, "bw", "status")
	statusOutput, _ := cmd.CombinedOutput()
	cancel()

	statusStr := strings.TrimSpace(string(statusOutput))
	isLoggedIn := strings.Contains(statusStr, `"status":"unlocked"`) || strings.Contains(statusStr, `"status":"locked"`)

	if !isLoggedIn {
		logger.Info.Println("Logging in to Bitwarden...")
		maxRetries := 3
		var loginErr error

		for attempt := 1; attempt <= maxRetries; attempt++ {
			if attempt > 1 {
				backoff := time.Duration(attempt*attempt) * 5 * time.Second
				logger.Info.Printf("Retry attempt %d/%d after %v...", attempt, maxRetries, backoff)
				time.Sleep(backoff)
			}

			ctx, cancel = context.WithTimeout(context.Background(), 15*time.Second)
			cmd = exec.CommandContext(ctx, "bw", "login", "--apikey")
			cmd.Env = append(os.Environ(),
				fmt.Sprintf("BW_CLIENTID=%s", clientID),
				fmt.Sprintf("BW_CLIENTSECRET=%s", clientSecret),
			)
			output, err := cmd.CombinedOutput()
			cancel()

			outputStr := strings.TrimSpace(string(output))
			if err == nil || strings.Contains(outputStr, "You are logged in!") {
				logger.Info.Println("Login successful")
				loginErr = nil
				break
			}

			if strings.Contains(outputStr, "Rate limit") {
				logger.Warn.Printf("Rate limited (attempt %d/%d)", attempt, maxRetries)
				loginErr = fmt.Errorf("rate limited: %s", outputStr)
				continue
			}

			loginErr = fmt.Errorf("login failed: %w - %s", err, outputStr)
			break
		}

		if loginErr != nil {
			return "", loginErr
		}
	} else {
		logger.Info.Println("Already logged in, skipping login")
	}

	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd = exec.CommandContext(ctx, "bw", "unlock", "--passwordenv", "BW_PASSWORD", "--raw")
	cmd.Env = append(os.Environ(), fmt.Sprintf("BW_PASSWORD=%s", password))
	sessionToken, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("unlock failed: %w - %s", err, sessionToken)
	}

	token := strings.TrimSpace(string(sessionToken))
	if token == "" {
		return "", fmt.Errorf("received empty session token")
	}

	logger.Info.Println("Bitwarden CLI initialized successfully")
	return token, nil
}
