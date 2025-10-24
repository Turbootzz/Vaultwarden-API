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

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bw", "config", "server", serverURL)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("config server failed: %w - %s", err, output)
	}

	cmd = exec.CommandContext(ctx, "bw", "login", "--apikey")
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("BW_CLIENTID=%s", clientID),
		fmt.Sprintf("BW_CLIENTSECRET=%s", clientSecret),
	)
	output, err := cmd.CombinedOutput()

	outputStr := strings.TrimSpace(string(output))
	if err != nil && !strings.Contains(outputStr, "You are logged in!") {
		return "", fmt.Errorf("login failed: %w - %s", err, outputStr)
	}

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
