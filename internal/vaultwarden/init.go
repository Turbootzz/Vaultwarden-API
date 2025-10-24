package vaultwarden

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

func InitializeBitwardenCLI(serverURL, email, password string) (string, error) {
	logger.Info.Println("Initializing Bitwarden CLI...")

	cmd := exec.Command("bw", "config", "server", serverURL)
	if output, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("config server failed: %w - %s", err, output)
	}

	cmd = exec.Command("bw", "login", email, "--passwordenv", "BW_PASSWORD", "--raw")
	cmd.Env = append(os.Environ(), fmt.Sprintf("BW_PASSWORD=%s", password))
	output, err := cmd.CombinedOutput()

	outputStr := strings.TrimSpace(string(output))
	if err != nil && !strings.Contains(outputStr, "already logged in") {
		return "", fmt.Errorf("login failed: %w - %s", err, outputStr)
	}

	cmd = exec.Command("bw", "unlock", "--passwordenv", "BW_PASSWORD", "--raw")
	cmd.Env = append(os.Environ(), fmt.Sprintf("BW_PASSWORD=%s", password))
	sessionToken, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("unlock failed: %w", err)
	}

	token := strings.TrimSpace(string(sessionToken))
	if token == "" {
		return "", fmt.Errorf("received empty session token")
	}

	logger.Info.Println("Bitwarden CLI initialized successfully")
	return token, nil
}
