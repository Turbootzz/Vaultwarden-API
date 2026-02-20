package vaultwarden

import (
	"fmt"
	"time"

	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

// InitializeClient creates and initializes a fully authenticated vault client.
// clientID and clientSecret are optional — if provided, API key login is used (bypasses 2FA).
func InitializeClient(serverURL, email, password, clientID, clientSecret string, cacheTTL, syncInterval time.Duration) (*Client, error) {
	logger.Info.Println("Initializing Vaultwarden native API client...")

	api := NewAPIClient(serverURL, email, password, clientID, clientSecret)
	client := NewClient(api, cacheTTL, syncInterval)

	// Authenticate and perform initial sync with retry.
	maxRetries := 3
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(attempt*attempt) * 5 * time.Second
			logger.Info.Printf("Retry attempt %d/%d after %v...", attempt, maxRetries, backoff)
			time.Sleep(backoff)
		}

		if err := client.Initialize(); err != nil {
			logger.Warn.Printf("Initialization failed (attempt %d/%d): %v", attempt, maxRetries, err)
			lastErr = err
			continue
		}

		logger.Info.Println("Vaultwarden client initialized successfully")
		return client, nil
	}

	return nil, fmt.Errorf("failed to initialize after %d attempts: %w", maxRetries, lastErr)
}
