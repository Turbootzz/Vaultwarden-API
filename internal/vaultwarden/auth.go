package vaultwarden

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

// AuthManager handles authentication with Vaultwarden
type AuthManager struct {
	baseURL      string
	clientID     string
	clientSecret string
	httpClient   *http.Client

	// Token management
	mu           sync.RWMutex
	accessToken  string
	tokenExpiry  time.Time
}

// TokenResponse represents the OAuth token response from Vaultwarden
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(baseURL, clientID, clientSecret string) *AuthManager {
	return &AuthManager{
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// GetAccessToken returns a valid access token, refreshing if necessary
func (am *AuthManager) GetAccessToken() (string, error) {
	am.mu.RLock()
	// Check if we have a valid token
	if am.accessToken != "" && time.Now().Before(am.tokenExpiry) {
		token := am.accessToken
		am.mu.RUnlock()
		return token, nil
	}
	am.mu.RUnlock()

	// Token expired or doesn't exist, get a new one
	return am.refreshAccessToken()
}

// refreshAccessToken obtains a new access token from Vaultwarden
func (am *AuthManager) refreshAccessToken() (string, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	// Double-check after acquiring write lock
	if am.accessToken != "" && time.Now().Before(am.tokenExpiry) {
		return am.accessToken, nil
	}

	logger.Info.Println("Obtaining new access token from Vaultwarden...")

	// Prepare the token request
	data := url.Values{}
	data.Set("grant_type", "client_credentials")
	data.Set("scope", "api")
	data.Set("client_id", am.clientID)
	data.Set("client_secret", am.clientSecret)

	// Generate device identifier (required by Bitwarden protocol)
	deviceID := am.generateDeviceID()
	data.Set("deviceIdentifier", deviceID)
	data.Set("deviceType", "14") // SDK type
	data.Set("deviceName", "Vaultwarden-API")

	// Create request
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tokenURL := fmt.Sprintf("%s/identity/connect/token", am.baseURL)
	req, err := http.NewRequestWithContext(ctx, "POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	// Execute request
	resp, err := am.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// SECURITY: Do not log response body - may contain sensitive information
		logger.Error.Printf("Token request failed with status %d", resp.StatusCode)
		return "", fmt.Errorf("token request failed with status %d", resp.StatusCode)
	}

	// Parse response
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}

	// Store the token
	am.accessToken = tokenResp.AccessToken
	// Refresh 5 minutes before expiry to avoid edge cases
	am.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn-300) * time.Second)

	logger.Info.Printf("Successfully obtained access token (expires in %d seconds)", tokenResp.ExpiresIn)

	return am.accessToken, nil
}

// generateDeviceID creates a consistent device identifier
func (am *AuthManager) generateDeviceID() string {
	// Create a hash of client_id for consistent device ID
	hash := sha256.Sum256([]byte(am.clientID))
	return base64.StdEncoding.EncodeToString(hash[:16])
}
