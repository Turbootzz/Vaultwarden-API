package vaultwarden

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

// Client handles communication with Vaultwarden API
type Client struct {
	baseURL     string
	token       string // Legacy: session token for CLI fallback
	authManager *AuthManager
	httpClient  *http.Client
	cache       *secretCache
}

// secretCache provides a simple in-memory cache with TTL
type secretCache struct {
	mu      sync.RWMutex
	items   map[string]*cacheItem
	ttl     time.Duration
	enabled bool
}

type cacheItem struct {
	value     string
	expiresAt time.Time
}

// CipherResponse represents a Bitwarden/Vaultwarden cipher (item)
type CipherResponse struct {
	Data []struct {
		ID     string `json:"id"`
		Type   int    `json:"type"` // 1 = Login, 2 = Note, 3 = Card, 4 = Identity
		Name   string `json:"name"`
		Login  *struct {
			Username string `json:"username"`
			Password string `json:"password"`
			URIs     []struct {
				URI string `json:"uri"`
			} `json:"uris"`
		} `json:"login,omitempty"`
		Notes  string `json:"notes,omitempty"`
		Fields []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
			Type  int    `json:"type"` // 0 = Text, 1 = Hidden, 2 = Boolean
		} `json:"fields,omitempty"`
	} `json:"data"`
}

// NewClient creates a new Vaultwarden client
// token can be either:
// - A session token (from bw unlock) for CLI-based access
// - A client_id for API-based access (requires clientSecret via NewClientWithAuth)
func NewClient(baseURL, token string, cacheTTL time.Duration) *Client {
	cache := &secretCache{
		items:   make(map[string]*cacheItem),
		ttl:     cacheTTL,
		enabled: cacheTTL > 0,
	}

	if cacheTTL > 0 {
		go cache.startCleanup(cacheTTL)
	}

	if token == "" {
		if sessionData, err := os.ReadFile("/tmp/bw_session"); err == nil {
			token = strings.TrimSpace(string(sessionData))
			logger.Info.Println("Loaded session token from /tmp/bw_session")
		}
	}

	return &Client{
		baseURL: baseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: cache,
	}
}

// NewClientWithAuth creates a client with API key authentication (recommended)
// Use this method when you have client_id and client_secret from Vaultwarden
func NewClientWithAuth(baseURL, clientID, clientSecret string, cacheTTL time.Duration) *Client {
	cache := &secretCache{
		items:   make(map[string]*cacheItem),
		ttl:     cacheTTL,
		enabled: cacheTTL > 0,
	}

	// Start cache cleanup goroutine if caching is enabled
	if cacheTTL > 0 {
		go cache.startCleanup(cacheTTL)
	}

	return &Client{
		baseURL:     baseURL,
		authManager: NewAuthManager(baseURL, clientID, clientSecret),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		cache: cache,
	}
}

// GetSecret retrieves a secret by name from Vaultwarden
// It first checks the cache, then queries the API if needed
func (c *Client) GetSecret(name string) (string, error) {
	// Validate input
	if name == "" {
		return "", fmt.Errorf("secret name cannot be empty")
	}

	// Check cache first
	if c.cache.enabled {
		if value, found := c.cache.get(name); found {
			logger.Info.Printf("Cache hit for secret: %s", name)
			return value, nil
		}
	}

	// Cache miss - fetch from API
	logger.Info.Printf("Fetching secret from Vaultwarden: %s", name)
	value, err := c.fetchSecret(name)
	if err != nil {
		return "", err
	}

	// Store in cache
	if c.cache.enabled {
		c.cache.set(name, value)
	}

	return value, nil
}

// fetchSecret queries the Vaultwarden API for a secret
func (c *Client) fetchSecret(name string) (string, error) {
	// Only try CLI if using session token (not client credentials)
	if c.authManager == nil {
		if value, err := c.FetchSecretViaCLI(name); err == nil {
			return value, nil
		} else {
			logger.Warn.Printf("CLI method failed, trying API: %v", err)
		}
	}

	// Use API method
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url := fmt.Sprintf("%s/api/ciphers", c.baseURL)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set authentication header
	var token string
	var tokenErr error

	if c.authManager != nil {
		// Use API key authentication (preferred)
		token, tokenErr = c.authManager.GetAccessToken()
		if tokenErr != nil {
			return "", fmt.Errorf("failed to get access token: %w", tokenErr)
		}
	} else {
		// Fallback to session token
		token = c.token
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Device-Type", "14") // SDK type

	// Execute request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		// SECURITY: Do NOT log response body - may contain sensitive data
		logger.Error.Printf("Vaultwarden API error (status %d)", resp.StatusCode)
		return "", fmt.Errorf("vaultwarden api returned status %d", resp.StatusCode)
	}

	// Parse response
	var cipherResp CipherResponse
	if err := json.NewDecoder(resp.Body).Decode(&cipherResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	logger.Info.Printf("Found %d ciphers from Vaultwarden API", len(cipherResp.Data))

	for _, cipher := range cipherResp.Data {
		logger.Info.Printf("Cipher name: '%s' (looking for: '%s')", cipher.Name, name)
		if cipher.Name == name {
			return c.extractSecretValue(cipher)
		}
	}

	return "", fmt.Errorf("secret not found: %s", name)
}

// extractSecretValue extracts the secret value from a cipher based on its type
func (c *Client) extractSecretValue(cipher struct {
	ID     string `json:"id"`
	Type   int    `json:"type"`
	Name   string `json:"name"`
	Login  *struct {
		Username string `json:"username"`
		Password string `json:"password"`
		URIs     []struct {
			URI string `json:"uri"`
		} `json:"uris"`
	} `json:"login,omitempty"`
	Notes  string `json:"notes,omitempty"`
	Fields []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
		Type  int    `json:"type"`
	} `json:"fields,omitempty"`
}) (string, error) {
	// Type 1 = Login item
	if cipher.Type == 1 && cipher.Login != nil {
		// Return password by default for login items
		if cipher.Login.Password != "" {
			return cipher.Login.Password, nil
		}
	}

	// Type 2 = Secure note
	if cipher.Type == 2 && cipher.Notes != "" {
		return cipher.Notes, nil
	}

	// Check custom fields
	for _, field := range cipher.Fields {
		if field.Name == "value" || field.Name == "secret" {
			return field.Value, nil
		}
	}

	// If no specific field, return notes if available
	if cipher.Notes != "" {
		return cipher.Notes, nil
	}

	return "", fmt.Errorf("could not extract secret value from cipher")
}

// ClearCache clears all cached secrets
func (c *Client) ClearCache() {
	if c.cache.enabled {
		c.cache.clear()
		logger.Info.Println("Cache cleared")
	}
}

// Cache methods
func (sc *secretCache) get(key string) (string, bool) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	item, found := sc.items[key]
	if !found {
		return "", false
	}

	// Check if expired
	if time.Now().After(item.expiresAt) {
		return "", false
	}

	return item.value, true
}

func (sc *secretCache) set(key, value string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.items[key] = &cacheItem{
		value:     value,
		expiresAt: time.Now().Add(sc.ttl),
	}
}

func (sc *secretCache) clear() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	sc.items = make(map[string]*cacheItem)
}

// startCleanup runs a background goroutine to periodically remove expired cache entries
// This prevents memory leaks from accumulating expired items
func (sc *secretCache) startCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		sc.removeExpired()
	}
}

// removeExpired removes all expired items from the cache
func (sc *secretCache) removeExpired() {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	now := time.Now()
	for key, item := range sc.items {
		if now.After(item.expiresAt) {
			delete(sc.items, key)
		}
	}
}
