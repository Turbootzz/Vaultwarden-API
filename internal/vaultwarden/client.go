// Package vaultwarden provides a client for interacting with Vaultwarden via CLI
package vaultwarden

import (
	"fmt"
	"sync"
	"time"

	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

// Client handles communication with Vaultwarden via CLI
type Client struct {
	baseURL string
	token   string // Session token from CLI authentication
	cache   *secretCache
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

// NewClient creates a new Vaultwarden client with CLI session token
func NewClient(baseURL, token string, cacheTTL time.Duration) *Client {
	cache := &secretCache{
		items:   make(map[string]*cacheItem),
		ttl:     cacheTTL,
		enabled: cacheTTL > 0,
	}

	if cacheTTL > 0 {
		go cache.startCleanup(cacheTTL)
	}

	return &Client{
		baseURL: baseURL,
		token:   token,
		cache:   cache,
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

// fetchSecret queries the Vaultwarden for a secret via CLI
func (c *Client) fetchSecret(name string) (string, error) {
	return c.FetchSecretViaCLI(name)
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
