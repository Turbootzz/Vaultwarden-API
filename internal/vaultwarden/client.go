// Package vaultwarden provides a production-ready client for retrieving secrets
// from Vaultwarden using native Go HTTP and crypto (no CLI dependency).
package vaultwarden

import (
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/Turbootzz/vaultwarden-api/pkg/logger"
)

// Client manages vault access, caching, and background sync.
type Client struct {
	api       *APIClient
	cacheTTL  time.Duration
	syncEvery time.Duration

	mu    sync.RWMutex
	items map[string]DecryptedItem // keyed by cipher id

	// nameMaps from the last successful sync (for resolving filter names to UUIDs).
	nameMaps SyncNameMaps

	stopSync chan struct{}
}

// NewClient creates a new vault client backed by the native API client.
func NewClient(api *APIClient, cacheTTL, syncInterval time.Duration) *Client {
	return &Client{
		api:       api,
		cacheTTL:  cacheTTL,
		syncEvery: syncInterval,
		items:     make(map[string]DecryptedItem),
		stopSync:  make(chan struct{}),
	}
}

// Initialize authenticates and performs the initial vault sync.
func (c *Client) Initialize() error {
	if err := c.api.Authenticate(); err != nil {
		return fmt.Errorf("authenticate: %w", err)
	}

	if err := c.syncVault(); err != nil {
		return fmt.Errorf("initial sync: %w", err)
	}

	// Start background sync.
	go c.backgroundSync()

	return nil
}

// SecretFilter limits lookup by vault placement. Empty fields are ignored (no constraint).
// Use at most one of organization id vs name, etc., enforced at the HTTP layer.
type SecretFilter struct {
	OrganizationID string
	CollectionID   string
	FolderID       string
}

func matchesSecretFilter(item DecryptedItem, f SecretFilter) bool {
	if f.OrganizationID != "" && !strings.EqualFold(item.OrganizationID, f.OrganizationID) {
		return false
	}
	if f.CollectionID != "" {
		found := false
		for _, id := range item.CollectionIDs {
			if strings.EqualFold(id, f.CollectionID) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if f.FolderID != "" && !strings.EqualFold(item.FolderID, f.FolderID) {
		return false
	}
	return true
}

// GetSecret retrieves a decrypted secret by name.
// It searches by exact name (case-insensitive), then falls back to partial match.
func (c *Client) GetSecret(name string, filter SecretFilter) (string, error) {
	if name == "" {
		return "", fmt.Errorf("secret name cannot be empty")
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	key := strings.ToLower(name)

	candidates := make([]DecryptedItem, 0, len(c.items))
	for _, item := range c.items {
		if matchesSecretFilter(item, filter) {
			candidates = append(candidates, item)
		}
	}

	// Case 1: Exact match.
	for _, item := range candidates {
		if strings.EqualFold(item.Name, name) {
			return extractSecret(item), nil
		}
	}
	// Case 2: Partial match
	for _, item := range candidates {
		if strings.Contains(strings.ToLower(item.Name), key) {
			logger.Debug.Printf("Partial match found for secret lookup")
			return extractSecret(item), nil
		}
	}

	return "", fmt.Errorf("secret not found")
}

// ClearCache triggers a fresh vault sync.
func (c *Client) ClearCache() {
	if err := c.syncVault(); err != nil {
		logger.Error.Printf("Cache refresh sync failed: %v", err)
	}
}

// Stop stops the background sync goroutine.
func (c *Client) Stop() {
	close(c.stopSync)
}

// NameMaps returns a copy of decrypted organization, folder, and collection names
// from the last successful vault sync.
func (c *Client) NameMaps() SyncNameMaps {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return SyncNameMaps{
		Organizations: maps.Clone(c.nameMaps.Organizations),
		Folders:       maps.Clone(c.nameMaps.Folders),
		Collections:   maps.Clone(c.nameMaps.Collections),
	}
}

// syncVault fetches and decrypts all items from the vault.
func (c *Client) syncVault() error {
	items, nameMaps, err := c.api.Sync()
	if err != nil {
		return err
	}

	newItems := make(map[string]DecryptedItem, len(items))
	for _, item := range items {
		if item.ID == "" {
			continue
		}
		newItems[item.ID] = item
	}

	c.mu.Lock()
	c.items = newItems
	c.nameMaps = nameMaps
	c.mu.Unlock()

	return nil
}

// backgroundSync periodically syncs the vault to pick up changes.
func (c *Client) backgroundSync() {
	ticker := time.NewTicker(c.syncEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := c.syncVault(); err != nil {
				logger.Warn.Printf("Background sync failed: %v", err)
			} else {
				logger.Debug.Println("Background vault sync completed")
			}
		case <-c.stopSync:
			logger.Info.Println("Background sync stopped")
			return
		}
	}
}

// extractSecret extracts the most relevant secret value from a decrypted item.
// Priority: password > field named "value"/"secret"/"api_key" > notes > first field.
func extractSecret(item DecryptedItem) string {
	if item.Password != "" {
		return item.Password
	}

	// Check custom fields by priority.
	for _, name := range []string{"value", "secret", "api_key", "apikey", "token"} {
		if v, ok := item.Fields[name]; ok && v != "" {
			return v
		}
	}

	if item.Notes != "" {
		return item.Notes
	}

	// Return first non-empty field value.
	for _, v := range item.Fields {
		if v != "" {
			return v
		}
	}

	return ""
}
