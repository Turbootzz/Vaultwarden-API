// Package vaultwarden provides a production-ready client for retrieving secrets
// from Vaultwarden using native Go HTTP and crypto (no CLI dependency).
package vaultwarden

import (
	"context"
	"fmt"
	"maps"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Turbootzz/vaultwarden-api/pkg/logger"
)

// Client manages vault access, caching, and background sync.
type Client struct {
	api       *APIClient
	syncEvery time.Duration

	// strictMatch disables the substring fallback in GetSecret, so a name that
	// matches no vault item exactly is a 404 instead of a near miss.
	strictMatch bool

	// syncMu serializes whole sync cycles. Without it a POST /refresh and the
	// background tick race, and whichever fetch finishes last wins regardless of
	// which snapshot is newer — an older one can resurrect trashed or revoked
	// items. Lock order: syncMu before mu, never the reverse.
	syncMu sync.Mutex

	mu    sync.RWMutex
	items map[string]DecryptedItem // keyed by cipher id

	// nameMaps from the last successful sync (for resolving filter names to UUIDs).
	nameMaps SyncNameMaps

	// retained counts entries the last sync kept from the previous cache because
	// their cipher would not decrypt.
	retained int

	stopSync chan struct{}

	// ctx is cancelled by Stop so an in-flight vault request is abandoned at
	// shutdown instead of holding the process for the client timeout.
	ctx      context.Context
	cancel   context.CancelFunc
	stopOnce sync.Once
}

// ClientOption configures NewClient.
type ClientOption func(*Client)

// WithState preloads decrypted items and name maps (e.g. unit tests with api set to nil).
func WithState(items map[string]DecryptedItem, nameMaps SyncNameMaps) ClientOption {
	return func(c *Client) {
		if items != nil {
			c.items = items
		}
		c.nameMaps = nameMaps
	}
}

// WithStrictMatch requires an exact (case-insensitive) name match, disabling the
// substring fallback.
func WithStrictMatch(strict bool) ClientOption {
	return func(c *Client) {
		c.strictMatch = strict
	}
}

// NewClient creates a vault client. Pass WithState to preload cache data without calling Initialize.
func NewClient(api *APIClient, syncInterval time.Duration, opts ...ClientOption) *Client {
	ctx, cancel := context.WithCancel(context.Background())
	c := &Client{
		api:       api,
		syncEvery: syncInterval,
		items:     make(map[string]DecryptedItem),
		nameMaps:  emptySyncNameMaps(),
		stopSync:  make(chan struct{}),
		ctx:       ctx,
		cancel:    cancel,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Initialize authenticates and performs the initial vault sync.
func (c *Client) Initialize() error {
	if err := c.api.Authenticate(c.ctx); err != nil {
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
//
// The singular fields are client-supplied query filters (use at most one of id vs
// name per dimension, enforced at the HTTP layer). The plural fields are server-set
// from the authenticated key's scope and act as a hard boundary: a request must match
// both the client filter and the scope, so a client filter can only narrow within the
// scope, never widen beyond it. Empty plural slices impose no constraint.
type SecretFilter struct {
	OrganizationID string
	CollectionID   string
	FolderID       string

	OrganizationIDs []string
	CollectionIDs   []string
}

func containsFold(ids []string, target string) bool {
	for _, id := range ids {
		if strings.EqualFold(id, target) {
			return true
		}
	}
	return false
}

func intersectsFold(a, b []string) bool {
	for _, id := range a {
		if containsFold(b, id) {
			return true
		}
	}
	return false
}

func matchesSecretFilter(item DecryptedItem, f SecretFilter) bool {
	if f.OrganizationID != "" && !strings.EqualFold(item.OrganizationID, f.OrganizationID) {
		return false
	}
	if f.CollectionID != "" && !containsFold(item.CollectionIDs, f.CollectionID) {
		return false
	}
	if f.FolderID != "" && !strings.EqualFold(item.FolderID, f.FolderID) {
		return false
	}
	if len(f.OrganizationIDs) > 0 && !containsFold(f.OrganizationIDs, item.OrganizationID) {
		return false
	}
	if len(f.CollectionIDs) > 0 && !intersectsFold(item.CollectionIDs, f.CollectionIDs) {
		return false
	}
	return true
}

// selectMatch returns the first item satisfying pred, scanning in the order
// given. It warns when several items match, since the loser is a secret the
// caller asked for and did not get.
func selectMatch(candidates []DecryptedItem, kind string, pred func(DecryptedItem) bool) (DecryptedItem, bool) {
	var chosen DecryptedItem
	found := 0
	for _, item := range candidates {
		if !pred(item) {
			continue
		}
		found++
		if found == 1 {
			chosen = item
		}
	}
	if found == 0 {
		return DecryptedItem{}, false
	}
	if found > 1 {
		logger.Warn.Printf(
			"Ambiguous secret lookup: %d items %s-match the request; returning cipher %s. Narrow it with an organization/collection/folder filter",
			found, kind, chosen.ID)
	}
	return chosen, true
}

// GetSecret retrieves a decrypted secret by name.
// It searches by exact name (case-insensitive), then falls back to partial match
// unless strict matching is enabled.
//
// Candidates are sorted by cipher id so that repeating a request returns the
// same secret: ranging over the item map directly made the winner depend on Go's
// randomized map iteration order (#30).
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
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })

	// Case 1: Exact match.
	if item, ok := selectMatch(candidates, "exactly", func(item DecryptedItem) bool {
		return strings.EqualFold(item.Name, name)
	}); ok {
		return extractSecret(item), nil
	}

	// Case 2: Partial match, opt-out via strict matching.
	if c.strictMatch {
		return "", fmt.Errorf("secret not found")
	}
	if item, ok := selectMatch(candidates, "partially", func(item DecryptedItem) bool {
		return strings.Contains(strings.ToLower(item.Name), key)
	}); ok {
		logger.Debug.Printf("Partial match found for secret lookup")
		return extractSecret(item), nil
	}

	return "", fmt.Errorf("secret not found")
}

// ClearCache triggers a fresh vault sync.
func (c *Client) ClearCache() {
	if err := c.syncVault(); err != nil {
		logger.Error.Printf("Cache refresh sync failed: %v", err)
	}
}

// Stop stops the background sync goroutine and cancels any in-flight request.
// Safe to call more than once.
func (c *Client) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopSync)
		c.cancel()
	})
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

// retainFailedCiphers carries cached entries for ciphers that failed to decrypt into newItems and
// returns how many were retained. Callers must hold c.mu; old is the cache being replaced.
func retainFailedCiphers(newItems, old map[string]DecryptedItem, failed []FailedCipher) int {
	retained := 0
	for _, f := range failed {
		if _, ok := newItems[f.ID]; ok {
			continue
		}
		if item, ok := old[f.ID]; ok {
			// Placement is plaintext in the payload, so scope checks use current values, not the cached ones.
			item.OrganizationID = f.OrganizationID
			item.CollectionIDs = f.CollectionIDs
			item.FolderID = f.FolderID
			newItems[f.ID] = item
			retained++
		}
	}
	return retained
}

// syncVault fetches and decrypts all items from the vault. The whole cycle is
// serialized so a slower concurrent sync cannot publish a staler snapshot last.
func (c *Client) syncVault() error {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()

	items, nameMaps, failed, err := c.api.Sync(c.ctx)
	if err != nil {
		// A non-empty failure list means the payload was authentic but nothing decrypted (#25):
		// reconcile placement and drop removed items, instead of serving stale scopes for the whole
		// outage. Transport and auth errors report no failures and must leave the cache alone.
		if len(failed) == 0 {
			return err
		}
		newItems := make(map[string]DecryptedItem, len(failed))
		c.mu.Lock()
		retained := retainFailedCiphers(newItems, c.items, failed)
		c.items = newItems
		c.retained = retained
		c.mu.Unlock()

		logger.Warn.Printf(
			"Sync decrypted no ciphers; %d of %d cached entries kept with refreshed placement, name maps unchanged",
			retained, len(failed))
		return err
	}

	newItems := make(map[string]DecryptedItem, len(items))
	for _, item := range items {
		if item.ID == "" {
			continue
		}
		newItems[item.ID] = item
	}

	// Only ciphers the sync reported as decrypt failures are carried over (#25): a stale entry
	// beats a 404, while genuinely deleted and trashed items leave the payload and are dropped.
	c.mu.Lock()
	retained := retainFailedCiphers(newItems, c.items, failed)
	c.items = newItems
	c.nameMaps = nameMaps
	c.retained = retained
	c.mu.Unlock()

	if len(failed) > 0 {
		logger.Warn.Printf(
			"Sync completed with %d cipher(s) that failed to decrypt; %d served stale from the previous cache",
			len(failed), retained)
	}

	return nil
}

// retainedCount reports how many entries the last sync served from the previous
// cache because their cipher would not decrypt.
func (c *Client) retainedCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.retained
}

// syncFailureEscalationThreshold is the consecutive background-sync failure count at which the log escalates to error.
const syncFailureEscalationThreshold = 3

// shouldEscalateSyncFailure reports whether consecutive sync failures have reached the escalation threshold.
func shouldEscalateSyncFailure(consecutiveFailures int) bool {
	return consecutiveFailures >= syncFailureEscalationThreshold
}

// backgroundSync periodically syncs the vault to pick up changes.
func (c *Client) backgroundSync() {
	ticker := time.NewTicker(c.syncEvery)
	defer ticker.Stop()

	consecutiveFailures := 0
	consecutivePartial := 0
	for {
		select {
		case <-ticker.C:
			if err := c.syncVault(); err != nil {
				consecutiveFailures++
				if shouldEscalateSyncFailure(consecutiveFailures) {
					logger.Error.Printf("Background sync failed %d times in a row, cache is stale: %v", consecutiveFailures, err)
				} else {
					logger.Warn.Printf("Background sync failed: %v", err)
				}
			} else {
				consecutiveFailures = 0
				// A sync that decrypted something still succeeds even when some
				// ciphers failed, so the counter above never sees a vault that is
				// permanently half-readable — say after this account lost access to
				// a collection. Those are tracked separately so the condition still
				// escalates out of Warn instead of repeating forever (#28).
				if n := c.retainedCount(); n > 0 {
					consecutivePartial++
					if shouldEscalateSyncFailure(consecutivePartial) {
						logger.Error.Printf(
							"Background sync has served %d cipher(s) from a stale cache for %d syncs in a row; they may no longer be readable by this account",
							n, consecutivePartial)
					}
				} else {
					consecutivePartial = 0
				}
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

	// Return first non-empty field value, by field name, so that an item with
	// several custom fields resolves to the same one on every request.
	names := make([]string, 0, len(item.Fields))
	for name := range item.Fields {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if v := item.Fields[name]; v != "" {
			return v
		}
	}

	return ""
}
