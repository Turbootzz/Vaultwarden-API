// Package auth provides API key authentication middleware
package auth

import (
	"crypto/subtle"
	"strings"

	"github.com/Turbootzz/vaultwarden-api/pkg/logger"
	"github.com/gofiber/fiber/v2"
)

// Scope limits which secrets a key may read, enforced server-side.
// Entries may be organization/collection names or UUIDs (resolved per-request).
// An empty scope (no organizations and no collections) grants full access.
type Scope struct {
	Organizations []string
	Collections   []string
}

// IsEmpty reports whether the scope imposes no constraint (full access).
func (s Scope) IsEmpty() bool {
	return len(s.Organizations) == 0 && len(s.Collections) == 0
}

// APIKey is a single configured key with its server-side scope.
type APIKey struct {
	Name  string
	Key   string
	Scope Scope
}

// Store holds the configured API keys and resolves a presented key to its scope.
type Store struct {
	keys []APIKey
}

// NewStore builds a key store from the configured keys.
func NewStore(keys []APIKey) *Store {
	return &Store{keys: keys}
}

// Match returns the configured key matching the presented secret, if any.
// It compares against every key without short-circuiting so that timing does
// not reveal a key's position in the list.
func (s *Store) Match(provided string) (APIKey, bool) {
	var matched APIKey
	found := false
	for _, k := range s.keys {
		if secureCompare(provided, k.Key) {
			matched = k
			found = true
		}
	}
	return matched, found
}

// ctxKey is the unexported type for the scope stored in the request context.
type ctxKey struct{}

var scopeKey ctxKey

// ScopeFromCtx returns the authenticated key's scope from the request context.
func ScopeFromCtx(c *fiber.Ctx) (Scope, bool) {
	scope, ok := c.Locals(scopeKey).(Scope)
	return scope, ok
}

// Middleware creates an authentication middleware that validates the bearer
// API key against the store and attaches the matched key's scope to the context.
func Middleware(store *Store) fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Get the Authorization header
		authHeader := c.Get("Authorization")

		if authHeader == "" {
			logger.Warn.Println("Missing Authorization header")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "missing authorization header",
			})
		}

		// Expected format: "Bearer <API_KEY>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			logger.Warn.Println("Invalid Authorization header format")
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid authorization header format",
			})
		}

		providedKey := parts[1]

		key, ok := store.Match(providedKey)
		if !ok {
			logger.Warn.Printf("Invalid API key from IP: %s", c.IP())
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid api key",
			})
		}

		c.Locals(scopeKey, key.Scope)

		// Authentication successful
		return c.Next()
	}
}

// secureCompare performs a constant-time comparison of two strings
// This prevents timing attacks that could be used to guess the API key
func secureCompare(a, b string) bool {
	// If lengths differ, still perform comparison to maintain constant time
	// Use subtle.ConstantTimeCompare which returns 1 if equal, 0 otherwise
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
