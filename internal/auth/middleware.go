// Package auth provides API key authentication middleware
package auth

import (
	"crypto/subtle"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

// Middleware creates an authentication middleware for API key validation
func Middleware(apiKey string) fiber.Handler {
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

		// Use constant-time comparison to prevent timing attacks
		if !secureCompare(providedKey, apiKey) {
			logger.Warn.Printf("Invalid API key from IP: %s", c.IP())
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "invalid api key",
			})
		}

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
