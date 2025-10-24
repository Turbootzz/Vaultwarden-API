// Package handlers provides HTTP request handlers for the API
package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/thijsherman/vaultwarden-api/internal/validators"
	"github.com/thijsherman/vaultwarden-api/internal/vaultwarden"
	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

// Handler contains all HTTP handlers
type Handler struct {
	vaultClient *vaultwarden.Client
}

// NewHandler creates a new handler instance
func NewHandler(vaultClient *vaultwarden.Client) *Handler {
	return &Handler{
		vaultClient: vaultClient,
	}
}

// HealthCheck handles GET /health
func (h *Handler) HealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status": "ok",
		"service": "vaultwarden-api",
	})
}

// GetSecret handles GET /secret/:name
func (h *Handler) GetSecret(c *fiber.Ctx) error {
	secretName := c.Params("name")

	if secretName == "" {
		logger.Warn.Println("Secret name not provided")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "secret name is required",
		})
	}

	if !validators.IsValidSecretName(secretName) {
		logger.Warn.Printf("Invalid secret name attempted: %s", secretName)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid secret name format",
		})
	}

	value, err := h.vaultClient.GetSecret(secretName)
	if err != nil {
		logger.Error.Printf("Failed to fetch secret '%s': %v", secretName, err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "secret not found",
		})
	}

	// Return the secret value
	return c.JSON(fiber.Map{
		"name":  secretName,
		"value": value,
	})
}

// RefreshCache handles POST /refresh
func (h *Handler) RefreshCache(c *fiber.Ctx) error {
	h.vaultClient.ClearCache()

	logger.Info.Println("Cache refresh requested")
	return c.JSON(fiber.Map{
		"status":  "ok",
		"message": "cache cleared successfully",
	})
}
