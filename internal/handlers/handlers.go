// Package handlers provides HTTP request handlers for the API.
package handlers

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Turbootzz/vaultwarden-api/internal/validators"
	"github.com/Turbootzz/vaultwarden-api/internal/vaultwarden"
	"github.com/Turbootzz/vaultwarden-api/pkg/logger"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// Handler contains all HTTP handlers.
type Handler struct {
	vaultClient *vaultwarden.Client
}

// NewHandler creates a new handler instance.
func NewHandler(vaultClient *vaultwarden.Client) *Handler {
	return &Handler{
		vaultClient: vaultClient,
	}
}

// HealthCheck handles GET /health.
func (h *Handler) HealthCheck(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"status":  "ok",
		"service": "vaultwarden-api",
	})
}

// decodeSecretPathParam unescapes the name of the secret from the URL path.
// Mainly used to handle space decodings. Repeats until stable to handle
// typical double-encoded values (e.g. %2520). Fails if recursive encoding
// is detected.
func decodeSecretPathParam(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	const maxPasses = 4
	for range maxPasses {
		dec, err := url.PathUnescape(s)
		if err != nil {
			return "", err
		}
		if dec == s {
			return dec, nil
		}
		s = dec
	}
	return "", errors.New("path encoding depth exceeded")
}

// GetSecret handles GET /secret/:name.
func (h *Handler) GetSecret(c *fiber.Ctx) error {
	secretName, err := decodeSecretPathParam(c.Params("name"))
	if err != nil {
		logger.Warn.Printf("Invalid secret path encoding from IP: %s", c.IP())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid secret name format",
		})
	}

	if secretName == "" {
		logger.Warn.Println("Secret name not provided")
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "secret name is required",
		})
	}

	if !validators.IsValidSecretName(secretName) {
		logger.Warn.Printf("Invalid secret name format attempted from IP: %s", c.IP())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid secret name format",
		})
	}

	filter, err := h.parseSecretFilters(c)
	if err != nil {
		// Don't leak information about existence of correct filters
		// Security through obscurity ;)
		logger.Warn.Printf("Invalid secret filters attempted from IP: %s - %v", c.IP(), err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "secret not found",
		})
	}

	value, err := h.vaultClient.GetSecret(secretName, filter)
	if err != nil {
		logger.Error.Printf("Failed to fetch secret (requested by IP: %s)", c.IP())
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "secret not found",
		})
	}

	return c.JSON(fiber.Map{
		"name":  secretName,
		"value": value,
	})
}

func parseUUIDQuery(field, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	parsed, err := uuid.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid %s: must be a UUID", field)
	}
	return parsed.String(), nil
}

// parseSecretFilters reads placement query params: at most one of id or name per dimension.
func (h *Handler) parseSecretFilters(c *fiber.Ctx) (vaultwarden.SecretFilter, error) {
	var out vaultwarden.SecretFilter

	orgID, err := parseUUIDQuery("organization_id", c.Query("organization_id"))
	if err != nil {
		return out, err
	}
	orgName := strings.TrimSpace(c.Query("organization_name"))

	colID, err := parseUUIDQuery("collection_id", c.Query("collection_id"))
	if err != nil {
		return out, err
	}
	colName := strings.TrimSpace(c.Query("collection_name"))

	folderID, err := parseUUIDQuery("folder_id", c.Query("folder_id"))
	if err != nil {
		return out, err
	}
	folderName := strings.TrimSpace(c.Query("folder_name"))

	if orgID != "" && orgName != "" {
		return out, fmt.Errorf("use only one of organization_id and organization_name")
	}
	if colID != "" && colName != "" {
		return out, fmt.Errorf("use only one of collection_id and collection_name")
	}
	if folderID != "" && folderName != "" {
		return out, fmt.Errorf("use only one of folder_id and folder_name")
	}

	if orgName != "" && !validators.IsValidFilterQueryValue(orgName) {
		return out, fmt.Errorf("invalid organization_name")
	}
	if colName != "" && !validators.IsValidFilterQueryValue(colName) {
		return out, fmt.Errorf("invalid collection_name")
	}
	if folderName != "" && !validators.IsValidFilterQueryValue(folderName) {
		return out, fmt.Errorf("invalid folder_name")
	}

	nm := h.vaultClient.NameMaps()

	switch {
	case orgName != "":
		id, ok := vaultwarden.LookupIDByName(nm.Organizations, orgName)
		if !ok {
			return out, fmt.Errorf("unknown organization_name")
		}
		out.OrganizationID = id
	case orgID != "":
		out.OrganizationID = orgID
	}

	switch {
	case colName != "":
		id, ok := vaultwarden.LookupIDByName(nm.Collections, colName)
		if !ok {
			return out, fmt.Errorf("unknown collection_name")
		}
		out.CollectionID = id
	case colID != "":
		out.CollectionID = colID
	}

	switch {
	case folderName != "":
		id, ok := vaultwarden.LookupIDByName(nm.Folders, folderName)
		if !ok {
			return out, fmt.Errorf("unknown folder_name")
		}
		out.FolderID = id
	case folderID != "":
		out.FolderID = folderID
	}

	return out, nil
}

// RefreshCache handles POST /refresh.
func (h *Handler) RefreshCache(c *fiber.Ctx) error {
	h.vaultClient.ClearCache()

	logger.Info.Println("Cache refresh requested")
	return c.JSON(fiber.Map{
		"status":  "ok",
		"message": "cache cleared successfully",
	})
}
