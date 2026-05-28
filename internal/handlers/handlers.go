// Package handlers provides HTTP request handlers for the API.
package handlers

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Turbootzz/vaultwarden-api/internal/auth"
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

	// Enforce the authenticated key's scope server-side, regardless of query filters.
	if !h.applyKeyScope(c, &filter) {
		logger.Warn.Printf("Request denied by key scope from IP: %s", c.IP())
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

// resolveDim sets *out from either a friendly name (resolved via NameMaps) or a raw id.
// Name lookups use vaultwarden.LookupIDByName and return an error when the name is unknown.
// Id branch copies the value through without verifying it exists in the vault—only format
// validation (parseUUIDQuery) applies earlier. That asymmetry is intentional.
func resolveDim(dim, name, id string, nameMap map[string]string, out *string) error {
	switch {
	case name != "":
		resolved, ok := vaultwarden.LookupIDByName(nameMap, name)
		if !ok {
			return fmt.Errorf("unknown %s_name", dim)
		}
		*out = resolved
	case id != "":
		*out = id
	}
	return nil
}

// resolveRef resolves a scope reference that may be either a UUID or a friendly name.
// UUIDs pass through (existence not verified); names are looked up via NameMaps.
func resolveRef(nameMap map[string]string, ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", false
	}
	if parsed, err := uuid.Parse(ref); err == nil {
		return parsed.String(), true
	}
	return vaultwarden.LookupIDByName(nameMap, ref)
}

// resolveScopeRefs maps scope refs (UUIDs or names) to UUIDs, dropping any that
// don't resolve. The caller treats an all-unresolved dimension as deny (fail closed).
func resolveScopeRefs(refs []string, nameMap map[string]string) []string {
	out := make([]string, 0, len(refs))
	for _, ref := range refs {
		if id, ok := resolveRef(nameMap, ref); ok {
			out = append(out, id)
		}
	}
	return out
}

// applyKeyScope sets the server-side scope fields on the filter from the
// authenticated key's scope. It returns false to deny the request (404) when a
// constrained dimension resolves to nothing — including unknown names and the
// pre-first-sync window — so a scoped key can never read outside its scope.
func (h *Handler) applyKeyScope(c *fiber.Ctx, filter *vaultwarden.SecretFilter) bool {
	scope, ok := auth.ScopeFromCtx(c)
	if !ok {
		// No scope in context means the auth middleware did not run for this
		// request. Fail closed rather than silently granting full access.
		return false
	}
	if scope.IsEmpty() {
		return true // unscoped key: full access
	}

	nm := h.vaultClient.NameMaps()

	if len(scope.Organizations) > 0 {
		ids := resolveScopeRefs(scope.Organizations, nm.Organizations)
		if len(ids) == 0 {
			return false
		}
		filter.OrganizationIDs = ids
	}
	if len(scope.Collections) > 0 {
		ids := resolveScopeRefs(scope.Collections, nm.Collections)
		if len(ids) == 0 {
			return false
		}
		filter.CollectionIDs = ids
	}

	return true
}

// parseSecretFilters reads placement query params: at most one of id or name per dimension.
// Name-based filters are resolved against h.vaultClient.NameMaps(); unknown names fail.
// Id-based filters are accepted as-is after UUID parsing (existence is not checked here).
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

	if err := resolveDim("organization", orgName, orgID, nm.Organizations, &out.OrganizationID); err != nil {
		return out, err
	}
	if err := resolveDim("collection", colName, colID, nm.Collections, &out.CollectionID); err != nil {
		return out, err
	}
	if err := resolveDim("folder", folderName, folderID, nm.Folders, &out.FolderID); err != nil {
		return out, err
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
