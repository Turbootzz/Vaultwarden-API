// Package handlers provides HTTP request handlers for the API.
package handlers

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/Turbootzz/vaultwarden-api/internal/auth"
	"github.com/Turbootzz/vaultwarden-api/internal/realip"
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

// denyCaching marks a response as non-storable. Applied to every secret
// response, hits and misses alike, so an intermediary cannot retain a body that
// carries plaintext secrets (#32).
func denyCaching(c *fiber.Ctx) {
	c.Set(fiber.HeaderCacheControl, "no-store, no-cache, must-revalidate, private")
	c.Set(fiber.HeaderPragma, "no-cache")
}

// GetSecret handles GET /secret/:name.
func (h *Handler) GetSecret(c *fiber.Ctx) error {
	denyCaching(c)

	secretName, err := decodeSecretPathParam(c.Params("name"))
	if err != nil {
		logger.Warn.Printf("Invalid secret path encoding from IP: %s", realip.FromCtx(c))
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
		logger.Warn.Printf("Invalid secret name format attempted from IP: %s", realip.FromCtx(c))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "invalid secret name format",
		})
	}

	filter, err := h.parseSecretFilters(c)
	if err != nil {
		// Don't leak information about existence of correct filters
		// Security through obscurity ;)
		logger.Warn.Printf("Invalid secret filters attempted from IP: %s - %v", realip.FromCtx(c), err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "secret not found",
		})
	}

	// Enforce the authenticated key's scope server-side, regardless of query filters.
	if denial, ok := h.applyKeyScope(c, &filter); !ok {
		logger.Warn.Printf("Secret lookup denied for %q (%s, IP %s): %s",
			secretName, describeKey(c), realip.FromCtx(c), denial)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "secret not found",
		})
	}

	value, err := h.vaultClient.GetSecret(secretName, filter)
	if err != nil {
		logSecretLookupFailure(c, secretName, err)
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "secret not found",
		})
	}

	return c.JSON(fiber.Map{
		"name":  secretName,
		"value": value,
	})
}

// logSecretLookupFailure records why a lookup missed, for the operator only.
//
// The response tells a caller nothing beyond "not found": letting a scoped key
// tell "no such secret" apart from "exists but not yours" is precisely how it
// would enumerate the vault a name at a time. The server's own log has no such
// constraint and is where the answer belongs. Secret *names* appear here, as
// they already do in request-path logs; values never do, at any level.
//
// Note this write is synchronous and precedes the response, and its length
// varies by cause. See SecretLookupError: the uniform body is a defence against
// enumeration, not a constant-time guarantee.
//
// Warn, not Error: a caller asking for a secret that is not there is ordinary
// 404 traffic, and logging it at Error buries real faults under one
// misconfigured client's retry loop. An error of any other type is a genuine
// fault and keeps Error — that branch is also what stops a future non-lookup
// error from reaching Diagnosis() on a nil pointer.
func logSecretLookupFailure(c *fiber.Ctx, secretName string, err error) {
	var lookupErr *vaultwarden.SecretLookupError
	if errors.As(err, &lookupErr) {
		logger.Warn.Printf("Secret lookup failed for %q (%s, IP %s): %s",
			secretName, describeKey(c), realip.FromCtx(c), lookupErr.Diagnosis())
		return
	}
	logger.Error.Printf("Secret lookup failed for %q (%s, IP %s): %v",
		secretName, describeKey(c), realip.FromCtx(c), err)
}

// describeKey names the calling key for a log line. An unauthenticated request
// is called out rather than blended in with a key that has no configured name:
// the first means a secret route is reachable without auth, which is a routing
// fault, not a config one.
func describeKey(c *fiber.Ctx) string {
	name, ok := auth.KeyNameFromCtx(c)
	if !ok {
		return "UNAUTHENTICATED REQUEST — no auth middleware on this route"
	}
	return fmt.Sprintf("key %q", name)
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

// scopeDenialKind classifies why a request was refused before any lookup ran.
type scopeDenialKind int

const (
	scopeAllowed scopeDenialKind = iota
	// scopeNoAuthContext means the auth middleware did not run for this route.
	scopeNoAuthContext
	// scopeOrgsUnresolved / scopeCollectionsUnresolved mean every ref the key
	// names failed to match the last sync.
	scopeOrgsUnresolved
	scopeCollectionsUnresolved
)

// scopeDenial is the reason a request was refused, kept as data rather than
// prose so the log site owns the wording and a future caller — a metric, a
// structured-log field, a test — does not have to substring-match English.
type scopeDenial struct {
	kind       scopeDenialKind
	configured int // refs the key names
	known      int // refs the vault knows after the last sync
}

func (d scopeDenial) String() string {
	switch d.kind {
	case scopeNoAuthContext:
		return "no scope on the request; the auth middleware did not run for this route, failing closed"
	case scopeOrgsUnresolved:
		return fmt.Sprintf(
			"none of this key's %d scoped organization(s) resolve against the %d known to the vault; check the key config for a typo or a rename",
			d.configured, d.known)
	case scopeCollectionsUnresolved:
		return fmt.Sprintf(
			"none of this key's %d scoped collection(s) resolve against the %d known to the vault; check the key config for a typo or a rename",
			d.configured, d.known)
	default:
		return "allowed"
	}
}

// applyKeyScope sets the server-side scope fields on the filter from the
// authenticated key's scope, so a scoped key can never read outside its scope.
//
// It denies the request (404) when a constrained dimension resolves to nothing —
// including unknown names and the pre-first-sync window. The returned denial
// explains which, for the log only; it never reaches the response.
func (h *Handler) applyKeyScope(c *fiber.Ctx, filter *vaultwarden.SecretFilter) (scopeDenial, bool) {
	scope, ok := auth.ScopeFromCtx(c)
	if !ok {
		// No scope in context means the auth middleware did not run for this
		// request. Fail closed rather than silently granting full access.
		return scopeDenial{kind: scopeNoAuthContext}, false
	}
	if scope.IsEmpty() {
		return scopeDenial{}, true // unscoped key: full access
	}

	nm := h.vaultClient.NameMaps()

	if len(scope.Organizations) > 0 {
		ids := resolveScopeRefs(scope.Organizations, nm.Organizations)
		if len(ids) == 0 {
			// Names are matched against the last sync, so this is either a typo
			// in the key config or an org that has been renamed since.
			return scopeDenial{
				kind:       scopeOrgsUnresolved,
				configured: len(scope.Organizations),
				known:      len(nm.Organizations),
			}, false
		}
		filter.OrganizationIDs = ids
	}
	if len(scope.Collections) > 0 {
		ids := resolveScopeRefs(scope.Collections, nm.Collections)
		if len(ids) == 0 {
			return scopeDenial{
				kind:       scopeCollectionsUnresolved,
				configured: len(scope.Collections),
				known:      len(nm.Collections),
			}, false
		}
		filter.CollectionIDs = ids
	}

	return scopeDenial{}, true
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
