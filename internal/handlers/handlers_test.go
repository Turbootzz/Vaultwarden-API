package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Turbootzz/vaultwarden-api/internal/auth"
	"github.com/Turbootzz/vaultwarden-api/internal/vaultwarden"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// Global test constants. Also used in other test files
const (
	testOrgID      = "11111111-1111-4111-8111-111111111111"
	testColID      = "44444444-4444-4444-8444-444444444444"
	testFolderID   = "33333333-3333-4333-8333-333333333333"
	testOtherOrgID = "22222222-2222-4222-8222-222222222222"
)

func testNameMaps() vaultwarden.SyncNameMaps {
	return vaultwarden.SyncNameMaps{
		Organizations: map[string]string{testOrgID: "Acme"},
		Collections:   map[string]string{testColID: "Shared"},
		Folders:       map[string]string{testFolderID: "Work"},
	}
}

func testVaultItems() map[string]vaultwarden.DecryptedItem {
	return map[string]vaultwarden.DecryptedItem{
		"cipher-1": {
			ID:             "cipher-1",
			Name:           "db-password",
			Password:       "s3cret",
			OrganizationID: testOrgID,
			CollectionIDs:  []string{testColID},
			FolderID:       testFolderID,
		},
		"cipher-2": {
			ID:             "cipher-2",
			Name:           "other-password",
			Password:       "other-org",
			OrganizationID: testOtherOrgID,
		},
		"cipher-3": {
			ID:       "cipher-3",
			Name:     "my secret",
			Password: "partial",
		},
	}
}

func acquireTestCtx(t *testing.T, query string) (*fiber.App, *fiber.Ctx) {
	t.Helper()
	app := fiber.New()
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	ctx.Request().Header.SetMethod("GET")
	ctx.Request().URI().SetPath("/")
	if query != "" {
		ctx.Request().URI().SetQueryString(query)
	}
	t.Cleanup(func() { app.ReleaseCtx(ctx) })
	return app, ctx
}

func TestDecodeSecretPathParam(t *testing.T) {
	t.Parallel()

	// Test proper parsing of URL-encoded secret names
	// (mainly proper decoding of spaces)
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{"empty", "", "", false},
		{"plain", "my-secret", "my-secret", false},
		{"trim", "  spaced  ", "spaced", false},
		{"single encoded space", "hello%20world", "hello world", false},
		{"double encoded space", "hello%2520world", "hello world", false},
		{"invalid percent", "%ZZ", "", true},
		{"depth exceeded", "%252525252520", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := decodeSecretPathParam(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseUUIDQuery(t *testing.T) {
	t.Parallel()

	valid := "11111111-1111-4111-8111-111111111111"

	// Test proper parsing of UUID query values
	tests := []struct {
		name    string
		field   string
		raw     string
		want    string
		wantErr bool
	}{
		{"empty", "organization_id", "", "", false},
		{"trimmed valid", "organization_id", "  " + valid + "  ", valid, false},
		{"invalid", "collection_id", "not-a-uuid", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseUUIDQuery(tt.field, tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				if !strings.Contains(err.Error(), tt.field) {
					t.Errorf("error %v should mention field %q", err, tt.field)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSecretFilters(t *testing.T) {
	h := NewHandler(vaultwarden.NewClient(nil, 0, 0, vaultwarden.WithState(nil, testNameMaps())))

	// Test proper parsing of query arguments for secret filters
	tests := []struct {
		name    string
		query   string
		want    vaultwarden.SecretFilter
		wantErr string
	}{
		{"no filters", "", vaultwarden.SecretFilter{}, ""},
		{
			"organization id passthrough",
			"organization_id=" + testOrgID,
			vaultwarden.SecretFilter{OrganizationID: testOrgID},
			"",
		},
		{
			"organization name resolved",
			"organization_name=Acme",
			vaultwarden.SecretFilter{OrganizationID: testOrgID},
			"",
		},
		{
			"collection and folder by name",
			"collection_name=Shared&folder_name=Work",
			vaultwarden.SecretFilter{CollectionID: testColID, FolderID: testFolderID},
			"",
		},
		{
			"both org id and name",
			"organization_id=" + testOrgID + "&organization_name=Acme",
			vaultwarden.SecretFilter{},
			"use only one of organization_id and organization_name",
		},
		{
			"invalid organization uuid",
			"organization_id=bad",
			vaultwarden.SecretFilter{},
			"invalid organization_id",
		},
		{
			"unknown organization name",
			"organization_name=Missing",
			vaultwarden.SecretFilter{},
			"unknown organization_name",
		},
		{
			"invalid organization name chars",
			"organization_name=bad%0aname",
			vaultwarden.SecretFilter{},
			"invalid organization_name",
		},
		{
			"unknown id accepted",
			"folder_id=88888888-8888-4888-8888-888888888888",
			vaultwarden.SecretFilter{FolderID: "88888888-8888-4888-8888-888888888888"},
			"",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ctx := acquireTestCtx(t, tt.query)
			got, err := h.parseSecretFilters(ctx)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filter = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestGetSecret(t *testing.T) {
	const fullKey = "full-access-key-for-getsecret-test-000000"
	h := NewHandler(vaultwarden.NewClient(nil, 0, 0, vaultwarden.WithState(testVaultItems(), testNameMaps())))
	app := fiber.New()
	// Mirror production: auth runs first and attaches a (here unscoped) scope.
	app.Use(auth.Middleware(auth.NewStore([]auth.APIKey{{Name: "full", Key: fullKey}})))
	app.Get("/secret/:name", h.GetSecret)

	// Test the GetSecret handler with various input scenarios
	// Mainly tests that edge cases in GetSecret are handled properly
	tests := []struct {
		name       string
		path       string
		query      string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "invalid path encoding",
			path:       "/secret/%25ZZ",
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid secret name format",
		},
		{
			name:       "invalid secret name",
			path:       "/secret/..",
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid secret name format",
		},
		{
			name:       "whitespace only secret name",
			path:       "/secret/%20",
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid secret name format",
		},
		{
			name:       "invalid filter uuid",
			path:       "/secret/db-password",
			query:      "organization_id=not-a-uuid",
			wantStatus: http.StatusNotFound,
			wantBody:   "secret not found",
		},
		{
			name:       "unknown filter name",
			path:       "/secret/db-password",
			query:      "organization_name=Unknown",
			wantStatus: http.StatusNotFound,
			wantBody:   "secret not found",
		},
		{
			name:       "filtered out by folder",
			path:       "/secret/db-password",
			query:      "folder_id=88888888-8888-4888-8888-888888888888",
			wantStatus: http.StatusNotFound,
			wantBody:   "secret not found",
		},
		{
			name:       "secret not in vault",
			path:       "/secret/missing-item",
			wantStatus: http.StatusNotFound,
			wantBody:   "secret not found",
		},
		{
			name:       "success",
			path:       "/secret/db-password",
			wantStatus: http.StatusOK,
			wantBody:   "s3cret",
		},
		{
			name:       "success with encoded space in path",
			path:       "/secret/my%2520secret",
			wantStatus: http.StatusOK,
			wantBody:   "partial",
		},
		{
			name:       "success with organization filter",
			path:       "/secret/db-password",
			query:      "organization_name=Acme",
			wantStatus: http.StatusOK,
			wantBody:   "s3cret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := tt.path
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
			req.Header.Set("Authorization", "Bearer "+fullKey)
			resp, err := app.Test(req, -1)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			body, _ := io.ReadAll(resp.Body)
			if tt.wantStatus == http.StatusOK {
				var payload map[string]string
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("json: %v", err)
				}
				if payload["value"] != tt.wantBody {
					t.Errorf("value = %q, want %q", payload["value"], tt.wantBody)
				}
				return
			}
			if !strings.Contains(string(body), tt.wantBody) {
				t.Errorf("body = %s, want substring %q", body, tt.wantBody)
			}
		})
	}
}

// TestGetSecretFailsClosedWithoutAuth verifies that if the handler is reached
// without the auth middleware (no scope in context), it denies rather than
// granting full access.
func TestGetSecretFailsClosedWithoutAuth(t *testing.T) {
	h := NewHandler(vaultwarden.NewClient(nil, 0, 0, vaultwarden.WithState(testVaultItems(), testNameMaps())))
	app := fiber.New()
	app.Get("/secret/:name", h.GetSecret) // intentionally no auth.Middleware

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/secret/db-password", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want %d (fail closed)", resp.StatusCode, http.StatusNotFound)
	}
}

func TestGetSecretScoped(t *testing.T) {
	h := NewHandler(vaultwarden.NewClient(nil, 0, 0, vaultwarden.WithState(testVaultItems(), testNameMaps())))

	// Keys wired through the real auth middleware so scope flows via c.Locals.
	const (
		fullKey     = "full-access-0000000000000000000000000000"
		colKey      = "collection-scoped-11111111111111111111111"
		orgKey      = "org-scoped-2222222222222222222222222222222"
		badScopeKey = "bad-scope-33333333333333333333333333333333"
	)
	store := auth.NewStore([]auth.APIKey{
		{Name: "full", Key: fullKey},
		{Name: "dev", Key: colKey, Scope: auth.Scope{Collections: []string{"Shared"}}},
		{Name: "acme", Key: orgKey, Scope: auth.Scope{Organizations: []string{"Acme"}}},
		{Name: "broken", Key: badScopeKey, Scope: auth.Scope{Collections: []string{"Nonexistent"}}},
	})

	app := fiber.New()
	app.Use(auth.Middleware(store))
	app.Get("/secret/:name", h.GetSecret)

	tests := []struct {
		name       string
		key        string
		path       string
		query      string
		wantStatus int
		wantBody   string
	}{
		// db-password (cipher-1) lives in org "Acme" / collection "Shared".
		{"collection scope can read in-scope secret", colKey, "/secret/db-password", "", http.StatusOK, "s3cret"},
		// other-password (cipher-2) has no collection -> out of a collection scope.
		{"collection scope blocks out-of-scope secret", colKey, "/secret/other-password", "", http.StatusNotFound, "secret not found"},
		{"org scope can read in-scope secret", orgKey, "/secret/db-password", "", http.StatusOK, "s3cret"},
		// other-password is in a different org -> blocked server-side regardless of query.
		{"org scope blocks other org secret", orgKey, "/secret/other-password", "", http.StatusNotFound, "secret not found"},
		{"client filter cannot widen beyond org scope", orgKey, "/secret/other-password", "organization_id=" + testOtherOrgID, http.StatusNotFound, "secret not found"},
		// Unscoped (full-access) key sees everything.
		{"full access reads other org secret", fullKey, "/secret/other-password", "", http.StatusOK, "other-org"},
		// Scope referencing an unknown collection name fails closed.
		{"unresolvable scope fails closed", badScopeKey, "/secret/db-password", "", http.StatusNotFound, "secret not found"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := tt.path
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, url, nil)
			req.Header.Set("Authorization", "Bearer "+tt.key)
			resp, err := app.Test(req, -1)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}

			body, _ := io.ReadAll(resp.Body)
			if tt.wantStatus == http.StatusOK {
				var payload map[string]string
				if err := json.Unmarshal(body, &payload); err != nil {
					t.Fatalf("json: %v", err)
				}
				if payload["value"] != tt.wantBody {
					t.Errorf("value = %q, want %q", payload["value"], tt.wantBody)
				}
				return
			}
			if !strings.Contains(string(body), tt.wantBody) {
				t.Errorf("body = %s, want substring %q", body, tt.wantBody)
			}
		})
	}
}
