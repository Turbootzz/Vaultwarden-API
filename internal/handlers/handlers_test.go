package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/Turbootzz/vaultwarden-api/internal/auth"
	"github.com/Turbootzz/vaultwarden-api/internal/logtest"
	"github.com/Turbootzz/vaultwarden-api/internal/vaultwarden"
	"github.com/Turbootzz/vaultwarden-api/pkg/logger"
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
	h := NewHandler(vaultwarden.NewClient(nil, 0, vaultwarden.WithState(nil, testNameMaps())))

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
	h := NewHandler(vaultwarden.NewClient(nil, 0, vaultwarden.WithState(testVaultItems(), testNameMaps())))
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
	h := NewHandler(vaultwarden.NewClient(nil, 0, vaultwarden.WithState(testVaultItems(), testNameMaps())))
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
	h := NewHandler(vaultwarden.NewClient(nil, 0, vaultwarden.WithState(testVaultItems(), testNameMaps())))

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

// Regression for #32: responses carrying a plaintext secret must never be
// storable by an intermediary, on hits and on misses alike.
func TestGetSecretSetsNoStoreHeaders(t *testing.T) {
	const fullKey = "full-access-key-for-cache-header-test-000"
	h := NewHandler(vaultwarden.NewClient(nil, 0, vaultwarden.WithState(testVaultItems(), testNameMaps())))
	app := fiber.New()
	app.Use(auth.Middleware(auth.NewStore([]auth.APIKey{{Name: "full", Key: fullKey}})))
	app.Get("/secret/:name", h.GetSecret)

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{"hit", "/secret/db-password", http.StatusOK},
		{"miss", "/secret/nope-does-not-exist", http.StatusNotFound},
		{"rejected name", "/secret/..", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil)
			req.Header.Set("Authorization", "Bearer "+fullKey)

			resp, err := app.Test(req, -1)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
				t.Errorf("Cache-Control = %q, want it to contain no-store", got)
			}
			if got := resp.Header.Get("Pragma"); got != "no-cache" {
				t.Errorf("Pragma = %q, want no-cache", got)
			}
		})
	}
}

// The whole point of the opaque 404: a scoped key must not be able to tell a
// secret it may not see apart from one that does not exist. If these two
// responses ever differ by a byte, the vault can be enumerated a name at a time.
func TestGetSecretResponseIsIdenticalForMissingAndHiddenSecrets(t *testing.T) {
	h := NewHandler(vaultwarden.NewClient(nil, 0, vaultwarden.WithState(testVaultItems(), testNameMaps())))

	const scopedKey = "collection-scoped-11111111111111111111111"
	store := auth.NewStore([]auth.APIKey{
		{Name: "dev", Key: scopedKey, Scope: auth.Scope{Collections: []string{"Shared"}}},
	})

	app := fiber.New()
	app.Use(auth.Middleware(store))
	app.Get("/secret/:name", h.GetSecret)

	// "other-password" exists but sits outside the key's collection scope;
	// "does-not-exist-anywhere" is absent from the vault entirely.
	get := func(name string) (int, string, http.Header) {
		t.Helper()
		req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/secret/"+name, nil)
		req.Header.Set("Authorization", "Bearer "+scopedKey)
		resp, err := app.Test(req, -1)
		if err != nil {
			t.Fatalf("app.Test: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		return resp.StatusCode, string(body), resp.Header
	}

	hiddenStatus, hiddenBody, hiddenHeader := get("other-password")
	missingStatus, missingBody, missingHeader := get("does-not-exist-anywhere")

	if hiddenStatus != http.StatusNotFound || missingStatus != http.StatusNotFound {
		t.Fatalf("status: hidden=%d missing=%d, want 404 for both", hiddenStatus, missingStatus)
	}
	if hiddenBody != missingBody {
		t.Errorf("response body discloses existence:\n  hidden  = %q\n  missing = %q", hiddenBody, missingBody)
	}
	for _, header := range []string{"Content-Length", "Content-Type", "Cache-Control"} {
		if hiddenHeader.Get(header) != missingHeader.Get(header) {
			t.Errorf("%s differs: hidden=%q missing=%q",
				header, hiddenHeader.Get(header), missingHeader.Get(header))
		}
	}
}

// The log is the other half of that trade: opaque to the client, specific to the
// operator. It must name the secret, the key and the reason — and never a value.
func TestGetSecretLogsWhyTheLookupFailed(t *testing.T) {
	items := testVaultItems()
	h := NewHandler(vaultwarden.NewClient(nil, 0, vaultwarden.WithState(items, testNameMaps())))

	const scopedKey = "collection-scoped-11111111111111111111111"
	store := auth.NewStore([]auth.APIKey{
		{Name: "hearth", Key: scopedKey, Scope: auth.Scope{Collections: []string{"Shared"}}},
	})

	app := fiber.New()
	app.Use(auth.Middleware(store))
	app.Get("/secret/:name", h.GetSecret)

	tests := []struct {
		name     string
		secret   string
		wantLog  []string
		wantMiss []string
	}{
		{
			name:    "hidden by scope",
			secret:  "other-password",
			wantLog: []string{`"other-password"`, `"hearth"`, "outside this key's scope"},
			// The value of the secret it could not see must not appear.
			wantMiss: []string{"other-org", scopedKey},
		},
		{
			name:     "absent from the vault",
			secret:   "does-not-exist-anywhere",
			wantLog:  []string{`"does-not-exist-anywhere"`, `"hearth"`, "no item by that name anywhere"},
			wantMiss: []string{scopedKey},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Both levels: a regression that moved the line to Error would
			// otherwise leak to the real stderr where the assertions below
			// cannot see it, and the test would still pass.
			bufs := logtest.Capture(t, logger.Warn, logger.Error)
			warnBuf, errBuf := bufs[0], bufs[1]

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/secret/"+tt.secret, nil)
			req.Header.Set("Authorization", "Bearer "+scopedKey)
			resp, err := app.Test(req, -1)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", resp.StatusCode)
			}
			if errBuf.String() != "" {
				t.Errorf("an ordinary lookup miss logged at Error: %q", errBuf.String())
			}

			line := warnBuf.String()
			for _, want := range tt.wantLog {
				if !strings.Contains(line, want) {
					t.Errorf("log %q does not mention %q", line, want)
				}
			}
			for _, unwanted := range tt.wantMiss {
				if strings.Contains(line, unwanted) {
					t.Errorf("log %q leaks %q", line, unwanted)
				}
			}
		})
	}
}

// An error type other than *SecretLookupError is a genuine server fault, not a
// caller asking for something absent: it keeps Error level, and must not be fed
// to Diagnosis() on a nil pointer.
func TestLogSecretLookupFailureLevels(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		wantWarn  string
		wantError string
	}{
		{
			name:     "lookup miss is a warning",
			err:      realLookupError(t),
			wantWarn: "no item by that name anywhere",
		},
		{
			name:      "any other error stays an error",
			err:       errors.New("vault client exploded"),
			wantError: "vault client exploded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bufs := logtest.Capture(t, logger.Warn, logger.Error)
			warnBuf, errBuf := bufs[0], bufs[1]

			_, ctx := acquireTestCtx(t, "")
			logSecretLookupFailure(ctx, "JWT_SECRET", tt.err)

			if tt.wantWarn != "" {
				if !strings.Contains(warnBuf.String(), tt.wantWarn) {
					t.Errorf("warn log = %q, want it to contain %q", warnBuf.String(), tt.wantWarn)
				}
				if errBuf.String() != "" {
					t.Errorf("a lookup miss also logged at Error: %q", errBuf.String())
				}
			}
			if tt.wantError != "" {
				if !strings.Contains(errBuf.String(), tt.wantError) {
					t.Errorf("error log = %q, want it to contain %q", errBuf.String(), tt.wantError)
				}
				if warnBuf.String() != "" {
					t.Errorf("a server fault also logged at Warn: %q", warnBuf.String())
				}
			}
		})
	}
}

// realLookupError produces a genuine *vaultwarden.SecretLookupError by asking a
// real client for a secret it does not hold. Building one by hand would need the
// diagnostic fields exported, which is exactly what keeps them out of a JSON
// response.
func realLookupError(t *testing.T) error {
	t.Helper()
	client := vaultwarden.NewClient(nil, 0, vaultwarden.WithState(testVaultItems(), testNameMaps()))
	_, err := client.GetSecret("no-such-secret-anywhere", vaultwarden.SecretFilter{})
	if err == nil {
		t.Fatal("GetSecret returned no error for an absent secret")
	}
	return err
}

// The denial wording is what an operator acts on, so pin each branch — including
// the unauthenticated one, which must read as a routing fault rather than a
// mis-scoped key.
func TestScopeDenialString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		denial scopeDenial
		want   string
	}{
		{
			name:   "no auth context",
			denial: scopeDenial{kind: scopeNoAuthContext},
			want:   "the auth middleware did not run",
		},
		{
			name:   "organizations unresolved",
			denial: scopeDenial{kind: scopeOrgsUnresolved, configured: 2, known: 3},
			want:   "none of this key's 2 scoped organization(s) resolve against the 3 known",
		},
		{
			name:   "collections unresolved",
			denial: scopeDenial{kind: scopeCollectionsUnresolved, configured: 1, known: 11},
			want:   "none of this key's 1 scoped collection(s) resolve against the 11 known",
		},
		{
			name:   "zero value is not a denial",
			denial: scopeDenial{},
			want:   "allowed",
		},
		{
			// Defensive: a kind added without a String case must not render as
			// "allowed" and read like a permitted request in the log.
			name:   "unknown kind is not reported as allowed",
			denial: scopeDenial{kind: scopeDenialKind(99)},
			want:   "denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.denial.String(); !strings.Contains(got, tt.want) {
				t.Errorf("String() = %q, want it to contain %q", got, tt.want)
			}
		})
	}
}

// A secret route reachable without the auth middleware must fail closed and say
// so distinctly — the operator is looking at a routing bug, not a scope typo.
func TestGetSecretWithoutAuthMiddlewareIsCalledOut(t *testing.T) {
	h := NewHandler(vaultwarden.NewClient(nil, 0, vaultwarden.WithState(testVaultItems(), testNameMaps())))

	bufs := logtest.Capture(t, logger.Warn, logger.Error)
	warnBuf := bufs[0]

	app := fiber.New() // deliberately no auth.Middleware
	app.Get("/secret/:name", h.GetSecret)

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/secret/db-password", nil)
	resp, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("app.Test: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 (fail closed)", resp.StatusCode)
	}
	line := warnBuf.String()
	if !strings.Contains(line, "UNAUTHENTICATED REQUEST") {
		t.Errorf("log %q does not flag the missing auth middleware", line)
	}
	if strings.Contains(line, "<unnamed>") {
		t.Errorf("log %q reads as a key without a name, hiding a routing fault", line)
	}
}
