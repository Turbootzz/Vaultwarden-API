package auth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

const (
	keyFull   = "full-access-key-0000000000000000000000"
	keyScoped = "scoped-key-1111111111111111111111111111"
)

func testStore() *Store {
	return NewStore([]APIKey{
		{Name: "full", Key: keyFull},
		{Name: "dev", Key: keyScoped, Scope: Scope{Collections: []string{"Secrets - DEV"}}},
	})
}

func TestStoreMatch(t *testing.T) {
	t.Parallel()

	store := testStore()

	tests := []struct {
		name      string
		provided  string
		wantOK    bool
		wantName  string
		wantScope Scope
	}{
		{"full access key", keyFull, true, "full", Scope{}},
		{"scoped key", keyScoped, true, "dev", Scope{Collections: []string{"Secrets - DEV"}}},
		{"unknown key", "nope-nope-nope-nope-nope-nope-nope-nope", false, "", Scope{}},
		{"empty provided", "", false, "", Scope{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := store.Match(tt.provided)
			if ok != tt.wantOK {
				t.Fatalf("Match ok = %v, want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if got.Name != tt.wantName {
				t.Errorf("Match name = %q, want %q", got.Name, tt.wantName)
			}
			if !reflect.DeepEqual(got.Scope, tt.wantScope) {
				t.Errorf("Match scope = %+v, want %+v", got.Scope, tt.wantScope)
			}
		})
	}
}

func TestStoreMatchEmptyStore(t *testing.T) {
	t.Parallel()
	if _, ok := NewStore(nil).Match(keyFull); ok {
		t.Error("empty store should not match any key")
	}
}

func TestScopeIsEmpty(t *testing.T) {
	t.Parallel()
	if !(Scope{}).IsEmpty() {
		t.Error("zero scope should be empty")
	}
	if (Scope{Organizations: []string{"x"}}).IsEmpty() {
		t.Error("scope with organizations should not be empty")
	}
	if (Scope{Collections: []string{"x"}}).IsEmpty() {
		t.Error("scope with collections should not be empty")
	}
}

func TestMiddleware(t *testing.T) {
	t.Parallel()

	app := fiber.New()
	app.Use(Middleware(testStore()))
	app.Get("/", func(c *fiber.Ctx) error {
		scope, ok := ScopeFromCtx(c)
		if !ok {
			return c.Status(fiber.StatusInternalServerError).SendString("no scope")
		}
		if scope.IsEmpty() {
			return c.SendString("full")
		}
		return c.SendString("scoped")
	})

	tests := []struct {
		name       string
		header     string
		wantStatus int
		wantBody   string
	}{
		{"missing header", "", http.StatusUnauthorized, "missing authorization header"},
		{"malformed header", "Token abc", http.StatusUnauthorized, "invalid authorization header format"},
		{"unknown key", "Bearer wrong-key", http.StatusUnauthorized, "invalid api key"},
		{"full access key", "Bearer " + keyFull, http.StatusOK, "full"},
		{"scoped key", "Bearer " + keyScoped, http.StatusOK, "scoped"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/", nil)
			if tt.header != "" {
				req.Header.Set("Authorization", tt.header)
			}
			resp, err := app.Test(req, -1)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tt.wantStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.wantStatus)
			}
			body, _ := io.ReadAll(resp.Body)
			if !strings.Contains(string(body), tt.wantBody) {
				t.Errorf("body = %q, want substring %q", body, tt.wantBody)
			}
		})
	}
}

func TestScopeFromCtxAbsent(t *testing.T) {
	t.Parallel()
	app := fiber.New()
	ctx := app.AcquireCtx(&fasthttp.RequestCtx{})
	defer app.ReleaseCtx(ctx)
	if _, ok := ScopeFromCtx(ctx); ok {
		t.Error("ScopeFromCtx should report false when no scope set")
	}
}
