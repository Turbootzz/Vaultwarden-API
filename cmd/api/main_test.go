package main

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
)

func TestIsSecretPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path string
		want bool
	}{
		{"/secret/db", true},
		{"/Secret/db", true},
		{"/SECRET/db", true},
		{"/sEcReT/db", true},
		{"/secret/", true},
		{"/health", false},
		{"/refresh", false},
		{"/secrets/db", false},
		{"/", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := isSecretPath(tt.path); got != tt.want {
			t.Errorf("isSecretPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

// Regression for the #32 fix: fiber routes case-insensitively by default, so a
// case-sensitive skip predicate would leave /SECRET/db compressed while still
// serving the secret.
func TestSecretResponsesAreNotCompressed(t *testing.T) {
	t.Parallel()

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
		Next:  func(c *fiber.Ctx) bool { return isSecretPath(c.Path()) },
	}))
	// Long enough that compression is worth applying.
	body := strings.Repeat("secret-value-", 200)
	app.Get("/secret/:name", func(c *fiber.Ctx) error { return c.SendString(body) })
	app.Get("/health", func(c *fiber.Ctx) error { return c.SendString(body) })

	tests := []struct {
		name           string
		path           string
		wantCompressed bool
	}{
		{"lowercase secret", "/secret/db", false},
		{"capitalised secret", "/Secret/db", false},
		{"uppercase secret", "/SECRET/db", false},
		{"non-secret route still compresses", "/health", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, nil)
			req.Header.Set("Accept-Encoding", "gzip")

			resp, err := app.Test(req, -1)
			if err != nil {
				t.Fatalf("app.Test: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != fiber.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			gotCompressed := resp.Header.Get("Content-Encoding") != ""
			if gotCompressed != tt.wantCompressed {
				t.Errorf("Content-Encoding = %q, compressed=%v, want compressed=%v",
					resp.Header.Get("Content-Encoding"), gotCompressed, tt.wantCompressed)
			}
		})
	}
}

func TestGetTrustedProxiesAlwaysIncludesLoopback(t *testing.T) {
	clearProxyEnv(t)

	got, _, err := getTrustedProxies()
	if err != nil {
		t.Fatalf("getTrustedProxies: %v", err)
	}
	for _, want := range []string{"127.0.0.1", "::1"} {
		if !slices.Contains(got, want) {
			t.Errorf("getTrustedProxies() = %v, missing %s", got, want)
		}
	}
}

func TestGetTrustedProxiesRejectsInvalidEntries(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("TRUSTED_PROXY_IP", "172.18.0.2, bogus, 10.0.0.0/8, , 127.0.0.1, 10.0.0.0/99")

	got, _, err := getTrustedProxies()
	if err != nil {
		t.Fatalf("getTrustedProxies: %v", err)
	}
	want := []string{"127.0.0.1", "::1", "172.18.0.2", "10.0.0.0/8"}
	if len(got) != len(want) {
		t.Fatalf("getTrustedProxies() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("getTrustedProxies()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// The tests below assert exact results, so they must not inherit whatever the
// developer or CI runner happens to export — .env.example now tells operators to
// set TRUSTED_PROXY_PRESET, which would otherwise add 22 ranges to the result.
func clearProxyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TRUSTED_PROXY_IP", "")
	t.Setenv("TRUSTED_PROXY_PRESET", "")
}

// Issue #40: a CDN edge is a hop that must be trusted, and hand-maintaining a
// provider's range list is what operators get wrong. The preset expands to it.
func TestGetTrustedProxiesExpandsPresets(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_PRESET", " CloudFlare , ")
	t.Setenv("TRUSTED_PROXY_IP", "172.18.0.2")

	got, providers, err := getTrustedProxies()
	if err != nil {
		t.Fatalf("getTrustedProxies: %v", err)
	}
	for _, want := range []string{"127.0.0.1", "::1", "172.18.0.2", "172.64.0.0/13", "2606:4700::/32"} {
		if !slices.Contains(got, want) {
			t.Errorf("getTrustedProxies() = %v, missing %s", got, want)
		}
	}
	// The provider must also come back, or the resolver trusts the edge ranges
	// without the header that keeps the result unspoofable.
	if len(providers) != 1 || providers[0].ClientIPHeader != "CF-Connecting-IP" {
		t.Errorf("providers = %+v, want one cloudflare provider carrying CF-Connecting-IP", providers)
	}
}

// A misspelled preset must not start the server: the operator reached for it
// because requests were already being denied, and silently ignoring it leaves
// exactly that failure in place with no new signal.
func TestGetTrustedProxiesRejectsUnknownPreset(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_PRESET", "cloudfare")

	if _, _, err := getTrustedProxies(); err == nil {
		t.Fatal("getTrustedProxies() = nil error for an unknown preset, want an error")
	}
}

// An operator who names the preset twice, or lists one of its ranges in
// TRUSTED_PROXY_IP as well, must not end up with the entry twice in the set
// handed to fiber. 172.64.0.0/13 below is deliberately one of the preset's own.
func TestGetTrustedProxiesDeduplicatesPresetEntries(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_PRESET", "cloudflare,cloudflare")
	t.Setenv("TRUSTED_PROXY_IP", "172.64.0.0/13")

	got, _, err := getTrustedProxies()
	if err != nil {
		t.Fatalf("getTrustedProxies: %v", err)
	}
	seen := 0
	for _, entry := range got {
		if entry == "172.64.0.0/13" {
			seen++
		}
	}
	if seen != 1 {
		t.Errorf("getTrustedProxies() lists 172.64.0.0/13 %d times, want 1", seen)
	}
}
