package main

import (
	"net/http/httptest"
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
			req := httptest.NewRequest("GET", tt.path, nil)
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
	got := getTrustedProxies()
	for _, want := range []string{"127.0.0.1", "::1"} {
		found := false
		for _, entry := range got {
			if entry == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("getTrustedProxies() = %v, missing %s", got, want)
		}
	}
}

func TestGetTrustedProxiesRejectsInvalidEntries(t *testing.T) {
	t.Setenv("TRUSTED_PROXY_IP", "172.18.0.2, bogus, 10.0.0.0/8, , 127.0.0.1, 10.0.0.0/99")

	got := getTrustedProxies()
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
