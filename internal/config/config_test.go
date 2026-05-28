package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const (
	key32a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 35 chars
	key32b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// clearKeyEnv removes all key-related env vars so each case starts clean.
func clearKeyEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{"API_KEY", "API_KEYS", "API_KEYS_FILE"} {
		t.Setenv(k, "")
	}
}

func TestLoadAPIKeys(t *testing.T) {
	t.Run("legacy single key is full access", func(t *testing.T) {
		clearKeyEnv(t)
		t.Setenv("API_KEY", key32a)

		keys, err := loadAPIKeys()
		if err != nil {
			t.Fatalf("loadAPIKeys: %v", err)
		}
		if len(keys) != 1 || keys[0].Key != key32a || !keys[0].Scope.IsEmpty() {
			t.Fatalf("unexpected keys: %+v", keys)
		}
	})

	t.Run("inline API_KEYS with scope", func(t *testing.T) {
		clearKeyEnv(t)
		t.Setenv("API_KEYS", `[{"name":"dev","key":"`+key32a+`","collections":["Secrets - DEV"]}]`)

		keys, err := loadAPIKeys()
		if err != nil {
			t.Fatalf("loadAPIKeys: %v", err)
		}
		if len(keys) != 1 {
			t.Fatalf("want 1 key, got %d", len(keys))
		}
		if keys[0].Name != "dev" || len(keys[0].Scope.Collections) != 1 {
			t.Errorf("unexpected key: %+v", keys[0])
		}
	})

	t.Run("API_KEYS_FILE preferred over inline and merged with legacy", func(t *testing.T) {
		clearKeyEnv(t)
		dir := t.TempDir()
		path := filepath.Join(dir, "keys.json")
		if err := os.WriteFile(path, []byte(`[{"name":"file","key":"`+key32b+`"}]`), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("API_KEYS_FILE", path)
		t.Setenv("API_KEYS", `[{"name":"ignored","key":"`+key32a+`"}]`)
		t.Setenv("API_KEY", key32a)

		keys, err := loadAPIKeys()
		if err != nil {
			t.Fatalf("loadAPIKeys: %v", err)
		}
		// File entry + legacy entry; inline API_KEYS is ignored when file is set.
		if len(keys) != 2 {
			t.Fatalf("want 2 keys (file + legacy), got %d: %+v", len(keys), keys)
		}
		if keys[0].Name != "file" || keys[1].Name != "legacy" {
			t.Errorf("unexpected key order/names: %+v", keys)
		}
	})

	t.Run("no keys configured", func(t *testing.T) {
		clearKeyEnv(t)
		if _, err := loadAPIKeys(); err == nil {
			t.Error("expected error when no keys configured")
		}
	})

	t.Run("short key rejected", func(t *testing.T) {
		clearKeyEnv(t)
		t.Setenv("API_KEY", "too-short")
		if _, err := loadAPIKeys(); err == nil {
			t.Error("expected error for short key")
		}
	})

	t.Run("malformed JSON rejected", func(t *testing.T) {
		clearKeyEnv(t)
		t.Setenv("API_KEYS", `not json`)
		if _, err := loadAPIKeys(); err == nil {
			t.Error("expected error for malformed JSON")
		}
	})

	t.Run("unknown field rejected", func(t *testing.T) {
		clearKeyEnv(t)
		// "collection" (singular) is a typo for "collections"; must fail loudly
		// rather than silently leaving the key unscoped (full access).
		t.Setenv("API_KEYS", `[{"name":"dev","key":"`+key32a+`","collection":["DEV"]}]`)
		if _, err := loadAPIKeys(); err == nil {
			t.Error("expected error for unknown JSON field")
		}
	})

	t.Run("entry missing key rejected", func(t *testing.T) {
		clearKeyEnv(t)
		t.Setenv("API_KEYS", `[{"name":"x"}]`)
		if _, err := loadAPIKeys(); err == nil {
			t.Error("expected error for entry without key")
		}
	})
}

func TestParseInt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in       string
		fallback int
		want     int
	}{
		{"50", 30, 50},
		{"", 30, 30},
		{"abc", 30, 30},
		{"0", 30, 30},
		{"-5", 30, 30},
	}
	for _, tt := range tests {
		if got := parseInt(tt.in, tt.fallback); got != tt.want {
			t.Errorf("parseInt(%q, %d) = %d, want %d", tt.in, tt.fallback, got, tt.want)
		}
	}
}

func TestLoadRateLimitDefaultsAndOverrides(t *testing.T) {
	clearKeyEnv(t)
	t.Setenv("API_KEY", key32a)
	t.Setenv("VAULTWARDEN_URL", "https://vault.example.com")

	t.Run("defaults", func(t *testing.T) {
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.RateLimitMax != 30 {
			t.Errorf("RateLimitMax = %d, want 30", cfg.RateLimitMax)
		}
		if cfg.RateLimitWindow != time.Minute {
			t.Errorf("RateLimitWindow = %v, want 1m", cfg.RateLimitWindow)
		}
	})

	t.Run("overrides", func(t *testing.T) {
		t.Setenv("RATE_LIMIT_MAX", "100")
		t.Setenv("RATE_LIMIT_WINDOW", "30s")
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.RateLimitMax != 100 {
			t.Errorf("RateLimitMax = %d, want 100", cfg.RateLimitMax)
		}
		if cfg.RateLimitWindow != 30*time.Second {
			t.Errorf("RateLimitWindow = %v, want 30s", cfg.RateLimitWindow)
		}
	})
}
