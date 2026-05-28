// Package config handles application configuration and validation
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Turbootzz/vaultwarden-api/internal/auth"
)

// Config holds all application configuration
type Config struct {
	// Server settings
	Port         string
	Environment  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// Security
	APIKeys              []auth.APIKey
	AllowedIPs           []string
	EnableGitHubIPRanges bool

	// Vaultwarden
	VaultwardenURL   string
	VaultwardenToken string

	// Performance
	CacheTTL           time.Duration
	CORSAllowedOrigins string

	// Rate limiting
	RateLimitMax    int
	RateLimitWindow time.Duration
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Port:        getEnv("API_PORT", "8080"),
		Environment: getEnv("ENVIRONMENT", "development"),

		VaultwardenURL:   os.Getenv("VAULTWARDEN_URL"),
		VaultwardenToken: os.Getenv("VAULTWARDEN_ACCESS_TOKEN"),

		ReadTimeout:        parseDuration(getEnv("READ_TIMEOUT", "10s")),
		WriteTimeout:       parseDuration(getEnv("WRITE_TIMEOUT", "10s")),
		CacheTTL:           parseDuration(getEnv("CACHE_TTL", "5m")),
		CORSAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000"),

		EnableGitHubIPRanges: getEnv("ENABLE_GITHUB_IP_RANGES", "false") == "true",

		RateLimitMax:    parseInt(getEnv("RATE_LIMIT_MAX", "30"), 30),
		RateLimitWindow: parseDuration(getEnv("RATE_LIMIT_WINDOW", "1m")),
	}

	// Load API keys from API_KEYS_FILE / API_KEYS / legacy API_KEY.
	apiKeys, err := loadAPIKeys()
	if err != nil {
		return nil, err
	}
	cfg.APIKeys = apiKeys

	// Parse allowed IPs
	if allowedIPsStr := os.Getenv("ALLOWED_IPS"); allowedIPsStr != "" {
		ips := strings.Split(allowedIPsStr, ",")
		for _, ip := range ips {
			trimmed := strings.TrimSpace(ip)
			if trimmed != "" {
				if err := validateIPOrCIDR(trimmed); err != nil {
					return nil, fmt.Errorf("invalid IP in ALLOWED_IPS (%s): %w", trimmed, err)
				}
				cfg.AllowedIPs = append(cfg.AllowedIPs, trimmed)
			}
		}
	}

	// Validate required fields
	if cfg.VaultwardenURL == "" {
		return nil, fmt.Errorf("VAULTWARDEN_URL is required")
	}

	// Validate and normalize URL
	parsedURL, err := url.Parse(cfg.VaultwardenURL)
	if err != nil {
		return nil, fmt.Errorf("invalid VAULTWARDEN_URL: %w", err)
	}
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return nil, fmt.Errorf("VAULTWARDEN_URL must use http or https scheme")
	}
	// Remove trailing slash for consistency
	cfg.VaultwardenURL = strings.TrimSuffix(cfg.VaultwardenURL, "/")

	return cfg, nil
}

// IsProd returns true if running in production
func (c *Config) IsProd() bool {
	return c.Environment == "production"
}

// getEnv gets an environment variable with a fallback default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseDuration parses a duration string with a fallback
func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 10 * time.Second
	}
	return d
}

// parseInt parses a positive integer with a fallback for empty/invalid/non-positive input.
func parseInt(s string, fallback int) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return fallback
	}
	return n
}

// apiKeyJSON is the on-disk/env JSON schema for a scoped API key.
type apiKeyJSON struct {
	Name          string   `json:"name"`
	Key           string   `json:"key"`
	Organizations []string `json:"organizations"`
	Collections   []string `json:"collections"`
}

// loadAPIKeys assembles the configured keys from API_KEYS_FILE (preferred) or
// API_KEYS (inline JSON), plus a legacy unscoped API_KEY if set. At least one
// key is required and each must be at least 32 characters.
func loadAPIKeys() ([]auth.APIKey, error) {
	var keys []auth.APIKey

	if path := os.Getenv("API_KEYS_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read API_KEYS_FILE: %w", err)
		}
		parsed, err := parseAPIKeysJSON(data, "API_KEYS_FILE")
		if err != nil {
			return nil, err
		}
		keys = append(keys, parsed...)
	} else if raw := os.Getenv("API_KEYS"); raw != "" {
		parsed, err := parseAPIKeysJSON([]byte(raw), "API_KEYS")
		if err != nil {
			return nil, err
		}
		keys = append(keys, parsed...)
	}

	// Legacy single key remains a full-access (unscoped) key.
	if legacy := os.Getenv("API_KEY"); legacy != "" {
		keys = append(keys, auth.APIKey{Name: "legacy", Key: legacy})
	}

	if len(keys) == 0 {
		return nil, fmt.Errorf("no API keys configured: set API_KEY, API_KEYS, or API_KEYS_FILE")
	}

	for i, k := range keys {
		if len(k.Key) < 32 {
			return nil, fmt.Errorf("API key #%d (%q) must be at least 32 characters for security (run: openssl rand -base64 32)", i+1, k.Name)
		}
	}

	return keys, nil
}

// parseAPIKeysJSON parses a JSON array of scoped API keys. Unknown fields are
// rejected so a misspelled scope field (e.g. "collection") fails loudly at
// startup instead of silently leaving the key unscoped (full access).
func parseAPIKeysJSON(data []byte, source string) ([]auth.APIKey, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()

	var entries []apiKeyJSON
	if err := dec.Decode(&entries); err != nil {
		return nil, fmt.Errorf("invalid JSON in %s: %w", source, err)
	}

	keys := make([]auth.APIKey, 0, len(entries))
	for i, e := range entries {
		if e.Key == "" {
			return nil, fmt.Errorf("%s entry #%d is missing \"key\"", source, i+1)
		}
		keys = append(keys, auth.APIKey{
			Name: e.Name,
			Key:  e.Key,
			Scope: auth.Scope{
				Organizations: e.Organizations,
				Collections:   e.Collections,
			},
		})
	}
	return keys, nil
}

// validateIPOrCIDR validates if a string is a valid IP address or CIDR range
func validateIPOrCIDR(s string) error {
	// Try parsing as CIDR first
	if _, _, err := net.ParseCIDR(s); err == nil {
		return nil
	}
	// Try parsing as IP address
	if net.ParseIP(s) != nil {
		return nil
	}
	return fmt.Errorf("not a valid IP address or CIDR range")
}
