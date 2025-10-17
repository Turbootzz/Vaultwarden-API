package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Server settings
	Port         string
	Environment  string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration

	// Security
	APIKey string

	// Vaultwarden settings
	VaultwardenURL   string
	VaultwardenToken string

	// Cache settings
	CacheTTL time.Duration
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Port:        getEnv("API_PORT", "8080"),
		Environment: getEnv("ENVIRONMENT", "development"),
		APIKey:      os.Getenv("API_KEY"),

		VaultwardenURL:   os.Getenv("VAULTWARDEN_URL"),
		VaultwardenToken: os.Getenv("VAULTWARDEN_ACCESS_TOKEN"),

		ReadTimeout:  parseDuration(getEnv("READ_TIMEOUT", "10s")),
		WriteTimeout: parseDuration(getEnv("WRITE_TIMEOUT", "10s")),
		CacheTTL:     parseDuration(getEnv("CACHE_TTL", "5m")),
	}

	// Validate required fields
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API_KEY is required")
	}
	if len(cfg.APIKey) < 16 {
		return nil, fmt.Errorf("API_KEY must be at least 16 characters for security")
	}
	if cfg.VaultwardenURL == "" {
		return nil, fmt.Errorf("VAULTWARDEN_URL is required")
	}
	if cfg.VaultwardenToken == "" {
		return nil, fmt.Errorf("VAULTWARDEN_ACCESS_TOKEN is required")
	}

	// Validate and normalize URL
	parsedURL, err := url.Parse(cfg.VaultwardenURL)
	if err != nil {
		return nil, fmt.Errorf("VAULTWARDEN_URL is invalid: %w", err)
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
