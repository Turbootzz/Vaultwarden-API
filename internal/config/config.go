package config

import (
	"fmt"
	"net"
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
	APIKey                string
	AllowedIPs            []string
	EnableGitHubIPRanges  bool

	VaultwardenURL      string
	VaultwardenToken    string
	VaultwardenClientID string
	VaultwardenSecret   string

	CacheTTL           time.Duration
	CORSAllowedOrigins string
}

// Load reads configuration from environment variables
func Load() (*Config, error) {
	cfg := &Config{
		Port:        getEnv("API_PORT", "8080"),
		Environment: getEnv("ENVIRONMENT", "development"),
		APIKey:      os.Getenv("API_KEY"),

		VaultwardenURL:      os.Getenv("VAULTWARDEN_URL"),
		VaultwardenToken:    os.Getenv("VAULTWARDEN_ACCESS_TOKEN"),
		VaultwardenClientID: os.Getenv("VAULTWARDEN_CLIENT_ID"),
		VaultwardenSecret:   os.Getenv("VAULTWARDEN_CLIENT_SECRET"),

		ReadTimeout:        parseDuration(getEnv("READ_TIMEOUT", "10s")),
		WriteTimeout:       parseDuration(getEnv("WRITE_TIMEOUT", "10s")),
		CacheTTL:           parseDuration(getEnv("CACHE_TTL", "5m")),
		CORSAllowedOrigins: getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:3000"),

		EnableGitHubIPRanges: getEnv("ENABLE_GITHUB_IP_RANGES", "false") == "true",
	}

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
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("API_KEY is required")
	}
	if len(cfg.APIKey) < 32 {
		return nil, fmt.Errorf("API_KEY must be at least 32 characters for security (run: openssl rand -base64 32)")
	}
	if cfg.VaultwardenURL == "" {
		return nil, fmt.Errorf("VAULTWARDEN_URL is required")
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
