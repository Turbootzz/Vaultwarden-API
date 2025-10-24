package ipwhitelist

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

// IPWhitelist manages IP-based access control
type IPWhitelist struct {
	mu                sync.RWMutex
	allowedIPs        map[string]bool
	allowedCIDRs      []*net.IPNet
	githubIPRanges    []*net.IPNet
	enableGitHub      bool
	lastGitHubUpdate  time.Time
}

// GitHubMeta represents GitHub's API response for IP ranges
type GitHubMeta struct {
	Actions []string `json:"actions"`
}

// New creates a new IP whitelist
func New(allowedIPs []string, enableGitHub bool) (*IPWhitelist, error) {
	wl := &IPWhitelist{
		allowedIPs:   make(map[string]bool),
		enableGitHub: enableGitHub,
	}

	// Parse allowed IPs and CIDRs
	for _, ipStr := range allowedIPs {
		ipStr = strings.TrimSpace(ipStr)
		if ipStr == "" {
			continue
		}

		// Check if it's a CIDR
		if strings.Contains(ipStr, "/") {
			_, cidr, err := net.ParseCIDR(ipStr)
			if err != nil {
				logger.Warn.Printf("Invalid CIDR '%s': %v", ipStr, err)
				continue
			}
			wl.allowedCIDRs = append(wl.allowedCIDRs, cidr)
			logger.Info.Printf("Added CIDR to whitelist: %s", ipStr)
		} else {
			// Single IP
			ip := net.ParseIP(ipStr)
			if ip == nil {
				logger.Warn.Printf("Invalid IP '%s'", ipStr)
				continue
			}
			wl.allowedIPs[ipStr] = true
			logger.Info.Printf("Added IP to whitelist: %s", ipStr)
		}
	}

	// Fetch GitHub IP ranges if enabled
	if enableGitHub {
		if err := wl.updateGitHubIPRanges(); err != nil {
			logger.Warn.Printf("Failed to fetch GitHub IP ranges: %v", err)
		}
	}

	return wl, nil
}

// Middleware creates a Fiber middleware for IP whitelisting
func (wl *IPWhitelist) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// If no IPs configured and GitHub not enabled, allow all
		wl.mu.RLock()
		hasWhitelist := len(wl.allowedIPs) > 0 || len(wl.allowedCIDRs) > 0 || len(wl.githubIPRanges) > 0
		wl.mu.RUnlock()

		if !hasWhitelist {
			return c.Next()
		}

		clientIP := c.IP()

		if wl.IsAllowed(clientIP) {
			logger.Info.Printf("IP allowed: %s", clientIP)
			return c.Next()
		}

		logger.Warn.Printf("IP blocked (not whitelisted): %s on %s %s", clientIP, c.Method(), c.Path())
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "access denied: IP not whitelisted",
		})
	}
}

// IsAllowed checks if an IP is whitelisted
func (wl *IPWhitelist) IsAllowed(ipStr string) bool {
	wl.mu.RLock()
	defer wl.mu.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Check single IPs
	if wl.allowedIPs[ipStr] {
		return true
	}

	// Check CIDRs
	for _, cidr := range wl.allowedCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	// Check GitHub IP ranges
	for _, cidr := range wl.githubIPRanges {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

// updateGitHubIPRanges fetches GitHub Actions IP ranges
func (wl *IPWhitelist) updateGitHubIPRanges() error {
	logger.Info.Println("Fetching GitHub Actions IP ranges...")

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Get("https://api.github.com/meta")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github api returned status %d", resp.StatusCode)
	}

	var meta GitHubMeta
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return err
	}

	wl.mu.Lock()
	defer wl.mu.Unlock()

	wl.githubIPRanges = nil
	for _, cidrStr := range meta.Actions {
		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			logger.Warn.Printf("Invalid GitHub CIDR '%s': %v", cidrStr, err)
			continue
		}
		wl.githubIPRanges = append(wl.githubIPRanges, cidr)
	}

	wl.lastGitHubUpdate = time.Now()
	logger.Info.Printf("Loaded %d GitHub Actions IP ranges", len(wl.githubIPRanges))

	return nil
}

// StartPeriodicUpdate starts a goroutine that updates GitHub IP ranges periodically
func (wl *IPWhitelist) StartPeriodicUpdate(interval time.Duration) {
	if !wl.enableGitHub {
		return
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if err := wl.updateGitHubIPRanges(); err != nil {
				logger.Error.Printf("Failed to update GitHub IP ranges: %v", err)
			}
		}
	}()

	logger.Info.Printf("Started GitHub IP range auto-update (every %v)", interval)
}
