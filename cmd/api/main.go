package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/Turbootzz/vaultwarden-api/internal/auth"
	"github.com/Turbootzz/vaultwarden-api/internal/config"
	"github.com/Turbootzz/vaultwarden-api/internal/handlers"
	"github.com/Turbootzz/vaultwarden-api/internal/ipwhitelist"
	"github.com/Turbootzz/vaultwarden-api/internal/realip"
	"github.com/Turbootzz/vaultwarden-api/internal/vaultwarden"
	"github.com/Turbootzz/vaultwarden-api/pkg/logger"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
)

func main() {
	// Load configuration.
	cfg, err := config.Load()
	if err != nil {
		logger.Error.Fatalf("Failed to load configuration: %v", err)
	}

	logger.Info.Printf("Starting Vaultwarden API on port %s (environment: %s)", cfg.Port, cfg.Environment)

	// Initialize Vaultwarden client.
	email := os.Getenv("VAULTWARDEN_EMAIL")
	password := os.Getenv("VAULTWARDEN_PASSWORD")
	clientID := os.Getenv("VAULTWARDEN_CLIENT_ID")
	clientSecret := os.Getenv("VAULTWARDEN_CLIENT_SECRET")

	if email == "" || password == "" {
		logger.Error.Fatal("VAULTWARDEN_EMAIL and VAULTWARDEN_PASSWORD are required")
	}

	syncInterval := parseDurationEnv("SYNC_INTERVAL", "5m")

	vaultClient, err := vaultwarden.InitializeClient(
		cfg.VaultwardenURL,
		email,
		password,
		clientID,
		clientSecret,
		syncInterval,
		vaultwarden.WithStrictMatch(cfg.StrictSecretMatch),
	)
	if err != nil {
		logger.Error.Fatalf("Failed to initialize Vaultwarden client: %v", err)
	}

	// Initialize handlers.
	h := handlers.NewHandler(vaultClient)

	// Initialize IP whitelist.
	ipWhitelist, err := ipwhitelist.New(cfg.AllowedIPs, cfg.EnableGitHubIPRanges)
	if err != nil {
		logger.Error.Fatalf("Failed to initialize IP whitelist: %v", err)
	}

	// Client IP resolution shares the trusted proxy set with fiber.
	trustedProxies, providers, err := getTrustedProxies()
	if err != nil {
		logger.Error.Fatalf("Failed to resolve trusted proxies: %v", err)
	}
	ipResolver, err := realip.New(trustedProxies, providers...)
	if err != nil {
		logger.Error.Fatalf("Failed to initialize client IP resolver: %v", err)
	}

	// Start periodic GitHub IP range updates.
	var stopIPUpdate func()
	if cfg.EnableGitHubIPRanges {
		stopIPUpdate = ipWhitelist.StartPeriodicUpdate(24 * time.Hour)
	}

	// Create Fiber app with security configurations.
	app := fiber.New(fiber.Config{
		AppName:                 "Vaultwarden API v2.0",
		DisableStartupMessage:   false,
		ReadTimeout:             cfg.ReadTimeout,
		WriteTimeout:            cfg.WriteTimeout,
		ServerHeader:            "",
		ErrorHandler:            customErrorHandler(cfg.IsProd()),
		EnableTrustedProxyCheck: true,
		TrustedProxies:          trustedProxies,
		// ProxyHeader stays empty on purpose: fiber reads X-Forwarded-For left to
		// right, and the leftmost entry is whatever the client sent. c.IP() must
		// remain the socket peer; realip resolves the real client (see #29).
		ProxyHeader: "",
	})

	app.Use(helmet.New())
	app.Use(recover.New())
	// Must precede every middleware that makes a decision on the client IP.
	app.Use(realip.Middleware(ipResolver))
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
		// Secret responses mix a caller-supplied name with the secret itself;
		// compressing them leaks length information about the secret (#32).
		Next: func(c *fiber.Ctx) bool {
			return isSecretPath(c.Path())
		},
	}))

	app.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.CORSAllowedOrigins,
		AllowMethods:     "GET,POST",
		AllowHeaders:     "Authorization,Content-Type",
		AllowCredentials: false,
	}))

	// Public routes.
	app.Get("/health", h.HealthCheck)

	// Protected routes.
	api := app.Group("/")
	api.Use(ipWhitelist.Middleware())
	api.Use(limiter.New(limiter.Config{
		Max:        cfg.RateLimitMax,
		Expiration: cfg.RateLimitWindow,
		KeyGenerator: func(c *fiber.Ctx) string {
			return realip.FromCtx(c)
		},
		// Whitelisted/trusted IPs bypass rate limiting entirely.
		Next: func(c *fiber.Ctx) bool {
			return ipWhitelist.IsAllowed(realip.FromCtx(c))
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "too many requests, please slow down",
			})
		},
	}))
	api.Use(auth.Middleware(auth.NewStore(cfg.APIKeys)))

	api.Get("/secret/:name", h.GetSecret)
	api.Post("/refresh", h.RefreshCache)

	// Graceful shutdown.
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan

		logger.Info.Println("Shutting down gracefully...")

		vaultClient.Stop()

		if stopIPUpdate != nil {
			stopIPUpdate()
		}

		if err := app.Shutdown(); err != nil {
			logger.Error.Printf("Error during shutdown: %v", err)
		}
	}()

	// Start server.
	addr := fmt.Sprintf(":%s", cfg.Port)
	if err := app.Listen(addr); err != nil {
		if stopIPUpdate != nil {
			stopIPUpdate()
		}
		logger.Error.Printf("Failed to start server: %v", err)
		os.Exit(1)
	}
}

// isSecretPath reports whether a request path reaches the secret endpoint, and
// so must not be compressed. Matched case-insensitively: fiber's router is
// case-insensitive by default, so /SECRET/x and /secret/x reach the same
// handler and both return a secret.
func isSecretPath(path string) bool {
	return strings.HasPrefix(strings.ToLower(path), "/secret/")
}

// parseDurationEnv reads a duration from an env var with a fallback.
func parseDurationEnv(key, fallback string) time.Duration {
	s := os.Getenv(key)
	if s == "" {
		s = fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 5 * time.Minute
	}
	return d
}

// getTrustedProxies returns the list of trusted proxy IPs: loopback, whatever
// TRUSTED_PROXY_IP names, and the ranges of any TRUSTED_PROXY_PRESET.
//
// Every hop between the client and this service has to appear here — a CDN edge
// included — because the client IP walk stops at the first untrusted hop and
// returns it. An unnamed CDN edge is therefore what the IP whitelist ends up
// judging, and edge addresses rotate per request (#40).
func getTrustedProxies() ([]string, []realip.Provider, error) {
	seen := make(map[string]bool)
	result := []string{}

	add := func(entry string) {
		if entry == "" || seen[entry] {
			return
		}
		result = append(result, entry)
		seen[entry] = true
	}

	for _, ip := range []string{"127.0.0.1", "::1"} {
		add(ip)
	}

	for _, proxy := range strings.Split(os.Getenv("TRUSTED_PROXY_IP"), ",") {
		trimmed := strings.TrimSpace(proxy)
		if trimmed == "" {
			continue
		}
		if err := validateIPOrCIDR(trimmed); err != nil {
			logger.Warn.Printf("Ignoring invalid IP/CIDR in TRUSTED_PROXY_IP: %s (%v)", trimmed, err)
			continue
		}
		add(trimmed)
	}

	// A misspelled preset is fatal rather than skipped: it is reached for when
	// requests are already being denied, so ignoring it would leave that failure
	// in place and add no signal about why.
	var providers []realip.Provider
	for _, name := range strings.Split(os.Getenv("TRUSTED_PROXY_PRESET"), ",") {
		trimmed := strings.TrimSpace(name)
		if trimmed == "" {
			continue
		}
		provider, err := realip.Preset(trimmed)
		if err != nil {
			return nil, nil, fmt.Errorf("TRUSTED_PROXY_PRESET: %w", err)
		}
		logger.Info.Printf("Trusting %d %s edge ranges; client address taken from %s",
			len(provider.Ranges), provider.Name, provider.ClientIPHeader)
		for _, entry := range provider.Ranges {
			add(entry)
		}
		providers = append(providers, provider)
	}

	return result, providers, nil
}

// validateIPOrCIDR validates an IP or CIDR string.
func validateIPOrCIDR(s string) error {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid IP address")
	}
	return nil
}

// customErrorHandler creates a custom error handler.
func customErrorHandler(isProd bool) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError
		if e, ok := err.(*fiber.Error); ok {
			code = e.Code
		}

		logger.Error.Printf("Request error (status %d): %v", code, err)

		message := "Internal Server Error"
		if !isProd {
			message = err.Error()
		}

		return c.Status(code).JSON(fiber.Map{
			"error": message,
		})
	}
}
