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
		cfg.CacheTTL,
		syncInterval,
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
		TrustedProxies:          getTrustedProxies(),
		ProxyHeader:             fiber.HeaderXForwardedFor,
		// Avoid empty c.IP() when header is missing (e.g. behind a trusted proxy)
		EnableIPValidation: true,
	})

	app.Use(helmet.New())
	app.Use(recover.New())
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
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
		Max: 30,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "too many requests, please slow down",
			})
		},
	}))
	api.Use(auth.Middleware(cfg.APIKey))

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

// getTrustedProxies returns the list of trusted proxy IPs.
func getTrustedProxies() []string {
	seen := make(map[string]bool)
	result := []string{}

	for _, ip := range []string{"127.0.0.1", "::1"} {
		result = append(result, ip)
		seen[ip] = true
	}

	if proxyIP := os.Getenv("TRUSTED_PROXY_IP"); proxyIP != "" {
		proxies := strings.Split(proxyIP, ",")
		for _, proxy := range proxies {
			trimmed := strings.TrimSpace(proxy)
			if trimmed == "" || seen[trimmed] {
				continue
			}
			if err := validateIPOrCIDR(trimmed); err != nil {
				logger.Warn.Printf("Ignoring invalid IP/CIDR in TRUSTED_PROXY_IP: %s (%v)", trimmed, err)
				continue
			}
			result = append(result, trimmed)
			seen[trimmed] = true
		}
	}

	return result
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
