package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/helmet"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/thijsherman/vaultwarden-api/internal/auth"
	"github.com/thijsherman/vaultwarden-api/internal/config"
	"github.com/thijsherman/vaultwarden-api/internal/handlers"
	"github.com/thijsherman/vaultwarden-api/internal/vaultwarden"
	"github.com/thijsherman/vaultwarden-api/pkg/logger"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		logger.Error.Fatalf("Failed to load configuration: %v", err)
	}

	logger.Info.Printf("Starting Vaultwarden API on port %s (environment: %s)", cfg.Port, cfg.Environment)

	// Initialize Vaultwarden client
	var vaultClient *vaultwarden.Client
	if cfg.VaultwardenClientID != "" && cfg.VaultwardenSecret != "" {
		logger.Info.Println("Using API key authentication (recommended)")
		vaultClient = vaultwarden.NewClientWithAuth(cfg.VaultwardenURL, cfg.VaultwardenClientID, cfg.VaultwardenSecret, cfg.CacheTTL)
	} else {
		logger.Warn.Println("Using session token authentication (legacy - token will expire!)")
		vaultClient = vaultwarden.NewClient(cfg.VaultwardenURL, cfg.VaultwardenToken, cfg.CacheTTL)
	}

	// Initialize handlers
	h := handlers.NewHandler(vaultClient)

	// Create Fiber app with security configurations
	app := fiber.New(fiber.Config{
		AppName:               "Vaultwarden API v1.0",
		DisableStartupMessage: false,
		ReadTimeout:           cfg.ReadTimeout,
		WriteTimeout:          cfg.WriteTimeout,
		// Disable server header for security
		ServerHeader: "",
		// Don't expose stack traces in production
		ErrorHandler: customErrorHandler(cfg.IsProd()),
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

	app.Use(limiter.New(limiter.Config{
		Max: 30,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "too many requests, please slow down",
			})
		},
	}))

	// Public routes (no authentication required)
	app.Get("/health", h.HealthCheck)

	// Protected routes (authentication required)
	api := app.Group("/", auth.Middleware(cfg.APIKey))
	api.Get("/secret/:name", h.GetSecret)
	api.Post("/refresh", h.RefreshCache)

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan

		logger.Info.Println("Shutting down gracefully...")
		if err := app.Shutdown(); err != nil {
			logger.Error.Printf("Error during shutdown: %v", err)
		}
	}()

	// Start server
	addr := fmt.Sprintf(":%s", cfg.Port)
	if err := app.Listen(addr); err != nil {
		logger.Error.Fatalf("Failed to start server: %v", err)
	}
}

// customErrorHandler creates a custom error handler
func customErrorHandler(isProd bool) fiber.ErrorHandler {
	return func(c *fiber.Ctx, err error) error {
		code := fiber.StatusInternalServerError

		if e, ok := err.(*fiber.Error); ok {
			code = e.Code
		}

		// Log the error
		logger.Error.Printf("Request error (status %d): %v", code, err)

		// Don't expose internal errors in production
		message := "Internal Server Error"
		if !isProd {
			message = err.Error()
		}

		return c.Status(code).JSON(fiber.Map{
			"error": message,
		})
	}
}
