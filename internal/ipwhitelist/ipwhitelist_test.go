package ipwhitelist

import (
	"net"
	"testing"

	"github.com/Turbootzz/vaultwarden-api/internal/realip"
	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

func TestIsAllowed(t *testing.T) {
	t.Parallel()

	wl, err := New([]string{"10.0.0.5", "192.168.1.0/24", " ", "bogus", "10.0.0.0/99"}, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.5", true},
		{"192.168.1.77", true},
		{"192.168.2.1", false},
		{"10.0.0.6", false},
		{"not-an-ip", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := wl.IsAllowed(tt.ip); got != tt.want {
			t.Errorf("IsAllowed(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

// serve starts app on a loopback listener and returns its address. The peer is
// therefore 127.0.0.1, which is always a trusted proxy — the exact condition
// that made the whitelist spoofable in #29.
func serve(t *testing.T, app *fiber.App) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.Shutdown() })
	return ln.Addr().String()
}

func get(t *testing.T, addr, forwardedFor string) int {
	t.Helper()
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://" + addr + "/secret/db")
	if forwardedFor != "" {
		req.Header.Set(fiber.HeaderXForwardedFor, forwardedFor)
	}
	if err := fasthttp.Do(req, resp); err != nil {
		t.Fatalf("request: %v", err)
	}
	return resp.StatusCode()
}

// Regression for #29: a client that prepends a whitelisted address to
// X-Forwarded-For must not pass the whitelist. The trusted proxy appends the
// real peer, so the resolver reads the chain right to left and sees it.
func TestMiddlewareRejectsSpoofedForwardedFor(t *testing.T) {
	wl, err := New([]string{"10.0.0.5"}, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resolver, err := realip.New([]string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("realip.New: %v", err)
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(realip.Middleware(resolver))
	app.Use(wl.Middleware())
	app.Get("/secret/:name", func(c *fiber.Ctx) error { return c.SendString("ok") })
	addr := serve(t, app)

	// A trusted proxy always appends the address it saw, so the last element is
	// proxy-written and everything before it is client-written. Each header below
	// ends in 203.0.113.9, the unlisted address the proxy actually observed.
	tests := []struct {
		name         string
		forwardedFor string
		want         int
	}{
		{"spoofed whitelisted prefix", "10.0.0.5, 203.0.113.9", fiber.StatusForbidden},
		{"repeated spoofed prefix", "10.0.0.5, 10.0.0.5, 203.0.113.9", fiber.StatusForbidden},
		{"junk before the spoof", "not-an-ip, 10.0.0.5, 203.0.113.9", fiber.StatusForbidden},
		{"spoofed trusted proxy prefix", "127.0.0.1, 10.0.0.5, 203.0.113.9", fiber.StatusForbidden},
		{"unlisted client, no spoof", "203.0.113.9", fiber.StatusForbidden},
		{"no header at all", "", fiber.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := get(t, addr, tt.forwardedFor); got != tt.want {
				t.Errorf("status = %d, want %d", got, tt.want)
			}
		})
	}
}

// A request the proxy really did forward from a whitelisted client is allowed.
func TestMiddlewareAllowsForwardedWhitelistedClient(t *testing.T) {
	wl, err := New([]string{"203.0.113.9"}, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resolver, err := realip.New([]string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("realip.New: %v", err)
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(realip.Middleware(resolver))
	app.Use(wl.Middleware())
	app.Get("/secret/:name", func(c *fiber.Ctx) error { return c.SendString("ok") })
	addr := serve(t, app)

	if got := get(t, addr, "203.0.113.9"); got != fiber.StatusOK {
		t.Errorf("status = %d, want %d for a proxy-forwarded whitelisted client", got, fiber.StatusOK)
	}
	// Prepending junk must not change the verdict for the same real client.
	if got := get(t, addr, "10.0.0.5, 203.0.113.9"); got != fiber.StatusOK {
		t.Errorf("status = %d, want %d", got, fiber.StatusOK)
	}
}

// Documents the residual limit of trusting a proxy: a caller that connects from
// a trusted address is the proxy as far as the resolver can tell, so it can
// assert any client address. Trusting loopback therefore extends the whitelist
// to anything already running on the host — inherent to TRUSTED_PROXY_IP, not a
// regression of #29, which is about remote callers behind an appending proxy.
func TestMiddlewareTrustsHeaderFromTheProxyItself(t *testing.T) {
	wl, err := New([]string{"10.0.0.5"}, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resolver, err := realip.New([]string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("realip.New: %v", err)
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(realip.Middleware(resolver))
	app.Use(wl.Middleware())
	app.Get("/secret/:name", func(c *fiber.Ctx) error { return c.SendString("ok") })
	addr := serve(t, app)

	if got := get(t, addr, "10.0.0.5"); got != fiber.StatusOK {
		t.Errorf("status = %d, want %d", got, fiber.StatusOK)
	}
}

// With nothing configured the middleware is a no-op, as documented.
func TestMiddlewareAllowsAllWhenUnconfigured(t *testing.T) {
	wl, err := New(nil, false)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	resolver, err := realip.New([]string{"127.0.0.1"})
	if err != nil {
		t.Fatalf("realip.New: %v", err)
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(realip.Middleware(resolver))
	app.Use(wl.Middleware())
	app.Get("/secret/:name", func(c *fiber.Ctx) error { return c.SendString("ok") })
	addr := serve(t, app)

	if got := get(t, addr, "10.0.0.5"); got != fiber.StatusOK {
		t.Errorf("status = %d, want %d", got, fiber.StatusOK)
	}
}
