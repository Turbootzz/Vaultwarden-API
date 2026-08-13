package ipwhitelist

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/Turbootzz/vaultwarden-api/internal/logtest"
	"github.com/Turbootzz/vaultwarden-api/internal/realip"
	"github.com/Turbootzz/vaultwarden-api/pkg/logger"
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
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
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

// Regression: with ENABLE_GITHUB_IP_RANGES=true and no ALLOWED_IPS, a failed
// range fetch left the list empty, and an empty list used to read as
// "unrestricted" — turning a GitHub API outage into an open door. Access control
// that was asked for and could not be loaded must fail closed.
func TestMiddlewareFailsClosedWhenConfiguredButEmpty(t *testing.T) {
	resolver, err := realip.New([]string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("realip.New: %v", err)
	}

	// enableGitHub with an unreachable fetch: New logs a warning and carries on
	// with no ranges loaded.
	wl := &IPWhitelist{
		allowedIPs:   make(map[string]bool),
		enableGitHub: true,
		configured:   true,
	}

	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(realip.Middleware(resolver))
	app.Use(wl.Middleware())
	app.Get("/secret/:name", func(c *fiber.Ctx) error { return c.SendString("ok") })
	addr := serve(t, app)

	for _, forwarded := range []string{"", "203.0.113.9", "10.0.0.5"} {
		if got := get(t, addr, forwarded); got != fiber.StatusForbidden {
			t.Errorf("X-Forwarded-For=%q: status = %d, want %d", forwarded, got, fiber.StatusForbidden)
		}
	}
}

// Issue #40: a deployment behind a CDN denies every request because the walk
// stops at an untrusted edge hop. "IP blocked: 172.70.1.1" alone reads like a
// whitelist typo, so the warning has to carry the peer and the chain that
// produced the address.
func TestMiddlewareBlockLogExplainsTheProxyChain(t *testing.T) {
	// The warning is written on the server goroutine and read on this one, with
	// nothing between them to order the two accesses — a bare bytes.Buffer would
	// be a data race whether or not the detector happens to catch it.
	buf := logtest.Capture(t, logger.Warn)[0]

	wl, err := New([]string{"192.168.1.0/24"}, false)
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

	if got := get(t, addr, "192.168.1.81, 172.70.1.1"); got != fiber.StatusForbidden {
		t.Fatalf("status = %d, want %d", got, fiber.StatusForbidden)
	}

	line := buf.String()
	for _, want := range []string{
		"172.70.1.1",   // the address the whitelist actually judged
		"127.0.0.1",    // the socket peer
		"192.168.1.81", // the entry the operator expected to be used
		"GET",
		"/secret/db",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("blocked warning %q does not mention %q", line, want)
		}
	}
}

func TestNewRecordsWhetherAccessControlWasConfigured(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		allowedIPs   []string
		enableGitHub bool
		want         bool
	}{
		{"nothing configured", nil, false, false},
		{"explicit IPs", []string{"10.0.0.5"}, false, true},
		{"github ranges only", nil, true, true},
		{"both", []string{"10.0.0.5"}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wl, err := New(tt.allowedIPs, false)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			// New performs a live fetch when enableGitHub is set, so set the flag
			// the way New would rather than reaching over the network in a test.
			wl.configured = wl.configured || tt.enableGitHub
			if wl.configured != tt.want {
				t.Errorf("configured = %v, want %v", wl.configured, tt.want)
			}
		})
	}
}

// rawGet sends a request verbatim over a socket and returns the status line, so
// tests can express wire-level shapes the client libraries will not produce.
func rawGet(t *testing.T, addr, raw string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	if _, err := io.WriteString(conn, raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	status, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read status line: %v", err)
	}
	return strings.TrimSpace(status)
}

// End-to-end regression for the trailer-smuggling bypass: fasthttp merges
// chunked request trailers into the header table, and a trailer value lands to
// the right of the entry the proxy appended — exactly where the right-to-left
// walk looks. Behind a proxy that forwards trailers (HAProxy, Envoy) this let a
// remote client hand itself a whitelisted address.
func TestMiddlewareRejectsTrailerSmuggledForwardedFor(t *testing.T) {
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
	app.All("/secret/:name", func(c *fiber.Ctx) error { return c.SendString("ok") })
	addr := serve(t, app)

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "GET, undeclared trailer",
			raw: "GET /secret/db HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n" +
				"X-Forwarded-For: 203.0.113.9\r\nConnection: close\r\n\r\n" +
				"0\r\nX-Forwarded-For: 10.0.0.5\r\n\r\n",
		},
		{
			name: "POST, undeclared trailer",
			raw: "POST /secret/db HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n" +
				"X-Forwarded-For: 203.0.113.9\r\nConnection: close\r\n\r\n" +
				"4\r\nbody\r\n0\r\nX-Forwarded-For: 10.0.0.5\r\n\r\n",
		},
		{
			name: "GET, declared trailer",
			raw: "GET /secret/db HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\n" +
				"Trailer: X-Forwarded-For\r\nX-Forwarded-For: 203.0.113.9\r\nConnection: close\r\n\r\n" +
				"0\r\nX-Forwarded-For: 10.0.0.5\r\n\r\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rawGet(t, addr, tt.raw)
			if !strings.Contains(got, "403") {
				t.Errorf("status = %q, want 403 — a smuggled trailer must not pass the whitelist", got)
			}
		})
	}
}
