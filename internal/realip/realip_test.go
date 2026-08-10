package realip

import (
	"net"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
)

// loopback and the docker bridge range, mirroring the documented deployment.
func testResolver(t *testing.T) *Resolver {
	t.Helper()
	r, err := New([]string{"127.0.0.1", "::1", "172.16.0.0/12"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func acquireCtx(t *testing.T, peer, forwardedFor string) (*fiber.App, *fiber.Ctx) {
	t.Helper()
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	fctx.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP(peer), Port: 54321})
	ctx := app.AcquireCtx(fctx)
	ctx.Request().Header.SetMethod("GET")
	ctx.Request().URI().SetPath("/secret/db")
	if forwardedFor != "" {
		ctx.Request().Header.Set(fiber.HeaderXForwardedFor, forwardedFor)
	}
	t.Cleanup(func() { app.ReleaseCtx(ctx) })
	return app, ctx
}

func TestClientIP(t *testing.T) {
	tests := []struct {
		name         string
		peer         string
		forwardedFor string
		want         string
	}{
		{
			// #29: the leftmost entry is whatever the client sent. nginx's
			// $proxy_add_x_forwarded_for appends the real peer, so the rightmost
			// untrusted entry is the client and the spoofed prefix is ignored.
			name:         "spoofed prefix is ignored",
			peer:         "127.0.0.1",
			forwardedFor: "10.0.0.5, 203.0.113.9",
			want:         "203.0.113.9",
		},
		{
			name:         "untrusted peer wins over any header",
			peer:         "198.51.100.7",
			forwardedFor: "10.0.0.5",
			want:         "198.51.100.7",
		},
		{
			name:         "no header behind a trusted proxy falls back to the peer",
			peer:         "127.0.0.1",
			forwardedFor: "",
			want:         "127.0.0.1",
		},
		{
			name:         "single hop",
			peer:         "172.18.0.1",
			forwardedFor: "203.0.113.9",
			want:         "203.0.113.9",
		},
		{
			name:         "chained trusted proxies are skipped",
			peer:         "127.0.0.1",
			forwardedFor: "203.0.113.9, 172.18.0.4, 127.0.0.1",
			want:         "203.0.113.9",
		},
		{
			name:         "all-trusted chain falls back to the peer",
			peer:         "127.0.0.1",
			forwardedFor: "172.18.0.4, 127.0.0.1",
			want:         "127.0.0.1",
		},
		{
			name:         "junk entries cannot hide the appended client",
			peer:         "127.0.0.1",
			forwardedFor: "not-an-ip, 10.0.0.5, ., 203.0.113.9",
			want:         "203.0.113.9",
		},
		{
			name:         "trailing junk does not shadow the real client",
			peer:         "127.0.0.1",
			forwardedFor: "203.0.113.9, garbage",
			want:         "203.0.113.9",
		},
		{
			name:         "ipv6 client",
			peer:         "::1",
			forwardedFor: "2001:db8::42",
			want:         "2001:db8::42",
		},
		{
			name:         "entry carrying a port",
			peer:         "127.0.0.1",
			forwardedFor: "203.0.113.9:443",
			want:         "203.0.113.9",
		},
		{
			name:         "empty entries are skipped",
			peer:         "127.0.0.1",
			forwardedFor: "203.0.113.9, ,",
			want:         "203.0.113.9",
		},
	}

	resolver := testResolver(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ctx := acquireCtx(t, tt.peer, tt.forwardedFor)
			if got := resolver.ClientIP(ctx); got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientIPWithoutTrustedProxies(t *testing.T) {
	resolver, err := New(nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	_, ctx := acquireCtx(t, "203.0.113.9", "10.0.0.5")
	if got := resolver.ClientIP(ctx); got != "203.0.113.9" {
		t.Errorf("ClientIP() = %q, want the socket peer 203.0.113.9", got)
	}
}

func TestNewRejectsInvalidEntries(t *testing.T) {
	for _, entry := range []string{"not-an-ip", "10.0.0.0/99", "10.0.0.0/", "::/x"} {
		if _, err := New([]string{entry}); err == nil {
			t.Errorf("New(%q) = nil error, want an error", entry)
		}
	}
}

func TestNewIgnoresBlankEntries(t *testing.T) {
	r, err := New([]string{" ", "", " 127.0.0.1 "})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !r.IsTrustedProxy(net.ParseIP("127.0.0.1")) {
		t.Error("trimmed entry was not registered as trusted")
	}
}

func TestIsTrustedProxy(t *testing.T) {
	resolver := testResolver(t)

	tests := []struct {
		ip   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", true},
		{"172.18.0.4", true},
		{"172.31.255.255", true},
		{"172.32.0.1", false},
		{"203.0.113.9", false},
	}
	for _, tt := range tests {
		if got := resolver.IsTrustedProxy(net.ParseIP(tt.ip)); got != tt.want {
			t.Errorf("IsTrustedProxy(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
	if resolver.IsTrustedProxy(nil) {
		t.Error("IsTrustedProxy(nil) = true, want false")
	}
}

func TestMiddlewareStoresResolvedIP(t *testing.T) {
	app := fiber.New(fiber.Config{DisableStartupMessage: true})
	app.Use(Middleware(testResolver(t)))
	app.Get("/", func(c *fiber.Ctx) error { return c.SendString(FromCtx(c)) })

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = app.Listener(ln) }()
	t.Cleanup(func() { _ = app.Shutdown() })

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://" + ln.Addr().String() + "/")
	req.Header.Set(fiber.HeaderXForwardedFor, "10.0.0.5, 203.0.113.9")

	if err := fasthttp.Do(req, resp); err != nil {
		t.Fatalf("request: %v", err)
	}
	if got := string(resp.Body()); got != "203.0.113.9" {
		t.Errorf("FromCtx() = %q, want 203.0.113.9 (spoofed leftmost entry must not win)", got)
	}
}

func TestFromCtxFallsBackWithoutMiddleware(t *testing.T) {
	_, ctx := acquireCtx(t, "203.0.113.9", "")
	if got := FromCtx(ctx); got != ctx.IP() {
		t.Errorf("FromCtx() = %q, want fiber's c.IP() %q", got, ctx.IP())
	}
}
