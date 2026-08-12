package realip

import (
	"bufio"
	"net"
	"strings"
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

// acquireCtx builds a context from a real parsed request. Requests must go
// through the wire parser, not Header.Set, because the resolver reads the raw
// header block and Header.Set does not populate it.
func acquireCtx(t *testing.T, peer string, forwardedFor ...string) (*fiber.App, *fiber.Ctx) {
	t.Helper()

	var b strings.Builder
	b.WriteString("GET /secret/db HTTP/1.1\r\nHost: target\r\n")
	for _, line := range forwardedFor {
		if line == "" {
			continue
		}
		b.WriteString("X-Forwarded-For: " + line + "\r\n")
	}
	b.WriteString("\r\n")

	return acquireRawCtx(t, peer, b.String())
}

// acquireRawCtx parses a complete raw request, so tests can exercise wire-level
// shapes such as chunked bodies with trailers.
func acquireRawCtx(t *testing.T, peer, raw string) (*fiber.App, *fiber.Ctx) {
	t.Helper()
	app := fiber.New()
	fctx := &fasthttp.RequestCtx{}
	fctx.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP(peer), Port: 54321})
	if err := fctx.Request.Read(bufio.NewReader(strings.NewReader(raw))); err != nil {
		t.Fatalf("parse request: %v", err)
	}
	ctx := app.AcquireCtx(fctx)
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

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
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

// A proxy may add its own X-Forwarded-For line instead of extending the
// client's — HAProxy's forwardfor does. Reading only the first line would parse
// the line the client wrote and hand back an address of its choosing.
func TestClientIPReadsEveryForwardedForLine(t *testing.T) {
	resolver := testResolver(t)

	tests := []struct {
		name  string
		lines []string
		want  string
	}{
		{
			name:  "proxy appends its own line",
			lines: []string{"10.0.0.5", "203.0.113.9"},
			want:  "203.0.113.9",
		},
		{
			name:  "spoofed line carries several entries",
			lines: []string{"10.0.0.5, 10.0.0.6", "203.0.113.9"},
			want:  "203.0.113.9",
		},
		{
			name:  "trailing line holds only trusted proxies",
			lines: []string{"203.0.113.9", "172.18.0.4, 127.0.0.1"},
			want:  "203.0.113.9",
		},
		{
			name:  "junk line between",
			lines: []string{"10.0.0.5", "not-an-ip", "203.0.113.9"},
			want:  "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ctx := acquireCtx(t, "127.0.0.1", tt.lines...)
			if got := resolver.ClientIP(ctx); got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// fasthttp merges chunked request trailers into the same header table that
// Header.PeekAll reads, and X-Forwarded-For is not on its forbidden-trailer
// list. Trailer values land after every genuine header — precisely where the
// right-to-left walk looks — so sourcing the chain from PeekAll would let a
// client smuggle its chosen address past any proxy that forwards trailers
// (HAProxy and Envoy do; nginx does not). The chain comes from the raw header
// block instead, which the trailer reader never touches.
func TestClientIPIgnoresSmuggledTrailers(t *testing.T) {
	resolver := testResolver(t)

	const attack = "X-Forwarded-For: 10.0.0.5\r\n"

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "GET with an undeclared trailer",
			raw: "GET /secret/db HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n" +
				"X-Forwarded-For: 203.0.113.9\r\n\r\n0\r\n" + attack + "\r\n",
			want: "203.0.113.9",
		},
		{
			name: "POST with an undeclared trailer",
			raw: "POST /secret/db HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n" +
				"X-Forwarded-For: 203.0.113.9\r\n\r\n0\r\n" + attack + "\r\n",
			want: "203.0.113.9",
		},
		{
			name: "declared trailer",
			raw: "GET /secret/db HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n" +
				"Trailer: X-Forwarded-For\r\nX-Forwarded-For: 203.0.113.9\r\n\r\n0\r\n" + attack + "\r\n",
			want: "203.0.113.9",
		},
		{
			name: "trailer with a non-empty body chunk",
			raw: "POST /secret/db HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n" +
				"X-Forwarded-For: 203.0.113.9\r\n\r\n4\r\nbody\r\n0\r\n" + attack + "\r\n",
			want: "203.0.113.9",
		},
		{
			name: "trailer is the only X-Forwarded-For",
			raw: "GET /secret/db HTTP/1.1\r\nHost: target\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n" +
				attack + "\r\n",
			want: "127.0.0.1", // no genuine header, so the peer stands
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ctx := acquireRawCtx(t, "127.0.0.1", tt.raw)
			if got := resolver.ClientIP(ctx); got != tt.want {
				t.Errorf("ClientIP() = %q, want %q (smuggled trailer must not win)", got, tt.want)
			}
		})
	}
}

// A continuation line belongs to the header above it. Dropping one could remove
// an entry a proxy appended and promote a client-written entry to the right.
func TestClientIPHonoursLineFolding(t *testing.T) {
	resolver := testResolver(t)

	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "folded continuation carries the proxy entry",
			raw: "GET /secret/db HTTP/1.1\r\nHost: target\r\n" +
				"X-Forwarded-For: 10.0.0.5,\r\n 203.0.113.9\r\n\r\n",
			want: "203.0.113.9",
		},
		{
			name: "folded continuation on a client-written line stays left",
			raw: "GET /secret/db HTTP/1.1\r\nHost: target\r\n" +
				"X-Forwarded-For: 10.0.0.5,\r\n\t10.0.0.6\r\n" +
				"X-Forwarded-For: 203.0.113.9\r\n\r\n",
			want: "203.0.113.9",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ctx := acquireRawCtx(t, "127.0.0.1", tt.raw)
			if got := resolver.ClientIP(ctx); got != tt.want {
				t.Errorf("ClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}

// A continuation line that itself looks like a header is rejected by fasthttp
// before any handler runs, so smuggling one under an unrelated header never
// reaches the resolver. Pinned because the raw-header parse would otherwise have
// to decide what such a line means.
func TestFoldedHeaderMasqueradingAsForwardedForIsRejected(t *testing.T) {
	raw := "GET /secret/db HTTP/1.1\r\nHost: target\r\n" +
		"User-Agent: curl\r\n X-Forwarded-For: 10.0.0.5\r\n" +
		"X-Forwarded-For: 203.0.113.9\r\n\r\n"

	var fctx fasthttp.RequestCtx
	fctx.SetRemoteAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 54321})
	if err := fctx.Request.Read(bufio.NewReader(strings.NewReader(raw))); err == nil {
		t.Fatal("expected fasthttp to reject the folded header-shaped continuation line")
	}
}

func TestResolveReportsPeerAndChain(t *testing.T) {
	resolver := testResolver(t)
	_, ctx := acquireCtx(t, "127.0.0.1", "203.0.113.9, 172.18.0.4")

	got := resolver.Resolve(ctx)
	if got.Client != "203.0.113.9" {
		t.Errorf("Client = %q, want 203.0.113.9", got.Client)
	}
	if got.Peer != "127.0.0.1" {
		t.Errorf("Peer = %q, want 127.0.0.1", got.Peer)
	}
	want := []string{"203.0.113.9", "172.18.0.4"}
	if len(got.Chain) != len(want) {
		t.Fatalf("Chain = %v, want %v", got.Chain, want)
	}
	for i := range want {
		if got.Chain[i] != want[i] {
			t.Errorf("Chain[%d] = %q, want %q", i, got.Chain[i], want[i])
		}
	}
}

// The chain records what the resolver actually walked, so an unparseable entry
// is absent from it too — that is the point, it explains why the walk landed
// where it did rather than echoing the raw header back.
func TestResolveChainHoldsOnlyParsedEntries(t *testing.T) {
	resolver := testResolver(t)
	_, ctx := acquireCtx(t, "127.0.0.1", "not-an-ip, 203.0.113.9:443")

	got := resolver.Resolve(ctx)
	if len(got.Chain) != 1 || got.Chain[0] != "203.0.113.9" {
		t.Errorf("Chain = %v, want [203.0.113.9]", got.Chain)
	}
}

func TestResolutionStringExplainsTheWalk(t *testing.T) {
	t.Parallel()

	res := Resolution{Client: "172.70.1.1", Peer: "172.18.0.5", Chain: []string{"192.168.1.81", "172.70.1.1"}}
	want := "resolved 172.70.1.1, peer 172.18.0.5, xff=[192.168.1.81 172.70.1.1]"
	if got := res.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	empty := Resolution{Client: "203.0.113.9", Peer: "203.0.113.9"}
	if got := empty.String(); got != "resolved 203.0.113.9, peer 203.0.113.9, xff=[]" {
		t.Errorf("String() with no chain = %q", got)
	}
}

// A client controls how many entries it prepends, so the log line must not.
func TestResolutionStringTruncatesALongChain(t *testing.T) {
	t.Parallel()

	chain := make([]string, 0, maxLoggedChain+3)
	for i := 0; i < maxLoggedChain+3; i++ {
		chain = append(chain, "203.0.113.9")
	}
	got := Resolution{Client: "203.0.113.9", Peer: "127.0.0.1", Chain: chain}.String()

	if strings.Count(got, "203.0.113.9") != maxLoggedChain+1 { // +1 for the resolved address
		t.Errorf("String() = %q, want only %d chain entries", got, maxLoggedChain)
	}
	if !strings.Contains(got, "+3 more") {
		t.Errorf("String() = %q, want a truncation marker", got)
	}
}

// Issue #40: behind a CDN the chain reaching the service is
// "<real client>, <edge IP>". The edge is a hop like any other, so it has to be
// trusted or the right-to-left walk stops there and the whitelist is evaluated
// against an address that rotates per request.
func TestClientIPBehindACDN(t *testing.T) {
	const (
		client = "192.168.1.81"
		edge   = "172.70.1.1" // Cloudflare, inside 172.64.0.0/13
	)
	chain := client + ", " + edge

	// Only the local proxy trusted: the walk stops at the edge. This is the
	// reported bug, pinned so the behaviour cannot be changed by accident.
	localOnly, err := New([]string{"127.0.0.1", "::1"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, ctx := acquireCtx(t, "127.0.0.1", chain)
	if got := localOnly.ClientIP(ctx); got != edge {
		t.Errorf("ClientIP() with an untrusted edge = %q, want the edge address %q", got, edge)
	}

	// With the edge ranges trusted the walk reaches the real client.
	cf, err := Preset("cloudflare")
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	withEdge, err := New(append([]string{"127.0.0.1", "::1"}, cf...))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, ctx = acquireCtx(t, "127.0.0.1", chain)
	if got := withEdge.ClientIP(ctx); got != client {
		t.Errorf("ClientIP() with the edge trusted = %q, want %q", got, client)
	}
}

// Trusting the CDN's ranges must not make the CDN able to assert an address:
// it appends the visitor address it saw, and everything the visitor prepended
// stays to the left of that entry and is still ignored.
func TestTrustedCDNDoesNotMakeTheChainSpoofable(t *testing.T) {
	cf, err := Preset("cloudflare")
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	resolver, err := New(append([]string{"127.0.0.1", "::1"}, cf...))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// The attacker sent "X-Forwarded-For: 192.168.1.81"; the CDN appended the
	// address it saw (203.0.113.9) and the local proxy appended the edge.
	_, ctx := acquireCtx(t, "127.0.0.1", "192.168.1.81, 203.0.113.9, 172.70.1.1")
	if got := resolver.ClientIP(ctx); got != "203.0.113.9" {
		t.Errorf("ClientIP() = %q, want the CDN-observed address 203.0.113.9", got)
	}
}
