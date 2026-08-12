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
	assertChain(t, got.Chain, "203.0.113.9", "172.18.0.4")
}

// The chain records what the resolver actually walked, so an unparseable entry
// is absent from it too — that is the point, it explains why the walk landed
// where it did rather than echoing the raw header back.
func TestResolveChainHoldsOnlyParsedEntries(t *testing.T) {
	resolver := testResolver(t)
	_, ctx := acquireCtx(t, "127.0.0.1", "not-an-ip, 203.0.113.9:443")

	assertChain(t, resolver.Resolve(ctx).Chain, "203.0.113.9")
}

// The commonest #40-shaped misconfiguration is the reverse proxy itself missing
// from TRUSTED_PROXY_IP. The header is ignored in that case — correctly — but it
// still has to be reported, or the log cannot distinguish "no header was sent"
// from "a header was sent and not believed".
func TestResolveReportsTheChainEvenWhenThePeerIsUntrusted(t *testing.T) {
	resolver := testResolver(t)
	_, ctx := acquireCtx(t, "203.0.113.9", "192.168.1.81, 172.70.1.1")

	got := resolver.Resolve(ctx)
	if got.Client != "203.0.113.9" {
		t.Errorf("Client = %q, want the untrusted peer 203.0.113.9", got.Client)
	}
	assertChain(t, got.Chain, "192.168.1.81", "172.70.1.1")
}

func TestResolutionStringExplainsTheWalk(t *testing.T) {
	t.Parallel()

	res := Resolution{Client: "172.70.1.1", Peer: "172.18.0.5", Chain: ips("192.168.1.81", "172.70.1.1")}
	want := "resolved 172.70.1.1, peer 172.18.0.5, xff=[192.168.1.81 172.70.1.1]"
	if got := res.String(); got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}

	empty := Resolution{Client: "203.0.113.9", Peer: "203.0.113.9"}
	if got := empty.String(); got != "resolved 203.0.113.9, peer 203.0.113.9, xff=[]" {
		t.Errorf("String() with no chain = %q", got)
	}

	via := Resolution{Client: "192.168.1.81", Peer: "127.0.0.1", Via: "cloudflare", Chain: ips("172.70.1.1")}
	if got := via.String(); !strings.Contains(got, "via cloudflare") {
		t.Errorf("String() = %q, want it to name the provider", got)
	}

	missing := Resolution{Client: "172.70.1.1", Peer: "127.0.0.1", EdgeHeaderMissing: "cloudflare"}
	if got := missing.String(); !strings.Contains(got, "no usable client-IP header") {
		t.Errorf("String() = %q, want it to flag the missing edge header", got)
	}
}

// A client controls how many entries it prepends, so the log line must not. The
// entries kept must be the rightmost ones: those are the proxy-appended half,
// which is both the trustworthy half and the half that shows where the walk
// stopped. Truncating the other end would let a client blind the diagnostic by
// prepending junk.
func TestResolutionStringKeepsTheRightmostChainEntries(t *testing.T) {
	t.Parallel()

	chain := make([]net.IP, 0, maxLoggedChain+3)
	for i := 0; i < maxLoggedChain+1; i++ {
		chain = append(chain, net.ParseIP("10.9.9.9"))
	}
	chain = append(chain, net.ParseIP("192.168.1.81"), net.ParseIP("172.70.1.1"))

	got := Resolution{Client: "172.70.1.1", Peer: "127.0.0.1", Chain: chain}.String()

	for _, want := range []string{"192.168.1.81", "172.70.1.1", "+3 more"} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, want it to contain %q", got, want)
		}
	}
	if n := strings.Count(got, "10.9.9.9"); n != maxLoggedChain-2 {
		t.Errorf("String() = %q, kept %d prepended entries, want %d", got, n, maxLoggedChain-2)
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

	// With the edge trusted, CF-Connecting-IP supplies the visitor.
	withEdge := cloudflareResolver(t)
	_, ctx = acquireRawCtx(t, "127.0.0.1", request(chain, client))
	got := withEdge.Resolve(ctx)
	if got.Client != client {
		t.Errorf("Client = %q, want %q", got.Client, client)
	}
	if got.Via != "cloudflare" {
		t.Errorf("Via = %q, want cloudflare", got.Via)
	}
}

// Trusting a CDN's ranges re-opens the hole the right-to-left walk closes: the
// walk *skips* trusted entries, so a visitor whose own address is inside those
// ranges — one CDN zone proxying to another — gets its prepended entries reached
// and believed. CF-Connecting-IP is set by the edge and overwrites anything the
// visitor sent, so it is the one value such a visitor cannot choose.
func TestTrustedCDNTenantCannotSpoofTheClientAddress(t *testing.T) {
	resolver := cloudflareResolver(t)

	// The attacker's address as seen by the edge is itself a Cloudflare address,
	// and it prepends a whitelisted address hoping the walk reaches it.
	chain := "192.168.1.81, 162.158.0.1, 172.70.1.1"
	_, ctx := acquireRawCtx(t, "127.0.0.1", request(chain, "162.158.0.1"))

	if got := resolver.ClientIP(ctx); got != "162.158.0.1" {
		t.Errorf("ClientIP() = %q, want the edge-reported visitor 162.158.0.1", got)
	}
}

// A visitor sending its own CF-Connecting-IP is not a special case: the edge
// overwrites the line, so only one ever arrives. Two lines mean something other
// than the edge wrote one of them and neither can be attributed.
func TestAmbiguousEdgeHeaderIsNotBelieved(t *testing.T) {
	resolver := cloudflareResolver(t)

	raw := "GET /secret/db HTTP/1.1\r\nHost: target\r\n" +
		"X-Forwarded-For: 203.0.113.9, 172.70.1.1\r\n" +
		"CF-Connecting-IP: 192.168.1.81\r\n" +
		"CF-Connecting-IP: 203.0.113.9\r\n\r\n"
	_, ctx := acquireRawCtx(t, "127.0.0.1", raw)

	got := resolver.Resolve(ctx)
	if got.Client != "203.0.113.9" {
		t.Errorf("Client = %q, want the chain-walk answer 203.0.113.9; an ambiguous edge header must not be believed", got.Client)
	}
	if got.EdgeHeaderMissing != "cloudflare" {
		t.Errorf("EdgeHeaderMissing = %q, want cloudflare so the denial says why", got.EdgeHeaderMissing)
	}
}

// A proxy that strips the edge header must not take the deployment down; the
// walk degrades to X-Forwarded-For alone and records that it did.
func TestMissingEdgeHeaderDegradesToTheChainWalk(t *testing.T) {
	resolver := cloudflareResolver(t)

	_, ctx := acquireCtx(t, "127.0.0.1", "192.168.1.81, 172.70.1.1")
	got := resolver.Resolve(ctx)

	if got.Client != "192.168.1.81" {
		t.Errorf("Client = %q, want the chain-walk answer 192.168.1.81", got.Client)
	}
	if got.EdgeHeaderMissing != "cloudflare" {
		t.Errorf("EdgeHeaderMissing = %q, want cloudflare", got.EdgeHeaderMissing)
	}
}

// The header is only consulted for requests that actually arrived through the
// edge. Without a Cloudflare hop in the chain it is just another client-written
// header and must be ignored entirely.
func TestEdgeHeaderIsIgnoredWithoutAnEdgeHop(t *testing.T) {
	resolver := cloudflareResolver(t)

	_, ctx := acquireRawCtx(t, "127.0.0.1", request("203.0.113.9", "192.168.1.81"))
	if got := resolver.ClientIP(ctx); got != "203.0.113.9" {
		t.Errorf("ClientIP() = %q, want 203.0.113.9; CF-Connecting-IP must not be read off a non-CDN path", got)
	}
}

// The edge may also be the socket peer, when the provider reaches this service
// without a reverse proxy in between.
func TestEdgeHeaderIsUsedWhenTheEdgeIsThePeer(t *testing.T) {
	resolver := cloudflareResolver(t)

	_, ctx := acquireRawCtx(t, "172.70.1.1", request("", "192.168.1.81"))
	got := resolver.Resolve(ctx)
	if got.Client != "192.168.1.81" {
		t.Errorf("Client = %q, want 192.168.1.81", got.Client)
	}
	if got.Via != "cloudflare" {
		t.Errorf("Via = %q, want cloudflare", got.Via)
	}
}

// Same trailer-smuggling discipline as X-Forwarded-For: the edge header is read
// from the raw header block, so a trailer cannot supply it.
func TestEdgeHeaderIgnoresSmuggledTrailers(t *testing.T) {
	resolver := cloudflareResolver(t)

	raw := "POST /secret/db HTTP/1.1\r\nHost: target\r\n" +
		"X-Forwarded-For: 203.0.113.9, 172.70.1.1\r\n" +
		"Transfer-Encoding: chunked\r\nTrailer: CF-Connecting-IP\r\n\r\n" +
		"0\r\nCF-Connecting-IP: 192.168.1.81\r\n\r\n"
	_, ctx := acquireRawCtx(t, "127.0.0.1", raw)

	if got := resolver.ClientIP(ctx); got == "192.168.1.81" {
		t.Error("a trailer-supplied CF-Connecting-IP was believed")
	}
}

// cloudflareResolver trusts loopback plus the Cloudflare preset.
func cloudflareResolver(t *testing.T) *Resolver {
	t.Helper()
	provider, err := Preset("cloudflare")
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	r, err := New([]string{"127.0.0.1", "::1"}, provider)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

// request builds a raw request carrying an X-Forwarded-For chain and the
// Cloudflare edge header. Either may be empty to omit the line.
func request(forwardedFor, connectingIP string) string {
	var b strings.Builder
	b.WriteString("GET /secret/db HTTP/1.1\r\nHost: target\r\n")
	if forwardedFor != "" {
		b.WriteString("X-Forwarded-For: " + forwardedFor + "\r\n")
	}
	if connectingIP != "" {
		b.WriteString("CF-Connecting-IP: " + connectingIP + "\r\n")
	}
	b.WriteString("\r\n")
	return b.String()
}

func ips(addrs ...string) []net.IP {
	out := make([]net.IP, len(addrs))
	for i, a := range addrs {
		out[i] = net.ParseIP(a)
	}
	return out
}

func assertChain(t *testing.T, got []net.IP, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Chain = %v, want %v", got, want)
	}
	for i := range want {
		if got[i].String() != want[i] {
			t.Errorf("Chain[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

// A provider whose ranges are trusted with no header to verify against is the
// spoofing case Resolve documents, so it is refused rather than accepted.
func TestNewRejectsProviderRangesWithoutAClientIPHeader(t *testing.T) {
	t.Parallel()

	_, err := New(nil, Provider{Name: "headerless", Ranges: []string{"172.64.0.0/13"}})
	if err == nil {
		t.Fatal("New = nil error for ranges without a client-IP header, want an error")
	}
	if !strings.Contains(err.Error(), "headerless") {
		t.Errorf("error %q does not name the provider", err)
	}
}

// The header lookup rescans the raw header block, and the walk can reach an edge
// range once per chain entry — a count the client chooses. It must be read once.
func TestEdgeHeaderIsReadOncePerRequest(t *testing.T) {
	t.Parallel()

	provider, err := Preset("cloudflare")
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	resolver, err := New([]string{"127.0.0.1"}, provider)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Every entry but the last is inside a Cloudflare range, so an uncached
	// lookup would rescan the header block once per entry.
	chain := strings.TrimSuffix(strings.Repeat("172.70.1.1, ", 32), ", ") + ", 203.0.113.9"
	_, ctx := acquireCtx(t, "127.0.0.1", chain)

	cache := headerCache{ctx: ctx}
	e := &edge{name: "cloudflare", header: "CF-Connecting-IP"}
	for i := 0; i < 5; i++ {
		if _, ok := cache.clientIP(e); ok {
			t.Fatal("no CF-Connecting-IP was sent, yet one was reported")
		}
	}
	if len(cache.entries) != 1 {
		t.Errorf("cache holds %d entries after 5 lookups, want 1", len(cache.entries))
	}

	// The walk itself still lands on the untrusted tail entry.
	if got := resolver.ClientIP(ctx); got != "203.0.113.9" {
		t.Errorf("ClientIP() = %q, want 203.0.113.9", got)
	}
}
