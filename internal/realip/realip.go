// Package realip resolves the originating client address of a request that may
// have travelled through trusted reverse proxies.
package realip

import (
	"fmt"
	"net"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// Resolver matches addresses against the configured set of trusted proxies.
type Resolver struct {
	trusted []*net.IPNet
}

// New builds a resolver from IP addresses and CIDR ranges. A bare address is
// treated as a single-host range.
func New(trustedProxies []string) (*Resolver, error) {
	r := &Resolver{}
	for _, entry := range trustedProxies {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		network, err := parseNetwork(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid trusted proxy %q: %w", entry, err)
		}
		r.trusted = append(r.trusted, network)
	}
	return r, nil
}

func parseNetwork(s string) (*net.IPNet, error) {
	if strings.Contains(s, "/") {
		_, network, err := net.ParseCIDR(s)
		if err != nil {
			return nil, err
		}
		return network, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("not a valid IP address or CIDR range")
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// IsTrustedProxy reports whether ip belongs to a configured proxy.
func (r *Resolver) IsTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, network := range r.trusted {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// maxLoggedChain caps how many forwarded entries String reports. The client
// controls how many entries it prepends, so an uncapped log line is a client-
// controlled amount of output.
const maxLoggedChain = 8

// Resolution is the outcome of resolving one request's client address, together
// with the inputs it was derived from.
//
// The inputs are what makes a denied request diagnosable: "blocked 172.70.1.1"
// reads like a whitelist typo, while the same line carrying the socket peer and
// the forwarded chain shows an untrusted hop terminating the walk (#40).
type Resolution struct {
	// Client is the resolved originating address.
	Client string
	// Peer is the socket address the request arrived from.
	Peer string
	// Chain holds the parseable X-Forwarded-For entries, in header order.
	Chain []string
}

// String renders the resolution for a log line, truncating a long chain.
func (r Resolution) String() string {
	chain := r.Chain
	suffix := ""
	if len(chain) > maxLoggedChain {
		suffix = fmt.Sprintf(" +%d more", len(chain)-maxLoggedChain)
		chain = chain[:maxLoggedChain]
	}
	return fmt.Sprintf("resolved %s, peer %s, xff=[%s%s]", r.Client, r.Peer, strings.Join(chain, " "), suffix)
}

// ClientIP returns the originating client address for c.
func (r *Resolver) ClientIP(c *fiber.Ctx) string {
	return r.Resolve(c).Client
}

// Resolve determines the originating client address for c and reports the
// inputs it used.
//
// The socket peer wins unless it is itself a trusted proxy. For a trusted peer
// the X-Forwarded-For chain is walked right to left and the first entry that is
// not a trusted proxy is the client. The direction is what makes the result
// unspoofable: a client can prepend anything it likes to the header, but it
// cannot forge the entries the trusted proxies appended after it. Reading the
// header left to right — as fiber's c.IP() does — hands an attacker the answer.
//
// Every hop between the client and this service must therefore be trusted, CDN
// edges included; an untrusted hop is where the walk stops and becomes the
// answer. A chain of nothing but trusted proxies falls back to the peer.
func (r *Resolver) Resolve(c *fiber.Ctx) Resolution {
	peer := c.Context().RemoteIP()
	res := Resolution{Peer: peer.String()}

	if !r.IsTrustedProxy(peer) {
		res.Client = res.Peer
		return res
	}

	forwarded := forwardedFor(c)
	res.Chain = make([]string, len(forwarded))
	for i, ip := range forwarded {
		res.Chain[i] = ip.String()
	}

	res.Client = res.Peer
	for i := len(forwarded) - 1; i >= 0; i-- {
		if !r.IsTrustedProxy(forwarded[i]) {
			res.Client = res.Chain[i]
			break
		}
	}
	return res
}

// forwardedFor extracts the valid addresses from the request's X-Forwarded-For
// header lines, in order. Malformed entries are dropped rather than aborting the
// parse, so a client cannot hide the proxy-appended entries behind junk.
//
// Every line is read, not just the first: a proxy is free to add its own header
// line rather than extend the client's (HAProxy's forwardfor does), and reading
// only the first would hand back the line the client wrote.
//
// The lines come from the raw header block rather than Header.PeekAll, because
// fasthttp merges HTTP/1.1 chunked *request trailers* into the same lookup table
// and X-Forwarded-For is not on its forbidden-trailer list. Trailer values land
// after every genuine header, which is exactly the position the right-to-left
// walk trusts, so a client could smuggle its chosen address past a proxy that
// forwards trailers. Header.RawHeaders() is filled during header parsing only
// and never by the trailer reader, so it holds what the proxy actually sent.
func forwardedFor(c *fiber.Ctx) []net.IP {
	var ips []net.IP
	for _, value := range rawForwardedForValues(c.Request().Header.RawHeaders()) {
		for _, part := range strings.Split(value, ",") {
			if ip := parseHeaderIP(part); ip != nil {
				ips = append(ips, ip)
			}
		}
	}
	return ips
}

// rawForwardedForValues returns the value of every X-Forwarded-For line in a raw
// HTTP/1.1 header block, in order.
//
// Obsolete line folding is honoured rather than discarded: a continuation line
// belongs to the header above it, and dropping one could remove the entry a
// proxy appended and promote a client-written entry to the right-hand end.
func rawForwardedForValues(raw []byte) []string {
	var out []string
	inTarget := false

	for _, line := range strings.Split(string(raw), "\r\n") {
		if line == "" {
			inTarget = false
			continue
		}

		if line[0] == ' ' || line[0] == '\t' {
			if inTarget && len(out) > 0 {
				out[len(out)-1] += " " + strings.TrimSpace(line)
			}
			continue
		}

		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			inTarget = false
			continue
		}
		// No TrimSpace on the name: whitespace before the colon is not a valid
		// header, and accepting it would honour a line the server itself did not.
		if strings.EqualFold(line[:colon], fiber.HeaderXForwardedFor) {
			inTarget = true
			out = append(out, line[colon+1:])
			continue
		}
		inTarget = false
	}

	return out
}

// parseHeaderIP parses one X-Forwarded-For element, tolerating the host:port and
// [v6]:port forms some proxies emit.
func parseHeaderIP(s string) net.IP {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		return net.ParseIP(host)
	}
	return nil
}

// ctxKey is the unexported type for the resolution in the request context.
type ctxKey struct{}

var clientIPKey ctxKey

// Middleware resolves the client address once per request and stores it for
// FromCtx. It must run before any middleware that makes decisions on client IP.
func Middleware(r *Resolver) fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Locals(clientIPKey, r.Resolve(c))
		return c.Next()
	}
}

// FromCtx returns the address resolved by Middleware, falling back to fiber's
// own c.IP() when the middleware is not installed.
func FromCtx(c *fiber.Ctx) string {
	return ResolutionFromCtx(c).Client
}

// ResolutionFromCtx returns the resolution stored by Middleware. Without the
// middleware installed it falls back to fiber's own c.IP(), reporting no chain
// rather than one this package did not verify.
func ResolutionFromCtx(c *fiber.Ctx) Resolution {
	if res, ok := c.Locals(clientIPKey).(Resolution); ok && res.Client != "" {
		return res
	}
	ip := c.IP()
	return Resolution{Client: ip, Peer: ip}
}
