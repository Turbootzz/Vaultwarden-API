package realip

import (
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// cloudflareIPs holds Cloudflare's published edge ranges. It is embedded rather
// than fetched at startup so that resolving the trusted proxy set never depends
// on the network: a fetch that failed would leave the edge untrusted, which is
// exactly the outage this preset exists to prevent.
//
//go:embed cloudflare_ips.txt
var cloudflareIPs string

// Provider is a fronting network placed in front of this service: a set of edge
// ranges to trust as proxies, and the header its edge uses to publish the
// visitor address.
type Provider struct {
	// Name identifies the provider in configuration and log lines.
	Name string
	// Ranges are the provider's edge networks, as IPs or CIDRs.
	Ranges []string
	// ClientIPHeader is set by the edge and overwrites any line the visitor
	// sent, which is what makes it trustworthy where X-Forwarded-For is not.
	// Empty means the provider publishes no such header.
	ClientIPHeader string
}

// presetSources maps a preset name to its raw range list and client-IP header.
var presetSources = map[string]struct {
	ranges string
	header string
}{
	// https://developers.cloudflare.com/fundamentals/reference/http-headers/
	"cloudflare": {ranges: cloudflareIPs, header: "CF-Connecting-IP"},
}

var (
	presetOnce sync.Once
	presets    map[string]Provider
	presetErr  error
)

// Preset returns the provider published under name.
//
// A CDN or load balancer in front of the service is a hop like any other: it
// appends the address it saw to X-Forwarded-For, so the right-to-left walk in
// Resolve stops at the edge address unless the edge's own ranges are trusted.
// Presets spare the operator from hand-maintaining a provider's range list, and
// carry the client-IP header that keeps the result unspoofable once those broad
// ranges are trusted (see #40 and Resolve).
func Preset(name string) (Provider, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return Provider{}, fmt.Errorf("empty trusted proxy preset name (known presets: %s)", strings.Join(PresetNames(), ", "))
	}

	parsed, err := parsedPresets()
	if err != nil {
		return Provider{}, err
	}

	p, ok := parsed[key]
	if !ok {
		return Provider{}, fmt.Errorf("unknown trusted proxy preset %q (known presets: %s)", name, strings.Join(PresetNames(), ", "))
	}

	// Callers append their own entries to the ranges, so hand back a copy.
	p.Ranges = append([]string(nil), p.Ranges...)
	return p, nil
}

// PresetNames returns the known preset names in sorted order.
func PresetNames() []string {
	names := make([]string, 0, len(presetSources))
	for name := range presetSources {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func parsedPresets() (map[string]Provider, error) {
	presetOnce.Do(func() {
		presets = make(map[string]Provider, len(presetSources))
		for name, src := range presetSources {
			ranges, err := parseRangeList(src.ranges)
			if err != nil {
				// The list is embedded, so this is a botched refresh rather than
				// operator input. Say which preset, or the failure surfaces later
				// as an unattributed "invalid trusted proxy" and sends the
				// operator to audit their own TRUSTED_PROXY_IP.
				presetErr = fmt.Errorf("preset %q: %w", name, err)
				return
			}
			presets[name] = Provider{Name: name, Ranges: ranges, ClientIPHeader: src.header}
		}
	})
	return presets, presetErr
}

// parseRangeList reads one CIDR per line, ignoring blank lines and # comments.
// Every entry is validated here so a corrupt list fails where it can be named.
func parseRangeList(raw string) ([]string, error) {
	var out []string
	for i, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, err := parseNetwork(line); err != nil {
			return nil, fmt.Errorf("line %d: invalid range %q: %w", i+1, line, err)
		}
		out = append(out, line)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no ranges")
	}
	return out, nil
}
