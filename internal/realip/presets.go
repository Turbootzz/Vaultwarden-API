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

// presetSources maps a preset name to its raw range list.
var presetSources = map[string]string{
	"cloudflare": cloudflareIPs,
}

var (
	presetOnce   sync.Once
	presetParsed map[string][]string
)

// Preset returns the trusted proxy ranges published under name.
//
// A CDN or load balancer in front of the service is a hop like any other: it
// appends the address it saw to X-Forwarded-For, so the right-to-left walk in
// ClientIP stops at the edge address unless the edge's own ranges are trusted.
// Presets spare the operator from hand-maintaining a provider's range list
// (see #40).
//
// Trusting a provider's ranges means anything connecting from inside them can
// assert a client address. For a CDN that risk is bounded by the fact that the
// edge appends the visitor address it observed, so a visitor's own prepended
// entries stay to the left of it and are still ignored — but it does mean the
// origin should only accept traffic from the CDN (authenticated origin pulls or
// a tunnel), or an attacker can reach it directly and skip the edge entirely.
func Preset(name string) ([]string, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		return nil, fmt.Errorf("empty trusted proxy preset name (known presets: %s)", strings.Join(PresetNames(), ", "))
	}

	ranges, ok := parsedPresets()[key]
	if !ok {
		return nil, fmt.Errorf("unknown trusted proxy preset %q (known presets: %s)", name, strings.Join(PresetNames(), ", "))
	}

	// Callers append their own entries to the result, so hand back a copy.
	return append([]string(nil), ranges...), nil
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

func parsedPresets() map[string][]string {
	presetOnce.Do(func() {
		presetParsed = make(map[string][]string, len(presetSources))
		for name, raw := range presetSources {
			presetParsed[name] = parseRangeList(raw)
		}
	})
	return presetParsed
}

// parseRangeList reads one CIDR per line, ignoring blank lines and # comments.
func parseRangeList(raw string) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}
