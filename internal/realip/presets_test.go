package realip

import (
	"net"
	"strings"
	"testing"
)

func TestPresetCloudflareCoversTheEdgeRanges(t *testing.T) {
	t.Parallel()

	ranges, err := Preset("cloudflare")
	if err != nil {
		t.Fatalf("Preset(cloudflare): %v", err)
	}
	if len(ranges) == 0 {
		t.Fatal("Preset(cloudflare) is empty")
	}

	r, err := New(ranges)
	if err != nil {
		t.Fatalf("New(preset ranges): %v", err)
	}

	// Addresses drawn from Cloudflare's published v4 and v6 blocks. If a refresh
	// of the embedded list ever drops one of these, that is a real regression.
	for _, ip := range []string{"172.70.1.1", "104.16.0.1", "162.158.0.1", "2606:4700::1", "2400:cb00::1"} {
		if !r.IsTrustedProxy(net.ParseIP(ip)) {
			t.Errorf("IsTrustedProxy(%s) = false, want true", ip)
		}
	}
	// The preset must stay a Cloudflare list, not a blanket allow.
	for _, ip := range []string{"203.0.113.9", "192.168.1.81", "2001:db8::1"} {
		if r.IsTrustedProxy(net.ParseIP(ip)) {
			t.Errorf("IsTrustedProxy(%s) = true, want false", ip)
		}
	}
}

func TestPresetNameIsNormalised(t *testing.T) {
	t.Parallel()

	for _, name := range []string{"cloudflare", "Cloudflare", "  CLOUDFLARE  "} {
		if _, err := Preset(name); err != nil {
			t.Errorf("Preset(%q): %v", name, err)
		}
	}
}

func TestPresetUnknownNameErrorsAndListsWhatExists(t *testing.T) {
	t.Parallel()

	_, err := Preset("cloudfare")
	if err == nil {
		t.Fatal("Preset(cloudfare) = nil error, want an error")
	}
	// The operator reached for a preset because the whitelist was already broken;
	// the error has to point at the fix rather than just say "no".
	if !strings.Contains(err.Error(), "cloudflare") {
		t.Errorf("error %q does not name the known presets", err)
	}
}

func TestPresetEmptyNameErrors(t *testing.T) {
	t.Parallel()

	if _, err := Preset("   "); err == nil {
		t.Error("Preset(blank) = nil error, want an error")
	}
}

// Callers append the preset to their own trusted list, so handing out the
// package's backing array would let one caller's append corrupt the next one's.
func TestPresetReturnsAnIndependentCopy(t *testing.T) {
	t.Parallel()

	first, err := Preset("cloudflare")
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	original := first[0]
	first[0] = "0.0.0.0/0"

	second, err := Preset("cloudflare")
	if err != nil {
		t.Fatalf("Preset: %v", err)
	}
	if second[0] != original {
		t.Errorf("Preset returned mutated data: got %q, want %q", second[0], original)
	}
}

func TestPresetNamesAreSortedAndResolvable(t *testing.T) {
	t.Parallel()

	names := PresetNames()
	if len(names) == 0 {
		t.Fatal("PresetNames() is empty")
	}
	for i, name := range names {
		if i > 0 && names[i-1] >= name {
			t.Errorf("PresetNames() = %v, want sorted unique names", names)
		}
		if _, err := Preset(name); err != nil {
			t.Errorf("Preset(%q) from PresetNames(): %v", name, err)
		}
	}
}
