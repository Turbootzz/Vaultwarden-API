package validators

import (
	"strings"
	"testing"
)

func TestIsValidFilterQueryValue(t *testing.T) {
	t.Parallel()

	// Test allowed length of filter query values
	longOK := strings.Repeat("a", SecretNameMaxLength)
	tooLong := strings.Repeat("a", SecretNameMaxLength+1)

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		// Add test cases here
		{"simple name", "Acme Corp", true},
		{"trimmed valid", "  Dev Team  ", true},
		{"unicode printable", "Team-α", true},
		{"max length", longOK, true},
		{"empty", "", false},
		{"whitespace only", "   ", false},
		{"too long", tooLong, false},
		{"newline", "bad\nname", false},
		{"tab", "bad\tname", false},
		{"del control", "bad\x7fname", false},
		{"null", "bad\x00name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsValidFilterQueryValue(tt.input); got != tt.want {
				t.Errorf("IsValidFilterQueryValue(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
