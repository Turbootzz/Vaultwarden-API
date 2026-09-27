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

func TestIsValidSecretName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{"env style", "DATABASE_URL", true},
		{"brackets", "Database (prod)", true},
		{"ends with bracket", "GitHub (work)", true},
		{"leading dot", ".env", true},
		{"leading underscore", "_KEY", true},
		{"punctuation", "user@host+a:b,c&d'e", true},
		{"slash", "path/to/secret", true},
		{"single char", "x", true},
		{"max length", strings.Repeat("a", SecretNameMaxLength), true},
		{"empty", "", false},
		{"too long", strings.Repeat("a", SecretNameMaxLength+1), false},
		{"leading space", " name", false},
		{"trailing space", "name ", false},
		{"dot dot", "a..b", false},
		{"tab", "bad\tname", false},
		{"newline", "bad\nname", false},
		{"del", "bad\x7fname", false},
		{"null", "bad\x00name", false},
		{"non-ascii", "Café", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsValidSecretName(tt.input); got != tt.want {
				t.Errorf("IsValidSecretName(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
