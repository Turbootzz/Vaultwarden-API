// Package validators provides input validation for secret names
package validators

import (
	"strings"
)

const SecretNameMaxLength = 255

// IsValidSecretName accepts printable ASCII: the name is only compared against
// decrypted vault item names, so the rule exists to keep control bytes out of logs.
func IsValidSecretName(name string) bool {
	if len(name) == 0 || len(name) > SecretNameMaxLength {
		return false
	}

	if strings.Contains(name, "..") || name[0] == ' ' || name[len(name)-1] == ' ' {
		return false
	}

	for _, ch := range name {
		if ch < 32 || ch > 126 {
			return false
		}
	}

	return true
}

func SanitizeSecretName(name string) (string, bool) {
	name = strings.TrimSpace(name)

	cleaned := strings.Map(func(r rune) rune {
		if r >= 32 && r <= 126 {
			return r
		}
		return -1
	}, name)

	if IsValidSecretName(cleaned) {
		return cleaned, true
	}

	return "", false
}

func IsValidFilterQueryValue(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > SecretNameMaxLength {
		return false
	}
	for _, r := range s {
		if r < 32 || r == 127 {
			return false
		}
	}
	return true
}
