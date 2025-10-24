package validators

import (
	"regexp"
	"strings"
)

const SecretNameMaxLength = 255

var SecretNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_\-\./]*[a-zA-Z0-9]$`)

func IsValidSecretName(name string) bool {
	if len(name) == 0 || len(name) > SecretNameMaxLength {
		return false
	}

	if strings.Contains(name, "..") || strings.Contains(name, "\x00") {
		return false
	}

	for _, ch := range name {
		if ch < 32 || ch > 126 {
			return false
		}
	}

	return SecretNamePattern.MatchString(name)
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