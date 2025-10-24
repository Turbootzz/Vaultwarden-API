package logger

import (
	"io"
	"log"
	"os"
	"strings"
)

var (
	Debug *log.Logger
	Info  *log.Logger
	Warn  *log.Logger
	Error *log.Logger
)

func init() {
	// Check if DEBUG mode is enabled
	debugEnabled := os.Getenv("DEBUG") == "true"

	if debugEnabled {
		Debug = log.New(os.Stdout, "DEBUG: ", log.Ldate|log.Ltime|log.Lshortfile)
	} else {
		// Discard debug logs in production
		Debug = log.New(io.Discard, "", 0)
	}

	Info = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	Warn = log.New(os.Stdout, "WARN: ", log.Ldate|log.Ltime|log.Lshortfile)
	Error = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

// Sanitize removes sensitive data from log messages
// This prevents accidental logging of secrets, tokens, or API keys
func Sanitize(msg string) string {
	// List of sensitive keywords to redact
	sensitive := []string{"token", "key", "password", "secret", "apikey", "bearer"}

	lower := strings.ToLower(msg)
	for _, keyword := range sensitive {
		if strings.Contains(lower, keyword) {
			return "[REDACTED - Contains sensitive data]"
		}
	}
	return msg
}

// InfoSafe logs an info message after sanitizing it
func InfoSafe(format string, v ...interface{}) {
	Info.Printf(Sanitize(format), v...)
}

// WarnSafe logs a warning message after sanitizing it
func WarnSafe(format string, v ...interface{}) {
	Warn.Printf(Sanitize(format), v...)
}

// ErrorSafe logs an error message after sanitizing it
func ErrorSafe(format string, v ...interface{}) {
	Error.Printf(Sanitize(format), v...)
}
