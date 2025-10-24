// Package logger provides structured logging for the application
package logger

import (
	"io"
	"log"
	"os"
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
