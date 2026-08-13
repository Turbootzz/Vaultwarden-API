// Package logtest captures package-level logger output in tests.
//
// Assertions on log lines are how several packages pin diagnostics that exist
// for the operator rather than the caller — the blocked-IP warning, the failed
// secret lookup. Each of them needs the same two things: a buffer that survives
// being written by a handler goroutine while the test reads it, and the
// SetOutput/restore dance around it.
package logtest

import (
	"bytes"
	"log"
	"sync"
	"testing"
)

// Buffer is a bytes.Buffer safe for concurrent use. A handler running on the
// server goroutine writes it while the test goroutine reads, with nothing
// ordering the two — a plain bytes.Buffer there is a data race whether or not
// the detector happens to observe it.
type Buffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns everything written so far.
func (b *Buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// Capture redirects each logger into its own buffer for the rest of the test,
// restoring the previous writers on cleanup. The buffers are returned in the
// order the loggers were given.
//
// Capture every level a code path might take, not only the expected one: a test
// that redirects Warn alone still passes its "no secret value is logged"
// assertion when a regression moves the line to Error, because the leak then
// goes to the real stderr where nothing inspects it.
func Capture(t *testing.T, loggers ...*log.Logger) []*Buffer {
	t.Helper()

	buffers := make([]*Buffer, len(loggers))
	for i, l := range loggers {
		buf := &Buffer{}
		previous := l.Writer()
		l.SetOutput(buf)
		t.Cleanup(func() { l.SetOutput(previous) })
		buffers[i] = buf
	}
	return buffers
}
