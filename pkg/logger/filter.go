package logger

import (
	"io"
	"log"
	"strings"
)

// filterWriter silences specific TLS errors.
type FilterWriter struct {
	w io.Writer
}

func (f *FilterWriter) Write(p []byte) (n int, err error) {
	if strings.Contains(string(p), "remote error: tls: unknown certificate") {
		return len(p), nil
	}
	return f.w.Write(p)
}

func FilterLogger(w io.Writer) *log.Logger {
	return log.New(&FilterWriter{w: w}, "", log.LstdFlags)
}



type DiscardWriter struct {
}

func (d *DiscardWriter) Write(p []byte) (n int, err error) {
	return len(p), nil
}