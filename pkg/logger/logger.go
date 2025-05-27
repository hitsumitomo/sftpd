package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	LevelInfo  string = "INF"
	LevelError string = "ERR"
	LevelWarn  string = "WRN"
	LevelDebug string = "DBG"
)

type Logger struct {
	mu        sync.Mutex
	file      *os.File
	skipDebug bool
}

var logger *Logger

func New(target string, globalLevel ...string) *Logger {
	if target == "stdout" {
		return &Logger{
			file:      os.Stdout,
			skipDebug: len(globalLevel) > 0 && globalLevel[0] != "debug",
		}
	}

	_ = os.MkdirAll(filepath.Dir(target), 0755)
	f, err := os.OpenFile(target, os.O_APPEND | os.O_CREATE | os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("failed to open log file %s: %v\n", target, err)
		logger = &Logger{}
		return logger
	}

	logger = &Logger{
		file: f,
		skipDebug: len(globalLevel) > 0 && globalLevel[0] != "debug",
	}
	return logger
}

func Get() *Logger {
	return logger
}

func (l *Logger) logf(level string, format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return
	}

	format = time.Now().Format(time.DateTime) + " " + level + " " + format + "\n"

	if len(args) > 0 {
		fmt.Fprintf(l.file, format, args...)

	} else {
		l.file.WriteString(format)
	}
}

func (l *Logger) Print(format string, args ...any) {
	l.logf(LevelInfo, format, args...)
}

func (l *Logger) Info(format string, args ...any) {
	l.logf(LevelInfo, format, args...)
}

func (l *Logger) Error(format string, args ...any) {
	l.logf(LevelError, format, args...)
}

func (l *Logger) Warn(format string, args ...any) {
	l.logf(LevelWarn, format, args...)
}

func (l *Logger) Debug(format string, args ...any) {
	if l.skipDebug {
		return
	}
	l.logf(LevelDebug, format, args...)
}

func (l *Logger) Fatal(format string, args ...any) {
	l.logf(LevelError, format, args...)
	os.Exit(1)
}

func (l *Logger) Dump(v any) {
	if l.skipDebug {
		return
	}
	data, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		l.logf(LevelError, "Dump marshal error: %v", err)
		return
	}
	l.logf(LevelDebug, string(data))
}
