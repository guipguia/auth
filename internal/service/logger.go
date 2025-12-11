package service

import (
	"log"
	"os"
)

// Logger defines a simple logging interface for the auth service
type Logger interface {
	// Error logs an error message with optional context
	Error(msg string, keysAndValues ...interface{})
	// Warn logs a warning message with optional context
	Warn(msg string, keysAndValues ...interface{})
	// Info logs an info message with optional context
	Info(msg string, keysAndValues ...interface{})
	// Debug logs a debug message with optional context
	Debug(msg string, keysAndValues ...interface{})
}

// DefaultLogger provides a simple default implementation using the standard library
type DefaultLogger struct {
	logger *log.Logger
	level  LogLevel
}

// LogLevel represents the logging level
type LogLevel int

const (
	LogLevelDebug LogLevel = iota
	LogLevelInfo
	LogLevelWarn
	LogLevelError
)

// NewDefaultLogger creates a new default logger
func NewDefaultLogger(level LogLevel) *DefaultLogger {
	return &DefaultLogger{
		logger: log.New(os.Stderr, "", log.LstdFlags|log.Lmicroseconds),
		level:  level,
	}
}

func (l *DefaultLogger) Error(msg string, keysAndValues ...interface{}) {
	if l.level <= LogLevelError {
		l.logger.Printf("[ERROR] %s %v", msg, formatKeyValues(keysAndValues))
	}
}

func (l *DefaultLogger) Warn(msg string, keysAndValues ...interface{}) {
	if l.level <= LogLevelWarn {
		l.logger.Printf("[WARN] %s %v", msg, formatKeyValues(keysAndValues))
	}
}

func (l *DefaultLogger) Info(msg string, keysAndValues ...interface{}) {
	if l.level <= LogLevelInfo {
		l.logger.Printf("[INFO] %s %v", msg, formatKeyValues(keysAndValues))
	}
}

func (l *DefaultLogger) Debug(msg string, keysAndValues ...interface{}) {
	if l.level <= LogLevelDebug {
		l.logger.Printf("[DEBUG] %s %v", msg, formatKeyValues(keysAndValues))
	}
}

// formatKeyValues formats key-value pairs for logging
func formatKeyValues(keysAndValues []interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for i := 0; i < len(keysAndValues)-1; i += 2 {
		key, ok := keysAndValues[i].(string)
		if ok {
			result[key] = keysAndValues[i+1]
		}
	}
	return result
}

// NopLogger is a no-op logger that discards all log messages
type NopLogger struct{}

func (l *NopLogger) Error(msg string, keysAndValues ...interface{}) {}
func (l *NopLogger) Warn(msg string, keysAndValues ...interface{})  {}
func (l *NopLogger) Info(msg string, keysAndValues ...interface{})  {}
func (l *NopLogger) Debug(msg string, keysAndValues ...interface{}) {}
