// Package common provides shared utilities for the BlackPoint CLI application
package common

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Log levels
const (
	LogLevelDebug = "debug"
	LogLevelInfo  = "info"
	LogLevelWarn  = "warn"
	LogLevelError = "error"
)

// Default configuration values
const (
	defaultRotationSize  = 10 * 1024 * 1024 // 10MB
	defaultRetentionDays = 30
	defaultBufferSize    = 1024
)

// LogConfig holds configuration for the logger
type LogConfig struct {
	FilePath      string
	RotationSize  int64
	RetentionDays int
	BufferSize    int
	Format        string
	Level         string
}

// LogBuffer implements buffered logging with thread-safe operations
type LogBuffer struct {
	buffer []string
	size   int
	mu     sync.Mutex
}

// LogRotator handles log file rotation and retention
type LogRotator struct {
	filePath      string
	maxSize       int64
	retentionDays int
	currentSize   int64
	mu           sync.Mutex
}

// Logger provides thread-safe structured logging functionality
type Logger struct {
	level     string
	format    string
	stdLogger *log.Logger
	mu        sync.Mutex
	buffer    *LogBuffer
	rotator   *LogRotator
	config    LogConfig
}

// Global logger instance
var logger *Logger

// LogEntry represents a structured log entry
type LogEntry struct {
	Timestamp string                 `json:"timestamp"`
	Level     string                 `json:"level"`
	Message   string                 `json:"message"`
	Fields    map[string]interface{} `json:"fields,omitempty"`
}

// InitLogger initializes the global logger instance
func InitLogger(level, format string, config *LogConfig) error {
	if config == nil {
		config = &LogConfig{
			Level:         DefaultLogLevel,
			Format:        "text",
			RotationSize:  defaultRotationSize,
			RetentionDays: defaultRetentionDays,
			BufferSize:    defaultBufferSize,
		}
	}

	l, err := newLogger(level, format, config)
	if err != nil {
		return NewCLIError("E2001", "Failed to initialize logger", err)
	}

	logger = l
	return nil
}

// newLogger creates a new Logger instance
func newLogger(level, format string, config *LogConfig) (*Logger, error) {
	if !isValidLogLevel(level) {
		return nil, NewCLIError("E2002", "Invalid log level", nil)
	}

	var output io.Writer = os.Stdout
	if config.FilePath != "" {
		file, err := setupLogFile(config.FilePath)
		if err != nil {
			return nil, err
		}
		output = file
	}

	l := &Logger{
		level:     level,
		format:    format,
		stdLogger: log.New(output, "", 0),
		buffer:    newLogBuffer(config.BufferSize),
		config:    *config,
	}

	if config.FilePath != "" {
		l.rotator = &LogRotator{
			filePath:      config.FilePath,
			maxSize:       config.RotationSize,
			retentionDays: config.RetentionDays,
		}
		go l.startRotationCheck()
	}

	return l, nil
}

// Debug logs a debug level message
func (l *Logger) Debug(msg string, fields map[string]interface{}) {
	if l.shouldLog(LogLevelDebug) {
		l.log(LogLevelDebug, msg, fields, nil)
	}
}

// Info logs an info level message
func (l *Logger) Info(msg string, fields map[string]interface{}) {
	if l.shouldLog(LogLevelInfo) {
		l.log(LogLevelInfo, msg, fields, nil)
	}
}

// Warn logs a warning level message
func (l *Logger) Warn(msg string, fields map[string]interface{}) {
	if l.shouldLog(LogLevelWarn) {
		l.log(LogLevelWarn, msg, fields, nil)
	}
}

// Error logs an error level message
func (l *Logger) Error(msg string, err error, fields map[string]interface{}) {
	if l.shouldLog(LogLevelError) {
		if fields == nil {
			fields = make(map[string]interface{})
		}
		if err != nil {
			fields["error"] = err.Error()
			if cliErr, ok := err.(*CLIError); ok {
				fields["error_code"] = cliErr.Code
				fields["stack_trace"] = cliErr.StackTraceString()
			}
		}
		l.log(LogLevelError, msg, fields, nil)
	}
}

// WithContext creates a new log entry with context
func (l *Logger) WithContext(ctx context.Context) *Logger {
	return l
}

// WithFields creates a new log entry with predefined fields
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	return l
}

// log performs the actual logging operation
func (l *Logger) log(level, msg string, fields map[string]interface{}, ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := l.formatEntry(level, msg, fields, ctx)
	if l.buffer != nil {
		l.buffer.append(entry)
	}
	l.stdLogger.Println(entry)
}

// formatEntry formats a log entry based on the configured format
func (l *Logger) formatEntry(level, msg string, fields map[string]interface{}, ctx context.Context) string {
	entry := LogEntry{
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
		Level:     level,
		Message:   msg,
		Fields:    fields,
	}

	if l.format == "json" {
		if jsonBytes, err := json.Marshal(entry); err == nil {
			return string(jsonBytes)
		}
	}

	// Default to text format
	text := fmt.Sprintf("[%s] %s - %s", entry.Timestamp, level, msg)
	if len(fields) > 0 {
		text += fmt.Sprintf(" | %v", fields)
	}
	return text
}

// shouldLog determines if a message should be logged based on level
func (l *Logger) shouldLog(level string) bool {
	levels := map[string]int{
		LogLevelDebug: 0,
		LogLevelInfo:  1,
		LogLevelWarn:  2,
		LogLevelError: 3,
	}
	return levels[level] >= levels[l.level]
}

// setupLogFile creates and sets up the log file
func setupLogFile(filePath string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return nil, NewCLIError("E2003", "Failed to create log directory", err)
	}
	return os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

// isValidLogLevel validates the log level
func isValidLogLevel(level string) bool {
	validLevels := map[string]bool{
		LogLevelDebug: true,
		LogLevelInfo:  true,
		LogLevelWarn:  true,
		LogLevelError: true,
	}
	return validLevels[level]
}

// newLogBuffer creates a new log buffer
func newLogBuffer(size int) *LogBuffer {
	return &LogBuffer{
		buffer: make([]string, 0, size),
		size:   size,
	}
}

// append adds an entry to the buffer
func (b *LogBuffer) append(entry string) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.buffer) >= b.size {
		b.buffer = b.buffer[1:]
	}
	b.buffer = append(b.buffer, entry)
}

// startRotationCheck starts the log rotation check routine
func (l *Logger) startRotationCheck() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		if err := l.checkRotation(); err != nil {
			l.Error("Failed to rotate log file", err, nil)
		}
	}
}

// checkRotation checks and performs log rotation if needed
func (l *Logger) checkRotation() error {
	l.rotator.mu.Lock()
	defer l.rotator.mu.Unlock()

	if info, err := os.Stat(l.rotator.filePath); err == nil {
		if info.Size() >= l.rotator.maxSize {
			return l.rotateLog()
		}
	}
	return nil
}

// rotateLog performs the actual log rotation
func (l *Logger) rotateLog() error {
	timestamp := time.Now().Format("20060102-150405")
	rotatedPath := fmt.Sprintf("%s.%s", l.rotator.filePath, timestamp)
	
	if err := os.Rename(l.rotator.filePath, rotatedPath); err != nil {
		return NewCLIError("E2004", "Failed to rotate log file", err)
	}

	file, err := setupLogFile(l.rotator.filePath)
	if err != nil {
		return err
	}

	l.mu.Lock()
	l.stdLogger.SetOutput(file)
	l.mu.Unlock()

	go l.cleanOldLogs()
	return nil
}

// cleanOldLogs removes logs older than retention period
func (l *Logger) cleanOldLogs() {
	dir := filepath.Dir(l.rotator.filePath)
	pattern := filepath.Base(l.rotator.filePath) + ".*"
	
	matches, err := filepath.Glob(filepath.Join(dir, pattern))
	if err != nil {
		l.Error("Failed to list old log files", err, nil)
		return
	}

	cutoff := time.Now().AddDate(0, 0, -l.rotator.retentionDays)
	for _, match := range matches {
		if info, err := os.Stat(match); err == nil {
			if info.ModTime().Before(cutoff) {
				if err := os.Remove(match); err != nil {
					l.Error("Failed to remove old log file", err, map[string]interface{}{"file": match})
				}
			}
		}
	}
}