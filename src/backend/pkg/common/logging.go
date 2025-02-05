// Package common provides shared utilities for the BlackPoint Security Integration Framework
package common

import (
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/blackpoint/pkg/common" // Internal errors package
	"go.uber.org/zap"                  // v1.24.0
	"go.uber.org/zap/zapcore"          // v1.24.0
	"gopkg.in/natefinch/lumberjack.v2" // v2.0.0
)

// Global variables for logger management
var (
	logger              *zap.Logger
	logConfig           LogConfig
	securityAuditEnabled bool
	sensitiveDataPatterns []string
	loggerMutex        sync.RWMutex
)

// MonitoringConfig defines monitoring integration settings
type MonitoringConfig struct {
	MetricsEnabled bool
	MetricsPrefix  string
	TraceEnabled   bool
	TraceSampling  float64
}

// LogConfig defines enhanced logging configuration with security and monitoring settings
type LogConfig struct {
	Level                string
	Environment          string
	OutputPath           string
	MaxSize             int  // megabytes
	MaxBackups          int  // number of backups
	MaxAge              int  // days
	Compress            bool
	EnableSecurityAudit bool
	EnableMonitoring    bool
	SensitiveDataPatterns []string
	MonitoringSettings   MonitoringConfig
}

// NewLogConfig creates a new LogConfig with security-aware defaults
func NewLogConfig() LogConfig {
	return LogConfig{
		Level:                "info",
		Environment:          "development",
		OutputPath:           "logs/blackpoint.log",
		MaxSize:             100,
		MaxBackups:          10,
		MaxAge:              30,
		Compress:            true,
		EnableSecurityAudit: true,
		EnableMonitoring:    true,
		SensitiveDataPatterns: []string{
			`password=\S+`,
			`key=\S+`,
			`token=\S+`,
			`secret=\S+`,
		},
		MonitoringSettings: MonitoringConfig{
			MetricsEnabled: true,
			MetricsPrefix:  "blackpoint_logging",
			TraceEnabled:   true,
			TraceSampling:  0.1,
		},
	}
}

// Validate validates the logging configuration
func (c *LogConfig) Validate() error {
	if c.Level == "" {
		return common.NewError("E4001", "log level must be specified", nil)
	}

	// Ensure output directory exists
	dir := filepath.Dir(c.OutputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return common.WrapError(err, "failed to create log directory", nil)
	}

	// Validate rotation settings
	if c.MaxSize <= 0 {
		return common.NewError("E4001", "invalid MaxSize value", nil)
	}
	if c.MaxBackups < 0 {
		return common.NewError("E4001", "invalid MaxBackups value", nil)
	}
	if c.MaxAge < 0 {
		return common.NewError("E4001", "invalid MaxAge value", nil)
	}

	// Compile sensitive data patterns
	for _, pattern := range c.SensitiveDataPatterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return common.WrapError(err, "invalid sensitive data pattern", map[string]interface{}{
				"pattern": pattern,
			})
		}
	}

	return nil
}

// InitLogger initializes the global logger with security and monitoring integration
func InitLogger(config LogConfig) error {
	loggerMutex.Lock()
	defer loggerMutex.Unlock()

	if err := config.Validate(); err != nil {
		return err
	}

	// Configure log rotation
	rotator := &lumberjack.Logger{
		Filename:   config.OutputPath,
		MaxSize:    config.MaxSize,
		MaxBackups: config.MaxBackups,
		MaxAge:     config.MaxAge,
		Compress:   config.Compress,
	}

	// Configure encoder with security-aware defaults
	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "timestamp",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "message",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.SecondsDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	}

	// Set log level
	var level zapcore.Level
	if err := level.UnmarshalText([]byte(config.Level)); err != nil {
		return common.WrapError(err, "invalid log level", nil)
	}

	// Create core with file and console output
	core := zapcore.NewTee(
		zapcore.NewCore(
			zapcore.NewJSONEncoder(encoderConfig),
			zapcore.AddSync(rotator),
			level,
		),
		zapcore.NewCore(
			zapcore.NewConsoleEncoder(encoderConfig),
			zapcore.AddSync(os.Stdout),
			level,
		),
	)

	// Create logger with security options
	logger = zap.New(core,
		zap.AddCaller(),
		zap.AddStacktrace(zapcore.ErrorLevel),
		zap.Fields(
			zap.String("environment", config.Environment),
			zap.Time("startup_time", time.Now().UTC()),
		),
	)

	// Store configuration
	logConfig = config
	securityAuditEnabled = config.EnableSecurityAudit
	sensitiveDataPatterns = config.SensitiveDataPatterns

	return nil
}

// Info logs an informational message with security context
func Info(message string, fields ...zap.Field) {
	loggerMutex.RLock()
	defer loggerMutex.RUnlock()

	if logger == nil {
		return
	}

	// Add security context
	fields = append(fields,
		zap.Time("log_time", time.Now().UTC()),
		zap.String("security_level", "info"),
	)

	// Sanitize sensitive data
	message = sanitizeMessage(message)
	fields = sanitizeFields(fields)

	logger.Info(message, fields...)
}

// Error logs an error message with enhanced security tracking
func Error(message string, err error, fields ...zap.Field) {
	loggerMutex.RLock()
	defer loggerMutex.RUnlock()

	if logger == nil {
		return
	}

	// Extract error code if BlackPointError
	var bpErr *common.BlackPointError
	errorCode := "E4001" // Default system error
	if errors.As(err, &bpErr) {
		errorCode = bpErr.Code
	}

	// Add error context
	fields = append(fields,
		zap.Time("log_time", time.Now().UTC()),
		zap.String("error_code", errorCode),
		zap.String("security_level", "error"),
		zap.Error(err),
	)

	// Sanitize sensitive data
	message = sanitizeMessage(message)
	fields = sanitizeFields(fields)

	logger.Error(message, fields...)
}

// sanitizeMessage removes sensitive data from log messages
func sanitizeMessage(message string) string {
	for _, pattern := range sensitiveDataPatterns {
		re, err := regexp.Compile(pattern)
		if err != nil {
			continue
		}
		message = re.ReplaceAllString(message, "[REDACTED]")
	}
	return message
}

// sanitizeFields removes sensitive data from log fields
func sanitizeFields(fields []zap.Field) []zap.Field {
	sanitized := make([]zap.Field, len(fields))
	for i, field := range fields {
		if field.Type == zapcore.StringType {
			field.String = sanitizeMessage(field.String)
		}
		sanitized[i] = field
	}
	return sanitized
}