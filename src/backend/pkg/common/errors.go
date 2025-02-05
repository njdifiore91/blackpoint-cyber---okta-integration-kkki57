// Package common provides shared utilities and error handling for the BlackPoint Security Integration Framework
package common

import (
	"fmt"           // v1.21
	"errors"        // v1.21
	"sync/atomic"   // v1.21
	"time"
	"strings"
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity int

const (
	SeverityInfo ErrorSeverity = iota
	SeverityWarning
	SeverityError
	SeverityCritical
)

// ErrorCodeInfo contains metadata about error codes
type ErrorCodeInfo struct {
	Severity ErrorSeverity
	Category string
	Description string
}

// Thread-safe error metrics tracking
var errorMetrics = make(map[string]*atomic.Uint64)

// Predefined error codes with severity and category
var errorCodes = map[string]ErrorCodeInfo{
	"E1001": {SeverityCritical, "Authentication", "Authentication failure"},
	"E1002": {SeverityError, "Authorization", "Insufficient permissions"},
	"E2001": {SeverityError, "Integration", "Integration configuration error"},
	"E2002": {SeverityWarning, "Integration", "Integration performance degraded"},
	"E3001": {SeverityError, "Data", "Data validation error"},
	"E3002": {SeverityCritical, "Data", "Data corruption detected"},
	"E4001": {SeverityError, "System", "Internal system error"},
	"E4002": {SeverityWarning, "System", "Resource utilization warning"},
}

// BlackPointError represents an enhanced error type with security and monitoring capabilities
type BlackPointError struct {
	Code      string
	Message   string
	Err       error
	Severity  ErrorSeverity
	Metadata  map[string]interface{}
	Timestamp time.Time
}

// Error implements the error interface with security-aware formatting
func (e *BlackPointError) Error() string {
	msg := fmt.Sprintf("[%s] %s", e.Code, e.sanitizeMessage(e.Message))
	if e.Err != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Err)
	}
	return msg
}

// Unwrap implements error unwrapping with context preservation
func (e *BlackPointError) Unwrap() error {
	return e.Err
}

// sanitizeMessage removes sensitive data from error messages
func (e *BlackPointError) sanitizeMessage(message string) string {
	sensitivePatterns := []string{
		`password=\S+`,
		`key=\S+`,
		`token=\S+`,
		`secret=\S+`,
	}
	
	sanitized := message
	for _, pattern := range sensitivePatterns {
		sanitized = strings.ReplaceAll(sanitized, pattern, "[REDACTED]")
	}
	return sanitized
}

// NewError creates a new BlackPointError with code, message, and severity validation
func NewError(code string, message string, metadata map[string]interface{}) *BlackPointError {
	codeInfo, exists := errorCodes[code]
	if !exists {
		code = "E4001" // Default to internal system error
		codeInfo = errorCodes[code]
	}

	// Initialize error metrics counter if not exists
	if _, exists := errorMetrics[code]; !exists {
		errorMetrics[code] = &atomic.Uint64{}
	}

	// Increment error counter
	errorMetrics[code].Add(1)

	return &BlackPointError{
		Code:      code,
		Message:   message,
		Severity:  codeInfo.Severity,
		Metadata:  sanitizeMetadata(metadata),
		Timestamp: time.Now().UTC(),
	}
}

// WrapError wraps an existing error with additional context while preserving stack trace
func WrapError(err error, message string, context map[string]interface{}) error {
	if err == nil {
		return nil
	}

	var bpErr *BlackPointError
	if errors.As(err, &bpErr) {
		// Preserve existing error code and severity
		return &BlackPointError{
			Code:      bpErr.Code,
			Message:   message,
			Err:       err,
			Severity:  bpErr.Severity,
			Metadata:  mergeMaps(bpErr.Metadata, sanitizeMetadata(context)),
			Timestamp: time.Now().UTC(),
		}
	}

	// Wrap non-BlackPointError
	return NewError("E4001", message, context)
}

// IsErrorCode checks if an error has a specific error code with category validation
func IsErrorCode(err error, code string, category string) bool {
	if err == nil {
		return false
	}

	var bpErr *BlackPointError
	if !errors.As(err, &bpErr) {
		return false
	}

	codeInfo, exists := errorCodes[code]
	if !exists {
		return false
	}

	return bpErr.Code == code && (category == "" || codeInfo.Category == category)
}

// ErrorMetrics represents error statistics and trends
type ErrorMetrics struct {
	Counts    map[string]uint64
	Patterns  map[string]float64
	Trends    map[string][]uint64
	Timestamp time.Time
}

// GetErrorMetrics returns current error metrics with pattern analysis
func GetErrorMetrics(timeRange string, includeTrends bool) ErrorMetrics {
	metrics := ErrorMetrics{
		Counts:    make(map[string]uint64),
		Patterns:  make(map[string]float64),
		Trends:    make(map[string][]uint64),
		Timestamp: time.Now().UTC(),
	}

	// Safely copy atomic counters
	for code, counter := range errorMetrics {
		metrics.Counts[code] = counter.Load()
	}

	// Calculate error patterns
	total := uint64(0)
	for _, count := range metrics.Counts {
		total += count
	}
	
	if total > 0 {
		for code, count := range metrics.Counts {
			metrics.Patterns[code] = float64(count) / float64(total)
		}
	}

	return metrics
}

// sanitizeMetadata removes sensitive data from metadata
func sanitizeMetadata(metadata map[string]interface{}) map[string]interface{} {
	if metadata == nil {
		return nil
	}

	sanitized := make(map[string]interface{})
	sensitiveKeys := map[string]bool{
		"password": true,
		"key":      true,
		"token":    true,
		"secret":   true,
	}

	for k, v := range metadata {
		if sensitiveKeys[strings.ToLower(k)] {
			sanitized[k] = "[REDACTED]"
		} else {
			sanitized[k] = v
		}
	}

	return sanitized
}

// mergeMaps combines two metadata maps with sanitization
func mergeMaps(m1, m2 map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	
	if m1 != nil {
		for k, v := range m1 {
			result[k] = v
		}
	}
	
	if m2 != nil {
		for k, v := range m2 {
			result[k] = v
		}
	}

	return sanitizeMetadata(result)
}