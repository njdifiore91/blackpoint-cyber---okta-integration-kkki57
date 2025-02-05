// Package common provides shared utilities for the BlackPoint Security Integration Framework
package common

import (
	"crypto/rand"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/blackpoint/pkg/common/errors"
	"github.com/blackpoint/pkg/common/logging"
	"github.com/google/uuid"           // v1.3.0
	"github.com/prometheus/client_golang/prometheus" // v1.12.0
)

var (
	// Metrics collectors
	utilMetrics = struct {
		functionLatency *prometheus.HistogramVec
		validationErrors *prometheus.CounterVec
		sanitizationCount *prometheus.CounterVec
	}{
		functionLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name: "blackpoint_utils_latency_seconds",
				Help: "Latency of utility functions",
			},
			[]string{"function"},
		),
		validationErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blackpoint_utils_validation_errors_total",
				Help: "Number of validation errors by type",
			},
			[]string{"type"},
		),
		sanitizationCount: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "blackpoint_utils_sanitization_total",
				Help: "Number of sanitization operations",
			},
			[]string{"type"},
		),
	}

	// Thread-safe cache for validation patterns
	patternCache sync.Map
)

// ValidationOptions configures JSON validation behavior
type ValidationOptions struct {
	MaxDepth    int   `json:"max_depth"`
	MaxSize     int64 `json:"max_size"`
	AllowNulls  bool  `json:"allow_nulls"`
	StrictMode  bool  `json:"strict_mode"`
}

// SanitizationOptions configures string sanitization behavior
type SanitizationOptions struct {
	MaxLength       int      `json:"max_length"`
	AllowedPatterns []string `json:"allowed_patterns"`
	StripHTML      bool     `json:"strip_html"`
	TrimSpace      bool     `json:"trim_space"`
}

// GenerateUUID generates a cryptographically secure UUID v4 with entropy validation
func GenerateUUID() (string, error) {
	timer := prometheus.NewTimer(utilMetrics.functionLatency.WithLabelValues("generate_uuid"))
	defer timer.ObserveDuration()

	// Ensure sufficient entropy
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		logging.Error("Failed to generate random bytes for UUID", err)
		return "", errors.NewError("E4001", "insufficient entropy for UUID generation", nil)
	}

	id, err := uuid.NewRandomFromReader(rand.Reader)
	if err != nil {
		logging.Error("Failed to generate UUID", err)
		return "", errors.WrapError(err, "uuid generation failed", nil)
	}

	// Log security audit
	logging.SecurityAudit("Generated new UUID", map[string]interface{}{
		"uuid_version": "4",
		"timestamp":    time.Now().UTC(),
	})

	return id.String(), nil
}

// ValidateJSON validates JSON data with depth limits and security checks
func ValidateJSON(jsonStr string, opts ValidationOptions) error {
	timer := prometheus.NewTimer(utilMetrics.functionLatency.WithLabelValues("validate_json"))
	defer timer.ObserveDuration()

	// Apply default limits if not specified
	if opts.MaxDepth <= 0 {
		opts.MaxDepth = 20
	}
	if opts.MaxSize <= 0 {
		opts.MaxSize = 1 << 20 // 1MB
	}

	// Check size limit
	if int64(len(jsonStr)) > opts.MaxSize {
		utilMetrics.validationErrors.WithLabelValues("size_exceeded").Inc()
		return errors.NewError("E3001", "JSON size exceeds limit", map[string]interface{}{
			"max_size": opts.MaxSize,
			"actual_size": len(jsonStr),
		})
	}

	// Validate JSON structure
	var data interface{}
	decoder := json.NewDecoder(strings.NewReader(jsonStr))
	decoder.UseNumber()
	
	if opts.StrictMode {
		decoder.DisallowUnknownFields()
	}

	if err := decoder.Decode(&data); err != nil {
		utilMetrics.validationErrors.WithLabelValues("invalid_json").Inc()
		return errors.WrapError(err, "invalid JSON format", nil)
	}

	// Check depth and structure
	if err := validateJSONDepth(data, opts.MaxDepth, 0); err != nil {
		utilMetrics.validationErrors.WithLabelValues("depth_exceeded").Inc()
		return err
	}

	return nil
}

// validateJSONDepth recursively checks JSON structure depth
func validateJSONDepth(data interface{}, maxDepth, currentDepth int) error {
	if currentDepth > maxDepth {
		return errors.NewError("E3001", "JSON depth exceeds limit", map[string]interface{}{
			"max_depth": maxDepth,
		})
	}

	switch v := data.(type) {
	case map[string]interface{}:
		for _, val := range v {
			if err := validateJSONDepth(val, maxDepth, currentDepth+1); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, val := range v {
			if err := validateJSONDepth(val, maxDepth, currentDepth+1); err != nil {
				return err
			}
		}
	}

	return nil
}

// SanitizeString sanitizes input string using configurable security rules
func SanitizeString(input string, opts SanitizationOptions) string {
	timer := prometheus.NewTimer(utilMetrics.functionLatency.WithLabelValues("sanitize_string"))
	defer timer.ObserveDuration()

	// Apply default options if not specified
	if opts.MaxLength <= 0 {
		opts.MaxLength = 1000
	}

	result := input

	// Trim whitespace if enabled
	if opts.TrimSpace {
		result = strings.TrimSpace(result)
	}

	// Truncate to max length
	if len(result) > opts.MaxLength {
		result = result[:opts.MaxLength]
		utilMetrics.sanitizationCount.WithLabelValues("truncated").Inc()
	}

	// Apply pattern-based sanitization
	if len(opts.AllowedPatterns) > 0 {
		result = applyAllowedPatterns(result, opts.AllowedPatterns)
		utilMetrics.sanitizationCount.WithLabelValues("pattern_filtered").Inc()
	}

	// Strip HTML if enabled
	if opts.StripHTML {
		result = stripHTML(result)
		utilMetrics.sanitizationCount.WithLabelValues("html_stripped").Inc()
	}

	// Log sanitization if content was modified
	if result != input {
		logging.Debug("String sanitized", map[string]interface{}{
			"original_length": len(input),
			"final_length":    len(result),
			"modifications":   getSanitizationModifications(input, result),
		})
	}

	return result
}

// applyAllowedPatterns filters string content based on allowed patterns
func applyAllowedPatterns(input string, patterns []string) string {
	for _, pattern := range patterns {
		// Get or compile regex pattern
		var regex interface{}
		if cached, ok := patternCache.Load(pattern); ok {
			regex = cached
		} else {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				logging.Error("Invalid pattern", err, map[string]interface{}{
					"pattern": pattern,
				})
				continue
			}
			patternCache.Store(pattern, compiled)
			regex = compiled
		}

		if r, ok := regex.(*regexp.Regexp); ok {
			input = r.ReplaceAllString(input, "")
		}
	}
	return input
}

// stripHTML removes HTML tags from string
func stripHTML(input string) string {
	// Basic HTML tag stripping - for more complex needs, consider using a proper HTML parser
	return regexp.MustCompile("<[^>]*>").ReplaceAllString(input, "")
}

// getSanitizationModifications returns a summary of applied modifications
func getSanitizationModifications(original, sanitized string) []string {
	var mods []string
	if len(sanitized) != len(original) {
		mods = append(mods, "length_modified")
	}
	if strings.TrimSpace(original) != original {
		mods = append(mods, "whitespace_trimmed")
	}
	if strings.Contains(original, "<") && !strings.Contains(sanitized, "<") {
		mods = append(mods, "html_removed")
	}
	return mods
}

func init() {
	// Register metrics with Prometheus
	prometheus.MustRegister(
		utilMetrics.functionLatency,
		utilMetrics.validationErrors,
		utilMetrics.sanitizationCount,
	)
}