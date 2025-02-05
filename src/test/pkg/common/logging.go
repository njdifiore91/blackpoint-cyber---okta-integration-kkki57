// Package common provides shared utilities for the BlackPoint Security Integration Framework testing suite.
// Version: 1.0.0
package common

import (
	"fmt" // v1.21
	"testing" // v1.21
	"time" // v1.21
	"github.com/sirupsen/logrus" // v1.9.0
)

// logLevels maps string level names to logrus levels
var logLevels = map[string]logrus.Level{
	"debug": logrus.DebugLevel,
	"info":  logrus.InfoLevel,
	"warn":  logrus.WarnLevel,
	"error": logrus.ErrorLevel,
	"fatal": logrus.FatalLevel,
}

// defaultLogFields defines standard fields included in all log entries
var defaultLogFields = map[string]interface{}{
	"component":   "test-framework",
	"version":     "1.0.0",
	"environment": "test",
	"service":     "integration-testing",
}

// InitTestLogger initializes a new logger instance with monitoring integration
func InitTestLogger(t *testing.T) *logrus.Logger {
	logger := logrus.New()

	// Configure JSON formatter for monitoring compatibility
	logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat:   time.RFC3339Nano,
		DisableTimestamp: false,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "severity",
			logrus.FieldKeyMsg:   "message",
		},
	})

	// Set default fields
	logger.WithFields(defaultLogFields)

	// Add test context
	logger.WithFields(logrus.Fields{
		"test_name":    t.Name(),
		"test_package": t.Name(),
		"trace_id":     fmt.Sprintf("test-%d", time.Now().UnixNano()),
	})

	// Configure sampling for high-volume events
	logger.SetLevel(logrus.InfoLevel)
	
	return logger
}

// LogTestInfo logs test information with enhanced context
func LogTestInfo(t *testing.T, message string, fields map[string]interface{}) {
	logger := InitTestLogger(t)
	
	// Enrich with test context
	enrichedFields := make(map[string]interface{})
	for k, v := range fields {
		enrichedFields[k] = v
	}
	enrichedFields["test_name"] = t.Name()
	enrichedFields["timestamp"] = time.Now().Format(time.RFC3339Nano)
	enrichedFields["event_type"] = "test_info"

	// Add validation context if present
	if threshold, ok := ValidationThresholds["accuracy"]; ok {
		enrichedFields["accuracy_threshold"] = threshold
	}

	logger.WithFields(enrichedFields).Info(message)
}

// LogTestError logs test errors with correlation and stack traces
func LogTestError(t *testing.T, err error, fields map[string]interface{}) {
	logger := InitTestLogger(t)

	// Extract error code and create correlation ID
	errorCode := ExtractErrorCode(err)
	if errorCode == "" {
		errorCode = TestErrorCodes["PROCESSING_ERROR"]
	}

	// Enrich error context
	errorFields := map[string]interface{}{
		"error_code":     errorCode,
		"error_message":  err.Error(),
		"test_name":      t.Name(),
		"correlation_id": fmt.Sprintf("error-%d", time.Now().UnixNano()),
		"timestamp":      time.Now().Format(time.RFC3339Nano),
		"event_type":     "test_error",
	}

	// Add custom fields
	for k, v := range fields {
		errorFields[k] = v
	}

	// Log error with full context
	logger.WithFields(errorFields).Error(err.Error())

	// Mark test as failed
	t.Error(err)
}

// LogTestMetrics logs performance metrics and validation results
func LogTestMetrics(t *testing.T, metrics map[string]interface{}) {
	logger := InitTestLogger(t)

	// Add standard metric fields
	metricFields := map[string]interface{}{
		"test_name":        t.Name(),
		"timestamp":        time.Now().Format(time.RFC3339Nano),
		"event_type":       "test_metrics",
		"execution_time":   time.Since(time.Now()),
	}

	// Add validation thresholds
	metricFields["accuracy_threshold"] = ValidationThresholds["accuracy"]
	metricFields["performance_threshold"] = ValidationThresholds["performance"]
	metricFields["availability_threshold"] = ValidationThresholds["availability"]

	// Add latency thresholds
	for tier, threshold := range ProcessingLatencyThresholds {
		metricFields[fmt.Sprintf("%s_latency_threshold", tier)] = threshold
	}

	// Add custom metrics
	for k, v := range metrics {
		metricFields[k] = v
	}

	// Log metrics with monitoring annotations
	logger.WithFields(metricFields).Info("Test metrics recorded")

	// Validate against minimum throughput requirement
	if throughput, ok := metrics["events_per_second"].(float64); ok {
		if throughput < float64(MinThroughputEventsPerSecond) {
			logger.WithFields(logrus.Fields{
				"actual_throughput":    throughput,
				"required_throughput":  MinThroughputEventsPerSecond,
				"validation_status":    "failed",
			}).Warn("Throughput below minimum requirement")
		}
	}
}