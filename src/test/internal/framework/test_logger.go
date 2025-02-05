// Package framework provides enhanced testing utilities for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package framework

import (
	"context" // v1.21
	"fmt"
	"sync"
	"testing" // v1.21
	"time"    // v1.21

	"github.com/sirupsen/logrus" // v1.9.0

	"../../pkg/common/constants"
	"../../pkg/common/errors"
	"../../pkg/common/logging"
)

// TestLogger provides enhanced logging capabilities for test execution with monitoring
// and metrics collection integration.
type TestLogger struct {
	t              *testing.T
	ctx            context.Context
	logger         *logrus.Logger
	metrics        map[string]interface{}
	startTime      time.Time
	thresholds     map[string]float64
	fields         logrus.Fields
	metricsLock    sync.RWMutex
	monitoringHook *logrus.Hook
}

// logLevels maps string level names to logrus levels
var logLevels = map[string]logrus.Level{
	"debug": logrus.DebugLevel,
	"info":  logrus.InfoLevel,
	"warn":  logrus.WarnLevel,
	"error": logrus.ErrorLevel,
}

// defaultLogFields defines standard fields included in all test log entries
var defaultLogFields = map[string]interface{}{
	"component":   "test-framework",
	"version":     "1.0.0",
	"environment": "test",
	"service":     "integration-framework",
}

// validationThresholds defines minimum thresholds for test validation
var validationThresholds = map[string]float64{
	"accuracy":     80.0,
	"performance": 95.0,
	"coverage":    85.0,
}

// NewTestLogger creates and configures a new test logger instance with monitoring integration
func NewTestLogger(t *testing.T, ctx context.Context) *TestLogger {
	logger := &TestLogger{
		t:          t,
		ctx:        ctx,
		logger:     logrus.New(),
		metrics:    make(map[string]interface{}),
		startTime:  time.Now(),
		thresholds: validationThresholds,
		fields:     make(logrus.Fields),
	}

	// Configure JSON formatter for monitoring compatibility
	logger.logger.SetFormatter(&logrus.JSONFormatter{
		TimestampFormat: time.RFC3339Nano,
		FieldMap: logrus.FieldMap{
			logrus.FieldKeyTime:  "timestamp",
			logrus.FieldKeyLevel: "severity",
			logrus.FieldKeyMsg:   "message",
		},
	})

	// Set default fields
	logger.fields = logrus.Fields{
		"test_name":    t.Name(),
		"test_package": t.Name(),
		"trace_id":     fmt.Sprintf("test-%d", time.Now().UnixNano()),
	}
	for k, v := range defaultLogFields {
		logger.fields[k] = v
	}

	return logger
}

// LogTestStep logs a test step with enhanced context and metrics
func (l *TestLogger) LogTestStep(stepName string, fields map[string]interface{}) error {
	stepStart := time.Now()
	
	// Merge step fields with default fields
	stepFields := make(logrus.Fields)
	for k, v := range l.fields {
		stepFields[k] = v
	}
	for k, v := range fields {
		stepFields[k] = v
	}
	
	stepFields["step_name"] = stepName
	stepFields["step_start_time"] = stepStart.Format(time.RFC3339Nano)
	stepFields["event_type"] = "test_step"

	// Log step execution
	l.logger.WithFields(stepFields).Info(fmt.Sprintf("Executing test step: %s", stepName))

	// Update metrics
	l.metricsLock.Lock()
	l.metrics[fmt.Sprintf("step_%s_duration", stepName)] = time.Since(stepStart).Milliseconds()
	l.metricsLock.Unlock()

	return nil
}

// LogTestAssertion logs test assertions with validation thresholds
func (l *TestLogger) LogTestAssertion(assertion string, actual interface{}, expected interface{}, fields map[string]interface{}) {
	assertionFields := make(logrus.Fields)
	for k, v := range l.fields {
		assertionFields[k] = v
	}
	for k, v := range fields {
		assertionFields[k] = v
	}

	assertionFields["assertion"] = assertion
	assertionFields["actual_value"] = actual
	assertionFields["expected_value"] = expected
	assertionFields["event_type"] = "test_assertion"

	l.logger.WithFields(assertionFields).Info("Test assertion executed")
}

// LogTestMetrics logs test metrics with performance tracking
func (l *TestLogger) LogTestMetrics() {
	l.metricsLock.RLock()
	defer l.metricsLock.RUnlock()

	metricFields := make(logrus.Fields)
	for k, v := range l.fields {
		metricFields[k] = v
	}

	// Add execution metrics
	metricFields["total_duration_ms"] = time.Since(l.startTime).Milliseconds()
	metricFields["event_type"] = "test_metrics"
	
	// Add validation thresholds
	for k, v := range l.thresholds {
		metricFields[fmt.Sprintf("%s_threshold", k)] = v
	}

	// Add collected metrics
	for k, v := range l.metrics {
		metricFields[k] = v
	}

	l.logger.WithFields(metricFields).Info("Test metrics recorded")
}

// WithField adds a field to the logger context
func (l *TestLogger) WithField(key string, value interface{}) *TestLogger {
	newLogger := &TestLogger{
		t:          l.t,
		ctx:        l.ctx,
		logger:     l.logger,
		metrics:    l.metrics,
		startTime:  l.startTime,
		thresholds: l.thresholds,
		fields:     make(logrus.Fields),
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	
	// Add new field
	newLogger.fields[key] = value

	return newLogger
}

// WithFields adds multiple fields to the logger context
func (l *TestLogger) WithFields(fields map[string]interface{}) *TestLogger {
	newLogger := &TestLogger{
		t:          l.t,
		ctx:        l.ctx,
		logger:     l.logger,
		metrics:    l.metrics,
		startTime:  l.startTime,
		thresholds: l.thresholds,
		fields:     make(logrus.Fields),
	}

	// Copy existing fields
	for k, v := range l.fields {
		newLogger.fields[k] = v
	}
	
	// Add new fields
	for k, v := range fields {
		newLogger.fields[k] = v
	}

	return newLogger
}

// AddMetric adds a metric value with thread-safe access
func (l *TestLogger) AddMetric(name string, value interface{}) {
	l.metricsLock.Lock()
	defer l.metricsLock.Unlock()
	
	l.metrics[name] = value
}

// ValidateMetrics checks if metrics meet defined thresholds
func (l *TestLogger) ValidateMetrics() error {
	l.metricsLock.RLock()
	defer l.metricsLock.RUnlock()

	// Check accuracy threshold
	if accuracy, ok := l.metrics["accuracy"].(float64); ok {
		if accuracy < l.thresholds["accuracy"] {
			return errors.NewTestError("DATA_ACCURACY_ERROR",
				fmt.Sprintf("accuracy %.2f%% below threshold %.2f%%", accuracy, l.thresholds["accuracy"]))
		}
	}

	// Check performance threshold
	if performance, ok := l.metrics["performance"].(float64); ok {
		if performance < l.thresholds["performance"] {
			return errors.NewTestError("PROCESSING_ERROR",
				fmt.Sprintf("performance %.2f%% below threshold %.2f%%", performance, l.thresholds["performance"]))
		}
	}

	return nil
}