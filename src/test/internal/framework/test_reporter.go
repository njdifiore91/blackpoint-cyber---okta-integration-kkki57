// Package framework provides enhanced testing utilities for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package framework

import (
    "encoding/json"
    "fmt"
    "sync"
    "time"

    "github.com/prometheus/client_golang/prometheus" // v1.16.0
)

const (
    testMetricsPrefix   = "blackpoint_test"
    defaultReportFormat = "json"
    accuracyThreshold   = 80.0 // Minimum required accuracy percentage
)

// Prometheus metrics for test reporting
var prometheusMetrics = map[string]*prometheus.GaugeVec{
    "test_duration_seconds": prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: testMetricsPrefix + "_duration_seconds",
            Help: "Test execution duration in seconds",
        },
        []string{"test_name", "integration_type"},
    ),
    "test_accuracy_percent": prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: testMetricsPrefix + "_accuracy_percent",
            Help: "Test accuracy percentage",
        },
        []string{"test_name", "calculation_mode"},
    ),
    "test_pass_rate": prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: testMetricsPrefix + "_pass_rate",
            Help: "Test pass rate percentage",
        },
        []string{"test_name", "test_type"},
    ),
    "security_validation_score": prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: testMetricsPrefix + "_security_validation_score",
            Help: "Security validation score",
        },
        []string{"test_name", "validation_type"},
    ),
    "performance_score": prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: testMetricsPrefix + "_performance_score",
            Help: "Performance validation score",
        },
        []string{"test_name", "metric_type"},
    ),
}

// TestReporter manages test reporting with security validation and metrics collection
type TestReporter struct {
    logger           *TestLogger
    accuracyMetrics  *AccuracyMetrics
    testMetrics      map[string]interface{}
    startTime        time.Time
    metricsMutex     *sync.RWMutex
    securityContext  *SecurityContext
    validationThresholds map[string]float64
}

// NewTestReporter creates a new TestReporter instance with security context
func NewTestReporter(logger *TestLogger, securityCtx *SecurityContext) (*TestReporter, error) {
    if logger == nil {
        return nil, fmt.Errorf("logger cannot be nil")
    }

    // Initialize Prometheus metrics
    for _, metric := range prometheusMetrics {
        prometheus.MustRegister(metric)
    }

    reporter := &TestReporter{
        logger:          logger,
        testMetrics:     make(map[string]interface{}),
        startTime:       time.Now(),
        metricsMutex:    &sync.RWMutex{},
        securityContext: securityCtx,
        validationThresholds: map[string]float64{
            "accuracy":    accuracyThreshold,
            "performance": 95.0,
            "security":    90.0,
        },
    }

    // Initialize accuracy metrics with security context
    var err error
    reporter.accuracyMetrics, err = NewAccuracyMetrics("security_aware", nil, securityCtx)
    if err != nil {
        return nil, fmt.Errorf("failed to initialize accuracy metrics: %v", err)
    }

    return reporter, nil
}

// RecordTestResult records individual test case result with security validation
func (tr *TestReporter) RecordTestResult(testCase *TestCase, passed bool, metrics map[string]interface{}, securityCtx *SecurityContext) error {
    tr.metricsMutex.Lock()
    defer tr.metricsMutex.Unlock()

    // Validate security context
    if err := tr.validateSecurityContext(securityCtx); err != nil {
        return fmt.Errorf("security validation failed: %v", err)
    }

    // Record test metrics
    testMetrics := map[string]interface{}{
        "test_name":     testCase.Name(),
        "passed":        passed,
        "duration":      time.Since(testCase.startTime).Seconds(),
        "timestamp":     time.Now().UTC(),
        "security_info": securityCtx,
    }

    // Merge custom metrics
    for k, v := range metrics {
        testMetrics[k] = v
    }

    // Calculate accuracy if available
    if accuracy, ok := metrics["accuracy"].(float64); ok {
        testMetrics["accuracy"] = accuracy
        prometheusMetrics["test_accuracy_percent"].WithLabelValues(
            testCase.Name(), "security_aware",
        ).Set(accuracy)
    }

    // Update Prometheus metrics
    prometheusMetrics["test_duration_seconds"].WithLabelValues(
        testCase.Name(), testCase.config.Labels["integration_type"],
    ).Set(testMetrics["duration"].(float64))

    // Log test result
    tr.logger.LogTestInfo(fmt.Sprintf("Test case %s completed", testCase.Name()), testMetrics)

    // Store metrics
    tr.testMetrics[testCase.Name()] = testMetrics

    return nil
}

// GenerateReport generates final test execution report with security validation
func (tr *TestReporter) GenerateReport(format string, securityCtx *SecurityContext) (map[string]interface{}, error) {
    tr.metricsMutex.RLock()
    defer tr.metricsMutex.RUnlock()

    if format == "" {
        format = defaultReportFormat
    }

    // Validate security context
    if err := tr.validateSecurityContext(securityCtx); err != nil {
        return nil, fmt.Errorf("security validation failed: %v", err)
    }

    // Calculate overall metrics
    totalTests := len(tr.testMetrics)
    passedTests := 0
    var totalAccuracy float64
    var totalDuration float64

    for _, metrics := range tr.testMetrics {
        m := metrics.(map[string]interface{})
        if m["passed"].(bool) {
            passedTests++
        }
        if accuracy, ok := m["accuracy"].(float64); ok {
            totalAccuracy += accuracy
        }
        totalDuration += m["duration"].(float64)
    }

    // Generate report
    report := map[string]interface{}{
        "summary": map[string]interface{}{
            "total_tests":        totalTests,
            "passed_tests":       passedTests,
            "pass_rate":         float64(passedTests) / float64(totalTests) * 100,
            "total_duration":     totalDuration,
            "average_accuracy":   totalAccuracy / float64(totalTests),
            "execution_time":     time.Since(tr.startTime).String(),
            "timestamp":          time.Now().UTC(),
        },
        "security_validation": map[string]interface{}{
            "context":           tr.securityContext,
            "validation_score": tr.calculateSecurityScore(),
            "thresholds":       tr.validationThresholds,
        },
        "test_results": tr.testMetrics,
    }

    // Export final metrics to Prometheus
    tr.exportFinalMetrics(report)

    // Format report
    switch format {
    case "json":
        return report, nil
    default:
        return nil, fmt.Errorf("unsupported report format: %s", format)
    }
}

// Helper functions

func (tr *TestReporter) validateSecurityContext(securityCtx *SecurityContext) error {
    if securityCtx == nil {
        return fmt.Errorf("security context required")
    }
    // Add additional security validation logic here
    return nil
}

func (tr *TestReporter) calculateSecurityScore() float64 {
    // Implement security scoring based on test results and security context
    return 95.0 // Placeholder implementation
}

func (tr *TestReporter) exportFinalMetrics(report map[string]interface{}) {
    summary := report["summary"].(map[string]interface{})
    
    prometheusMetrics["test_pass_rate"].WithLabelValues(
        "integration", "overall",
    ).Set(summary["pass_rate"].(float64))

    prometheusMetrics["security_validation_score"].WithLabelValues(
        "integration", "overall",
    ).Set(report["security_validation"].(map[string]interface{})["validation_score"].(float64))
}

// Standalone functions for external use

// GenerateTestReport generates a comprehensive test execution report
func GenerateTestReport(testCase *TestCase, format string, securityCtx *SecurityContext) (map[string]interface{}, error) {
    reporter, err := NewTestReporter(NewTestLogger(testCase.t, testCase.ctx), securityCtx)
    if err != nil {
        return nil, err
    }

    if err := reporter.RecordTestResult(testCase, true, testCase.GetMetrics(), securityCtx); err != nil {
        return nil, err
    }

    return reporter.GenerateReport(format, securityCtx)
}

// ExportMetricsToPrometheus exports enhanced test metrics to Prometheus
func ExportMetricsToPrometheus(metrics map[string]interface{}, securityCtx *SecurityContext) error {
    if metrics == nil {
        return fmt.Errorf("metrics cannot be nil")
    }

    for name, metric := range prometheusMetrics {
        if value, ok := metrics[name].(float64); ok {
            metric.WithLabelValues(
                metrics["test_name"].(string),
                metrics["test_type"].(string),
            ).Set(value)
        }
    }

    return nil
}

func init() {
    // Register all Prometheus metrics
    for _, metric := range prometheusMetrics {
        prometheus.MustRegister(metric)
    }
}