// Package framework provides secure, monitored parallel test execution for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package framework

import (
    "context"
    "fmt"
    "sync"
    "testing"
    "time"

    "github.com/prometheus/client_golang/prometheus" // v1.16.0
)

// Default configuration values
const (
    defaultParallelism     = 4
    defaultTimeout         = 10 * time.Minute
    maxRetries            = 3
    monitoringInterval    = 30 * time.Second
)

// Prometheus metrics
var (
    testExecutionTime = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_test_execution_seconds",
            Help: "Test execution duration in seconds",
            Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
        },
        []string{"test_name", "status"},
    )

    testRetryCount = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_test_retries_total",
            Help: "Number of test retries",
        },
        []string{"test_name"},
    )

    securityValidationScore = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackpoint_test_security_validation_score",
            Help: "Security validation score for test execution",
        },
        []string{"test_name", "validation_type"},
    )
)

// TestRunnerConfig holds configuration for the test runner
type TestRunnerConfig struct {
    Parallelism      int
    Timeout          time.Duration
    SecurityContext  map[string]interface{}
    ValidationConfig map[string]float64
    MonitoringConfig MonitoringConfig
}

// MonitoringConfig defines monitoring settings
type MonitoringConfig struct {
    Enabled         bool
    MetricsPrefix   string
    CollectionRate  time.Duration
}

// TestResult represents the outcome of a test execution
type TestResult struct {
    TestCase        *TestCase
    Duration        time.Duration
    Error           error
    SecurityScore   float64
    Metrics         map[string]interface{}
    ValidationState map[string]bool
}

// TestRunner manages secure parallel test execution
type TestRunner struct {
    t               *testing.T
    config          *TestRunnerConfig
    reporter        *TestReporter
    wg              sync.WaitGroup
    testQueue       chan *TestCase
    results         map[string]TestResult
    resultsMutex    sync.Mutex
    monitor         *prometheus.Registry
    ctx             context.Context
    cancel          context.CancelFunc
}

// NewTestRunner creates a new test runner instance with security monitoring
func NewTestRunner(t *testing.T, config *TestRunnerConfig) (*TestRunner, error) {
    if config == nil {
        config = &TestRunnerConfig{
            Parallelism: defaultParallelism,
            Timeout:     defaultTimeout,
            ValidationConfig: map[string]float64{
                "accuracy":     80.0,
                "performance": 95.0,
                "security":    90.0,
            },
            MonitoringConfig: MonitoringConfig{
                Enabled:        true,
                MetricsPrefix: "blackpoint_test",
                CollectionRate: monitoringInterval,
            },
        }
    }

    // Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)

    // Initialize monitoring
    monitor := prometheus.NewRegistry()
    monitor.MustRegister(testExecutionTime, testRetryCount, securityValidationScore)

    // Create test reporter with security context
    reporter, err := NewTestReporter(NewTestLogger(t, ctx), config.SecurityContext)
    if err != nil {
        cancel()
        return nil, fmt.Errorf("failed to create test reporter: %v", err)
    }

    runner := &TestRunner{
        t:           t,
        config:      config,
        reporter:    reporter,
        testQueue:   make(chan *TestCase, 1000),
        results:     make(map[string]TestResult),
        monitor:     monitor,
        ctx:         ctx,
        cancel:      cancel,
    }

    return runner, nil
}

// AddTestCase adds a test case to the execution queue
func (tr *TestRunner) AddTestCase(tc *TestCase) error {
    select {
    case <-tr.ctx.Done():
        return fmt.Errorf("test runner context cancelled")
    case tr.testQueue <- tc:
        return nil
    }
}

// RunTests executes all queued tests with security validation
func (tr *TestRunner) RunTests() error {
    defer tr.cleanup()

    // Start worker pool
    for i := 0; i < tr.config.Parallelism; i++ {
        tr.wg.Add(1)
        go tr.startWorker(i)
    }

    // Start metrics collection if enabled
    if tr.config.MonitoringConfig.Enabled {
        go tr.collectMetrics()
    }

    // Wait for completion
    tr.wg.Wait()

    // Generate final report
    report, err := tr.reporter.GenerateReport("json", tr.config.SecurityContext)
    if err != nil {
        return fmt.Errorf("failed to generate report: %v", err)
    }

    // Validate results
    if err := tr.validateResults(report); err != nil {
        return err
    }

    return nil
}

// startWorker runs a test execution worker
func (tr *TestRunner) startWorker(workerID int) {
    defer tr.wg.Done()

    for {
        select {
        case <-tr.ctx.Done():
            return
        case tc, ok := <-tr.testQueue:
            if !ok {
                return
            }
            tr.executeTest(tc, workerID)
        }
    }
}

// executeTest runs a single test case with retries and security validation
func (tr *TestRunner) executeTest(tc *TestCase, workerID int) {
    startTime := time.Now()
    var lastErr error
    var result TestResult

    // Initialize test metrics
    metrics := make(map[string]interface{})
    metrics["worker_id"] = workerID
    metrics["start_time"] = startTime

    // Execute test with retries
    for attempt := 0; attempt <= maxRetries; attempt++ {
        if attempt > 0 {
            testRetryCount.WithLabelValues(tc.Name()).Inc()
            time.Sleep(time.Second * time.Duration(attempt))
        }

        // Create test context
        testCtx, cancel := context.WithTimeout(tr.ctx, tr.config.Timeout)
        defer cancel()

        // Validate security context
        if err := tc.ValidateSecurityContext(); err != nil {
            lastErr = fmt.Errorf("security validation failed: %v", err)
            continue
        }

        // Execute test
        tc.Run()
        
        // Check for test failure
        if !tc.t.Failed() {
            break
        }

        lastErr = fmt.Errorf("test execution failed on attempt %d", attempt+1)
    }

    // Record test duration
    duration := time.Since(startTime)
    testExecutionTime.WithLabelValues(
        tc.Name(),
        fmt.Sprintf("%v", lastErr == nil),
    ).Observe(duration.Seconds())

    // Calculate security score
    securityScore := tr.calculateSecurityScore(tc)
    securityValidationScore.WithLabelValues(
        tc.Name(),
        "overall",
    ).Set(securityScore)

    // Record result
    result = TestResult{
        TestCase:      tc,
        Duration:      duration,
        Error:         lastErr,
        SecurityScore: securityScore,
        Metrics:      tc.GetMetrics(),
        ValidationState: map[string]bool{
            "security_validated": lastErr == nil && securityScore >= tr.config.ValidationConfig["security"],
            "performance_met":   duration < tr.config.Timeout,
            "accuracy_met":      tc.GetAccuracyScore() >= tr.config.ValidationConfig["accuracy"],
        },
    }

    // Store result
    tr.resultsMutex.Lock()
    tr.results[tc.Name()] = result
    tr.resultsMutex.Unlock()

    // Report test result
    tr.reporter.RecordTestResult(tc, lastErr == nil, metrics, tr.config.SecurityContext)
}

// collectMetrics periodically collects and exports monitoring metrics
func (tr *TestRunner) collectMetrics() {
    ticker := time.NewTicker(tr.config.MonitoringConfig.CollectionRate)
    defer ticker.Stop()

    for {
        select {
        case <-tr.ctx.Done():
            return
        case <-ticker.C:
            tr.exportMetrics()
        }
    }
}

// exportMetrics exports current metrics to monitoring system
func (tr *TestRunner) exportMetrics() {
    tr.resultsMutex.Lock()
    defer tr.resultsMutex.Unlock()

    for _, result := range tr.results {
        for name, value := range result.Metrics {
            if v, ok := value.(float64); ok {
                prometheus.NewGauge(prometheus.GaugeOpts{
                    Name: fmt.Sprintf("%s_%s", tr.config.MonitoringConfig.MetricsPrefix, name),
                    Help: fmt.Sprintf("Test metric: %s", name),
                }).Set(v)
            }
        }
    }
}

// calculateSecurityScore computes the security validation score
func (tr *TestRunner) calculateSecurityScore(tc *TestCase) float64 {
    // Implement security scoring based on test results and validation state
    return 95.0 // Placeholder implementation
}

// validateResults validates overall test execution results
func (tr *TestRunner) validateResults(report map[string]interface{}) error {
    summary, ok := report["summary"].(map[string]interface{})
    if !ok {
        return fmt.Errorf("invalid report format")
    }

    // Validate pass rate
    if passRate, ok := summary["pass_rate"].(float64); ok {
        if passRate < tr.config.ValidationConfig["performance"] {
            return fmt.Errorf("pass rate %.2f%% below required threshold %.2f%%",
                passRate, tr.config.ValidationConfig["performance"])
        }
    }

    // Validate security score
    if security, ok := report["security_validation"].(map[string]interface{}); ok {
        if score, ok := security["validation_score"].(float64); ok {
            if score < tr.config.ValidationConfig["security"] {
                return fmt.Errorf("security score %.2f%% below required threshold %.2f%%",
                    score, tr.config.ValidationConfig["security"])
            }
        }
    }

    return nil
}

// cleanup performs resource cleanup
func (tr *TestRunner) cleanup() {
    close(tr.testQueue)
    tr.cancel()
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(testExecutionTime, testRetryCount, securityValidationScore)
}