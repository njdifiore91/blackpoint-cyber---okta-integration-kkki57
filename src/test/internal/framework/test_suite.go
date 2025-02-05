// Package framework provides enhanced testing capabilities for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package framework

import (
    "context"
    "fmt"
    "sync"
    "testing"
    "time"

    "github.com/prometheus/client_golang/prometheus" // v1.16.0
    "github.com/blackpoint/security" // v1.0.0
)

// Global constants for test suite configuration
const (
    defaultSuiteTimeout = 30 * time.Minute
    defaultParallelization = true
    defaultRetryAttempts = 3
    defaultAccuracyThreshold = 0.80
)

// TestSuiteConfig holds configuration for test suite execution
type TestSuiteConfig struct {
    Timeout          time.Duration
    Parallel         bool
    SecurityEnabled  bool
    MonitoringEnabled bool
    RetryAttempts    int
    ResourceLimits   map[string]interface{}
    ValidationConfig map[string]float64
}

// Prometheus metrics for test suite monitoring
var (
    suiteExecutionTime = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_test_suite_duration_seconds",
            Help: "Test suite execution duration in seconds",
            Buckets: prometheus.ExponentialBuckets(1, 2, 10),
        },
        []string{"suite_name", "status"},
    )

    suiteAccuracyGauge = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackpoint_test_suite_accuracy",
            Help: "Test suite accuracy score",
        },
        []string{"suite_name"},
    )

    suiteSecurityScore = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackpoint_test_suite_security_score",
            Help: "Test suite security validation score",
        },
        []string{"suite_name", "validation_type"},
    )
)

// TestSuite represents a collection of related test cases with enhanced lifecycle management
type TestSuite struct {
    t                *testing.T
    name             string
    config           *TestSuiteConfig
    runner           *TestRunner
    reporter         *TestReporter
    securityValidator *security.Validator
    testCases        []*TestCase
    setupFn          func(context.Context) error
    teardownFn       func(context.Context) error
    mutex            sync.Mutex
    resources        map[string]interface{}
    ctx              context.Context
    cancel           context.CancelFunc
}

// NewTestSuite creates a new test suite instance with enhanced configuration
func NewTestSuite(t *testing.T, name string, config *TestSuiteConfig) *TestSuite {
    if config == nil {
        config = &TestSuiteConfig{
            Timeout:          defaultSuiteTimeout,
            Parallel:         defaultParallelization,
            SecurityEnabled:  true,
            MonitoringEnabled: true,
            RetryAttempts:    defaultRetryAttempts,
            ValidationConfig: map[string]float64{
                "accuracy":     defaultAccuracyThreshold,
                "performance": 0.95,
                "security":    0.90,
            },
        }
    }

    // Create context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)

    // Initialize test runner with resource management
    runner, err := NewTestRunner(t, &TestRunnerConfig{
        Parallelism:     4,
        Timeout:         config.Timeout,
        SecurityContext: map[string]interface{}{
            "validation_enabled": config.SecurityEnabled,
        },
        ValidationConfig: config.ValidationConfig,
    })
    if err != nil {
        t.Fatalf("Failed to create test runner: %v", err)
    }

    // Initialize test reporter with monitoring
    reporter, err := NewTestReporter(NewTestLogger(t, ctx), &SecurityContext{
        Level:      "high",
        Compliance: []string{"SOC2", "ISO27001"},
    })
    if err != nil {
        t.Fatalf("Failed to create test reporter: %v", err)
    }

    // Initialize security validator
    validator, err := security.NewValidator(security.ValidatorConfig{
        StrictMode:    true,
        RequireSigned: true,
        AuditEnabled:  true,
    })
    if err != nil {
        t.Fatalf("Failed to create security validator: %v", err)
    }

    suite := &TestSuite{
        t:                t,
        name:             name,
        config:           config,
        runner:           runner,
        reporter:         reporter,
        securityValidator: validator,
        testCases:        make([]*TestCase, 0),
        resources:        make(map[string]interface{}),
        ctx:             ctx,
        cancel:          cancel,
    }

    // Register metrics
    prometheus.MustRegister(suiteExecutionTime, suiteAccuracyGauge, suiteSecurityScore)

    return suite
}

// AddTestCase adds a test case to the suite with security validation
func (s *TestSuite) AddTestCase(tc *TestCase) error {
    s.mutex.Lock()
    defer s.mutex.Unlock()

    // Validate test case configuration
    if err := s.validateTestCase(tc); err != nil {
        return fmt.Errorf("test case validation failed: %v", err)
    }

    s.testCases = append(s.testCases, tc)
    return nil
}

// Setup configures suite-level setup with retry capabilities
func (s *TestSuite) Setup(fn func(context.Context) error) {
    s.setupFn = fn
}

// Teardown configures suite-level teardown with cleanup guarantees
func (s *TestSuite) Teardown(fn func(context.Context) error) {
    s.teardownFn = fn
}

// Run executes the test suite with comprehensive monitoring and validation
func (s *TestSuite) Run() error {
    defer s.cleanup()
    startTime := time.Now()

    // Execute setup if configured
    if s.setupFn != nil {
        if err := s.executeWithRetry(s.ctx, "setup", s.setupFn); err != nil {
            return fmt.Errorf("suite setup failed: %v", err)
        }
    }

    // Execute test cases
    if err := s.executeTestCases(); err != nil {
        return err
    }

    // Calculate suite metrics
    duration := time.Since(startTime)
    accuracy := s.calculateAccuracy()
    securityScore := s.validateSecurity()

    // Record metrics
    suiteExecutionTime.WithLabelValues(s.name, "completed").Observe(duration.Seconds())
    suiteAccuracyGauge.WithLabelValues(s.name).Set(accuracy)
    suiteSecurityScore.WithLabelValues(s.name, "overall").Set(securityScore)

    // Generate report
    report, err := s.reporter.GenerateReport("json", &SecurityContext{
        Level:      "high",
        Compliance: []string{"SOC2", "ISO27001"},
    })
    if err != nil {
        return fmt.Errorf("failed to generate report: %v", err)
    }

    // Validate results against requirements
    if err := s.validateResults(report); err != nil {
        return err
    }

    return nil
}

// executeTestCases runs test cases with resource management and monitoring
func (s *TestSuite) executeTestCases() error {
    if s.config.Parallel {
        return s.executeParallel()
    }
    return s.executeSequential()
}

// executeParallel runs test cases in parallel with resource management
func (s *TestSuite) executeParallel() error {
    var wg sync.WaitGroup
    errors := make(chan error, len(s.testCases))

    for _, tc := range s.testCases {
        wg.Add(1)
        go func(testCase *TestCase) {
            defer wg.Done()
            if err := s.runner.AddTestCase(testCase); err != nil {
                errors <- err
            }
        }(tc)
    }

    wg.Wait()
    close(errors)

    // Collect errors
    var errs []error
    for err := range errors {
        errs = append(errs, err)
    }

    if len(errs) > 0 {
        return fmt.Errorf("test execution errors: %v", errs)
    }

    return s.runner.RunTests()
}

// executeSequential runs test cases sequentially
func (s *TestSuite) executeSequential() error {
    for _, tc := range s.testCases {
        if err := s.runner.AddTestCase(tc); err != nil {
            return err
        }
    }
    return s.runner.RunTests()
}

// Helper functions

func (s *TestSuite) executeWithRetry(ctx context.Context, operation string, fn func(context.Context) error) error {
    var lastErr error
    for attempt := 0; attempt <= s.config.RetryAttempts; attempt++ {
        select {
        case <-ctx.Done():
            return ctx.Err()
        default:
            if err := fn(ctx); err == nil {
                return nil
            } else {
                lastErr = err
                if attempt < s.config.RetryAttempts {
                    time.Sleep(time.Second * time.Duration(attempt+1))
                }
            }
        }
    }
    return lastErr
}

func (s *TestSuite) validateTestCase(tc *TestCase) error {
    if tc == nil {
        return fmt.Errorf("test case cannot be nil")
    }

    // Validate security configuration
    if s.config.SecurityEnabled {
        if err := s.securityValidator.ValidateTestCase(tc); err != nil {
            return fmt.Errorf("security validation failed: %v", err)
        }
    }

    return nil
}

func (s *TestSuite) calculateAccuracy() float64 {
    var totalAccuracy float64
    for _, tc := range s.testCases {
        totalAccuracy += tc.GetAccuracyScore()
    }
    return totalAccuracy / float64(len(s.testCases))
}

func (s *TestSuite) validateSecurity() float64 {
    if !s.config.SecurityEnabled {
        return 1.0
    }
    return s.securityValidator.CalculateScore()
}

func (s *TestSuite) validateResults(report map[string]interface{}) error {
    summary, ok := report["summary"].(map[string]interface{})
    if !ok {
        return fmt.Errorf("invalid report format")
    }

    // Validate accuracy requirement
    if accuracy, ok := summary["average_accuracy"].(float64); ok {
        if accuracy < s.config.ValidationConfig["accuracy"] {
            return fmt.Errorf("accuracy %.2f%% below required threshold %.2f%%",
                accuracy*100, s.config.ValidationConfig["accuracy"]*100)
        }
    }

    // Validate performance requirement
    if performance, ok := summary["pass_rate"].(float64); ok {
        if performance < s.config.ValidationConfig["performance"] {
            return fmt.Errorf("pass rate %.2f%% below required threshold %.2f%%",
                performance*100, s.config.ValidationConfig["performance"]*100)
        }
    }

    return nil
}

func (s *TestSuite) cleanup() {
    if s.teardownFn != nil {
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
        defer cancel()
        if err := s.teardownFn(ctx); err != nil {
            s.t.Errorf("Suite teardown failed: %v", err)
        }
    }
    s.cancel()
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(suiteExecutionTime, suiteAccuracyGauge, suiteSecurityScore)
}