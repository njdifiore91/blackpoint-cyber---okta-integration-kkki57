// Package framework provides core test case abstractions for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package framework

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert" // v1.8.4
	"github.com/prometheus/client_golang/prometheus" // v1.16.0
	"../../pkg/common/logging"
)

// Global constants for test execution
const (
	defaultTestTimeout    = 5 * time.Minute
	defaultRetryAttempts = 3
	defaultRetryDelay    = 1 * time.Second
	minAccuracyThreshold = 0.80
	maxExecutionTime     = 30 * time.Minute
)

// TestConfig holds test case configuration
type TestConfig struct {
	Timeout        time.Duration
	RetryAttempts  int
	RetryDelay     time.Duration
	CleanupTimeout time.Duration
	Thresholds     map[string]float64
	Labels         map[string]string
}

// TestStep represents a single test execution step
type TestStep struct {
	Name     string
	Exec     func(context.Context) error
	Cleanup  func(context.Context) error
	Timeout  time.Duration
	Retries  int
	Critical bool
}

// TestCase represents a single test case with enhanced lifecycle management
type TestCase struct {
	t             *testing.T
	name          string
	ctx           context.Context
	cancel        context.CancelFunc
	config        *TestConfig
	steps         []*TestStep
	setupFn       func(context.Context) error
	teardownFn    func(context.Context) error
	cleanupFns    []func(context.Context) error
	metrics       map[string]interface{}
	accuracyScore float64
	startTime     time.Time
	duration      time.Duration
	mu            sync.RWMutex

	// Prometheus metrics
	executionTime prometheus.Histogram
	stepDuration  prometheus.Histogram
	errorCounter  prometheus.Counter
	accuracyGauge prometheus.Gauge
}

// NewTestCase creates a new test case instance with monitoring integration
func NewTestCase(t *testing.T, name string, config *TestConfig) *TestCase {
	if config == nil {
		config = &TestConfig{
			Timeout:        defaultTestTimeout,
			RetryAttempts:  defaultRetryAttempts,
			RetryDelay:     defaultRetryDelay,
			CleanupTimeout: 1 * time.Minute,
			Thresholds:     make(map[string]float64),
			Labels:         make(map[string]string),
		}
	}

	// Set default accuracy threshold if not specified
	if _, ok := config.Thresholds["accuracy"]; !ok {
		config.Thresholds["accuracy"] = minAccuracyThreshold
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)

	// Initialize test case
	tc := &TestCase{
		t:             t,
		name:          name,
		ctx:           ctx,
		cancel:        cancel,
		config:        config,
		steps:         make([]*TestStep, 0),
		cleanupFns:    make([]func(context.Context) error, 0),
		metrics:       make(map[string]interface{}),
		startTime:     time.Now(),
	}

	// Initialize Prometheus metrics
	tc.initMetrics()

	// Initialize test logger
	logging.InitTestLogger(t)

	return tc
}

// initMetrics initializes Prometheus metrics for the test case
func (tc *TestCase) initMetrics() {
	labels := prometheus.Labels{
		"test_name": tc.name,
		"test_type": "integration",
	}
	for k, v := range tc.config.Labels {
		labels[k] = v
	}

	tc.executionTime = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "test_execution_duration_seconds",
		Help:        "Duration of test case execution",
		Buckets:     prometheus.ExponentialBuckets(0.1, 2, 10),
		ConstLabels: labels,
	})

	tc.stepDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:        "test_step_duration_seconds",
		Help:        "Duration of individual test steps",
		Buckets:     prometheus.ExponentialBuckets(0.01, 2, 10),
		ConstLabels: labels,
	})

	tc.errorCounter = prometheus.NewCounter(prometheus.CounterOpts{
		Name:        "test_errors_total",
		Help:        "Total number of test errors",
		ConstLabels: labels,
	})

	tc.accuracyGauge = prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        "test_accuracy_score",
		Help:        "Current test accuracy score",
		ConstLabels: labels,
	})

	// Register metrics
	prometheus.MustRegister(tc.executionTime)
	prometheus.MustRegister(tc.stepDuration)
	prometheus.MustRegister(tc.errorCounter)
	prometheus.MustRegister(tc.accuracyGauge)
}

// Setup configures test setup with enhanced resource management
func (tc *TestCase) Setup(setupFn func(context.Context) error) {
	tc.setupFn = setupFn
}

// Teardown configures test teardown with cleanup guarantees
func (tc *TestCase) Teardown(teardownFn func(context.Context) error) {
	tc.teardownFn = teardownFn
}

// AddStep adds a test step with retry and monitoring capabilities
func (tc *TestCase) AddStep(step *TestStep) {
	if step.Timeout == 0 {
		step.Timeout = tc.config.Timeout
	}
	if step.Retries == 0 {
		step.Retries = tc.config.RetryAttempts
	}
	tc.steps = append(tc.steps, step)
}

// Run executes the test case with comprehensive monitoring
func (tc *TestCase) Run() {
	defer tc.cleanup()
	defer tc.recordMetrics()

	// Execute setup if configured
	if tc.setupFn != nil {
		if err := tc.executeWithRetry(tc.ctx, "setup", tc.setupFn, tc.config.RetryAttempts); err != nil {
			logging.LogTestError(tc.t, err, map[string]interface{}{
				"phase": "setup",
			})
			return
		}
	}

	// Execute test steps
	for _, step := range tc.steps {
		stepCtx, cancel := context.WithTimeout(tc.ctx, step.Timeout)
		defer cancel()

		startTime := time.Now()
		err := tc.executeWithRetry(stepCtx, step.Name, step.Exec, step.Retries)
		duration := time.Since(startTime)

		// Record step metrics
		tc.stepDuration.Observe(duration.Seconds())

		if err != nil {
			tc.errorCounter.Inc()
			logging.LogTestError(tc.t, err, map[string]interface{}{
				"step":     step.Name,
				"duration": duration.String(),
			})
			if step.Critical {
				return
			}
		}

		// Register step cleanup if provided
		if step.Cleanup != nil {
			tc.cleanupFns = append(tc.cleanupFns, step.Cleanup)
		}
	}

	// Execute teardown if configured
	if tc.teardownFn != nil {
		if err := tc.executeWithRetry(tc.ctx, "teardown", tc.teardownFn, tc.config.RetryAttempts); err != nil {
			logging.LogTestError(tc.t, err, map[string]interface{}{
				"phase": "teardown",
			})
		}
	}
}

// Assert performs test assertions with accuracy tracking
func (tc *TestCase) Assert(assertion func() bool, message string) bool {
	result := assertion()
	if !result {
		tc.errorCounter.Inc()
	}
	assert.True(tc.t, result, message)
	return result
}

// GetMetrics returns test execution metrics
func (tc *TestCase) GetMetrics() map[string]interface{} {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.metrics
}

// GetAccuracyScore returns the current accuracy score
func (tc *TestCase) GetAccuracyScore() float64 {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.accuracyScore
}

// cleanup executes registered cleanup functions
func (tc *TestCase) cleanup() {
	cleanupCtx, cancel := context.WithTimeout(context.Background(), tc.config.CleanupTimeout)
	defer cancel()

	// Execute cleanup functions in reverse order
	for i := len(tc.cleanupFns) - 1; i >= 0; i-- {
		if err := tc.cleanupFns[i](cleanupCtx); err != nil {
			logging.LogTestError(tc.t, err, map[string]interface{}{
				"phase": "cleanup",
			})
		}
	}
}

// executeWithRetry executes a function with retry logic
func (tc *TestCase) executeWithRetry(ctx context.Context, name string, fn func(context.Context) error, retries int) error {
	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if err := fn(ctx); err == nil {
				return nil
			} else {
				lastErr = err
				if attempt < retries {
					time.Sleep(tc.config.RetryDelay)
				}
			}
		}
	}
	return lastErr
}

// recordMetrics records final test metrics
func (tc *TestCase) recordMetrics() {
	tc.duration = time.Since(tc.startTime)
	tc.executionTime.Observe(tc.duration.Seconds())
	tc.accuracyGauge.Set(tc.accuracyScore)

	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.metrics["duration"] = tc.duration.String()
	tc.metrics["accuracy"] = tc.accuracyScore
	tc.metrics["error_count"] = tc.errorCounter

	logging.LogTestMetrics(tc.t, tc.metrics)
}