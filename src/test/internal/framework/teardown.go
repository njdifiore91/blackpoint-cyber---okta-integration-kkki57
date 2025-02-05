// Package framework provides test environment management for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package framework

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus" // v1.16.0
	"../../pkg/common"
)

// Global constants for teardown operations
const (
	defaultCleanupTimeout   = 30 * time.Second
	defaultResourceWaitTime = 5 * time.Second
	maxCleanupRetries      = 3
	cleanupRetryDelay      = 2 * time.Second
)

// Prometheus metrics for teardown monitoring
var (
	teardownDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "test_teardown_duration_seconds",
			Help:    "Duration of test environment teardown operations",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
		},
		[]string{"test_name", "status"},
	)

	resourceCleanupErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_resource_cleanup_errors_total",
			Help: "Total number of resource cleanup errors",
		},
		[]string{"resource_type", "error_type"},
	)

	cleanupRetryCount = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "test_cleanup_retry_count_total",
			Help: "Total number of cleanup retry attempts",
		},
		[]string{"resource_type"},
	)
)

func init() {
	// Register prometheus metrics
	prometheus.MustRegister(teardownDuration)
	prometheus.MustRegister(resourceCleanupErrors)
	prometheus.MustRegister(cleanupRetryCount)
}

// TeardownConfig provides configuration for test environment teardown
type TeardownConfig struct {
	timeout       time.Duration
	resources     map[string]interface{}
	forceCleanup  bool
	maxRetries    int
	enableMetrics bool
	mu           sync.RWMutex
}

// NewTeardownConfig creates a new teardown configuration with defaults
func NewTeardownConfig() *TeardownConfig {
	return &TeardownConfig{
		timeout:       defaultCleanupTimeout,
		resources:     make(map[string]interface{}),
		forceCleanup:  false,
		maxRetries:    maxCleanupRetries,
		enableMetrics: true,
	}
}

// WithTimeout sets a custom timeout for teardown operations
func (c *TeardownConfig) WithTimeout(timeout time.Duration) *TeardownConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	if timeout > 0 {
		c.timeout = timeout
	}
	return c
}

// WithForceCleanup configures forced cleanup behavior
func (c *TeardownConfig) WithForceCleanup(force bool) *TeardownConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.forceCleanup = force
	return c
}

// WithMetrics enables or disables metrics collection
func (c *TeardownConfig) WithMetrics(enable bool) *TeardownConfig {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.enableMetrics = enable
	return c
}

// TeardownTestEnvironment orchestrates the complete test environment teardown
func TeardownTestEnvironment(t *testing.T, config *TeardownConfig) error {
	if config == nil {
		config = NewTeardownConfig()
	}

	startTime := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), config.timeout)
	defer cancel()

	// Initialize metrics if enabled
	if config.enableMetrics {
		defer func() {
			duration := time.Since(startTime)
			status := "success"
			if t.Failed() {
				status = "failed"
			}
			teardownDuration.WithLabelValues(t.Name(), status).Observe(duration.Seconds())
		}()
	}

	common.LogTestInfo(t, "Starting test environment teardown", map[string]interface{}{
		"timeout":      config.timeout.String(),
		"forceCleanup": config.forceCleanup,
	})

	// Execute resource cleanup with retries
	if err := CleanupResources(ctx, config); err != nil {
		common.LogTestError(t, err, map[string]interface{}{
			"phase": "resource_cleanup",
		})
		return err
	}

	// Verify cleanup completion
	if err := VerifyCleanup(ctx, config); err != nil {
		common.LogTestError(t, err, map[string]interface{}{
			"phase": "cleanup_verification",
		})
		return err
	}

	common.LogTestInfo(t, "Test environment teardown completed successfully", map[string]interface{}{
		"duration": time.Since(startTime).String(),
	})

	return nil
}

// CleanupResources executes phased cleanup of test resources
func CleanupResources(ctx context.Context, config *TeardownConfig) error {
	var lastErr error

	// Define cleanup phases
	phases := []struct {
		name     string
		cleanup  func(context.Context) error
		critical bool
	}{
		{"mock_services", stopMockServices, true},
		{"test_data", cleanTestData, true},
		{"connections", closeConnections, true},
		{"resources", cleanupResources, false},
	}

	for _, phase := range phases {
		for attempt := 0; attempt <= config.maxRetries; attempt++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				if err := phase.cleanup(ctx); err != nil {
					lastErr = err
					if config.enableMetrics {
						cleanupRetryCount.WithLabelValues(phase.name).Inc()
						resourceCleanupErrors.WithLabelValues(phase.name, err.Error()).Inc()
					}
					if attempt < config.maxRetries {
						time.Sleep(cleanupRetryDelay)
						continue
					}
					if phase.critical && !config.forceCleanup {
						return fmt.Errorf("critical phase %s failed: %w", phase.name, err)
					}
				}
				break
			}
		}
	}

	return lastErr
}

// VerifyCleanup performs comprehensive verification of cleanup completion
func VerifyCleanup(ctx context.Context, config *TeardownConfig) error {
	verifications := []struct {
		name    string
		verify  func(context.Context) error
		retries int
	}{
		{"mock_services", verifyMockServicesStopped, 2},
		{"test_data", verifyDataCleanup, 2},
		{"connections", verifyConnectionsClosed, 1},
	}

	for _, v := range verifications {
		var err error
		for attempt := 0; attempt <= v.retries; attempt++ {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
				if err = v.verify(ctx); err == nil {
					break
				}
				time.Sleep(defaultResourceWaitTime)
			}
		}
		if err != nil {
			return fmt.Errorf("verification failed for %s: %w", v.name, err)
		}
	}

	return nil
}

// Helper functions for resource cleanup
func stopMockServices(ctx context.Context) error {
	// Implementation for stopping mock services
	return nil
}

func cleanTestData(ctx context.Context) error {
	// Implementation for cleaning test data
	return nil
}

func closeConnections(ctx context.Context) error {
	// Implementation for closing connections
	return nil
}

func cleanupResources(ctx context.Context) error {
	// Implementation for cleaning up additional resources
	return nil
}

// Helper functions for cleanup verification
func verifyMockServicesStopped(ctx context.Context) error {
	// Implementation for verifying mock services are stopped
	return nil
}

func verifyDataCleanup(ctx context.Context) error {
	// Implementation for verifying data cleanup
	return nil
}

func verifyConnectionsClosed(ctx context.Context) error {
	// Implementation for verifying connections are closed
	return nil
}