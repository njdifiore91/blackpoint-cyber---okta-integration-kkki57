// Package framework provides core test framework functionality for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package framework

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus" // v1.17.0
	"../../pkg/common"
)

// CleanupPriority defines the execution order for cleanup operations
type CleanupPriority int

const (
	PriorityHigh   CleanupPriority = 100
	PriorityNormal CleanupPriority = 50
	PriorityLow    CleanupPriority = 10
)

// Global constants for cleanup management
const (
	defaultCleanupTimeout   = 30 * time.Second
	defaultCleanupRetries   = 3
	maxConcurrentCleanups   = 5
	retryBackoffFactor     = 1.5
)

// CleanupOperation represents a single cleanup task with dependencies
type CleanupOperation struct {
	name         string
	fn           func(context.Context) error
	dependencies []string
	priority     CleanupPriority
	metrics      *operationMetrics
}

// operationMetrics holds Prometheus metrics for cleanup operations
type operationMetrics struct {
	duration    prometheus.Histogram
	retries     prometheus.Counter
	failures    prometheus.Counter
	lastStatus  prometheus.Gauge
}

// CleanupManager handles cleanup operations with dependency management
type CleanupManager struct {
	t              *testing.T
	ctx            context.Context
	timeout        time.Duration
	maxRetries     int
	operations     map[string]*CleanupOperation
	dependencies   map[string][]string
	workerPool    *sync.WaitGroup
	metrics       *prometheus.Registry
	metricsPrefix string
	mu            sync.RWMutex
}

// NewCleanupManager creates a new cleanup manager instance
func NewCleanupManager(t *testing.T, ctx context.Context, metricsReporter *prometheus.Registry) *CleanupManager {
	cm := &CleanupManager{
		t:              t,
		ctx:            ctx,
		timeout:        defaultCleanupTimeout,
		maxRetries:     defaultCleanupRetries,
		operations:     make(map[string]*CleanupOperation),
		dependencies:   make(map[string][]string),
		workerPool:    &sync.WaitGroup{},
		metrics:       metricsReporter,
		metricsPrefix: "blackpoint_test_cleanup",
	}

	// Initialize metrics
	cm.initMetrics()

	return cm
}

// RegisterCleanupOperation registers a new cleanup operation with dependencies
func (cm *CleanupManager) RegisterCleanupOperation(name string, fn func(context.Context) error, dependencies []string, priority CleanupPriority) error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Validate operation
	if _, exists := cm.operations[name]; exists {
		return fmt.Errorf("cleanup operation %s already registered", name)
	}

	// Create operation metrics
	metrics := &operationMetrics{
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    fmt.Sprintf("%s_duration_seconds", cm.metricsPrefix),
			Help:    "Duration of cleanup operation execution",
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
			ConstLabels: prometheus.Labels{
				"operation": name,
			},
		}),
		retries: prometheus.NewCounter(prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_retries_total", cm.metricsPrefix),
			Help: "Number of cleanup operation retry attempts",
			ConstLabels: prometheus.Labels{
				"operation": name,
			},
		}),
		failures: prometheus.NewCounter(prometheus.CounterOpts{
			Name: fmt.Sprintf("%s_failures_total", cm.metricsPrefix),
			Help: "Number of cleanup operation failures",
			ConstLabels: prometheus.Labels{
				"operation": name,
			},
		}),
		lastStatus: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: fmt.Sprintf("%s_last_status", cm.metricsPrefix),
			Help: "Last execution status (1=success, 0=failure)",
			ConstLabels: prometheus.Labels{
				"operation": name,
			},
		}),
	}

	// Register metrics
	cm.metrics.MustRegister(metrics.duration)
	cm.metrics.MustRegister(metrics.retries)
	cm.metrics.MustRegister(metrics.failures)
	cm.metrics.MustRegister(metrics.lastStatus)

	// Create cleanup operation
	op := &CleanupOperation{
		name:         name,
		fn:           fn,
		dependencies: dependencies,
		priority:     priority,
		metrics:      metrics,
	}

	cm.operations[name] = op
	cm.dependencies[name] = dependencies

	// Validate dependency graph for cycles
	if err := cm.validateDependencies(); err != nil {
		delete(cm.operations, name)
		delete(cm.dependencies, name)
		return fmt.Errorf("invalid dependencies: %v", err)
	}

	common.LogTestInfo(cm.t, fmt.Sprintf("Registered cleanup operation: %s", name), map[string]interface{}{
		"dependencies": dependencies,
		"priority":     priority,
	})

	return nil
}

// ExecuteCleanup executes all registered cleanup operations
func (cm *CleanupManager) ExecuteCleanup() error {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	// Create execution context with timeout
	ctx, cancel := context.WithTimeout(cm.ctx, cm.timeout)
	defer cancel()

	// Sort operations by dependencies and priority
	sortedOps, err := cm.sortOperations()
	if err != nil {
		return fmt.Errorf("failed to sort cleanup operations: %v", err)
	}

	// Execute operations in batches based on dependencies
	for _, batch := range sortedOps {
		errors := make(chan error, len(batch))
		var batchWg sync.WaitGroup

		// Execute batch operations concurrently
		for _, op := range batch {
			batchWg.Add(1)
			go func(op *CleanupOperation) {
				defer batchWg.Done()
				if err := cm.executeOperation(ctx, op); err != nil {
					errors <- fmt.Errorf("cleanup operation %s failed: %v", op.name, err)
				}
			}(op)
		}

		// Wait for batch completion
		batchWg.Wait()
		close(errors)

		// Collect errors
		var batchErrors []error
		for err := range errors {
			batchErrors = append(batchErrors, err)
		}

		if len(batchErrors) > 0 {
			return fmt.Errorf("cleanup batch failed with %d errors: %v", len(batchErrors), batchErrors)
		}
	}

	return nil
}

// executeOperation executes a single cleanup operation with retries
func (cm *CleanupManager) executeOperation(ctx context.Context, op *CleanupOperation) error {
	startTime := time.Now()
	var lastErr error

	for attempt := 0; attempt <= cm.maxRetries; attempt++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			if attempt > 0 {
				op.metrics.retries.Inc()
				// Exponential backoff
				backoff := time.Duration(float64(time.Second) * retryBackoffFactor * float64(attempt))
				time.Sleep(backoff)
			}

			err := op.fn(ctx)
			if err == nil {
				duration := time.Since(startTime)
				op.metrics.duration.Observe(duration.Seconds())
				op.metrics.lastStatus.Set(1)
				common.LogTestInfo(cm.t, fmt.Sprintf("Cleanup operation completed: %s", op.name), map[string]interface{}{
					"duration": duration.String(),
					"attempts": attempt + 1,
				})
				return nil
			}

			lastErr = err
			op.metrics.failures.Inc()
			op.metrics.lastStatus.Set(0)
		}
	}

	return fmt.Errorf("cleanup operation failed after %d retries: %v", cm.maxRetries, lastErr)
}

// sortOperations sorts cleanup operations by dependencies and priority
func (cm *CleanupManager) sortOperations() ([][]*CleanupOperation, error) {
	visited := make(map[string]bool)
	sorted := make([][]*CleanupOperation, 0)
	
	// Group operations by dependency level
	for len(visited) < len(cm.operations) {
		batch := make([]*CleanupOperation, 0)
		
		for name, op := range cm.operations {
			if visited[name] {
				continue
			}
			
			// Check if all dependencies are satisfied
			depsResolved := true
			for _, dep := range op.dependencies {
				if !visited[dep] {
					depsResolved = false
					break
				}
			}
			
			if depsResolved {
				batch = append(batch, op)
				visited[name] = true
			}
		}
		
		if len(batch) == 0 && len(visited) < len(cm.operations) {
			return nil, fmt.Errorf("circular dependency detected")
		}
		
		// Sort batch by priority
		sortByPriority(batch)
		sorted = append(sorted, batch)
	}
	
	return sorted, nil
}

// validateDependencies checks for circular dependencies
func (cm *CleanupManager) validateDependencies() error {
	visited := make(map[string]bool)
	stack := make(map[string]bool)

	var checkCycles func(string) error
	checkCycles = func(name string) error {
		visited[name] = true
		stack[name] = true

		for _, dep := range cm.dependencies[name] {
			if !visited[dep] {
				if err := checkCycles(dep); err != nil {
					return err
				}
			} else if stack[dep] {
				return fmt.Errorf("circular dependency detected: %s -> %s", name, dep)
			}
		}

		stack[name] = false
		return nil
	}

	for name := range cm.operations {
		if !visited[name] {
			if err := checkCycles(name); err != nil {
				return err
			}
		}
	}

	return nil
}

// initMetrics initializes global cleanup metrics
func (cm *CleanupManager) initMetrics() {
	totalOps := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: fmt.Sprintf("%s_operations_total", cm.metricsPrefix),
		Help: "Total number of registered cleanup operations",
	})
	
	totalFailures := prometheus.NewCounter(prometheus.CounterOpts{
		Name: fmt.Sprintf("%s_total_failures", cm.metricsPrefix),
		Help: "Total number of cleanup operation failures",
	})
	
	cm.metrics.MustRegister(totalOps)
	cm.metrics.MustRegister(totalFailures)
}

// sortByPriority sorts cleanup operations by priority (highest first)
func sortByPriority(ops []*CleanupOperation) {
	for i := 0; i < len(ops)-1; i++ {
		for j := i + 1; j < len(ops); j++ {
			if ops[i].priority < ops[j].priority {
				ops[i], ops[j] = ops[j], ops[i]
			}
		}
	}
}