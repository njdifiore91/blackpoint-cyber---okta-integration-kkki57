// Package monitor provides health monitoring functionality for the BlackPoint CLI
package monitor

import (
    "context"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/blackpoint/cli/pkg/api/client"
    "github.com/blackpoint/cli/pkg/common/constants"
    cerrors "github.com/blackpoint/cli/pkg/common/errors"
    "github.com/blackpoint/cli/pkg/monitor/types"
)

// Default values for health checking
const (
    defaultCheckInterval = 30 * time.Second
    defaultTimeout      = 10 * time.Second
    maxRetries         = 3
    retryDelay         = 2 * time.Second
)

// Supported component types
var validComponents = []string{
    "collectors",
    "processors",
    "api-gateway",
}

// HealthChecker manages health checking functionality with thread-safe operations
type HealthChecker struct {
    mu            sync.RWMutex
    client        *client.APIClient
    checkInterval time.Duration
    components    []string
    lastStatus    map[string]*types.ComponentStatus
    lastMetrics   *types.SystemMetrics
}

// NewHealthChecker creates a new HealthChecker instance with validation
func NewHealthChecker(client *client.APIClient) (*HealthChecker, error) {
    if client == nil {
        return nil, cerrors.NewCLIError("1001", "API client is required", nil)
    }

    checker := &HealthChecker{
        client:        client,
        checkInterval: defaultCheckInterval,
        components:    validComponents,
        lastStatus:    make(map[string]*types.ComponentStatus),
        lastMetrics:   &types.SystemMetrics{},
    }

    return checker, nil
}

// CheckComponentHealth performs a thread-safe health check of a specific component
func (h *HealthChecker) CheckComponentHealth(ctx context.Context, component string) (*types.ComponentStatus, error) {
    // Validate component
    if !isValidComponent(component) {
        return nil, cerrors.NewCLIError("1004", fmt.Sprintf("invalid component: %s", component), nil)
    }

    // Create context with timeout
    ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
    defer cancel()

    var status *types.ComponentStatus
    var err error

    // Implement retry logic for transient failures
    for attempt := 0; attempt <= maxRetries; attempt++ {
        if attempt > 0 {
            time.Sleep(retryDelay)
        }

        status, err = h.fetchComponentHealth(ctx, component)
        if err == nil {
            break
        }

        if !cerrors.IsRetryable(err) {
            return nil, cerrors.WrapError(err, fmt.Sprintf("non-retryable error checking %s health", component))
        }
    }

    if err != nil {
        return nil, cerrors.WrapError(err, fmt.Sprintf("failed to check %s health after %d attempts", component, maxRetries))
    }

    // Thread-safe update of last status
    h.mu.Lock()
    h.lastStatus[component] = status
    h.mu.Unlock()

    return status, nil
}

// CheckSystemHealth executes concurrent system-wide health check
func (h *HealthChecker) CheckSystemHealth(ctx context.Context) ([]*types.ComponentStatus, error) {
    ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
    defer cancel()

    var wg sync.WaitGroup
    results := make(map[string]*types.ComponentStatus)
    errors := make(map[string]error)
    resultMu := sync.Mutex{}

    // Check each component concurrently
    for _, component := range h.components {
        wg.Add(1)
        go func(comp string) {
            defer wg.Done()

            status, err := h.CheckComponentHealth(ctx, comp)
            
            resultMu.Lock()
            if err != nil {
                errors[comp] = err
            } else {
                results[comp] = status
            }
            resultMu.Unlock()
        }(component)
    }

    wg.Wait()

    // Process results and errors
    if len(errors) > 0 {
        var errMsg string
        for comp, err := range errors {
            errMsg += fmt.Sprintf("%s: %v; ", comp, err)
        }
        return nil, cerrors.NewCLIError("1003", fmt.Sprintf("health check failures: %s", errMsg), nil)
    }

    // Convert results map to slice
    statuses := make([]*types.ComponentStatus, 0, len(results))
    for _, status := range results {
        statuses = append(statuses, status)
    }

    return statuses, nil
}

// GetSystemMetrics collects comprehensive system performance metrics
func (h *HealthChecker) GetSystemMetrics(ctx context.Context) (*types.SystemMetrics, error) {
    ctx, cancel := context.WithTimeout(ctx, defaultTimeout)
    defer cancel()

    metrics := &types.SystemMetrics{}
    endpoint := "api/v1/metrics/system"

    err := h.client.Get(ctx, endpoint, metrics)
    if err != nil {
        return nil, cerrors.WrapError(err, "failed to fetch system metrics")
    }

    // Validate metric data
    if err := validateMetrics(metrics); err != nil {
        return nil, cerrors.WrapError(err, "invalid system metrics received")
    }

    // Thread-safe update of last metrics
    h.mu.Lock()
    h.lastMetrics = metrics
    h.mu.Unlock()

    return metrics, nil
}

// fetchComponentHealth makes the actual API call to check component health
func (h *HealthChecker) fetchComponentHealth(ctx context.Context, component string) (*types.ComponentStatus, error) {
    endpoint := fmt.Sprintf("api/v1/health/%s", component)
    status := &types.ComponentStatus{}

    err := h.client.Get(ctx, endpoint, status)
    if err != nil {
        return nil, err
    }

    return status, nil
}

// isValidComponent checks if a component is supported
func isValidComponent(component string) bool {
    for _, valid := range validComponents {
        if valid == component {
            return true
        }
    }
    return false
}

// validateMetrics ensures all required metric fields are present
func validateMetrics(metrics *types.SystemMetrics) error {
    if metrics == nil {
        return errors.New("nil metrics received")
    }

    if metrics.ProcessingLatency == nil {
        return errors.New("missing processing latency data")
    }

    requiredTiers := []string{"bronze", "silver", "gold"}
    for _, tier := range requiredTiers {
        if _, exists := metrics.ProcessingLatency[tier]; !exists {
            return fmt.Errorf("missing latency data for %s tier", tier)
        }
    }

    return nil
}