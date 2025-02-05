// Package integration provides data collection management functionality for security platform integrations
package integration

import (
    "context"
    "sync"
    "time"

    "github.com/blackpoint/cli/pkg/api/client"
    "github.com/blackpoint/cli/pkg/common/errors"
    "github.com/blackpoint/cli/pkg/integration/types"
)

// CollectionState represents the current state of the collector
type CollectionState string

const (
    StateInitialized CollectionState = "initialized"
    StateRunning     CollectionState = "running"
    StatePaused      CollectionState = "paused"
    StateStopped     CollectionState = "stopped"
    StateError       CollectionState = "error"
)

// ResourceMetrics represents resource utilization metrics for the collector
type ResourceMetrics struct {
    CPUUsage    float64 `json:"cpu_usage"`
    MemoryUsage float64 `json:"memory_usage"`
    DiskUsage   float64 `json:"disk_usage"`
}

// CollectorStatus represents the detailed status of a collector
type CollectorStatus struct {
    State               CollectionState  `json:"state"`
    EventsCollected     int64           `json:"events_collected"`
    Uptime             time.Duration    `json:"uptime"`
    EventsPerSecond    float64         `json:"events_per_second"`
    LastError          string          `json:"last_error,omitempty"`
    ResourceUtilization ResourceMetrics `json:"resource_utilization"`
}

// RetryConfig defines retry behavior for collection operations
type RetryConfig struct {
    MaxAttempts int           `json:"max_attempts"`
    Delay       time.Duration `json:"delay"`
    MaxDelay    time.Duration `json:"max_delay"`
}

// Collector manages data collection for a security platform integration
type Collector struct {
    integration  *types.Integration
    apiClient    *client.APIClient
    ctx          context.Context
    cancel       context.CancelFunc
    collectionWg *sync.WaitGroup
    metrics      *CollectionMetrics
    state        CollectionState
    retryConfig  *RetryConfig
    mu           sync.RWMutex
    startTime    time.Time
}

// CollectionMetrics tracks collection performance metrics
type CollectionMetrics struct {
    EventsCollected int64
    LastEventTime   time.Time
    ErrorCount      int64
    mu             sync.RWMutex
}

// NewCollector creates a new collector instance with the specified configuration
func NewCollector(integration *types.Integration, apiClient *client.APIClient, retryConfig *RetryConfig) (*Collector, error) {
    if integration == nil || apiClient == nil {
        return nil, errors.NewCLIError("E1001", "integration and apiClient are required", nil)
    }

    if err := integration.Validate(); err != nil {
        return nil, errors.WrapError(err, "invalid integration configuration")
    }

    ctx, cancel := context.WithCancel(context.Background())

    collector := &Collector{
        integration:  integration,
        apiClient:    apiClient,
        ctx:         ctx,
        cancel:      cancel,
        collectionWg: &sync.WaitGroup{},
        metrics: &CollectionMetrics{
            LastEventTime: time.Now(),
        },
        state:       StateInitialized,
        retryConfig: retryConfig,
    }

    return collector, nil
}

// Start begins the data collection process
func (c *Collector) Start() error {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.state == StateRunning {
        return errors.NewCLIError("E1004", "collector is already running", nil)
    }

    c.startTime = time.Now()

    // Initialize collection based on mode
    switch c.integration.Config.Collection.Mode {
    case "realtime":
        go c.startRealtimeCollection()
    case "batch":
        go c.startBatchCollection()
    case "hybrid":
        go c.startHybridCollection()
    default:
        return errors.NewCLIError("E1004", "unsupported collection mode", nil)
    }

    c.state = StateRunning
    return nil
}

// Stop gracefully stops the data collection process
func (c *Collector) Stop() error {
    c.mu.Lock()
    defer c.mu.Unlock()

    if c.state != StateRunning {
        return errors.NewCLIError("E1004", "collector is not running", nil)
    }

    c.cancel()
    c.collectionWg.Wait()
    c.state = StateStopped
    return nil
}

// Status returns the current collector status with metrics
func (c *Collector) Status() (CollectorStatus, error) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    status := CollectorStatus{
        State:           c.state,
        EventsCollected: c.metrics.EventsCollected,
        Uptime:         time.Since(c.startTime),
        ResourceUtilization: ResourceMetrics{
            CPUUsage:    c.calculateCPUUsage(),
            MemoryUsage: c.calculateMemoryUsage(),
            DiskUsage:   c.calculateDiskUsage(),
        },
    }

    if c.state == StateRunning {
        status.EventsPerSecond = c.calculateEventsPerSecond()
    }

    return status, nil
}

// startRealtimeCollection handles real-time event collection
func (c *Collector) startRealtimeCollection() {
    c.collectionWg.Add(1)
    defer c.collectionWg.Done()

    for {
        select {
        case <-c.ctx.Done():
            return
        default:
            if err := c.collectRealtimeEvents(); err != nil {
                if !errors.IsRetryable(err) {
                    c.handleFatalError(err)
                    return
                }
                c.handleRetryableError(err)
            }
        }
    }
}

// startBatchCollection handles batch event collection
func (c *Collector) startBatchCollection() {
    c.collectionWg.Add(1)
    defer c.collectionWg.Done()

    ticker := time.NewTicker(c.getBatchInterval())
    defer ticker.Stop()

    for {
        select {
        case <-c.ctx.Done():
            return
        case <-ticker.C:
            if err := c.collectBatchEvents(); err != nil {
                if !errors.IsRetryable(err) {
                    c.handleFatalError(err)
                    return
                }
                c.handleRetryableError(err)
            }
        }
    }
}

// startHybridCollection handles hybrid event collection
func (c *Collector) startHybridCollection() {
    c.collectionWg.Add(2)
    go func() {
        defer c.collectionWg.Done()
        c.startRealtimeCollection()
    }()
    go func() {
        defer c.collectionWg.Done()
        c.startBatchCollection()
    }()
}

// handleFatalError processes non-recoverable collection errors
func (c *Collector) handleFatalError(err error) {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.state = StateError
    c.metrics.ErrorCount++
}

// handleRetryableError processes recoverable collection errors
func (c *Collector) handleRetryableError(err error) {
    c.metrics.mu.Lock()
    c.metrics.ErrorCount++
    c.metrics.mu.Unlock()
    time.Sleep(c.retryConfig.Delay)
}

// calculateEventsPerSecond calculates the current events per second rate
func (c *Collector) calculateEventsPerSecond() float64 {
    uptime := time.Since(c.startTime).Seconds()
    if uptime > 0 {
        return float64(c.metrics.EventsCollected) / uptime
    }
    return 0
}

// getBatchInterval returns the configured batch collection interval
func (c *Collector) getBatchInterval() time.Duration {
    // Default to 5 minutes if not specified
    return 5 * time.Minute
}

// Utility functions for resource metrics
func (c *Collector) calculateCPUUsage() float64 {
    // Implementation would use system metrics
    return 0.0
}

func (c *Collector) calculateMemoryUsage() float64 {
    // Implementation would use system metrics
    return 0.0
}

func (c *Collector) calculateDiskUsage() float64 {
    // Implementation would use system metrics
    return 0.0
}

// collectRealtimeEvents implements real-time event collection
func (c *Collector) collectRealtimeEvents() error {
    // Implementation would use c.apiClient to collect events
    return nil
}

// collectBatchEvents implements batch event collection
func (c *Collector) collectBatchEvents() error {
    // Implementation would use c.apiClient to collect events
    return nil
}