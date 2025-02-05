// Package monitor implements metrics collection and formatting functionality for the BlackPoint CLI
package monitor

import (
    "context"
    "errors"
    "fmt"
    "sync"
    "time"

    "github.com/blackpoint/cli/pkg/api/client"
    "github.com/blackpoint/cli/pkg/monitor/types"
    "github.com/blackpoint/cli/internal/output/formatter"
)

// MetricsCollector provides thread-safe metrics collection and formatting
type MetricsCollector struct {
    client        *client.APIClient
    pollInterval  time.Duration
    mutex         *sync.RWMutex
    thresholds    *types.MetricThresholds
    metricsCache  map[string]*types.SystemMetrics
}

// NewMetricsCollector creates a new metrics collector with validation
func NewMetricsCollector(client *client.APIClient, pollInterval time.Duration, thresholds *types.MetricThresholds) (*MetricsCollector, error) {
    if client == nil {
        return nil, errors.New("client cannot be nil")
    }
    if pollInterval <= 0 {
        return nil, errors.New("poll interval must be positive")
    }
    if thresholds == nil {
        return nil, errors.New("thresholds cannot be nil")
    }

    return &MetricsCollector{
        client:       client,
        pollInterval: pollInterval,
        mutex:        &sync.RWMutex{},
        thresholds:   thresholds,
        metricsCache: make(map[string]*types.SystemMetrics),
    }, nil
}

// GetSystemMetrics fetches current system-wide metrics with retry and validation
func (mc *MetricsCollector) GetSystemMetrics(ctx context.Context) (*types.SystemMetrics, error) {
    mc.mutex.RLock()
    defer mc.mutex.RUnlock()

    var metrics types.SystemMetrics
    err := mc.client.Get(ctx, "/api/v1/metrics/system", &metrics)
    if err != nil {
        return nil, fmt.Errorf("failed to fetch system metrics: %w", err)
    }

    // Cache the metrics with timestamp
    metrics.Timestamp = time.Now()
    mc.metricsCache["system"] = &metrics

    return &metrics, nil
}

// GetComponentStatus fetches status of system components in parallel
func (mc *MetricsCollector) GetComponentStatus(ctx context.Context, components []string) ([]*types.ComponentStatus, error) {
    if len(components) == 0 {
        return nil, errors.New("no components specified")
    }

    var (
        wg sync.WaitGroup
        mu sync.Mutex
        results = make([]*types.ComponentStatus, 0, len(components))
        errs = make([]error, 0)
    )

    for _, component := range components {
        wg.Add(1)
        go func(comp string) {
            defer wg.Done()

            var status types.ComponentStatus
            err := mc.client.Get(ctx, fmt.Sprintf("/api/v1/status/component/%s", comp), &status)
            
            mu.Lock()
            defer mu.Unlock()

            if err != nil {
                errs = append(errs, fmt.Errorf("failed to fetch status for %s: %w", comp, err))
                return
            }
            
            status.LastChecked = time.Now()
            results = append(results, &status)
        }(component)
    }

    wg.Wait()

    if len(errs) > 0 {
        return results, fmt.Errorf("errors fetching component status: %v", errs)
    }

    return results, nil
}

// FormatMetricsTable formats system metrics as colored table with progress indicators
func (mc *MetricsCollector) FormatMetricsTable(metrics *types.SystemMetrics, colors *formatter.ColorScheme) (string, error) {
    if metrics == nil {
        return "", errors.New("metrics cannot be nil")
    }

    headers := []string{"Metric", "Value", "Status"}
    data := [][]string{
        {"Events/sec", fmt.Sprintf("%.2f", metrics.EventsPerSecond), getStatusIndicator(metrics.EventsPerSecond, mc.thresholds.EventsPerSecond)},
        {"CPU Usage", fmt.Sprintf("%.1f%%", metrics.CPUUsage), getStatusIndicator(metrics.CPUUsage, mc.thresholds.CPUUsage)},
        {"Memory Usage", fmt.Sprintf("%.1f%%", metrics.MemoryUsage), getStatusIndicator(metrics.MemoryUsage, mc.thresholds.MemoryUsage)},
        {"Storage Usage", fmt.Sprintf("%.1f%%", metrics.StorageUsage), getStatusIndicator(metrics.StorageUsage, mc.thresholds.StorageUsage)},
    }

    // Add processing latency for each tier
    for tier, latency := range metrics.ProcessingLatency {
        data = append(data, []string{
            fmt.Sprintf("%s Latency", tier),
            fmt.Sprintf("%.2fms", latency),
            getLatencyIndicator(latency, mc.thresholds.ProcessingLatency[tier]),
        })
    }

    options := formatter.TableOptions{
        Border:       true,
        CenterAlign: true,
        ColorEnabled: colors != nil,
        ColorScheme: colors,
    }

    return formatter.FormatTable(headers, data, options)
}

// FormatComponentTable formats component status as detailed table with health indicators
func (mc *MetricsCollector) FormatComponentTable(components []*types.ComponentStatus, colors *formatter.ColorScheme) (string, error) {
    if len(components) == 0 {
        return "", errors.New("no components provided")
    }

    headers := []string{"Component", "Status", "Load", "Memory", "Disk", "Last Check"}
    data := make([][]string, len(components))

    for i, comp := range components {
        data[i] = []string{
            comp.Name,
            comp.Status,
            fmt.Sprintf("%.1f%%", comp.Load),
            fmt.Sprintf("%.1f%%", comp.MemoryUsage),
            fmt.Sprintf("%.1f%%", comp.DiskUsage),
            comp.LastChecked.Format("15:04:05"),
        }
    }

    options := formatter.TableOptions{
        Border:       true,
        CenterAlign: true,
        ColorEnabled: colors != nil,
        ColorScheme: colors,
    }

    return formatter.FormatTable(headers, data, options)
}

// Helper functions

func getStatusIndicator(value float64, threshold float64) string {
    if value >= threshold {
        return "⚠️ Warning"
    }
    return "✓ OK"
}

func getLatencyIndicator(latency float64, threshold float64) string {
    if latency >= threshold {
        return "⚠️ High"
    }
    return "✓ Normal"
}