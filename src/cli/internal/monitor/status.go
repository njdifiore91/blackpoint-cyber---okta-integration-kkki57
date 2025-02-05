// Package monitor provides system status monitoring functionality for the BlackPoint CLI
package monitor

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/blackpoint/cli/pkg/api/client"
    "github.com/blackpoint/cli/pkg/monitor/types"
    "github.com/blackpoint/cli/internal/output/formatter"
    "github.com/blackpoint/cli/pkg/common/errors"
)

// Default timeout and retry settings
const (
    defaultStatusTimeout  = 30 * time.Second
    defaultRetryAttempts = 3
    defaultRetryDelay    = 2 * time.Second
)

// API endpoints
const (
    statusEndpoint  = "/api/v1/monitor/status"
    metricsEndpoint = "/api/v1/monitor/metrics"
    alertsEndpoint  = "/api/v1/monitor/alerts"
)

// GetSystemStatus retrieves comprehensive system status with retry logic
func GetSystemStatus(ctx context.Context, apiClient *client.APIClient, retryConfig *client.RetryConfig) (*types.SystemMetrics, []types.ComponentStatus, error) {
    ctx, cancel := context.WithTimeout(ctx, defaultStatusTimeout)
    defer cancel()

    // Initialize result channels
    metricsChan := make(chan *types.SystemMetrics, 1)
    componentsChan := make(chan []types.ComponentStatus, 1)
    errorsChan := make(chan error, 2)

    // Fetch metrics and component status concurrently
    var wg sync.WaitGroup
    wg.Add(2)

    // Fetch system metrics
    go func() {
        defer wg.Done()
        metrics := &types.SystemMetrics{}
        err := apiClient.Get(ctx, metricsEndpoint, metrics)
        if err != nil {
            errorsChan <- errors.WrapError(err, "failed to fetch system metrics")
            return
        }
        metricsChan <- metrics
    }()

    // Fetch component status
    go func() {
        defer wg.Done()
        var components []types.ComponentStatus
        err := apiClient.Get(ctx, statusEndpoint, &components)
        if err != nil {
            errorsChan <- errors.WrapError(err, "failed to fetch component status")
            return
        }
        componentsChan <- components
    }()

    // Wait for goroutines to complete
    go func() {
        wg.Wait()
        close(errorsChan)
    }()

    // Collect errors
    var errs []error
    for err := range errorsChan {
        errs = append(errs, err)
    }
    if len(errs) > 0 {
        return nil, nil, errors.WrapError(errs[0], "status check failed")
    }

    // Get results
    metrics := <-metricsChan
    components := <-componentsChan

    return metrics, components, nil
}

// GetActiveAlerts retrieves and processes active system alerts
func GetActiveAlerts(ctx context.Context, apiClient *client.APIClient, filter types.AlertFilter) ([]types.AlertInfo, error) {
    ctx, cancel := context.WithTimeout(ctx, defaultStatusTimeout)
    defer cancel()

    var alerts []types.AlertInfo
    err := apiClient.Get(ctx, alertsEndpoint, &alerts)
    if err != nil {
        return nil, errors.WrapError(err, "failed to fetch active alerts")
    }

    // Filter and sort alerts
    filteredAlerts := filterAlerts(alerts, filter)
    sortAlertsBySeverity(filteredAlerts)

    return filteredAlerts, nil
}

// FormatStatusOutput formats system status into readable output
func FormatStatusOutput(metrics *types.SystemMetrics, components []types.ComponentStatus, alerts []types.AlertInfo, colors *formatter.ColorScheme) (string, error) {
    if metrics == nil || len(components) == 0 {
        return "", errors.NewCLIError("E1004", "invalid status data", nil)
    }

    // Format metrics section
    metricsTable := [][]string{
        {fmt.Sprintf("Events/sec: %.2f", metrics.EventsPerSecond)},
        {fmt.Sprintf("CPU Usage: %.1f%%", metrics.CPUUsage)},
        {fmt.Sprintf("Memory Usage: %.1f%%", metrics.MemoryUsage)},
        {fmt.Sprintf("Storage Usage: %.1f%%", metrics.StorageUsage)},
    }

    // Format latency metrics
    for tier, latency := range metrics.ProcessingLatency {
        metricsTable = append(metricsTable, []string{
            fmt.Sprintf("%s Latency: %.2fms", tier, latency),
        })
    }

    // Format component status table
    componentHeaders := []string{"Component", "Status", "Load", "Memory", "Disk", "Last Check"}
    componentData := make([][]string, len(components))
    for i, comp := range components {
        componentData[i] = []string{
            comp.Name,
            comp.Status,
            fmt.Sprintf("%.1f%%", comp.Load),
            fmt.Sprintf("%.1f%%", comp.MemoryUsage),
            fmt.Sprintf("%.1f%%", comp.DiskUsage),
            comp.LastChecked.Format(time.RFC3339),
        }
    }

    // Format alerts section
    var alertData [][]string
    if len(alerts) > 0 {
        alertHeaders := []string{"Severity", "Component", "Message", "Time"}
        alertData = make([][]string, len(alerts))
        for i, alert := range alerts {
            alertData[i] = []string{
                alert.Severity,
                alert.Component,
                alert.Message,
                alert.Timestamp.Format(time.RFC3339),
            }
        }
    }

    // Configure table options
    tableOpts := formatter.TableOptions{
        Border:       true,
        CenterAlign: false,
        ColorEnabled: colors != nil,
        ColorScheme: map[string]string{
            "header":  "cyan",
            "healthy": "green",
            "warning": "yellow",
            "error":   "red",
        },
    }

    // Format complete output
    var output string
    metricsOut, err := formatter.FormatTable([]string{"System Metrics"}, metricsTable, tableOpts)
    if err != nil {
        return "", errors.WrapError(err, "failed to format metrics table")
    }
    output += metricsOut + "\n\n"

    componentOut, err := formatter.FormatTable(componentHeaders, componentData, tableOpts)
    if err != nil {
        return "", errors.WrapError(err, "failed to format component table")
    }
    output += "Component Status\n" + componentOut + "\n"

    if len(alertData) > 0 {
        alertOut, err := formatter.FormatTable([]string{"Active Alerts"}, alertData, tableOpts)
        if err != nil {
            return "", errors.WrapError(err, "failed to format alerts table")
        }
        output += "\n" + alertOut
    }

    return output, nil
}

// Helper functions

func filterAlerts(alerts []types.AlertInfo, filter types.AlertFilter) []types.AlertInfo {
    if len(alerts) == 0 {
        return alerts
    }

    filtered := make([]types.AlertInfo, 0)
    for _, alert := range alerts {
        if matchesFilter(alert, filter) {
            filtered = append(filtered, alert)
        }
    }
    return filtered
}

func matchesFilter(alert types.AlertInfo, filter types.AlertFilter) bool {
    // Implementation would check alert against filter criteria
    // This is a placeholder as the filter criteria are not specified in the imports
    return true
}

func sortAlertsBySeverity(alerts []types.AlertInfo) {
    if len(alerts) == 0 {
        return
    }

    // Sort alerts by severity (critical > warning > info) and timestamp
    severityWeight := map[string]int{
        "critical": 3,
        "warning":  2,
        "info":     1,
    }

    sort.Slice(alerts, func(i, j int) bool {
        if severityWeight[alerts[i].Severity] != severityWeight[alerts[j].Severity] {
            return severityWeight[alerts[i].Severity] > severityWeight[alerts[j].Severity]
        }
        return alerts[i].Timestamp.After(alerts[j].Timestamp)
    })
}