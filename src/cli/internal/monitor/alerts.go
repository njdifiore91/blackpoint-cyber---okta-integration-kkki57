// Package monitor implements alert monitoring functionality for the BlackPoint CLI
package monitor

import (
    "context"
    "fmt"
    "sort"
    "strings"
    "time"

    "github.com/blackpoint/cli/pkg/api/client"
    "github.com/blackpoint/cli/pkg/common/errors"
    "github.com/blackpoint/cli/pkg/monitor/types"
    "github.com/blackpoint/cli/internal/output/formatter"
)

// Default configuration values
const (
    defaultAlertLimit = 100
    maxTimeRange     = 168 * time.Hour // 7 days
)

// Valid severity levels for alerts
var validSeverityLevels = []string{"Critical", "High", "Medium", "Low", "Info"}

// Alert table headers and colors
var (
    alertTableHeaders = []string{"ID", "Severity", "Component", "Message", "Time"}
    severityColors = map[string]string{
        "Critical": "Red",
        "High":    "Yellow",
        "Medium":  "Blue",
        "Low":     "Green",
        "Info":    "White",
    }
)

// AlertFilter provides configuration for filtering system alerts
type AlertFilter struct {
    Severity   string
    Component  string
    TimeRange  time.Duration
    Limit      int
    Page       int
}

// NewAlertFilter creates a new alert filter with default values
func NewAlertFilter() *AlertFilter {
    return &AlertFilter{
        Limit:     defaultAlertLimit,
        TimeRange: 24 * time.Hour,
        Page:      1,
    }
}

// WithSeverity sets the severity filter with validation
func (f *AlertFilter) WithSeverity(severity string) *AlertFilter {
    severity = strings.Title(strings.ToLower(severity))
    for _, valid := range validSeverityLevels {
        if severity == valid {
            f.Severity = severity
            break
        }
    }
    return f
}

// WithComponent sets the component filter with validation
func (f *AlertFilter) WithComponent(component string) *AlertFilter {
    if component != "" && !strings.Contains(component, "*") { // Prevent injection
        f.Component = component
    }
    return f
}

// WithTimeRange sets the time range filter with validation
func (f *AlertFilter) WithTimeRange(duration time.Duration) *AlertFilter {
    if duration > 0 && duration <= maxTimeRange {
        f.TimeRange = duration
    }
    return f
}

// GetAlerts retrieves system alerts from the BlackPoint backend
func GetAlerts(ctx context.Context, client *client.APIClient, filter *AlertFilter) ([]types.AlertInfo, error) {
    if client == nil {
        return nil, errors.NewCLIError("E1004", "nil API client provided", nil)
    }

    if filter == nil {
        filter = NewAlertFilter()
    }

    // Construct API request parameters
    params := map[string]interface{}{
        "limit":      filter.Limit,
        "page":       filter.Page,
        "time_range": filter.TimeRange.String(),
    }
    if filter.Severity != "" {
        params["severity"] = filter.Severity
    }
    if filter.Component != "" {
        params["component"] = filter.Component
    }

    // Make API request with retry logic
    var alerts []types.AlertInfo
    endpoint := fmt.Sprintf("/api/v1/alerts")
    err := client.Get(ctx, endpoint, &alerts)
    if err != nil {
        return nil, errors.WrapError(err, "failed to retrieve alerts")
    }

    // Apply additional filtering and sorting
    return FilterAlerts(alerts, filter), nil
}

// FilterAlerts filters alerts based on provided criteria
func FilterAlerts(alerts []types.AlertInfo, filter *AlertFilter) []types.AlertInfo {
    if len(alerts) == 0 || filter == nil {
        return alerts
    }

    filtered := make([]types.AlertInfo, 0, len(alerts))
    cutoff := time.Now().Add(-filter.TimeRange)

    for _, alert := range alerts {
        // Apply time range filter
        if alert.Timestamp.Before(cutoff) {
            continue
        }

        // Apply severity filter
        if filter.Severity != "" && alert.Severity != filter.Severity {
            continue
        }

        // Apply component filter
        if filter.Component != "" && !strings.Contains(alert.Component, filter.Component) {
            continue
        }

        filtered = append(filtered, alert)
    }

    // Sort by timestamp descending
    sort.Slice(filtered, func(i, j int) bool {
        return filtered[i].Timestamp.After(filtered[j].Timestamp)
    })

    // Apply pagination
    start := (filter.Page - 1) * filter.Limit
    if start >= len(filtered) {
        return []types.AlertInfo{}
    }
    end := start + filter.Limit
    if end > len(filtered) {
        end = len(filtered)
    }

    return filtered[start:end]
}

// DisplayAlerts formats and displays alerts in a color-coded table
func DisplayAlerts(alerts []types.AlertInfo) error {
    if len(alerts) == 0 {
        return nil
    }

    // Convert alerts to table rows
    rows := make([][]string, len(alerts))
    for i, alert := range alerts {
        rows[i] = []string{
            alert.ID,
            alert.Severity,
            alert.Component,
            alert.Message,
            alert.Timestamp.Local().Format("2006-01-02 15:04:05"),
        }
    }

    // Configure table formatting options
    options := formatter.TableOptions{
        Border:       true,
        CenterAlign: false,
        ColorEnabled: true,
        ColorScheme: severityColors,
        MinColumnWidth: 10,
        WrapText:     true,
    }

    // Format and display the table
    output, err := formatter.FormatTable(alertTableHeaders, rows, options)
    if err != nil {
        return errors.WrapError(err, "failed to format alerts table")
    }

    fmt.Println(output)
    return nil
}