package monitor_test

import (
    "context"
    "encoding/json"
    "fmt"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/blackpoint/cli/pkg/api/client"
    "github.com/blackpoint/cli/pkg/monitor/types"
    "github.com/blackpoint/cli/internal/monitor/status"
    "github.com/blackpoint/cli/internal/output/formatter"
    "github.com/blackpoint/cli/pkg/common/errors"
)

const (
    testTimeout = 5 * time.Second
    mockAPIKey  = "test-api-key-12345"
)

// TestGetSystemStatus tests the system status retrieval functionality
func TestGetSystemStatus(t *testing.T) {
    // Create mock server
    mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        switch r.URL.Path {
        case "/api/v1/monitor/metrics":
            json.NewEncoder(w).Encode(types.SystemMetrics{
                EventsPerSecond: 1234.56,
                ProcessingLatency: map[string]float64{
                    "bronze": 0.8,
                    "silver": 3.2,
                    "gold":   12.5,
                },
                CPUUsage:     75.5,
                MemoryUsage:  60.2,
                StorageUsage: 45.8,
                Timestamp:    time.Now(),
            })
        case "/api/v1/monitor/status":
            json.NewEncoder(w).Encode([]types.ComponentStatus{
                {
                    Name:        "Collectors",
                    Status:      types.ComponentStatusHealthy,
                    Load:        75.0,
                    MemoryUsage: 60.0,
                    DiskUsage:   45.0,
                    LastChecked: time.Now(),
                },
                {
                    Name:        "Processors",
                    Status:      types.ComponentStatusDegraded,
                    Load:        82.0,
                    MemoryUsage: 70.0,
                    DiskUsage:   52.0,
                    LastChecked: time.Now(),
                },
            })
        }
    }))
    defer mockServer.Close()

    // Initialize API client
    apiClient, err := client.NewClient(mockServer.URL, mockAPIKey)
    if err != nil {
        t.Fatalf("Failed to create API client: %v", err)
    }

    // Test successful status retrieval
    t.Run("Successful Status Retrieval", func(t *testing.T) {
        ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
        defer cancel()

        metrics, components, err := status.GetSystemStatus(ctx, apiClient, nil)
        if err != nil {
            t.Fatalf("GetSystemStatus failed: %v", err)
        }

        // Validate metrics
        if metrics.EventsPerSecond <= 0 {
            t.Errorf("Expected non-zero events per second, got %.2f", metrics.EventsPerSecond)
        }
        if len(metrics.ProcessingLatency) != 3 {
            t.Errorf("Expected 3 latency metrics, got %d", len(metrics.ProcessingLatency))
        }

        // Validate components
        if len(components) != 2 {
            t.Errorf("Expected 2 components, got %d", len(components))
        }
        if components[0].Name != "Collectors" {
            t.Errorf("Expected Collectors component, got %s", components[0].Name)
        }
    })

    // Test timeout scenario
    t.Run("Timeout Scenario", func(t *testing.T) {
        ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
        defer cancel()

        _, _, err := status.GetSystemStatus(ctx, apiClient, nil)
        if err == nil {
            t.Error("Expected timeout error, got nil")
        }
        if !errors.IsRetryable(err) {
            t.Error("Expected retryable error for timeout")
        }
    })
}

// TestGetActiveAlerts tests the alert retrieval and processing functionality
func TestGetActiveAlerts(t *testing.T) {
    // Create mock server
    mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path == "/api/v1/monitor/alerts" {
            json.NewEncoder(w).Encode([]types.AlertInfo{
                {
                    ID:        "alert-1",
                    Severity:  types.AlertSeverityCritical,
                    Component: "Processors",
                    Message:   "High CPU utilization",
                    Timestamp: time.Now(),
                },
                {
                    ID:        "alert-2",
                    Severity:  types.AlertSeverityWarning,
                    Component: "Collectors",
                    Message:   "Increased latency detected",
                    Timestamp: time.Now(),
                },
            })
        }
    }))
    defer mockServer.Close()

    apiClient, err := client.NewClient(mockServer.URL, mockAPIKey)
    if err != nil {
        t.Fatalf("Failed to create API client: %v", err)
    }

    // Test alert retrieval
    t.Run("Alert Retrieval and Filtering", func(t *testing.T) {
        ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
        defer cancel()

        alerts, err := status.GetActiveAlerts(ctx, apiClient, types.AlertFilter{})
        if err != nil {
            t.Fatalf("GetActiveAlerts failed: %v", err)
        }

        if len(alerts) != 2 {
            t.Errorf("Expected 2 alerts, got %d", len(alerts))
        }

        // Verify alert ordering (critical first)
        if alerts[0].Severity != types.AlertSeverityCritical {
            t.Errorf("Expected first alert to be critical, got %s", alerts[0].Severity)
        }
    })
}

// TestFormatStatusOutput tests the status output formatting functionality
func TestFormatStatusOutput(t *testing.T) {
    // Test data
    metrics := &types.SystemMetrics{
        EventsPerSecond: 1234.56,
        ProcessingLatency: map[string]float64{
            "bronze": 0.8,
            "silver": 3.2,
            "gold":   12.5,
        },
        CPUUsage:     75.5,
        MemoryUsage:  60.2,
        StorageUsage: 45.8,
        Timestamp:    time.Now(),
    }

    components := []types.ComponentStatus{
        {
            Name:        "Collectors",
            Status:      types.ComponentStatusHealthy,
            Load:        75.0,
            MemoryUsage: 60.0,
            DiskUsage:   45.0,
            LastChecked: time.Now(),
        },
    }

    alerts := []types.AlertInfo{
        {
            ID:        "alert-1",
            Severity:  types.AlertSeverityCritical,
            Component: "Processors",
            Message:   "High CPU utilization",
            Timestamp: time.Now(),
        },
    }

    // Test output formatting
    t.Run("Format Status Output", func(t *testing.T) {
        colors := &formatter.ColorScheme{
            "header":  "cyan",
            "healthy": "green",
            "warning": "yellow",
            "error":   "red",
        }

        output, err := status.FormatStatusOutput(metrics, components, alerts, colors)
        if err != nil {
            t.Fatalf("FormatStatusOutput failed: %v", err)
        }

        // Verify output contains key information
        expectedStrings := []string{
            fmt.Sprintf("Events/sec: %.2f", metrics.EventsPerSecond),
            components[0].Name,
            alerts[0].Message,
        }

        for _, expected := range expectedStrings {
            if !strings.Contains(output, expected) {
                t.Errorf("Expected output to contain '%s'", expected)
            }
        }
    })

    // Test invalid input handling
    t.Run("Invalid Input Handling", func(t *testing.T) {
        _, err := status.FormatStatusOutput(nil, nil, nil, nil)
        if err == nil {
            t.Error("Expected error for nil input, got nil")
        }
    })
}

// TestComponentStatusValidation tests the component status validation logic
func TestComponentStatusValidation(t *testing.T) {
    t.Run("Healthy Status Validation", func(t *testing.T) {
        component := types.ComponentStatus{
            Name:        "TestComponent",
            Status:      types.ComponentStatusHealthy,
            Load:        50.0,
            MemoryUsage: 60.0,
            DiskUsage:   40.0,
            LastChecked: time.Now(),
        }

        if !component.IsHealthy() {
            t.Error("Expected component to be healthy")
        }
    })

    t.Run("Degraded Status Validation", func(t *testing.T) {
        component := types.ComponentStatus{
            Name:        "TestComponent",
            Status:      types.ComponentStatusDegraded,
            Load:        85.0,
            MemoryUsage: 90.0,
            DiskUsage:   70.0,
            LastChecked: time.Now(),
        }

        if component.IsHealthy() {
            t.Error("Expected component to be unhealthy")
        }
    })
}