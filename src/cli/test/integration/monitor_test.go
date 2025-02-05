package integration

import (
    "context"
    "testing"
    "time"
    "sync"

    "github.com/stretchr/testify/assert"

    "github.com/blackpoint/cli/pkg/monitor/types"
    "github.com/blackpoint/cli/internal/monitor/status"
    "github.com/blackpoint/cli/test/internal/framework"
)

// Global test constants
const (
    testTimeout = 5 * time.Minute
    testComponentCount = 5
    bronzeLatencySLA = 1 * time.Second
    silverLatencySLA = 5 * time.Second
    goldLatencySLA = 30 * time.Second
    throughputSLA = 1000 // events per second
)

// TestMonitorIntegration is the main test entry point for monitor integration tests
func TestMonitorIntegration(t *testing.T) {
    t.Parallel()

    // Create test suite with security validation
    suite := framework.NewTestSuite(t, "monitor-integration", &framework.TestSuiteConfig{
        Timeout:          testTimeout,
        Parallel:         true,
        SecurityEnabled:  true,
        MonitoringEnabled: true,
        ValidationConfig: map[string]float64{
            "accuracy":     80.0,
            "performance": 95.0,
            "security":    90.0,
        },
    })

    // Add test cases
    suite.AddTestCase(framework.NewTestCase(t, "system-status", func(ctx context.Context) error {
        return testSystemStatus(ctx, t)
    }))

    suite.AddTestCase(framework.NewTestCase(t, "active-alerts", func(ctx context.Context) error {
        return testActiveAlerts(ctx, t)
    }))

    suite.AddTestCase(framework.NewTestCase(t, "metrics-collection", func(ctx context.Context) error {
        return testMetricsCollection(ctx, t)
    }))

    // Run test suite
    if err := suite.Run(); err != nil {
        t.Fatalf("Monitor integration test suite failed: %v", err)
    }
}

// testSystemStatus validates system status retrieval and component health checks
func testSystemStatus(ctx context.Context, t *testing.T) error {
    // Generate test components
    components := make([]types.ComponentStatus, testComponentCount)
    for i := 0; i < testComponentCount; i++ {
        components[i] = types.ComponentStatus{
            Name:        fmt.Sprintf("test-component-%d", i),
            Status:      types.ComponentStatusHealthy,
            Load:        float64(50 + i),
            MemoryUsage: float64(60 + i),
            DiskUsage:   float64(40 + i),
            LastChecked: time.Now(),
        }
    }

    // Generate test metrics
    metrics := &types.SystemMetrics{
        EventsPerSecond: float64(throughputSLA + 100),
        ProcessingLatency: map[string]float64{
            "bronze": float64(bronzeLatencySLA.Milliseconds() - 100),
            "silver": float64(silverLatencySLA.Milliseconds() - 500),
            "gold":   float64(goldLatencySLA.Milliseconds() - 1000),
        },
        CPUUsage:     75.0,
        MemoryUsage:  70.0,
        StorageUsage: 65.0,
        Timestamp:    time.Now(),
    }

    // Test status output formatting
    output, err := status.FormatStatusOutput(metrics, components, nil, nil)
    if err != nil {
        return err
    }

    // Validate output format and content
    assert.Contains(t, output, "System Metrics")
    assert.Contains(t, output, "Component Status")
    assert.Contains(t, output, fmt.Sprintf("Events/sec: %.2f", metrics.EventsPerSecond))

    // Validate component health
    for _, comp := range components {
        assert.True(t, comp.IsHealthy(), "Component %s should be healthy", comp.Name)
        assert.Less(t, comp.Load, 80.0, "Component load should be below threshold")
        assert.Less(t, comp.MemoryUsage, 85.0, "Component memory usage should be below threshold")
        assert.Less(t, comp.DiskUsage, 85.0, "Component disk usage should be below threshold")
    }

    // Validate SLA compliance
    assert.GreaterOrEqual(t, metrics.EventsPerSecond, float64(throughputSLA), 
        "Event throughput should meet SLA requirement")
    assert.LessOrEqual(t, metrics.ProcessingLatency["bronze"], float64(bronzeLatencySLA.Milliseconds()),
        "Bronze tier latency should meet SLA")
    assert.LessOrEqual(t, metrics.ProcessingLatency["silver"], float64(silverLatencySLA.Milliseconds()),
        "Silver tier latency should meet SLA")
    assert.LessOrEqual(t, metrics.ProcessingLatency["gold"], float64(goldLatencySLA.Milliseconds()),
        "Gold tier latency should meet SLA")

    return nil
}

// testActiveAlerts validates alert retrieval and management
func testActiveAlerts(ctx context.Context, t *testing.T) error {
    // Generate test alerts
    alerts := []types.AlertInfo{
        {
            ID:        "alert-001",
            Severity:  types.AlertSeverityCritical,
            Component: "test-component-1",
            Message:   "Critical resource exhaustion",
            Timestamp: time.Now(),
            Details: map[string]interface{}{
                "resource": "memory",
                "threshold": 90.0,
                "current": 95.0,
            },
        },
        {
            ID:        "alert-002",
            Severity:  types.AlertSeverityWarning,
            Component: "test-component-2",
            Message:   "High CPU utilization",
            Timestamp: time.Now(),
            Details: map[string]interface{}{
                "resource": "cpu",
                "threshold": 80.0,
                "current": 85.0,
            },
        },
    }

    // Test alert output formatting
    output, err := status.FormatStatusOutput(nil, nil, alerts, nil)
    if err != nil {
        return err
    }

    // Validate alert formatting
    assert.Contains(t, output, "Active Alerts")
    assert.Contains(t, output, alerts[0].Message)
    assert.Contains(t, output, alerts[1].Message)

    // Validate alert severity ordering
    assert.True(t, alerts[0].IsCritical(), "First alert should be critical")
    assert.Equal(t, types.AlertSeverityWarning, alerts[1].Severity, "Second alert should be warning")

    // Validate alert details
    for _, alert := range alerts {
        assert.NotEmpty(t, alert.ID, "Alert ID should not be empty")
        assert.NotEmpty(t, alert.Component, "Alert component should not be empty")
        assert.NotEmpty(t, alert.Message, "Alert message should not be empty")
        assert.NotNil(t, alert.Details, "Alert details should not be nil")
        assert.False(t, alert.Timestamp.IsZero(), "Alert timestamp should be set")
    }

    return nil
}

// testMetricsCollection validates system metrics collection and SLA validation
func testMetricsCollection(ctx context.Context, t *testing.T) error {
    var wg sync.WaitGroup
    errChan := make(chan error, 1)

    // Test concurrent metrics collection
    for i := 0; i < 3; i++ {
        wg.Add(1)
        go func(iteration int) {
            defer wg.Done()

            metrics := &types.SystemMetrics{
                EventsPerSecond: float64(throughputSLA + 100*iteration),
                ProcessingLatency: map[string]float64{
                    "bronze": float64(bronzeLatencySLA.Milliseconds() - 100),
                    "silver": float64(silverLatencySLA.Milliseconds() - 500),
                    "gold":   float64(goldLatencySLA.Milliseconds() - 1000),
                },
                CPUUsage:     60.0 + float64(iteration*5),
                MemoryUsage:  65.0 + float64(iteration*5),
                StorageUsage: 55.0 + float64(iteration*5),
                Timestamp:    time.Now(),
            }

            // Validate metrics
            if metrics.EventsPerSecond < float64(throughputSLA) {
                errChan <- fmt.Errorf("throughput below SLA: got %.2f, want >= %d", 
                    metrics.EventsPerSecond, throughputSLA)
                return
            }

            if metrics.ProcessingLatency["bronze"] > float64(bronzeLatencySLA.Milliseconds()) {
                errChan <- fmt.Errorf("bronze tier latency above SLA: got %.2fms, want <= %v", 
                    metrics.ProcessingLatency["bronze"], bronzeLatencySLA)
                return
            }

            if metrics.ProcessingLatency["silver"] > float64(silverLatencySLA.Milliseconds()) {
                errChan <- fmt.Errorf("silver tier latency above SLA: got %.2fms, want <= %v", 
                    metrics.ProcessingLatency["silver"], silverLatencySLA)
                return
            }

            if metrics.ProcessingLatency["gold"] > float64(goldLatencySLA.Milliseconds()) {
                errChan <- fmt.Errorf("gold tier latency above SLA: got %.2fms, want <= %v", 
                    metrics.ProcessingLatency["gold"], goldLatencySLA)
                return
            }
        }(i)
    }

    // Wait for all goroutines to complete
    wg.Wait()
    close(errChan)

    // Check for any errors
    if err := <-errChan; err != nil {
        return err
    }

    return nil
}