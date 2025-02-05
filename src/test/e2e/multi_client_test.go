// Package e2e provides end-to-end tests for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package e2e

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/require" // v1.8.0

    "../../internal/framework/test_suite"
    "../../pkg/generators/load_generator"
    "../../pkg/metrics/performance_metrics"
)

// Global test configuration constants
const (
    testTimeout = 30 * time.Minute
    maxConcurrentClients = 100
    testDuration = 5 * time.Minute
    rampUpPeriod = 30 * time.Second
    securityContextTimeout = 1 * time.Minute
)

// TestMultiClientScenarios is the main test function for multi-client validation
func TestMultiClientScenarios(t *testing.T) {
    // Initialize test suite with security configuration
    suite := test_suite.NewTestSuite(t, "MultiClientTest", &test_suite.TestSuiteConfig{
        Timeout:          testTimeout,
        Parallel:         true,
        SecurityEnabled:  true,
        MonitoringEnabled: true,
        RetryAttempts:    3,
        ValidationConfig: map[string]float64{
            "accuracy":     80.0,
            "performance": 95.0,
            "security":    90.0,
        },
    })

    // Configure security context
    securityCtx := map[string]interface{}{
        "validation_level": "strict",
        "compliance":      []string{"SOC2", "ISO27001"},
        "audit_enabled":   true,
    }

    // Add test cases
    suite.AddTestCase(&test_suite.TestCase{
        Name: "ConcurrentClientLoad",
        Exec: func(ctx context.Context) error {
            return testConcurrentClientLoad(t, ctx, maxConcurrentClients)
        },
        SecurityContext: securityCtx,
        Critical:       true,
    })

    suite.AddTestCase(&test_suite.TestCase{
        Name: "ClientResourceIsolation",
        Exec: func(ctx context.Context) error {
            return testClientResourceIsolation(t, ctx)
        },
        SecurityContext: securityCtx,
        Critical:       true,
    })

    suite.AddTestCase(&test_suite.TestCase{
        Name: "ClientScalability",
        Exec: func(ctx context.Context) error {
            return testClientScalability(t, ctx)
        },
        SecurityContext: securityCtx,
        Critical:       true,
    })

    // Run test suite
    err := suite.Run()
    require.NoError(t, err, "Test suite execution failed")
}

// testConcurrentClientLoad validates system behavior under concurrent client load
func testConcurrentClientLoad(t *testing.T, ctx context.Context, numClients int) error {
    // Initialize load generator with security context
    loadGen, err := load_generator.NewLoadGenerator(&load_generator.LoadGeneratorConfig{
        Duration:      testDuration,
        Concurrency:   numClients,
        RampUpPeriod: rampUpPeriod,
        SecurityContext: map[string]interface{}{
            "validation_enabled": true,
            "audit_level":       "detailed",
        },
        ComplianceRules: map[string][]string{
            "SOC2":    {"security_monitoring", "access_control"},
            "ISO27001": {"data_protection", "encryption"},
        },
    }, &load_generator.SecurityContext{
        Level:      "high",
        Compliance: []string{"SOC2", "ISO27001"},
    })
    require.NoError(t, err, "Failed to initialize load generator")

    // Start load generation
    err = loadGen.Start(ctx)
    require.NoError(t, err, "Failed to start load generation")
    defer loadGen.Stop()

    // Collect performance metrics
    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "concurrent_load", testDuration)
    require.NoError(t, err, "Failed to collect performance metrics")

    // Validate throughput requirements
    require.GreaterOrEqual(t, metrics.Throughput.EventsPerSecond, float64(1000),
        "Throughput below requirement: got %.2f, want >= 1000", metrics.Throughput.EventsPerSecond)

    // Validate latency requirements
    require.LessOrEqual(t, metrics.Latency.Bronze.P95, float64(time.Second),
        "Bronze tier latency exceeds requirement: got %.2fs, want <= 1s", metrics.Latency.Bronze.P95)
    require.LessOrEqual(t, metrics.Latency.Silver.P95, float64(5*time.Second),
        "Silver tier latency exceeds requirement: got %.2fs, want <= 5s", metrics.Latency.Silver.P95)
    require.LessOrEqual(t, metrics.Latency.Gold.P95, float64(30*time.Second),
        "Gold tier latency exceeds requirement: got %.2fs, want <= 30s", metrics.Latency.Gold.P95)

    return nil
}

// testClientResourceIsolation validates resource and security isolation between clients
func testClientResourceIsolation(t *testing.T, ctx context.Context) error {
    // Initialize resource monitoring
    metrics, err := performance_metrics.MeasureResourceUtilization(t, "resource_isolation", func() error {
        // Create multiple client workloads
        for i := 0; i < 10; i++ {
            clientCtx := map[string]interface{}{
                "client_id": fmt.Sprintf("test-client-%d", i),
                "security_level": "high",
                "isolation_required": true,
            }

            loadGen, err := load_generator.NewLoadGenerator(&load_generator.LoadGeneratorConfig{
                Duration:    time.Minute,
                Concurrency: 5,
                SecurityContext: clientCtx,
            }, &load_generator.SecurityContext{
                Level:      "high",
                Compliance: []string{"SOC2"},
            })
            if err != nil {
                return err
            }

            err = loadGen.Start(ctx)
            if err != nil {
                return err
            }
            defer loadGen.Stop()
        }

        return nil
    })
    require.NoError(t, err, "Resource monitoring failed")

    // Validate resource isolation
    require.Less(t, metrics.CPU.Peak, 80.0,
        "CPU utilization exceeds isolation threshold: got %.2f%%, want < 80%%", metrics.CPU.Peak)
    require.Less(t, metrics.Memory.Peak, 85.0,
        "Memory utilization exceeds isolation threshold: got %.2f%%, want < 85%%", metrics.Memory.Peak)

    return nil
}

// testClientScalability validates system scalability with increasing client count
func testClientScalability(t *testing.T, ctx context.Context) error {
    clientCounts := []int{10, 25, 50, 100}
    var lastMetrics performance_metrics.PerformanceMetrics

    for _, count := range clientCounts {
        metrics, err := performance_metrics.CollectPerformanceMetrics(t, fmt.Sprintf("scalability_%d", count), time.Minute)
        require.NoError(t, err, "Failed to collect metrics for %d clients", count)

        // Validate performance remains within SLA as client count increases
        if lastMetrics.Throughput.EventsPerSecond > 0 {
            degradation := (lastMetrics.Throughput.EventsPerSecond - metrics.Throughput.EventsPerSecond) / 
                lastMetrics.Throughput.EventsPerSecond * 100
            require.Less(t, degradation, 20.0,
                "Performance degradation exceeds threshold at %d clients: %.2f%%", count, degradation)
        }

        lastMetrics = metrics
    }

    return nil
}