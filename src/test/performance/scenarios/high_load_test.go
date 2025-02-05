// Package scenarios implements comprehensive performance test scenarios for the BlackPoint Security Integration Framework
package scenarios

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/require"

    "../../pkg/generators/load_generator"
    "../../pkg/metrics/performance_metrics"
)

// Global test configuration constants
const (
    testDuration        = 10 * time.Minute
    maxConcurrentClients = 150
    rampUpPeriod        = 2 * time.Minute
    coolDownPeriod      = 1 * time.Minute
    confidenceInterval  = 0.95
    metricsSampleInterval = 1 * time.Second
)

// TestHighConcurrentLoad tests system behavior under high concurrent client load
// with advanced statistical analysis and visualization
func TestHighConcurrentLoad(t *testing.T) {
    // Initialize test context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), testDuration+coolDownPeriod)
    defer cancel()

    // Configure load generator
    loadConfig := &load_generator.LoadGeneratorConfig{
        Duration:     testDuration,
        Concurrency:  maxConcurrentClients,
        RampUpPeriod: rampUpPeriod,
        EventTypes:   []string{"auth", "access", "security"},
        SecurityContext: map[string]interface{}{
            "classification": "CONFIDENTIAL",
            "sensitivity":   "HIGH",
        },
        PerformanceParams: load_generator.PerformanceParams{
            ConcurrentBatches: 50,
            BatchTimeout:      5 * time.Second,
            RateLimit:        2000,
            BufferSize:       10000,
        },
    }

    generator, err := load_generator.NewLoadGenerator(loadConfig, nil)
    require.NoError(t, err, "Failed to initialize load generator")

    // Start resource utilization monitoring
    resourceMetrics, err := performance_metrics.MeasureResourceUtilization(t, "high_concurrent_load", func() error {
        return generator.Start(ctx)
    })
    require.NoError(t, err, "Failed to start resource monitoring")

    // Execute load test
    err = generator.Start(ctx)
    require.NoError(t, err, "Failed to start load test")

    // Collect performance metrics
    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "high_concurrent_load", testDuration)
    require.NoError(t, err, "Failed to collect performance metrics")

    // Validate performance requirements
    valid, err := performance_metrics.ValidatePerformanceRequirements(t, metrics)
    require.NoError(t, err, "Failed to validate performance requirements")
    require.True(t, valid, "Performance requirements not met")

    // Validate specific requirements
    require.GreaterOrEqual(t, metrics.Throughput.EventsPerSecond, float64(1000), 
        "Throughput below required 1000 events/second per client")
    require.LessOrEqual(t, metrics.Latency.Bronze.P95, float64(1*time.Second), 
        "Bronze tier latency exceeds 1s requirement")
    require.LessOrEqual(t, metrics.Latency.Silver.P95, float64(5*time.Second), 
        "Silver tier latency exceeds 5s requirement")
    require.LessOrEqual(t, metrics.Latency.Gold.P95, float64(30*time.Second), 
        "Gold tier latency exceeds 30s requirement")

    // Generate performance report
    report, err := performance_metrics.GeneratePerformanceReport(t, metrics)
    require.NoError(t, err, "Failed to generate performance report")

    // Clean up
    generator.Stop()
}

// TestMaximumThroughput tests system maximum sustainable throughput
// with trend analysis and stability verification
func TestMaximumThroughput(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), testDuration)
    defer cancel()

    // Configure load generator for maximum throughput
    loadConfig := &load_generator.LoadGeneratorConfig{
        Duration:     testDuration,
        Concurrency:  maxConcurrentClients,
        RampUpPeriod: rampUpPeriod,
        EventTypes:   []string{"security"},
        SecurityContext: map[string]interface{}{
            "classification": "CONFIDENTIAL",
            "sensitivity":   "HIGH",
        },
        PerformanceParams: load_generator.PerformanceParams{
            ConcurrentBatches: 100,
            BatchTimeout:      1 * time.Second,
            RateLimit:        5000,
            BufferSize:       50000,
        },
    }

    generator, err := load_generator.NewLoadGenerator(loadConfig, nil)
    require.NoError(t, err, "Failed to initialize load generator")

    // Start performance monitoring
    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "maximum_throughput", testDuration)
    require.NoError(t, err, "Failed to collect performance metrics")

    // Execute throughput test
    err = generator.Start(ctx)
    require.NoError(t, err, "Failed to start throughput test")

    // Validate throughput stability
    require.GreaterOrEqual(t, metrics.Throughput.EventsPerSecond, float64(1000),
        "Throughput below minimum requirement")
    require.LessOrEqual(t, metrics.Resources.CPU.Trend, float64(5.0),
        "CPU utilization trend exceeds threshold")
    require.LessOrEqual(t, metrics.Resources.Memory.Trend, float64(7.0),
        "Memory utilization trend exceeds threshold")

    // Clean up
    generator.Stop()
}

// TestResourceUtilization tests system resource utilization under load
// with trend analysis and threshold validation
func TestResourceUtilization(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), testDuration)
    defer cancel()

    // Configure load generator
    loadConfig := &load_generator.LoadGeneratorConfig{
        Duration:     testDuration,
        Concurrency:  maxConcurrentClients/2, // 50% capacity for baseline
        RampUpPeriod: rampUpPeriod,
        EventTypes:   []string{"auth", "security"},
        SecurityContext: map[string]interface{}{
            "classification": "CONFIDENTIAL",
            "sensitivity":   "HIGH",
        },
    }

    generator, err := load_generator.NewLoadGenerator(loadConfig, nil)
    require.NoError(t, err, "Failed to initialize load generator")

    // Start resource monitoring
    resourceMetrics, err := performance_metrics.MeasureResourceUtilization(t, "resource_utilization", func() error {
        return generator.Start(ctx)
    })
    require.NoError(t, err, "Failed to start resource monitoring")

    // Validate resource utilization
    require.LessOrEqual(t, resourceMetrics.CPU.Average, float64(80),
        "Average CPU utilization exceeds threshold")
    require.LessOrEqual(t, resourceMetrics.Memory.Average, float64(85),
        "Average memory utilization exceeds threshold")
    require.LessOrEqual(t, resourceMetrics.CPU.Trend, float64(5.0),
        "CPU utilization trend exceeds threshold")
    require.LessOrEqual(t, resourceMetrics.Memory.Trend, float64(7.0),
        "Memory utilization trend exceeds threshold")

    // Validate percentile metrics
    require.LessOrEqual(t, resourceMetrics.CPU.Percentiles[95], float64(90),
        "95th percentile CPU utilization exceeds threshold")
    require.LessOrEqual(t, resourceMetrics.Memory.Percentiles[95], float64(90),
        "95th percentile memory utilization exceeds threshold")

    // Clean up
    generator.Stop()
}