// Package benchmarks implements comprehensive performance benchmarks for the BlackPoint Security Integration Framework
package benchmarks

import (
    "testing"
    "time"

    "github.com/stretchr/testify/require"
    "github.com/montanaflynn/stats"

    "../../pkg/generators/event_generator"
    "../../pkg/metrics/performance_metrics"
    "../../../backend/pkg/bronze/event"
)

// Global constants for benchmark configuration
const (
    defaultBatchSize        = 1000
    defaultTestDuration     = 5 * time.Minute
    defaultConcurrentClients = 100
    confidenceInterval      = 0.95
    maxLatencyThreshold    = 1 * time.Second
    minThroughputThreshold = 1000
    maxCPUUtilization     = 80.0
    maxMemoryUtilization  = 85.0
)

// TestBronzeTierSingleEventProcessing benchmarks single event processing performance with security context validation
func BenchmarkBronzeTierSingleEventProcessing(b *testing.B) {
    // Initialize event generator with security context
    generator, err := event_generator.NewEventGenerator(&event_generator.GeneratorConfig{
        BatchSize:         1,
        ComplianceEnabled: true,
        SecurityContext: map[string]interface{}{
            "classification": "CONFIDENTIAL",
            "sensitivity":   "HIGH",
        },
    })
    require.NoError(b, err)

    // Initialize event processor
    processor, err := event.NewEventProcessor(maxLatencyThreshold, 1, nil)
    require.NoError(b, err)

    // Setup performance monitoring
    metrics, err := performance_metrics.CollectPerformanceMetrics(b, "bronze_single_event", defaultTestDuration)
    require.NoError(b, err)

    // Reset timer for accurate measurement
    b.ResetTimer()

    // Run benchmark
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            // Generate secure test event
            testEvent, err := generator.GenerateEvent("bronze", "security", nil)
            require.NoError(b, err)

            // Process event with timing
            start := time.Now()
            err = processor.ProcessEvent(testEvent, nil)
            require.NoError(b, err)
            
            // Record latency
            latency := time.Since(start)
            metrics.Latency.Bronze.P95 = stats.Percentile([]float64{latency.Seconds()}, 95)
        }
    })

    // Validate performance requirements
    valid, err := performance_metrics.ValidatePerformanceRequirements(b, metrics)
    require.NoError(b, err)
    require.True(b, valid, "Performance requirements not met")

    // Generate performance report
    report, err := performance_metrics.GeneratePerformanceReport(b, metrics)
    require.NoError(b, err)
    b.ReportMetric(report["performance"].(map[string]interface{})["throughput"].(float64), "events/sec")
}

// TestBronzeTierBatchProcessing benchmarks secure batch event processing with throughput validation
func BenchmarkBronzeTierBatchProcessing(b *testing.B) {
    // Initialize event generator for batch processing
    generator, err := event_generator.NewEventGenerator(&event_generator.GeneratorConfig{
        BatchSize:         defaultBatchSize,
        ComplianceEnabled: true,
        SecurityContext: map[string]interface{}{
            "classification": "CONFIDENTIAL",
            "sensitivity":   "HIGH",
        },
    })
    require.NoError(b, err)

    // Initialize processor with batch configuration
    processor, err := event.NewEventProcessor(maxLatencyThreshold, defaultBatchSize, nil)
    require.NoError(b, err)

    // Setup performance monitoring
    metrics, err := performance_metrics.CollectPerformanceMetrics(b, "bronze_batch", defaultTestDuration)
    require.NoError(b, err)

    b.ResetTimer()

    // Run batch processing benchmark
    b.RunParallel(func(pb *testing.PB) {
        for pb.Next() {
            // Generate batch of secure events
            events, err := generator.GenerateBatch("bronze", defaultBatchSize)
            require.NoError(b, err)

            // Process batch with timing
            start := time.Now()
            err = processor.BatchProcessEvents(events, nil)
            require.NoError(b, err)

            // Record metrics
            metrics.Throughput.EventsPerSecond = float64(defaultBatchSize) / time.Since(start).Seconds()
        }
    })

    // Validate batch processing requirements
    require.GreaterOrEqual(b, metrics.Throughput.EventsPerSecond, float64(minThroughputThreshold))

    // Generate and report batch processing metrics
    report, err := performance_metrics.GeneratePerformanceReport(b, metrics)
    require.NoError(b, err)
    b.ReportMetric(report["performance"].(map[string]interface{})["throughput"].(float64), "events/sec")
}

// TestBronzeTierConcurrentProcessing benchmarks concurrent secure event processing with multiple clients
func BenchmarkBronzeTierConcurrentProcessing(b *testing.B) {
    // Initialize event generator for concurrent processing
    generator, err := event_generator.NewEventGenerator(&event_generator.GeneratorConfig{
        BatchSize:         defaultBatchSize,
        ComplianceEnabled: true,
        PerformanceParams: event_generator.PerformanceParams{
            ConcurrentBatches: defaultConcurrentClients,
            RateLimit:        minThroughputThreshold,
        },
    })
    require.NoError(b, err)

    // Initialize processor for concurrent operations
    processor, err := event.NewEventProcessor(maxLatencyThreshold, defaultBatchSize, nil)
    require.NoError(b, err)

    // Setup resource monitoring
    resourceMetrics, err := performance_metrics.MeasureResourceUtilization(b, "bronze_concurrent", func() error {
        b.RunParallel(func(pb *testing.PB) {
            for pb.Next() {
                events, err := generator.GenerateBatch("bronze", defaultBatchSize/defaultConcurrentClients)
                require.NoError(b, err)
                err = processor.BatchProcessEvents(events, nil)
                require.NoError(b, err)
            }
        })
        return nil
    })
    require.NoError(b, err)

    // Validate resource utilization
    require.Less(b, resourceMetrics.CPU.Average, maxCPUUtilization)
    require.Less(b, resourceMetrics.Memory.Average, maxMemoryUtilization)

    // Report concurrent processing metrics
    b.ReportMetric(resourceMetrics.CPU.Average, "avg_cpu_%")
    b.ReportMetric(resourceMetrics.Memory.Average, "avg_memory_%")
}

// TestBronzeTierResourceUtilization performs comprehensive resource utilization analysis under security constraints
func TestBronzeTierResourceUtilization(t *testing.T) {
    // Initialize monitoring
    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "bronze_resources", defaultTestDuration)
    require.NoError(t, err)

    // Initialize processor with security context
    processor, err := event.NewEventProcessor(maxLatencyThreshold, defaultBatchSize, nil)
    require.NoError(t, err)

    // Monitor resource utilization during varied load scenarios
    for _, load := range []int{1000, 5000, 10000} {
        resourceMetrics, err := performance_metrics.MeasureResourceUtilization(t, "bronze_load_test", func() error {
            generator, err := event_generator.NewEventGenerator(&event_generator.GeneratorConfig{
                BatchSize: load,
                SecurityContext: map[string]interface{}{
                    "classification": "CONFIDENTIAL",
                    "sensitivity":   "HIGH",
                },
            })
            require.NoError(t, err)

            events, err := generator.GenerateBatch("bronze", load)
            require.NoError(t, err)

            return processor.BatchProcessEvents(events, nil)
        })
        require.NoError(t, err)

        // Validate resource metrics
        require.Less(t, resourceMetrics.CPU.Average, maxCPUUtilization)
        require.Less(t, resourceMetrics.Memory.Average, maxMemoryUtilization)
        require.Less(t, resourceMetrics.CPU.Trend, float64(5.0)) // Max 5% trend increase
    }

    // Generate final resource utilization report
    report, err := performance_metrics.GeneratePerformanceReport(t, metrics)
    require.NoError(t, err)
    require.NotNil(t, report["resource_utilization"])
}