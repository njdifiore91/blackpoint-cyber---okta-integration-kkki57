// Package benchmarks provides comprehensive performance benchmarks for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package benchmarks

import (
    "testing" // v1.21
    "time" // v1.21
    "sync"
    "github.com/stretchr/testify/require" // v1.8.0

    "../../pkg/metrics/performance_metrics"
    "../../pkg/metrics/latency_metrics"
    "../../pkg/metrics/throughput_metrics"
)

// Global constants for Silver Tier benchmarking
const (
    silverTierLatencyThreshold = 5 * time.Second
    silverTierThroughputSLA   = 1000.0 // events/second
    maxConcurrentClients      = 100
)

// Test data configuration
var (
    testEventSizes = []int{1, 10, 100, 1000}
    testBatchSizes = []int{100, 500, 1000, 5000}
)

// BenchmarkSilverTierLatency performs comprehensive latency benchmarking for Silver Tier processing
func BenchmarkSilverTierLatency(b *testing.B) {
    b.Helper()

    // Initialize test context
    require.NotNil(b, b, "benchmark context required")
    b.ResetTimer()

    // Measure single event processing latency
    b.Run("SingleEventLatency", func(b *testing.B) {
        for _, eventSize := range testEventSizes {
            b.Run(fmt.Sprintf("EventSize_%d", eventSize), func(b *testing.B) {
                for i := 0; i < b.N; i++ {
                    latency, err := latency_metrics.MeasureProcessingLatency(b, "silver", func() error {
                        // Simulate event processing
                        time.Sleep(time.Millisecond * time.Duration(eventSize))
                        return nil
                    })
                    require.NoError(b, err)
                    require.LessOrEqual(b, latency, silverTierLatencyThreshold)
                }
            })
        }
    })

    // Measure batch processing latency
    b.Run("BatchProcessingLatency", func(b *testing.B) {
        for _, batchSize := range testBatchSizes {
            b.Run(fmt.Sprintf("BatchSize_%d", batchSize), func(b *testing.B) {
                measurements, err := latency_metrics.MeasureBatchLatency(b, "silver", batchSize, func() error {
                    // Simulate batch processing
                    time.Sleep(time.Millisecond * 10)
                    return nil
                })
                require.NoError(b, err)
                
                // Validate batch latency statistics
                stats, err := latency_metrics.CalculateLatencyStats(measurements)
                require.NoError(b, err)
                require.LessOrEqual(b, stats["p95"], silverTierLatencyThreshold)
            })
        }
    })
}

// BenchmarkSilverTierThroughput measures and validates system throughput capabilities
func BenchmarkSilverTierThroughput(b *testing.B) {
    b.Helper()

    // Initialize test context
    require.NotNil(b, b, "benchmark context required")
    b.ResetTimer()

    // Measure baseline throughput
    b.Run("BaselineThroughput", func(b *testing.B) {
        metrics, err := throughput_metrics.MeasureThroughput(b, "silver_tier", func() (int, error) {
            // Simulate event processing
            time.Sleep(time.Millisecond)
            return b.N, nil
        }, time.Minute)
        require.NoError(b, err)
        require.GreaterOrEqual(b, metrics.EventsPerSecond, silverTierThroughputSLA)
    })

    // Measure concurrent client throughput
    b.Run("ConcurrentThroughput", func(b *testing.B) {
        results, err := throughput_metrics.MeasureConcurrentThroughput(b, maxConcurrentClients, func() (int, error) {
            // Simulate concurrent client processing
            time.Sleep(time.Millisecond)
            return b.N / maxConcurrentClients, nil
        })
        require.NoError(b, err)

        // Validate concurrent throughput
        for clientID, metrics := range results {
            valid, err := throughput_metrics.ValidateThroughputSLA(b, &metrics)
            require.NoError(b, err)
            require.True(b, valid, "SLA validation failed for client %s", clientID)
        }
    })
}

// BenchmarkSilverTierResourceUtilization measures and validates resource utilization
func BenchmarkSilverTierResourceUtilization(b *testing.B) {
    b.Helper()

    // Initialize test context
    require.NotNil(b, b, "benchmark context required")
    b.ResetTimer()

    // Measure resource utilization under load
    metrics, err := performance_metrics.MeasureResourceUtilization(b, "silver_tier", func() error {
        var wg sync.WaitGroup
        for i := 0; i < maxConcurrentClients; i++ {
            wg.Add(1)
            go func() {
                defer wg.Done()
                // Simulate resource-intensive processing
                time.Sleep(time.Millisecond * 100)
            }()
        }
        wg.Wait()
        return nil
    })
    require.NoError(b, err)

    // Validate resource utilization
    report, err := performance_metrics.GeneratePerformanceReport(b, metrics)
    require.NoError(b, err)
    require.NotNil(b, report)

    // Validate CPU utilization
    require.LessOrEqual(b, metrics.CPU.Average, 80.0, "CPU utilization exceeds threshold")
    require.LessOrEqual(b, metrics.Memory.Average, 85.0, "Memory utilization exceeds threshold")
}

// BenchmarkSilverTierScalability validates system scalability under increasing load
func BenchmarkSilverTierScalability(b *testing.B) {
    b.Helper()

    // Initialize test context
    require.NotNil(b, b, "benchmark context required")
    b.ResetTimer()

    clientIncrements := []int{10, 25, 50, 75, 100}
    baselineMetrics := make(map[string]*throughput_metrics.ThroughputMetrics)

    // Measure scalability with increasing client load
    for _, numClients := range clientIncrements {
        b.Run(fmt.Sprintf("Clients_%d", numClients), func(b *testing.B) {
            metrics, err := throughput_metrics.MeasureConcurrentThroughput(b, numClients, func() (int, error) {
                // Simulate scalable processing
                time.Sleep(time.Millisecond * 10)
                return b.N / numClients, nil
            })
            require.NoError(b, err)

            // Store baseline metrics for comparison
            for clientID, clientMetrics := range metrics {
                baselineMetrics[fmt.Sprintf("client_%d_%d", numClients, clientID)] = &clientMetrics
            }

            // Validate scalability requirements
            aggregateLatency := make([]time.Duration, 0)
            for _, m := range metrics {
                aggregateLatency = append(aggregateLatency, time.Duration(m.Mean))
            }

            valid, err := latency_metrics.ValidateLatencyRequirements(b, "silver", aggregateLatency)
            require.NoError(b, err)
            require.True(b, valid, "Latency requirements not met at %d clients", numClients)
        })
    }

    // Generate scalability report
    report := make(map[string]interface{})
    for clientCount, metrics := range baselineMetrics {
        report[clientCount] = map[string]interface{}{
            "throughput": metrics.EventsPerSecond,
            "latency_p95": metrics.P95,
            "stability": metrics.StabilityScore,
        }
    }

    // Log scalability results
    b.Logf("Scalability Report: %+v", report)
}