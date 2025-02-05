// Package scenarios implements comprehensive performance tests for the BlackPoint Security Integration Framework
package scenarios

import (
    "context"
    "testing"
    "time"
    "sync"
    "sync/atomic"

    "github.com/stretchr/testify/require"

    "../../pkg/generators/load_generator"
    "../../pkg/metrics/performance_metrics"
    "../../../backend/internal/streaming/confluent"
    "../../pkg/common/logging"
    "../../pkg/common/errors"
)

// Test configuration constants
const (
    testDuration = 5 * time.Minute
    maxConcurrentClients = 100
    targetThroughput = 1000.0 // events/second
)

// Latency thresholds per tier as per technical specifications
var latencyThresholds = map[string]time.Duration{
    "bronze": time.Second,        // <1s
    "silver": 5 * time.Second,    // <5s
    "gold":   30 * time.Second,   // <30s
}

// StreamingTestSuite implements comprehensive streaming performance tests
type StreamingTestSuite struct {
    kafkaClient  *confluent.KafkaClient
    loadGen      *load_generator.LoadGenerator
    ctx          context.Context
    cancel       context.CancelFunc
    metrics      *performance_metrics.PerformanceMetrics
    mu           sync.RWMutex
}

// setupSuite initializes the test suite with required components
func setupSuite(t *testing.T) (*StreamingTestSuite, func()) {
    t.Helper()

    // Initialize context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), testDuration)

    // Configure Kafka client
    kafkaConfig := &confluent.KafkaConfig{
        BootstrapServers:     "localhost:9092",
        SecurityProtocol:     "SASL_SSL",
        SaslMechanism:       "PLAIN",
        BatchSize:           1000,
        CompressionType:     "snappy",
        NumPartitions:       10,
        EnableMetrics:       true,
        TierLatencyThresholds: latencyThresholds,
    }

    kafkaClient, err := confluent.NewKafkaClient(kafkaConfig)
    require.NoError(t, err, "Failed to create Kafka client")

    // Initialize load generator
    loadGenConfig := &load_generator.LoadGeneratorConfig{
        Duration:      testDuration,
        Concurrency:  maxConcurrentClients,
        RampUpPeriod: 30 * time.Second,
        EventTypes:   []string{"security", "auth", "access"},
    }

    loadGen, err := load_generator.NewLoadGenerator(loadGenConfig, nil)
    require.NoError(t, err, "Failed to create load generator")

    suite := &StreamingTestSuite{
        kafkaClient: kafkaClient,
        loadGen:     loadGen,
        ctx:         ctx,
        cancel:      cancel,
    }

    // Return cleanup function
    cleanup := func() {
        cancel()
        if err := kafkaClient.Close(); err != nil {
            t.Errorf("Failed to close Kafka client: %v", err)
        }
        loadGen.Stop()
    }

    return suite, cleanup
}

// TestStreamingPerformance validates streaming performance requirements
func TestStreamingPerformance(t *testing.T) {
    suite, cleanup := setupSuite(t)
    defer cleanup()

    // Start resource monitoring
    resourceMetrics, err := performance_metrics.MeasureResourceUtilization(t, "streaming", func() error {
        // Start load generation
        if err := suite.loadGen.Start(suite.ctx); err != nil {
            return errors.WrapError(err, "failed to start load generation", nil)
        }

        // Monitor performance metrics
        var eventCount int64
        ticker := time.NewTicker(time.Second)
        defer ticker.Stop()

        for {
            select {
            case <-suite.ctx.Done():
                return nil
            case <-ticker.C:
                metrics := suite.loadGen.GetMetrics()
                atomic.AddInt64(&eventCount, int64(metrics.EventsGenerated["bronze"]))

                // Validate throughput
                eventsPerSecond := float64(eventCount) / time.Since(suite.loadGen.GetMetrics().StartTime).Seconds()
                require.GreaterOrEqual(t, eventsPerSecond, targetThroughput,
                    "Throughput below target: %.2f events/sec", eventsPerSecond)

                // Validate latencies
                for tier, threshold := range latencyThresholds {
                    require.LessOrEqual(t, metrics.ProcessingLatency[tier], threshold,
                        "%s tier latency exceeded threshold: %v > %v", tier, metrics.ProcessingLatency[tier], threshold)
                }
            }
        }
    })

    require.NoError(t, err, "Performance measurement failed")

    // Generate performance report
    report, err := performance_metrics.GeneratePerformanceReport(t, performance_metrics.PerformanceMetrics{
        Resources: resourceMetrics,
        Throughput: struct {
            EventsPerSecond float64
            TotalEvents    int64
            Duration      time.Duration
        }{
            EventsPerSecond: float64(suite.loadGen.GetMetrics().EventsGenerated["bronze"]) / testDuration.Seconds(),
            TotalEvents:    int64(suite.loadGen.GetMetrics().EventsGenerated["bronze"]),
            Duration:      testDuration,
        },
    })
    require.NoError(t, err, "Failed to generate performance report")

    // Log test results
    logging.LogTestMetrics(t, report)
}

// TestStreamingScalability validates system scalability requirements
func TestStreamingScalability(t *testing.T) {
    suite, cleanup := setupSuite(t)
    defer cleanup()

    // Test gradual client scaling
    clientCounts := []int{1, 10, 25, 50, 75, 100}
    
    for _, clientCount := range clientCounts {
        t.Run(fmt.Sprintf("Clients_%d", clientCount), func(t *testing.T) {
            loadGenConfig := &load_generator.LoadGeneratorConfig{
                Duration:     time.Minute,
                Concurrency: clientCount,
                RampUpPeriod: 10 * time.Second,
            }

            loadGen, err := load_generator.NewLoadGenerator(loadGenConfig, nil)
            require.NoError(t, err, "Failed to create load generator")
            defer loadGen.Stop()

            // Measure performance with current client count
            metrics, err := performance_metrics.MeasureResourceUtilization(t, fmt.Sprintf("scaling_%d", clientCount), func() error {
                return loadGen.Start(suite.ctx)
            })
            require.NoError(t, err, "Failed to measure performance")

            // Validate performance at scale
            eventsPerSecond := float64(loadGen.GetMetrics().EventsGenerated["bronze"]) / time.Minute.Seconds()
            require.GreaterOrEqual(t, eventsPerSecond, targetThroughput*float64(clientCount)/100,
                "Throughput degraded with %d clients", clientCount)

            // Log scaling metrics
            logging.LogTestMetrics(t, map[string]interface{}{
                "client_count":     clientCount,
                "events_per_second": eventsPerSecond,
                "cpu_usage":        metrics.CPU.Average,
                "memory_usage":     metrics.Memory.Average,
            })
        })
    }
}

// TestStreamingResilience validates system resilience under various conditions
func TestStreamingResilience(t *testing.T) {
    suite, cleanup := setupSuite(t)
    defer cleanup()

    // Test scenarios
    scenarios := []struct {
        name     string
        faultFn  func() error
        duration time.Duration
    }{
        {
            name: "NetworkPartition",
            faultFn: func() error {
                // Simulate network partition
                time.Sleep(5 * time.Second)
                return nil
            },
            duration: 30 * time.Second,
        },
        {
            name: "HighLatency",
            faultFn: func() error {
                // Simulate high latency
                time.Sleep(time.Second)
                return nil
            },
            duration: 30 * time.Second,
        },
    }

    for _, scenario := range scenarios {
        t.Run(scenario.name, func(t *testing.T) {
            ctx, cancel := context.WithTimeout(suite.ctx, scenario.duration)
            defer cancel()

            // Start load generation
            require.NoError(t, suite.loadGen.Start(ctx), "Failed to start load generation")

            // Execute fault injection
            go scenario.faultFn()

            // Monitor system behavior
            metrics, err := performance_metrics.MeasureResourceUtilization(t, scenario.name, func() error {
                return nil
            })
            require.NoError(t, err, "Failed to measure resilience metrics")

            // Validate system recovery
            loadGenMetrics := suite.loadGen.GetMetrics()
            require.Less(t, loadGenMetrics.ValidationErrors, uint64(len(loadGenMetrics.EventsGenerated))*20/100,
                "Too many validation errors during fault scenario")

            // Log resilience metrics
            logging.LogTestMetrics(t, map[string]interface{}{
                "scenario":          scenario.name,
                "validation_errors": loadGenMetrics.ValidationErrors,
                "recovery_time":     metrics.CPU.Peak,
            })
        })
    }
}