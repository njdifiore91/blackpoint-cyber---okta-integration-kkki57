// Package scenarios implements comprehensive performance tests for the BlackPoint Security Integration Framework
package scenarios

import (
    "context"
    "testing"
    "time"
    "sync/atomic"

    "github.com/sirupsen/logrus" // v1.9.0
    "github.com/stretchr/testify/require" // v1.8.0

    "../../pkg/generators/load_generator"
    "../../pkg/metrics/performance_metrics"
    "../../pkg/common/logging"
    "../../pkg/common/utils"
)

// Test configuration constants
const (
    testDuration           = 5 * time.Minute
    sustainedTestDuration  = 24 * time.Hour
    rampUpPeriod          = 30 * time.Second
    performanceMetricsInterval = 10 * time.Second
)

// Client concurrency levels for testing
var clientConcurrencyLevels = []int{1, 10, 50, 100, 200}

// PerformanceTestSuite encapsulates performance test functionality
type PerformanceTestSuite struct {
    loadGen          *load_generator.LoadGenerator
    metricsCollector *performance_metrics.MetricsCollector
    ctx             context.Context
    cancel          context.CancelFunc
    logger          *logrus.Logger
    activeClients   int32
}

// newPerformanceTestSuite initializes a new performance test suite
func newPerformanceTestSuite(t *testing.T) *PerformanceTestSuite {
    ctx, cancel := context.WithCancel(context.Background())
    logger := logging.InitTestLogger(t)

    return &PerformanceTestSuite{
        ctx:    ctx,
        cancel: cancel,
        logger: logger,
    }
}

// setup prepares the test environment
func (s *PerformanceTestSuite) setup(t *testing.T) error {
    // Initialize load generator with security context
    config := &load_generator.LoadGeneratorConfig{
        Duration:      testDuration,
        RampUpPeriod: rampUpPeriod,
        EventTypes:   []string{"auth", "access", "security"},
        SecurityContext: map[string]interface{}{
            "classification": "CONFIDENTIAL",
            "sensitivity":   "HIGH",
            "compliance":    []string{"PCI-DSS", "SOC2"},
        },
        ValidationRules: []load_generator.ValidationRule{
            {Field: "event_type", Required: true},
            {Field: "timestamp", Required: true},
            {Field: "client_id", Required: true},
        },
        PerformanceParams: load_generator.PerformanceParams{
            ConcurrentBatches: 10,
            BatchTimeout:     5 * time.Second,
            RateLimit:       1000,
            BufferSize:      10000,
        },
    }

    var err error
    s.loadGen, err = load_generator.NewLoadGenerator(config, nil)
    if err != nil {
        return err
    }

    // Initialize metrics collector
    s.metricsCollector = performance_metrics.NewMetricsCollector()

    return nil
}

// TestConcurrentClientScalability tests system performance with increasing client load
func TestConcurrentClientScalability(t *testing.T) {
    t.Parallel()

    suite := newPerformanceTestSuite(t)
    require.NoError(t, suite.setup(t))
    defer suite.cancel()

    // Test each concurrency level
    for _, clientCount := range clientConcurrencyLevels {
        t.Run(fmt.Sprintf("Clients_%d", clientCount), func(t *testing.T) {
            metrics, err := suite.runConcurrencyTest(t, clientCount)
            require.NoError(t, err)

            // Validate performance requirements
            suite.validatePerformanceMetrics(t, metrics, clientCount)
        })
    }
}

// runConcurrencyTest executes a single concurrency level test
func (s *PerformanceTestSuite) runConcurrencyTest(t *testing.T, clientCount int) (*performance_metrics.PerformanceMetrics, error) {
    s.logger.WithFields(logrus.Fields{
        "client_count": clientCount,
        "duration":     testDuration,
    }).Info("Starting concurrency test")

    // Configure load generator for concurrent clients
    s.loadGen.SetConcurrency(clientCount)
    atomic.StoreInt32(&s.activeClients, int32(clientCount))

    // Start load generation
    if err := s.loadGen.Start(s.ctx); err != nil {
        return nil, err
    }
    defer s.loadGen.Stop()

    // Collect metrics during test
    metrics, err := s.collectTestMetrics(t, clientCount)
    if err != nil {
        return nil, err
    }

    return metrics, nil
}

// collectTestMetrics gathers performance metrics during test execution
func (s *PerformanceTestSuite) collectTestMetrics(t *testing.T, clientCount int) (*performance_metrics.PerformanceMetrics, error) {
    metrics := &performance_metrics.PerformanceMetrics{}
    
    // Wait for test duration while collecting metrics
    err := utils.WaitForCondition(t, func() bool {
        // Collect tier latencies
        bronzeLatency, silverLatency, goldLatency := s.metricsCollector.CollectTierLatencies()
        
        metrics.Latency.Bronze.Average = bronzeLatency
        metrics.Latency.Silver.Average = silverLatency
        metrics.Latency.Gold.Average = goldLatency

        // Get load generator metrics
        loadMetrics := s.loadGen.GetMetrics()
        metrics.Throughput.EventsPerSecond = float64(loadMetrics.EventsGenerated["bronze"]) / testDuration.Seconds()
        metrics.Throughput.TotalEvents = int64(loadMetrics.EventsGenerated["bronze"])

        return false
    }, testDuration)

    if err != nil {
        return nil, err
    }

    // Analyze performance metrics
    s.metricsCollector.AnalyzePerformance(metrics)

    return metrics, nil
}

// validatePerformanceMetrics validates collected metrics against requirements
func (s *PerformanceTestSuite) validatePerformanceMetrics(t *testing.T, metrics *performance_metrics.PerformanceMetrics, clientCount int) {
    // Validate throughput requirements
    minThroughput := float64(1000 * clientCount) // 1000 events/sec per client
    require.GreaterOrEqual(t, metrics.Throughput.EventsPerSecond, minThroughput,
        "Insufficient throughput for %d clients. Got %.2f events/sec, expected >= %.2f",
        clientCount, metrics.Throughput.EventsPerSecond, minThroughput)

    // Validate latency requirements
    require.Less(t, metrics.Latency.Bronze.P95, float64(time.Second),
        "Bronze tier P95 latency exceeds 1s requirement")
    require.Less(t, metrics.Latency.Silver.P95, float64(5*time.Second),
        "Silver tier P95 latency exceeds 5s requirement")
    require.Less(t, metrics.Latency.Gold.P95, float64(30*time.Second),
        "Gold tier P95 latency exceeds 30s requirement")

    // Validate resource utilization
    require.Less(t, metrics.Resources.CPU.Average, 80.0,
        "Average CPU utilization exceeds 80% threshold")
    require.Less(t, metrics.Resources.Memory.Average, 85.0,
        "Average memory utilization exceeds 85% threshold")

    // Log test results
    s.logger.WithFields(logrus.Fields{
        "client_count":        clientCount,
        "throughput":          metrics.Throughput.EventsPerSecond,
        "bronze_latency_p95":  metrics.Latency.Bronze.P95,
        "silver_latency_p95":  metrics.Latency.Silver.P95,
        "gold_latency_p95":    metrics.Latency.Gold.P95,
        "cpu_utilization":     metrics.Resources.CPU.Average,
        "memory_utilization":  metrics.Resources.Memory.Average,
    }).Info("Concurrency test completed")
}