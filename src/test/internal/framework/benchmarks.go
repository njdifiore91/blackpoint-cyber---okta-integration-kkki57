// Package framework provides benchmarking functionality for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package framework

import (
    "fmt"
    "runtime"
    "testing"
    "time"

    "github.com/montanaflynn/stats" // v0.7.1
    "github.com/stretchr/testify/require" // v1.8.0

    "../../pkg/metrics" // Local package for performance metrics
    "./test_case" // Local package for test case functionality
)

// Default benchmark parameters
const (
    defaultBenchmarkDuration = 1 * time.Minute
    defaultWarmupDuration   = 10 * time.Second
    defaultCooldownDuration = 5 * time.Second
    defaultSampleInterval   = 100 * time.Millisecond
    confidenceLevel        = 0.95
    minSampleSize         = 1000
)

// BenchmarkConfig holds configuration for benchmark execution
type BenchmarkConfig struct {
    Duration        time.Duration
    WarmupDuration  time.Duration
    CooldownDuration time.Duration
    SampleInterval   time.Duration
    ConcurrentClients int
    SLAThresholds    struct {
        BronzeLatency time.Duration
        SilverLatency time.Duration
        GoldLatency   time.Duration
        MinThroughput float64
    }
}

// BenchmarkResults contains comprehensive benchmark measurements
type BenchmarkResults struct {
    ThroughputMetrics struct {
        EventsPerSecond float64
        TotalEvents    int64
        Duration      time.Duration
    }
    LatencyMetrics struct {
        Bronze metrics.LatencyStats
        Silver metrics.LatencyStats
        Gold   metrics.LatencyStats
    }
    ResourceMetrics   metrics.ResourceMetrics
    StatisticalAnalysis struct {
        ConfidenceIntervals map[string]struct {
            Lower, Upper float64
        }
        Outliers map[string]int
        Trends   map[string]float64
    }
    ValidationResults map[string]bool
}

// BenchmarkCase represents a performance benchmark test case
type BenchmarkCase struct {
    t            *testing.T
    name         string
    config       *BenchmarkConfig
    testCase     *test_case.TestCase
    metrics      *metrics.ResourceMetrics
    results      *BenchmarkResults
    cleanupFuncs []func()
}

// NewBenchmarkCase creates a new benchmark test case
func NewBenchmarkCase(t *testing.T, name string, config *BenchmarkConfig) *BenchmarkCase {
    if config == nil {
        config = &BenchmarkConfig{
            Duration:        defaultBenchmarkDuration,
            WarmupDuration:  defaultWarmupDuration,
            CooldownDuration: defaultCooldownDuration,
            SampleInterval:   defaultSampleInterval,
            ConcurrentClients: 1,
            SLAThresholds: struct {
                BronzeLatency time.Duration
                SilverLatency time.Duration
                GoldLatency   time.Duration
                MinThroughput float64
            }{
                BronzeLatency: time.Second,
                SilverLatency: 5 * time.Second,
                GoldLatency:   30 * time.Second,
                MinThroughput: 1000,
            },
        }
    }

    bc := &BenchmarkCase{
        t:       t,
        name:    name,
        config:  config,
        results: &BenchmarkResults{
            ValidationResults: make(map[string]bool),
        },
    }

    // Initialize test case with concurrency support
    bc.testCase = test_case.NewTestCase(t, name, &test_case.TestConfig{
        Timeout: config.Duration + config.WarmupDuration + config.CooldownDuration,
    })

    return bc
}

// WithConcurrency configures concurrent client load testing
func (bc *BenchmarkCase) WithConcurrency(clients int) *BenchmarkCase {
    bc.config.ConcurrentClients = clients
    bc.testCase.WithConcurrency(clients)
    return bc
}

// WithStatisticalAnalysis configures statistical analysis parameters
func (bc *BenchmarkCase) WithStatisticalAnalysis(confidenceLevel float64, sampleSize int) *BenchmarkCase {
    if confidenceLevel <= 0 || confidenceLevel >= 1 {
        bc.t.Fatalf("invalid confidence level: %v", confidenceLevel)
    }
    if sampleSize < minSampleSize {
        bc.t.Fatalf("sample size must be at least %d", minSampleSize)
    }
    return bc
}

// RunBenchmark executes the benchmark with comprehensive measurements
func RunBenchmark(bc *BenchmarkCase) (BenchmarkResults, error) {
    defer func() {
        for _, cleanup := range bc.cleanupFuncs {
            cleanup()
        }
    }()

    // Execute warmup phase
    if err := executeWarmup(bc); err != nil {
        return *bc.results, fmt.Errorf("warmup failed: %w", err)
    }

    // Initialize measurement collectors
    collectors := initializeCollectors(bc)

    // Execute benchmark
    benchmarkErr := executeBenchmark(bc, collectors)
    if benchmarkErr != nil {
        return *bc.results, fmt.Errorf("benchmark execution failed: %w", benchmarkErr)
    }

    // Execute cooldown phase
    if err := executeCooldown(bc); err != nil {
        return *bc.results, fmt.Errorf("cooldown failed: %w", err)
    }

    // Calculate final results
    if err := calculateResults(bc, collectors); err != nil {
        return *bc.results, fmt.Errorf("results calculation failed: %w", err)
    }

    // Validate against SLA requirements
    validateSLARequirements(bc)

    return *bc.results, nil
}

// Helper functions

func executeWarmup(bc *BenchmarkCase) error {
    warmupCtx, cancel := context.WithTimeout(context.Background(), bc.config.WarmupDuration)
    defer cancel()

    return bc.testCase.Run(warmupCtx)
}

func executeCooldown(bc *BenchmarkCase) error {
    cooldownCtx, cancel := context.WithTimeout(context.Background(), bc.config.CooldownDuration)
    defer cancel()

    return bc.testCase.Run(cooldownCtx)
}

func initializeCollectors(bc *BenchmarkCase) *metrics.Collectors {
    return metrics.NewCollectors(bc.config.SampleInterval)
}

func executeBenchmark(bc *BenchmarkCase, collectors *metrics.Collectors) error {
    benchmarkCtx, cancel := context.WithTimeout(context.Background(), bc.config.Duration)
    defer cancel()

    // Start resource monitoring
    resourceMetrics, err := metrics.MeasureResourceUtilization(bc.t, bc.name, func() error {
        return bc.testCase.Run(benchmarkCtx)
    })
    
    if err != nil {
        return err
    }
    bc.metrics = &resourceMetrics

    return nil
}

func calculateResults(bc *BenchmarkCase, collectors *metrics.Collectors) error {
    // Calculate throughput metrics
    bc.results.ThroughputMetrics = collectors.CalculateThroughput()

    // Calculate latency metrics
    latencyStats := collectors.CalculateLatencyStats()
    bc.results.LatencyMetrics.Bronze = latencyStats.Bronze
    bc.results.LatencyMetrics.Silver = latencyStats.Silver
    bc.results.LatencyMetrics.Gold = latencyStats.Gold

    // Calculate statistical analysis
    bc.results.StatisticalAnalysis = calculateStatisticalAnalysis(collectors)

    // Copy resource metrics
    bc.results.ResourceMetrics = *bc.metrics

    return nil
}

func calculateStatisticalAnalysis(collectors *metrics.Collectors) struct {
    ConfidenceIntervals map[string]struct{ Lower, Upper float64 }
    Outliers           map[string]int
    Trends             map[string]float64
} {
    analysis := struct {
        ConfidenceIntervals map[string]struct{ Lower, Upper float64 }
        Outliers           map[string]int
        Trends             map[string]float64
    }{
        ConfidenceIntervals: make(map[string]struct{ Lower, Upper float64 }),
        Outliers:           make(map[string]int),
        Trends:             make(map[string]float64),
    }

    // Calculate confidence intervals, outliers, and trends for each metric
    for _, metric := range collectors.GetMetrics() {
        ci, err := stats.ConfidenceInterval(metric.Samples, confidenceLevel)
        if err == nil {
            analysis.ConfidenceIntervals[metric.Name] = struct{ Lower, Upper float64 }{
                Lower: ci.Lower,
                Upper: ci.Upper,
            }
        }

        outliers, _ := stats.QuartileOutliers(metric.Samples)
        analysis.Outliers[metric.Name] = len(outliers.Mild) + len(outliers.Extreme)

        trend, _ := stats.LinearRegression(metric.Timestamps, metric.Samples)
        analysis.Trends[metric.Name] = trend
    }

    return analysis
}

func validateSLARequirements(bc *BenchmarkCase) {
    // Validate throughput
    bc.results.ValidationResults["throughput"] = 
        bc.results.ThroughputMetrics.EventsPerSecond >= bc.config.SLAThresholds.MinThroughput

    // Validate latency requirements
    bc.results.ValidationResults["bronze_latency"] = 
        bc.results.LatencyMetrics.Bronze.P95 <= float64(bc.config.SLAThresholds.BronzeLatency)
    bc.results.ValidationResults["silver_latency"] = 
        bc.results.LatencyMetrics.Silver.P95 <= float64(bc.config.SLAThresholds.SilverLatency)
    bc.results.ValidationResults["gold_latency"] = 
        bc.results.LatencyMetrics.Gold.P95 <= float64(bc.config.SLAThresholds.GoldLatency)

    // Validate resource utilization
    bc.results.ValidationResults["resource_utilization"] = 
        bc.results.ResourceMetrics.CPU.Average <= 80.0 &&
        bc.results.ResourceMetrics.Memory.Average <= 85.0
}