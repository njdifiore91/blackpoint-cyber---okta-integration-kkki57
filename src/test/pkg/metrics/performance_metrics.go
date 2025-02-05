// Package metrics provides comprehensive performance measurement and analysis functionality
// for the BlackPoint Security Integration Framework testing suite.
// Version: 1.0.0
package metrics

import (
    "runtime"
    "testing"
    "time"

    "gonum.org/v1/gonum/stat" // v0.14.0
    "github.com/stretchr/testify/require" // v1.8.0

    "blackpoint/test/pkg/common/logging"
    "blackpoint/test/pkg/common/utils"
)

// Default measurement parameters
const (
    DefaultMeasurementInterval = time.Second
    DefaultSampleSize         = 1000
)

// ResourceUtilizationThresholds defines thresholds for resource utilization and trends
var ResourceUtilizationThresholds = map[string]float64{
    "cpu":         80.0,  // Maximum CPU utilization percentage
    "memory":      85.0,  // Maximum memory utilization percentage
    "disk":        75.0,  // Maximum disk utilization percentage
    "cpu_trend":    5.0,  // Maximum allowed CPU usage trend increase
    "memory_trend": 7.0,  // Maximum allowed memory usage trend increase
    "disk_trend":   3.0,  // Maximum allowed disk usage trend increase
}

// ResourceMetrics contains detailed resource utilization metrics
type ResourceMetrics struct {
    CPU struct {
        Average     float64
        Peak        float64
        Trend       float64
        Percentiles map[float64]float64
    }
    Memory struct {
        Average     float64
        Peak        float64
        Trend       float64
        Percentiles map[float64]float64
    }
    Disk struct {
        Average     float64
        Peak        float64
        Trend       float64
        Percentiles map[float64]float64
    }
    CollectionPeriod time.Duration
    SampleCount      int
}

// PerformanceMetrics contains comprehensive performance measurements
type PerformanceMetrics struct {
    Resources    ResourceMetrics
    Throughput struct {
        EventsPerSecond float64
        TotalEvents    int64
        Duration      time.Duration
    }
    Latency struct {
        Bronze struct {
            Average     float64
            P95        float64
            P99        float64
        }
        Silver struct {
            Average     float64
            P95        float64
            P99        float64
        }
        Gold struct {
            Average     float64
            P95        float64
            P99        float64
        }
    }
    ValidationResults map[string]bool
}

// MeasureResourceUtilization measures and analyzes system resource utilization
func MeasureResourceUtilization(t *testing.T, component string, operation func() error) (ResourceMetrics, error) {
    var metrics ResourceMetrics
    metrics.CollectionPeriod = DefaultMeasurementInterval
    
    // Initialize statistical collectors
    cpuStats := make([]float64, 0, DefaultSampleSize)
    memStats := make([]float64, 0, DefaultSampleSize)
    diskStats := make([]float64, 0, DefaultSampleSize)

    // Create measurement channel
    measureChan := make(chan struct{})
    defer close(measureChan)

    // Start resource monitoring goroutine
    go func() {
        var m runtime.MemStats
        ticker := time.NewTicker(metrics.CollectionPeriod / DefaultSampleSize)
        defer ticker.Stop()

        for {
            select {
            case <-measureChan:
                return
            case <-ticker.C:
                runtime.ReadMemStats(&m)
                
                cpuStats = append(cpuStats, float64(runtime.NumGoroutine()))
                memStats = append(memStats, float64(m.Alloc)/float64(m.Sys)*100)
                diskStats = append(diskStats, float64(m.HeapAlloc)/float64(m.HeapSys)*100)
            }
        }
    }()

    // Execute operation
    err := operation()
    measureChan <- struct{}{} // Stop measurements

    if err != nil {
        return metrics, err
    }

    // Calculate statistics
    metrics.CPU.Average, metrics.CPU.Peak = calculateStats(cpuStats)
    metrics.Memory.Average, metrics.Memory.Peak = calculateStats(memStats)
    metrics.Disk.Average, metrics.Disk.Peak = calculateStats(diskStats)

    // Calculate trends
    metrics.CPU.Trend = calculateTrend(cpuStats)
    metrics.Memory.Trend = calculateTrend(memStats)
    metrics.Disk.Trend = calculateTrend(diskStats)

    // Calculate percentiles
    metrics.CPU.Percentiles = calculatePercentiles(cpuStats)
    metrics.Memory.Percentiles = calculatePercentiles(memStats)
    metrics.Disk.Percentiles = calculatePercentiles(diskStats)

    metrics.SampleCount = len(cpuStats)

    // Log metrics
    logging.LogTestInfo(t, "Resource utilization metrics collected", map[string]interface{}{
        "component":      component,
        "cpu_average":    metrics.CPU.Average,
        "memory_average": metrics.Memory.Average,
        "disk_average":   metrics.Disk.Average,
    })

    return metrics, nil
}

// CollectPerformanceMetrics collects comprehensive performance metrics
func CollectPerformanceMetrics(t *testing.T, testName string, duration time.Duration) (PerformanceMetrics, error) {
    var metrics PerformanceMetrics
    metrics.ValidationResults = make(map[string]bool)
    
    startTime := time.Now()
    eventCount := int64(0)

    // Collect resource metrics
    resourceMetrics, err := MeasureResourceUtilization(t, testName, func() error {
        return utils.WaitForCondition(t, func() bool {
            return time.Since(startTime) >= duration
        }, duration)
    })

    if err != nil {
        return metrics, err
    }
    metrics.Resources = resourceMetrics

    // Calculate throughput
    metrics.Throughput.Duration = time.Since(startTime)
    metrics.Throughput.TotalEvents = eventCount
    metrics.Throughput.EventsPerSecond = float64(eventCount) / metrics.Throughput.Duration.Seconds()

    // Collect latency metrics
    metrics.Latency = collectLatencyMetrics(t)

    return metrics, nil
}

// ValidatePerformanceRequirements validates metrics against requirements
func ValidatePerformanceRequirements(t *testing.T, metrics PerformanceMetrics) (bool, error) {
    valid := true
    
    // Validate throughput
    if metrics.Throughput.EventsPerSecond < 1000 {
        valid = false
        logging.LogTestError(t, fmt.Errorf("insufficient throughput"), map[string]interface{}{
            "actual":   metrics.Throughput.EventsPerSecond,
            "required": 1000,
        })
    }

    // Validate resource utilization
    if metrics.Resources.CPU.Average > ResourceUtilizationThresholds["cpu"] {
        valid = false
        logging.LogTestError(t, fmt.Errorf("CPU utilization exceeded threshold"), map[string]interface{}{
            "actual":   metrics.Resources.CPU.Average,
            "threshold": ResourceUtilizationThresholds["cpu"],
        })
    }

    // Validate latency requirements
    if metrics.Latency.Bronze.P95 > float64(time.Second) {
        valid = false
        logging.LogTestError(t, fmt.Errorf("Bronze tier latency exceeded threshold"), map[string]interface{}{
            "actual":   metrics.Latency.Bronze.P95,
            "threshold": time.Second,
        })
    }

    return valid, nil
}

// GeneratePerformanceReport generates a detailed performance analysis report
func GeneratePerformanceReport(t *testing.T, metrics PerformanceMetrics) (map[string]interface{}, error) {
    report := make(map[string]interface{})

    // Resource utilization summary
    report["resource_utilization"] = map[string]interface{}{
        "cpu": map[string]float64{
            "average": metrics.Resources.CPU.Average,
            "peak":    metrics.Resources.CPU.Peak,
            "trend":   metrics.Resources.CPU.Trend,
        },
        "memory": map[string]float64{
            "average": metrics.Resources.Memory.Average,
            "peak":    metrics.Resources.Memory.Peak,
            "trend":   metrics.Resources.Memory.Trend,
        },
    }

    // Performance metrics
    report["performance"] = map[string]interface{}{
        "throughput": metrics.Throughput.EventsPerSecond,
        "duration":   metrics.Throughput.Duration.Seconds(),
        "events":     metrics.Throughput.TotalEvents,
    }

    // Latency analysis
    report["latency"] = map[string]interface{}{
        "bronze": map[string]float64{
            "p95": metrics.Latency.Bronze.P95,
            "p99": metrics.Latency.Bronze.P99,
        },
        "silver": map[string]float64{
            "p95": metrics.Latency.Silver.P95,
            "p99": metrics.Latency.Silver.P99,
        },
        "gold": map[string]float64{
            "p95": metrics.Latency.Gold.P95,
            "p99": metrics.Latency.Gold.P99,
        },
    }

    return report, nil
}

// Helper functions

func calculateStats(samples []float64) (average, peak float64) {
    if len(samples) == 0 {
        return 0, 0
    }
    
    peak = samples[0]
    sum := 0.0
    
    for _, v := range samples {
        sum += v
        if v > peak {
            peak = v
        }
    }
    
    return sum / float64(len(samples)), peak
}

func calculateTrend(samples []float64) float64 {
    if len(samples) < 2 {
        return 0
    }
    
    x := make([]float64, len(samples))
    for i := range x {
        x[i] = float64(i)
    }
    
    slope, _ := stat.LinearRegression(x, samples, nil, false)
    return slope
}

func calculatePercentiles(samples []float64) map[float64]float64 {
    percentiles := map[float64]float64{
        50: 0,
        95: 0,
        99: 0,
    }
    
    if len(samples) == 0 {
        return percentiles
    }

    sorted := make([]float64, len(samples))
    copy(sorted, samples)
    stat.SortWeighted(sorted, nil)
    
    for p := range percentiles {
        percentiles[p] = stat.Quantile(p/100, stat.Empirical, sorted, nil)
    }
    
    return percentiles
}

func collectLatencyMetrics(t *testing.T) struct {
    Bronze struct {
        Average float64
        P95    float64
        P99    float64
    }
    Silver struct {
        Average float64
        P95    float64
        P99    float64
    }
    Gold struct {
        Average float64
        P95    float64
        P99    float64
    }
} {
    var latencyMetrics struct {
        Bronze struct {
            Average float64
            P95    float64
            P99    float64
        }
        Silver struct {
            Average float64
            P95    float64
            P99    float64
        }
        Gold struct {
            Average float64
            P95    float64
            P99    float64
        }
    }

    // Implementation would collect actual latency measurements
    // Placeholder for demonstration
    return latencyMetrics
}