// Package metrics provides performance measurement utilities for the BlackPoint Security Integration Framework.
// Version: 1.0.0
package metrics

import (
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"gonum.org/v1/gonum/stat" // v0.14.0
	"github.com/stretchr/testify/require" // v1.8.0

	"../common/logging"
	"../common/utils"
)

// Global constants for throughput measurement and validation
const (
	DefaultThroughputInterval    = 5 * time.Second
	MinimumThroughputSLA        = 1000.0 // events/second per client
	ThroughputSampleSize        = 100
	StatisticalConfidenceLevel  = 0.95
)

// ThroughputMetrics represents comprehensive throughput measurement results
type ThroughputMetrics struct {
	EventsPerSecond     float64
	Mean               float64
	Median             float64
	StdDev             float64
	P90                float64
	P95                float64
	P99                float64
	StabilityScore     float64
	ConfidenceInterval struct {
		Lower float64
		Upper float64
	}
	SampleCount        int
	MeasurementPeriod  time.Duration
	Component          string
	Timestamp          time.Time
}

// MeasureThroughput measures event processing throughput with enhanced statistical analysis
func MeasureThroughput(t *testing.T, component string, operation func() (int, error), duration time.Duration) (*ThroughputMetrics, error) {
	samples := make([]float64, 0, ThroughputSampleSize)
	metrics := &ThroughputMetrics{
		Component:         component,
		MeasurementPeriod: duration,
		Timestamp:         time.Now(),
	}

	logging.LogTestInfo(t, "Starting throughput measurement", map[string]interface{}{
		"component": component,
		"duration":  duration.String(),
	})

	start := time.Now()
	deadline := start.Add(duration)

	for time.Now().Before(deadline) {
		sampleStart := time.Now()
		count, err := operation()
		if err != nil {
			return nil, fmt.Errorf("operation failed during measurement: %w", err)
		}

		sampleDuration := time.Since(sampleStart).Seconds()
		throughput := float64(count) / sampleDuration
		samples = append(samples, throughput)

		if len(samples) >= ThroughputSampleSize {
			break
		}
	}

	metrics.SampleCount = len(samples)
	if metrics.SampleCount == 0 {
		return nil, fmt.Errorf("no samples collected during measurement period")
	}

	// Calculate basic statistics
	metrics.Mean, metrics.StdDev = stat.MeanStdDev(samples, nil)
	metrics.EventsPerSecond = metrics.Mean

	// Calculate percentiles
	sort.Float64s(samples)
	metrics.Median = stat.Quantile(0.5, stat.Empirical, samples, nil)
	metrics.P90 = stat.Quantile(0.90, stat.Empirical, samples, nil)
	metrics.P95 = stat.Quantile(0.95, stat.Empirical, samples, nil)
	metrics.P99 = stat.Quantile(0.99, stat.Empirical, samples, nil)

	// Calculate confidence interval
	metrics.ConfidenceInterval.Lower, metrics.ConfidenceInterval.Upper = stat.MeanConfidenceInterval(
		metrics.Mean,
		metrics.StdDev,
		float64(metrics.SampleCount),
		StatisticalConfidenceLevel,
	)

	// Calculate stability score (lower variance = higher stability)
	metrics.StabilityScore = 1.0 - (metrics.StdDev / metrics.Mean)

	logging.LogTestMetrics(t, map[string]interface{}{
		"component":           component,
		"events_per_second":   metrics.EventsPerSecond,
		"mean":               metrics.Mean,
		"median":             metrics.Median,
		"std_dev":            metrics.StdDev,
		"p90":                metrics.P90,
		"p95":                metrics.P95,
		"p99":                metrics.P99,
		"stability_score":    metrics.StabilityScore,
		"confidence_level":   StatisticalConfidenceLevel,
		"confidence_interval": []float64{metrics.ConfidenceInterval.Lower, metrics.ConfidenceInterval.Upper},
		"sample_count":       metrics.SampleCount,
	})

	return metrics, nil
}

// ValidateThroughputSLA validates throughput against SLA with statistical confidence
func ValidateThroughputSLA(t *testing.T, metrics *ThroughputMetrics) (bool, error) {
	require.NotNil(t, metrics, "metrics cannot be nil")

	// Validate with confidence interval
	if metrics.ConfidenceInterval.Lower < MinimumThroughputSLA {
		return false, fmt.Errorf("throughput below SLA (%.2f events/sec) with %.0f%% confidence [%.2f-%.2f]",
			MinimumThroughputSLA,
			StatisticalConfidenceLevel*100,
			metrics.ConfidenceInterval.Lower,
			metrics.ConfidenceInterval.Upper)
	}

	// Check stability
	if metrics.StabilityScore < 0.8 {
		return false, fmt.Errorf("throughput stability below threshold: %.2f", metrics.StabilityScore)
	}

	// Validate percentiles
	if metrics.P95 < MinimumThroughputSLA*0.9 {
		return false, fmt.Errorf("95th percentile throughput (%.2f) below 90%% of SLA", metrics.P95)
	}

	logging.LogTestInfo(t, "Throughput SLA validation passed", map[string]interface{}{
		"component":          metrics.Component,
		"sla_threshold":      MinimumThroughputSLA,
		"measured_throughput": metrics.EventsPerSecond,
		"stability_score":    metrics.StabilityScore,
	})

	return true, nil
}

// MeasureConcurrentThroughput measures throughput under concurrent client load
func MeasureConcurrentThroughput(t *testing.T, numClients int, clientOperation func() (int, error)) (map[string]ThroughputMetrics, error) {
	results := make(map[string]ThroughputMetrics)
	var wg sync.WaitGroup
	var mu sync.Mutex
	errChan := make(chan error, numClients)

	logging.LogTestInfo(t, "Starting concurrent throughput measurement", map[string]interface{}{
		"num_clients": numClients,
	})

	for i := 0; i < numClients; i++ {
		clientID := fmt.Sprintf("client-%d", i)
		wg.Add(1)

		go func(id string) {
			defer wg.Done()

			metrics, err := MeasureThroughput(t, id, clientOperation, DefaultThroughputInterval)
			if err != nil {
				errChan <- fmt.Errorf("client %s measurement failed: %w", id, err)
				return
			}

			mu.Lock()
			results[id] = *metrics
			mu.Unlock()
		}(clientID)
	}

	wg.Wait()
	close(errChan)

	// Check for errors
	for err := range errChan {
		if err != nil {
			return nil, err
		}
	}

	return results, nil
}

// GenerateThroughputReport generates comprehensive throughput analysis report
func GenerateThroughputReport(t *testing.T, metrics *ThroughputMetrics) (map[string]interface{}, error) {
	require.NotNil(t, metrics, "metrics cannot be nil")

	report := map[string]interface{}{
		"summary": map[string]interface{}{
			"component":           metrics.Component,
			"timestamp":          metrics.Timestamp,
			"measurement_period": metrics.MeasurementPeriod.String(),
			"events_per_second":  metrics.EventsPerSecond,
			"sla_compliance":     metrics.EventsPerSecond >= MinimumThroughputSLA,
		},
		"statistics": map[string]interface{}{
			"mean":               metrics.Mean,
			"median":            metrics.Median,
			"std_dev":           metrics.StdDev,
			"stability_score":   metrics.StabilityScore,
			"sample_count":      metrics.SampleCount,
		},
		"percentiles": map[string]interface{}{
			"p90": metrics.P90,
			"p95": metrics.P95,
			"p99": metrics.P99,
		},
		"confidence_interval": map[string]interface{}{
			"level": StatisticalConfidenceLevel,
			"lower": metrics.ConfidenceInterval.Lower,
			"upper": metrics.ConfidenceInterval.Upper,
		},
	}

	logging.LogTestMetrics(t, report)
	return report, nil
}