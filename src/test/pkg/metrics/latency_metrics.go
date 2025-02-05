// Package metrics provides comprehensive latency measurement and analysis utilities
// for the BlackPoint Security Integration Framework testing suite.
package metrics

import (
	"sort"
	"testing"
	"time"

	"gonum.org/v1/gonum/stat" // v0.14.0
	"github.com/stretchr/testify/require" // v1.8.0

	"../common/constants"
	"../common/logging"
	"../common/utils"
)

// Global constants for latency measurement configuration
const (
	LatencyMeasurementInterval = 100 * time.Millisecond
	DefaultSampleSize         = 1000
	MinSampleSize            = 100
	MaxRetries              = 3
	OutlierThreshold        = 2.0 // Standard deviations for outlier detection
)

// LatencyPercentiles defines the standard percentiles for statistical analysis
var LatencyPercentiles = []float64{50, 90, 95, 99}

// MeasureProcessingLatency measures and validates processing latency for a single operation
func MeasureProcessingLatency(t *testing.T, tier string, operation func() error) (time.Duration, error) {
	// Validate tier specification
	threshold, ok := constants.ProcessingLatencyThresholds[tier]
	if !ok {
		return 0, utils.NewTestError("VALIDATION_ERROR", "invalid tier specified: %s", tier)
	}

	// Initialize measurement context
	start := time.Now()
	var latency time.Duration
	var err error

	// Execute operation with retry support
	for attempt := 0; attempt < MaxRetries; attempt++ {
		operationStart := time.Now()
		err = operation()
		latency = time.Since(operationStart)

		if err == nil {
			break
		}

		logging.LogTestInfo(t, "Operation retry", map[string]interface{}{
			"tier":     tier,
			"attempt":  attempt + 1,
			"latency":  latency.String(),
			"error":    err.Error(),
		})
	}

	if err != nil {
		return 0, utils.WrapTestError(err, "operation failed after %d retries", MaxRetries)
	}

	// Validate against threshold
	if latency > threshold {
		return latency, utils.NewTestError("VALIDATION_ERROR",
			"latency %v exceeds threshold %v for tier %s",
			latency, threshold, tier)
	}

	// Log measurement results
	logging.LogTestInfo(t, "Latency measurement completed", map[string]interface{}{
		"tier":      tier,
		"latency":   latency.String(),
		"threshold": threshold.String(),
		"status":    "success",
	})

	return latency, nil
}

// MeasureBatchLatency measures processing latency for a batch of operations
func MeasureBatchLatency(t *testing.T, tier string, batchSize int, batchOperation func() error) ([]time.Duration, error) {
	// Validate batch size
	if batchSize < MinSampleSize {
		return nil, utils.NewTestError("VALIDATION_ERROR",
			"batch size %d below minimum requirement of %d",
			batchSize, MinSampleSize)
	}

	// Initialize measurement slice
	measurements := make([]time.Duration, 0, batchSize)

	// Execute batch operations
	for i := 0; i < batchSize; i++ {
		latency, err := MeasureProcessingLatency(t, tier, batchOperation)
		if err != nil {
			return measurements, utils.WrapTestError(err,
				"batch operation %d/%d failed", i+1, batchSize)
		}
		measurements = append(measurements, latency)
		time.Sleep(LatencyMeasurementInterval) // Prevent overwhelming the system
	}

	// Calculate and validate statistics
	stats, err := CalculateLatencyStats(measurements)
	if err != nil {
		return measurements, err
	}

	// Log batch results
	logging.LogTestInfo(t, "Batch latency measurements completed", map[string]interface{}{
		"tier":        tier,
		"batch_size":  batchSize,
		"statistics":  stats,
		"status":      "success",
	})

	return measurements, nil
}

// CalculateLatencyStats performs comprehensive statistical analysis on latency measurements
func CalculateLatencyStats(measurements []time.Duration) (map[string]time.Duration, error) {
	if len(measurements) < MinSampleSize {
		return nil, utils.NewTestError("VALIDATION_ERROR",
			"insufficient samples for statistical analysis: %d < %d",
			len(measurements), MinSampleSize)
	}

	// Convert measurements to float64 slice for statistical analysis
	data := make([]float64, len(measurements))
	for i, m := range measurements {
		data[i] = float64(m.Nanoseconds())
	}

	// Calculate basic statistics
	mean, std := stat.MeanStdDev(data, nil)
	
	// Remove outliers
	filtered := make([]float64, 0, len(data))
	for _, v := range data {
		if abs((v-mean)/std) <= OutlierThreshold {
			filtered = append(filtered, v)
		}
	}

	// Sort filtered data for percentile calculations
	sort.Float64s(filtered)

	// Calculate statistics
	stats := make(map[string]time.Duration)
	stats["mean"] = time.Duration(stat.Mean(filtered, nil))
	stats["median"] = time.Duration(stat.Quantile(0.5, stat.Empirical, filtered, nil))
	stats["stddev"] = time.Duration(stat.StdDev(filtered, nil))

	// Calculate percentiles
	for _, p := range LatencyPercentiles {
		q := stat.Quantile(p/100.0, stat.Empirical, filtered, nil)
		stats[fmt.Sprintf("p%d", int(p))] = time.Duration(q)
	}

	return stats, nil
}

// ValidateLatencyRequirements performs detailed validation of latency measurements
func ValidateLatencyRequirements(t *testing.T, tier string, measurements []time.Duration) (bool, error) {
	threshold, ok := constants.ProcessingLatencyThresholds[tier]
	if !ok {
		return false, utils.NewTestError("VALIDATION_ERROR", "invalid tier specified: %s", tier)
	}

	stats, err := CalculateLatencyStats(measurements)
	if err != nil {
		return false, err
	}

	// Validate p95 against threshold
	if stats["p95"] > threshold {
		return false, utils.NewTestError("VALIDATION_ERROR",
			"p95 latency %v exceeds threshold %v for tier %s",
			stats["p95"], threshold, tier)
	}

	// Log validation results
	logging.LogTestInfo(t, "Latency requirements validated", map[string]interface{}{
		"tier":       tier,
		"threshold":  threshold.String(),
		"statistics": stats,
		"status":     "success",
	})

	return true, nil
}

// GenerateLatencyReport generates a detailed latency analysis report
func GenerateLatencyReport(t *testing.T, tierMeasurements map[string][]time.Duration) (map[string]interface{}, error) {
	report := make(map[string]interface{})
	report["timestamp"] = time.Now().UTC()
	report["summary"] = make(map[string]interface{})

	for tier, measurements := range tierMeasurements {
		stats, err := CalculateLatencyStats(measurements)
		if err != nil {
			return nil, utils.WrapTestError(err,
				"failed to calculate statistics for tier %s", tier)
		}

		valid, err := ValidateLatencyRequirements(t, tier, measurements)
		if err != nil {
			return nil, err
		}

		report["summary"].(map[string]interface{})[tier] = map[string]interface{}{
			"statistics":        stats,
			"sample_size":      len(measurements),
			"meets_threshold":   valid,
			"threshold":        constants.ProcessingLatencyThresholds[tier],
		}
	}

	// Log report generation
	logging.LogTestInfo(t, "Latency report generated", map[string]interface{}{
		"report": report,
		"status": "success",
	})

	return report, nil
}

// Helper function to calculate absolute value
func abs(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}