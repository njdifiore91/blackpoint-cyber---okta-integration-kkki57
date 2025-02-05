// Package common provides shared utilities for the BlackPoint Security Integration Framework testing suite.
// Version: 1.0.0
package common

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require" // v1.8.0
)

// testEnvironment holds the context for a test environment
type testEnvironment struct {
	testID      string
	testDir     string
	cleanupFns  []func()
	startTime   time.Time
	metricsData map[string]float64
}

// SetupTestEnvironment initializes a comprehensive test environment with required
// configurations, resources, and cleanup handling
func SetupTestEnvironment(t *testing.T, testName string) func() {
	t.Helper()

	// Initialize test environment
	env := &testEnvironment{
		testID:      fmt.Sprintf("%s-%d", testName, time.Now().UnixNano()),
		startTime:   time.Now(),
		metricsData: make(map[string]float64),
	}

	// Create test directory structure
	env.testDir = filepath.Join(DefaultTestDataDir, env.testID)
	require.NoError(t, createTestDirectories(env.testDir))

	// Initialize test logger
	LogTestInfo(t, "Setting up test environment", map[string]interface{}{
		"test_id":   env.testID,
		"test_dir":  env.testDir,
		"test_name": testName,
	})

	// Register cleanup function
	cleanup := func() {
		for i := len(env.cleanupFns) - 1; i >= 0; i-- {
			env.cleanupFns[i]()
		}
		// Log final metrics
		LogTestMetrics(t, map[string]interface{}{
			"total_duration": time.Since(env.startTime).Seconds(),
			"metrics":       env.metricsData,
		})
	}

	return cleanup
}

// WaitForCondition implements a robust wait mechanism for test conditions
// with configurable timeout and retry logic
func WaitForCondition(t *testing.T, condition func() bool, timeout time.Duration) error {
	t.Helper()

	start := time.Now()
	retryInterval := time.Millisecond * 100

	for {
		if condition() {
			return nil
		}

		if time.Since(start) > timeout {
			return NewTestError("TEST_TIMEOUT",
				"condition not met within timeout: %v", timeout)
		}

		// Log intermediate state for debugging
		LogTestInfo(t, "Waiting for condition", map[string]interface{}{
			"elapsed":        time.Since(start).String(),
			"timeout":        timeout.String(),
			"retry_interval": retryInterval.String(),
		})

		time.Sleep(retryInterval)
		// Exponential backoff with cap
		if retryInterval < time.Second {
			retryInterval *= 2
		}
	}
}

// ValidateTestData performs comprehensive validation of test data against schema
// with type checking and nested validation
func ValidateTestData(t *testing.T, data interface{}, schema map[string]interface{}) error {
	t.Helper()

	validationStart := time.Now()
	validationErrors := make([]string, 0)

	// Validate data structure recursively
	if err := validateDataStructure(data, schema, "", &validationErrors); err != nil {
		return WrapTestError(err, "schema validation failed")
	}

	// Calculate validation accuracy
	accuracy := calculateValidationAccuracy(len(validationErrors))
	
	// Log validation metrics
	LogTestMetrics(t, map[string]interface{}{
		"validation_duration": time.Since(validationStart).Seconds(),
		"validation_errors":  len(validationErrors),
		"validation_accuracy": accuracy,
	})

	// Check against accuracy threshold
	if accuracy < ValidationThresholds["accuracy"] {
		return NewTestError("DATA_ACCURACY_ERROR",
			"validation accuracy %.2f%% below threshold %.2f%%",
			accuracy*100, ValidationThresholds["accuracy"]*100)
	}

	return nil
}

// CalculateTestMetrics calculates comprehensive test metrics including
// performance, accuracy, and statistical analysis
func CalculateTestMetrics(t *testing.T, results []interface{}) map[string]float64 {
	t.Helper()

	metrics := make(map[string]float64)
	
	// Calculate success rate
	successCount := 0
	for _, result := range results {
		if result != nil {
			successCount++
		}
	}
	successRate := float64(successCount) / float64(len(results))
	metrics["success_rate"] = successRate

	// Calculate processing metrics
	if processingTimes, ok := extractProcessingTimes(results); ok {
		metrics["avg_processing_time"] = calculateAverage(processingTimes)
		metrics["p95_processing_time"] = calculatePercentile(processingTimes, 95)
		metrics["p99_processing_time"] = calculatePercentile(processingTimes, 99)
	}

	// Calculate throughput
	metrics["events_per_second"] = float64(len(results)) / time.Since(time.Now()).Seconds()

	// Log calculated metrics
	LogTestMetrics(t, map[string]interface{}{
		"metrics": metrics,
	})

	return metrics
}

// Helper functions

func createTestDirectories(baseDir string) error {
	dirs := []string{
		baseDir,
		filepath.Join(baseDir, DefaultConfigDir),
		filepath.Join(baseDir, "data"),
		filepath.Join(baseDir, "logs"),
	}

	for _, dir := range dirs {
		if err := createDirIfNotExists(dir); err != nil {
			return WrapTestError(err, "failed to create test directory: %s", dir)
		}
	}

	return nil
}

func createDirIfNotExists(dir string) error {
	return filepath.MkdirAll(dir, 0755)
}

func validateDataStructure(data interface{}, schema map[string]interface{}, path string, errors *[]string) error {
	for key, schemaType := range schema {
		value, ok := data.(map[string]interface{})[key]
		if !ok {
			*errors = append(*errors, fmt.Sprintf("missing required field: %s", path+key))
			continue
		}

		if err := validateField(value, schemaType, path+key, errors); err != nil {
			return err
		}
	}
	return nil
}

func validateField(value interface{}, schemaType interface{}, path string, errors *[]string) error {
	switch st := schemaType.(type) {
	case map[string]interface{}:
		return validateDataStructure(value, st, path+".", errors)
	default:
		if err := validateType(value, st, path); err != nil {
			*errors = append(*errors, err.Error())
		}
	}
	return nil
}

func validateType(value interface{}, expectedType interface{}, path string) error {
	switch expectedType.(type) {
	case string:
		if _, ok := value.(string); !ok {
			return fmt.Errorf("invalid type for %s: expected string", path)
		}
	case float64:
		if _, ok := value.(float64); !ok {
			return fmt.Errorf("invalid type for %s: expected number", path)
		}
	case bool:
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("invalid type for %s: expected boolean", path)
		}
	}
	return nil
}

func calculateValidationAccuracy(errorCount int) float64 {
	if errorCount == 0 {
		return 1.0
	}
	return 1.0 - (float64(errorCount) / 100.0) // Simplified accuracy calculation
}

func extractProcessingTimes(results []interface{}) ([]float64, bool) {
	times := make([]float64, 0, len(results))
	for _, result := range results {
		if r, ok := result.(map[string]interface{}); ok {
			if t, ok := r["processing_time"].(float64); ok {
				times = append(times, t)
			}
		}
	}
	return times, len(times) > 0
}

func calculateAverage(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func calculatePercentile(values []float64, percentile float64) float64 {
	if len(values) == 0 {
		return 0
	}
	// Simple percentile calculation for demonstration
	index := int(float64(len(values)) * percentile / 100)
	if index >= len(values) {
		index = len(values) - 1
	}
	return values[index]
}