// Package common provides shared constants and utilities for the BlackPoint Security Integration Framework testing suite.
// Version: 1.0.0
package common

import (
	"time" // v1.21
)

// DefaultTestTimeout defines the standard timeout duration for test operations
// to prevent hanging tests in CI/CD pipeline
const DefaultTestTimeout = 30 * time.Second

// DefaultTestDataDir specifies the standard directory path for test data files
// following Go testing conventions
const DefaultTestDataDir = "testdata"

// DefaultConfigDir specifies the standard directory path for test configuration files
const DefaultConfigDir = "configs"

// MaxRetries defines maximum retry attempts for test operations to handle transient failures
const MaxRetries = 3

// TestEventBatchSize sets the standard batch size for test events to validate throughput requirements
const TestEventBatchSize = 1000

// MinThroughputEventsPerSecond establishes minimum required events processed per second
// for performance validation as per technical specifications
const MinThroughputEventsPerSecond = 1000

// TestEnvironments defines valid test environment names for environment-specific test configurations
var TestEnvironments = []string{
	"development",
	"staging",
	"production",
}

// ProcessingLatencyThresholds defines maximum allowed processing times for each tier
// as specified in technical requirements (Bronze: <1s, Silver: <5s, Gold: <30s)
var ProcessingLatencyThresholds = map[string]time.Duration{
	"bronze": time.Second,
	"silver": 5 * time.Second,
	"gold":   30 * time.Second,
}

// ValidationThresholds sets minimum thresholds for validation metrics
// as per technical specifications:
// - Accuracy: 80% minimum for automated validation
// - Performance: 95% success rate for deployments
// - Availability: 99.9% uptime requirement
var ValidationThresholds = map[string]float64{
	"accuracy":     0.80,
	"performance": 0.95,
	"availability": 0.999,
}