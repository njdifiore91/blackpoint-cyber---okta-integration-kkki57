// Package monitor provides validation logic for monitoring-related data structures
package monitor

import (
	"regexp"
	"sync"
	"time"

	"github.com/blackpoint/cli/pkg/common/errors"
	"github.com/blackpoint/cli/pkg/monitor/types"
)

const (
	// Validation thresholds
	maxEventsPerSecond     = 1000000
	maxBronzeLatency      = 1.0  // seconds
	maxSilverLatency      = 5.0  // seconds
	maxGoldLatency        = 30.0 // seconds
	componentNameMaxLen    = 64
	alertMessageMaxLen     = 1000
	futureTimestampBuffer = 5 * time.Second
)

var (
	// Validation caches with TTL
	metricsCache     sync.Map
	componentCache   sync.Map
	metricsCacheTTL = 5 * time.Second

	// Compiled regex patterns
	componentNamePattern = regexp.MustCompile(`^[a-zA-Z0-9-_]+$`)
)

// ValidateSystemMetrics validates system-wide performance metrics data
func ValidateSystemMetrics(metrics *types.SystemMetrics) error {
	if metrics == nil {
		return errors.NewCLIError("1004", "metrics cannot be nil", nil)
	}

	// Check cache first
	if cached, ok := metricsCache.Load(metrics); ok {
		lastValidated := cached.(time.Time)
		if time.Since(lastValidated) < metricsCacheTTL {
			return nil
		}
	}

	// Validate events per second
	if metrics.EventsPerSecond < 0 || metrics.EventsPerSecond > maxEventsPerSecond {
		return errors.NewCLIError("1004", 
			"events_per_second must be between 0 and 1000000", nil)
	}

	// Validate processing latency
	if metrics.ProcessingLatency != nil {
		if bronze, ok := metrics.ProcessingLatency["bronze"]; ok {
			if bronze < 0 || bronze > maxBronzeLatency {
				return errors.NewCLIError("1004", 
					"bronze tier latency exceeds SLA limit", nil)
			}
		}
		if silver, ok := metrics.ProcessingLatency["silver"]; ok {
			if silver < 0 || silver > maxSilverLatency {
				return errors.NewCLIError("1004", 
					"silver tier latency exceeds SLA limit", nil)
			}
		}
		if gold, ok := metrics.ProcessingLatency["gold"]; ok {
			if gold < 0 || gold > maxGoldLatency {
				return errors.NewCLIError("1004", 
					"gold tier latency exceeds SLA limit", nil)
			}
		}
	}

	// Validate resource usage metrics
	if !isValidPercentage(metrics.CPUUsage) {
		return errors.NewCLIError("1004", "invalid CPU usage percentage", nil)
	}
	if !isValidPercentage(metrics.MemoryUsage) {
		return errors.NewCLIError("1004", "invalid memory usage percentage", nil)
	}
	if !isValidPercentage(metrics.StorageUsage) {
		return errors.NewCLIError("1004", "invalid storage usage percentage", nil)
	}

	// Validate timestamp
	if err := validateTimestamp(metrics.Timestamp); err != nil {
		return err
	}

	// Cache successful validation
	metricsCache.Store(metrics, time.Now())
	return nil
}

// ValidateComponentStatus validates component status information
func ValidateComponentStatus(status *types.ComponentStatus) error {
	if status == nil {
		return errors.NewCLIError("1004", "status cannot be nil", nil)
	}

	// Validate component name
	if err := validateComponentName(status.Name); err != nil {
		return err
	}

	// Validate status value
	validStatuses := map[string]bool{
		"Running":  true,
		"Degraded": true,
		"Failed":   true,
		"Starting": true,
		"Stopping": true,
	}
	if !validStatuses[status.Status] {
		return errors.NewCLIError("1004", "invalid component status value", nil)
	}

	// Validate resource metrics
	if !isValidPercentage(status.Load) {
		return errors.NewCLIError("1004", "invalid load percentage", nil)
	}
	if !isValidPercentage(status.MemoryUsage) {
		return errors.NewCLIError("1004", "invalid memory usage percentage", nil)
	}
	if !isValidPercentage(status.DiskUsage) {
		return errors.NewCLIError("1004", "invalid disk usage percentage", nil)
	}

	// Validate last checked timestamp
	if time.Since(status.LastChecked) > 5*time.Minute {
		return errors.NewCLIError("1004", "component status is stale", nil)
	}

	return nil
}

// ValidateAlertInfo validates alert information with severity classification
func ValidateAlertInfo(alert *types.AlertInfo) error {
	if alert == nil {
		return errors.NewCLIError("1004", "alert cannot be nil", nil)
	}

	// Validate alert ID format (UUID v4)
	if !isValidUUID(alert.ID) {
		return errors.NewCLIError("1004", "invalid alert ID format", nil)
	}

	// Validate severity
	validSeverities := map[string]bool{
		"Critical": true,
		"High":     true,
		"Medium":   true,
		"Low":      true,
	}
	if !validSeverities[alert.Severity] {
		return errors.NewCLIError("1004", "invalid alert severity", nil)
	}

	// Validate component name
	if err := validateComponentName(alert.Component); err != nil {
		return err
	}

	// Validate alert message
	if len(alert.Message) == 0 || len(alert.Message) > alertMessageMaxLen {
		return errors.NewCLIError("1004", "invalid alert message length", nil)
	}

	// Validate timestamp
	if err := validateTimestamp(alert.Timestamp); err != nil {
		return err
	}

	return nil
}

// ValidateMonitoringConfig validates monitoring configuration settings
func ValidateMonitoringConfig(config *types.MonitoringConfig) error {
	if config == nil {
		return errors.NewCLIError("1004", "config cannot be nil", nil)
	}

	// Validate check interval
	if config.CheckInterval < 10*time.Second || config.CheckInterval > 5*time.Minute {
		return errors.NewCLIError("1004", 
			"check interval must be between 10s and 5m", nil)
	}

	// Validate components
	if len(config.Components) == 0 {
		return errors.NewCLIError("1004", 
			"at least one component must be specified", nil)
	}
	for _, component := range config.Components {
		if err := validateComponentName(component); err != nil {
			return err
		}
	}

	// Validate alert retention
	if config.AlertRetention < 1 || config.AlertRetention > 90 {
		return errors.NewCLIError("1004", 
			"alert retention must be between 1 and 90 days", nil)
	}

	// Validate thresholds
	if err := validateThresholds(config.Thresholds); err != nil {
		return err
	}

	return nil
}

// Helper functions

func isValidPercentage(value float64) bool {
	return value >= 0 && value <= 100
}

func validateComponentName(name string) error {
	if name == "" || len(name) > componentNameMaxLen {
		return errors.NewCLIError("1004", "invalid component name length", nil)
	}
	if !componentNamePattern.MatchString(name) {
		return errors.NewCLIError("1004", "invalid component name format", nil)
	}
	return nil
}

func validateTimestamp(ts time.Time) error {
	if ts.IsZero() {
		return errors.NewCLIError("1004", "timestamp cannot be zero", nil)
	}
	if ts.After(time.Now().Add(futureTimestampBuffer)) {
		return errors.NewCLIError("1004", "timestamp cannot be in the future", nil)
	}
	return nil
}

func isValidUUID(id string) bool {
	r := regexp.MustCompile("^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-4[a-fA-F0-9]{3}-[8|9|aA|bB][a-fA-F0-9]{3}-[a-fA-F0-9]{12}$")
	return r.MatchString(id)
}

func validateThresholds(thresholds map[string]interface{}) error {
	requiredThresholds := []string{"cpu", "memory", "disk", "events_per_second"}
	for _, required := range requiredThresholds {
		threshold, ok := thresholds[required]
		if !ok {
			return errors.NewCLIError("1004", 
				"missing required threshold: "+required, nil)
		}
		value, ok := threshold.(float64)
		if !ok || value <= 0 || value > 100 {
			return errors.NewCLIError("1004", 
				"invalid threshold value for: "+required, nil)
		}
	}
	return nil
}