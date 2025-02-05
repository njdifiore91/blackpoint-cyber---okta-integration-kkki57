// Package monitor provides core data types and structures for the BlackPoint CLI monitoring functionality
package monitor

import (
	"fmt"
	"strings"
	"time"

	"github.com/blackpoint/cli/pkg/common/errors"
)

// Component status constants
const (
	ComponentStatusHealthy   = "healthy"
	ComponentStatusDegraded = "degraded"
	ComponentStatusUnhealthy = "unhealthy"
)

// Alert severity constants
const (
	AlertSeverityCritical = "critical"
	AlertSeverityWarning  = "warning"
	AlertSeverityInfo     = "info"
)

// SystemMetrics represents comprehensive system-wide performance metrics with timing
type SystemMetrics struct {
	EventsPerSecond    float64            `json:"events_per_second"`
	ProcessingLatency  map[string]float64 `json:"processing_latency"` // Key: tier (bronze/silver/gold)
	CPUUsage          float64            `json:"cpu_usage"`          // Percentage (0-100)
	MemoryUsage       float64            `json:"memory_usage"`       // Percentage (0-100)
	StorageUsage      float64            `json:"storage_usage"`      // Percentage (0-100)
	Timestamp         time.Time          `json:"timestamp"`
}

// String returns a formatted string representation of system metrics
func (sm *SystemMetrics) String() string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("System Metrics [%s]\n", sm.Timestamp.Format(time.RFC3339)))
	b.WriteString(fmt.Sprintf("Events/sec: %.2f\n", sm.EventsPerSecond))
	
	// Format processing latency
	b.WriteString("Processing Latency:\n")
	for tier, latency := range sm.ProcessingLatency {
		b.WriteString(fmt.Sprintf("  %s: %.2fms\n", strings.Title(tier), latency))
	}
	
	b.WriteString(fmt.Sprintf("CPU Usage: %.1f%%\n", sm.CPUUsage))
	b.WriteString(fmt.Sprintf("Memory Usage: %.1f%%\n", sm.MemoryUsage))
	b.WriteString(fmt.Sprintf("Storage Usage: %.1f%%\n", sm.StorageUsage))
	
	return b.String()
}

// ComponentStatus represents detailed status of an individual system component with timing
type ComponentStatus struct {
	Name        string    `json:"name"`
	Status      string    `json:"status"`
	Load        float64   `json:"load"`        // Percentage (0-100)
	MemoryUsage float64   `json:"memory_usage"` // Percentage (0-100)
	DiskUsage   float64   `json:"disk_usage"`   // Percentage (0-100)
	LastChecked time.Time `json:"last_checked"`
}

// IsHealthy checks if component is in healthy state based on all metrics
func (cs *ComponentStatus) IsHealthy() bool {
	const (
		loadThreshold      = 80.0
		memoryThreshold   = 85.0
		diskThreshold     = 85.0
	)
	
	return cs.Status == ComponentStatusHealthy &&
		cs.Load < loadThreshold &&
		cs.MemoryUsage < memoryThreshold &&
		cs.DiskUsage < diskThreshold
}

// AlertInfo represents a detailed system alert or notification with context
type AlertInfo struct {
	ID        string                 `json:"id"`
	Severity  string                 `json:"severity"`
	Component string                 `json:"component"`
	Message   string                 `json:"message"`
	Timestamp time.Time             `json:"timestamp"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// IsCritical checks if alert is of critical severity requiring immediate attention
func (a *AlertInfo) IsCritical() bool {
	return a.Severity == AlertSeverityCritical
}

// MonitoringConfig represents configuration settings for monitoring functionality with validation
type MonitoringConfig struct {
	CheckInterval  time.Duration          `json:"check_interval"`
	Components    []string               `json:"components"`
	AlertRetention int                   `json:"alert_retention"` // days
	Thresholds    map[string]interface{} `json:"thresholds"`
}

// Validate performs comprehensive validation of monitoring configuration
func (mc *MonitoringConfig) Validate() error {
	// Check interval validation
	if mc.CheckInterval < time.Second || mc.CheckInterval > time.Hour {
		return errors.NewCLIError("1004", "check_interval must be between 1s and 1h", nil)
	}

	// Components validation
	if len(mc.Components) == 0 {
		return errors.NewCLIError("1004", "at least one component must be specified", nil)
	}

	// Alert retention validation
	if mc.AlertRetention < 1 || mc.AlertRetention > 90 {
		return errors.NewCLIError("1004", "alert_retention must be between 1 and 90 days", nil)
	}

	// Thresholds validation
	requiredThresholds := []string{"cpu", "memory", "disk", "events_per_second"}
	for _, required := range requiredThresholds {
		if _, exists := mc.Thresholds[required]; !exists {
			return errors.NewCLIError("1004", 
				fmt.Sprintf("missing required threshold: %s", required), nil)
		}
	}

	// Validate threshold values are within acceptable ranges
	for metric, value := range mc.Thresholds {
		threshold, ok := value.(float64)
		if !ok {
			return errors.NewCLIError("1004", 
				fmt.Sprintf("invalid threshold value type for %s", metric), nil)
		}

		if threshold <= 0 || threshold > 100 {
			return errors.NewCLIError("1004", 
				fmt.Sprintf("threshold for %s must be between 0 and 100", metric), nil)
		}
	}

	return nil
}