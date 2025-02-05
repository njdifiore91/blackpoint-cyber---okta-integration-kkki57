// Package integration provides standardized interfaces and types for third-party security platform integrations
package integration

import (
    "context"
    "time"

    "github.com/prometheus/client_golang/prometheus" // v1.16.0

    "../../pkg/common/errors"
    "../../pkg/integration/config"
)

// Global constants for platform management
var (
    supportedPlatforms = []string{"aws", "azure", "gcp", "okta", "crowdstrike"}
    platformStatuses = map[string]string{
        "initializing": "INIT",
        "running":     "RUNNING", 
        "stopped":     "STOPPED",
        "error":       "ERROR",
    }
    defaultTimeout = time.Duration(30 * time.Second)
)

// Prometheus metrics
var (
    platformEventsProcessed = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_platform_events_processed_total",
            Help: "Total number of events processed by platform",
        },
        []string{"platform_type", "status"},
    )

    platformProcessingLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "blackpoint_platform_processing_latency_seconds",
            Help:    "Event processing latency in seconds",
            Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
        },
        []string{"platform_type"},
    )

    platformErrorRate = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackpoint_platform_error_rate",
            Help: "Current error rate for platform operations",
        },
        []string{"platform_type"},
    )
)

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(platformEventsProcessed)
    prometheus.MustRegister(platformProcessingLatency)
    prometheus.MustRegister(platformErrorRate)
}

// Platform defines the interface that all security platform integrations must implement
type Platform interface {
    // Initialize sets up the platform with provided configuration
    Initialize(ctx context.Context, config *config.IntegrationConfig) error

    // StartCollection begins data collection from the platform
    StartCollection(ctx context.Context) error

    // StopCollection safely stops data collection
    StopCollection(ctx context.Context) error

    // GetStatus retrieves current platform status and metrics
    GetStatus(ctx context.Context) (*PlatformStatus, error)
}

// PlatformStatus represents the current state and metrics of a platform integration
type PlatformStatus struct {
    PlatformType      string                 `json:"platform_type"`
    Status           string                 `json:"status"`
    LastUpdated      time.Time             `json:"last_updated"`
    EventsProcessed  int64                 `json:"events_processed"`
    ProcessingLatency float64               `json:"processing_latency"`
    ErrorRate        float64               `json:"error_rate"`
    Metrics          map[string]interface{} `json:"metrics"`
}

// UpdateMetrics updates platform metrics with new values
func (ps *PlatformStatus) UpdateMetrics(metrics map[string]interface{}) error {
    if metrics == nil {
        return errors.NewError("E2001", "metrics cannot be nil", nil)
    }

    // Update platform metrics
    ps.Metrics = metrics
    ps.LastUpdated = time.Now().UTC()

    // Update Prometheus metrics
    platformEventsProcessed.WithLabelValues(ps.PlatformType, ps.Status).Add(float64(ps.EventsProcessed))
    platformProcessingLatency.WithLabelValues(ps.PlatformType).Observe(ps.ProcessingLatency)
    platformErrorRate.WithLabelValues(ps.PlatformType).Set(ps.ErrorRate)

    return nil
}

// NewPlatformStatus creates a new PlatformStatus instance with initialized metrics
func NewPlatformStatus(platformType string, status string) (*PlatformStatus, error) {
    // Validate platform type
    validPlatform := false
    for _, p := range supportedPlatforms {
        if p == platformType {
            validPlatform = true
            break
        }
    }
    if !validPlatform {
        return nil, errors.NewError("E2001", "unsupported platform type", map[string]interface{}{
            "platform_type": platformType,
            "supported_platforms": supportedPlatforms,
        })
    }

    // Validate status
    if _, exists := platformStatuses[status]; !exists {
        return nil, errors.NewError("E2001", "invalid platform status", map[string]interface{}{
            "status": status,
            "valid_statuses": platformStatuses,
        })
    }

    // Create and initialize platform status
    ps := &PlatformStatus{
        PlatformType:      platformType,
        Status:           platformStatuses[status],
        LastUpdated:      time.Now().UTC(),
        EventsProcessed:  0,
        ProcessingLatency: 0.0,
        ErrorRate:        0.0,
        Metrics:          make(map[string]interface{}),
    }

    // Initialize base metrics
    ps.Metrics["uptime"] = 0.0
    ps.Metrics["memory_usage"] = 0.0
    ps.Metrics["cpu_usage"] = 0.0
    ps.Metrics["collection_rate"] = 0.0

    return ps, nil
}