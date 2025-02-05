// Package analyzer implements metrics collection and monitoring for the security analyzer component
package analyzer

import (
    "sync"
    "time"

    "github.com/blackpoint/pkg/common/logging"
    "github.com/blackpoint/internal/metrics/telemetry"
    "github.com/prometheus/client_golang/prometheus" // v1.14.0
    "github.com/prometheus/client_golang/prometheus/promauto" // v1.14.0
    "k8s.io/metrics/pkg/client/clientset/versioned" // v0.26.0
)

var (
    // eventProcessingDuration tracks event processing time
    eventProcessingDuration *prometheus.HistogramVec

    // correlationAccuracy tracks the accuracy of event correlation
    correlationAccuracy *prometheus.GaugeVec

    // alertsGenerated tracks the number of generated alerts
    alertsGenerated *prometheus.CounterVec

    // eventsProcessed tracks the number of processed events
    eventsProcessed *prometheus.CounterVec

    // activeCorrelations tracks active correlation operations
    activeCorrelations *prometheus.GaugeVec

    // metricLabels contains standard Kubernetes labels
    metricLabels = map[string]string{
        "client_id":   "",
        "pod_name":    "",
        "node_name":   "",
        "environment": "",
    }

    // mutex for thread-safe operations
    metricMutex sync.RWMutex
)

// InitMetrics initializes analyzer metrics collection with enhanced Kubernetes integration
func InitMetrics(config telemetry.MetricConfig) error {
    metricMutex.Lock()
    defer metricMutex.Unlock()

    // Initialize event processing duration histogram
    eventProcessingDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Namespace: "blackpoint",
            Subsystem: "analyzer",
            Name:      "event_processing_duration_seconds",
            Help:      "Duration of event processing operations",
            Buckets:   []float64{0.1, 0.5, 1.0, 2.0, 5.0},
        },
        []string{"client_id", "pod_name", "node_name", "environment"},
    )

    // Initialize correlation accuracy gauge
    correlationAccuracy = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Namespace: "blackpoint",
            Subsystem: "analyzer",
            Name:      "correlation_accuracy_percent",
            Help:      "Accuracy percentage of event correlation",
        },
        []string{"client_id", "pod_name", "environment"},
    )

    // Initialize alerts generated counter
    alertsGenerated = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: "blackpoint",
            Subsystem: "analyzer",
            Name:      "alerts_generated_total",
            Help:      "Total number of security alerts generated",
        },
        []string{"client_id", "severity", "pod_name", "environment"},
    )

    // Initialize events processed counter
    eventsProcessed = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Namespace: "blackpoint",
            Subsystem: "analyzer",
            Name:      "events_processed_total",
            Help:      "Total number of events processed",
        },
        []string{"client_id", "success", "pod_name", "environment"},
    )

    // Initialize active correlations gauge
    activeCorrelations = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Namespace: "blackpoint",
            Subsystem: "analyzer",
            Name:      "active_correlations",
            Help:      "Number of active correlation operations",
        },
        []string{"client_id", "pod_name", "environment"},
    )

    // Set environment in metric labels
    metricLabels["environment"] = config.Environment

    logging.Info("analyzer metrics initialized",
        logging.Field("environment", config.Environment),
        logging.Field("namespace", config.Namespace))

    return nil
}

// RecordEventProcessing records the duration and result of event processing
func RecordEventProcessing(clientID string, duration time.Duration, success bool) {
    metricMutex.RLock()
    defer metricMutex.RUnlock()

    // Validate client ID
    if clientID == "" {
        logging.Error("invalid client ID for metrics", nil)
        return
    }

    // Update metric labels
    labels := prometheus.Labels{
        "client_id":   clientID,
        "pod_name":    metricLabels["pod_name"],
        "node_name":   metricLabels["node_name"],
        "environment": metricLabels["environment"],
    }

    // Record processing duration
    eventProcessingDuration.With(labels).Observe(duration.Seconds())

    // Update events processed counter
    eventsProcessed.With(prometheus.Labels{
        "client_id":   clientID,
        "success":     string(success),
        "pod_name":    metricLabels["pod_name"],
        "environment": metricLabels["environment"],
    }).Inc()
}

// UpdateCorrelationAccuracy updates the correlation accuracy metrics
func UpdateCorrelationAccuracy(clientID string, accuracy float64) {
    metricMutex.RLock()
    defer metricMutex.RUnlock()

    // Validate accuracy value
    if accuracy < 0 || accuracy > 100 {
        logging.Error("invalid accuracy value", nil)
        return
    }

    // Update correlation accuracy gauge
    correlationAccuracy.With(prometheus.Labels{
        "client_id":   clientID,
        "pod_name":    metricLabels["pod_name"],
        "environment": metricLabels["environment"],
    }).Set(accuracy)

    // Update active correlations
    activeCorrelations.With(prometheus.Labels{
        "client_id":   clientID,
        "pod_name":    metricLabels["pod_name"],
        "environment": metricLabels["environment"],
    }).Inc()
}

// RecordAlertGeneration records metrics about generated security alerts
func RecordAlertGeneration(clientID string, severity string) {
    metricMutex.RLock()
    defer metricMutex.RUnlock()

    // Validate severity level
    validSeverities := map[string]bool{
        "critical": true,
        "high":     true,
        "medium":   true,
        "low":      true,
    }

    if !validSeverities[severity] {
        logging.Error("invalid alert severity", nil)
        return
    }

    // Increment alerts generated counter
    alertsGenerated.With(prometheus.Labels{
        "client_id":   clientID,
        "severity":    severity,
        "pod_name":    metricLabels["pod_name"],
        "environment": metricLabels["environment"],
    }).Inc()
}