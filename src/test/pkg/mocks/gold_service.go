// Package mocks provides mock implementations for testing the BlackPoint Security Integration Framework
package mocks

import (
    "sync"
    "time"

    "github.com/prometheus/client_golang/prometheus" // v1.17.0
    "github.com/sirupsen/logrus"                    // v1.9.3
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/gold"
)

// MockGoldService implements a mock version of the Gold tier service for testing
type MockGoldService struct {
    alerts            map[string]*gold.Alert
    lock             sync.RWMutex
    metrics          *prometheus.TestMetrics
    logger           *logrus.Logger
    operationLatencies map[string]time.Time
}

// mockMetrics tracks test-specific metrics
var mockMetrics = struct {
    alertCreations    prometheus.Counter
    alertUpdates     prometheus.Counter
    alertRetrieval   prometheus.Counter
    operationLatency prometheus.Histogram
    validationErrors prometheus.Counter
}{
    alertCreations: prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackpoint_test_alert_creations_total",
        Help: "Total number of test alert creations",
    }),
    alertUpdates: prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackpoint_test_alert_updates_total",
        Help: "Total number of test alert status updates",
    }),
    alertRetrieval: prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackpoint_test_alert_retrievals_total",
        Help: "Total number of test alert retrievals",
    }),
    operationLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
        Name:    "blackpoint_test_operation_latency_seconds",
        Help:    "Latency of mock operations",
        Buckets: prometheus.LinearBuckets(0, 0.1, 10),
    }),
    validationErrors: prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackpoint_test_validation_errors_total",
        Help: "Total number of validation errors in tests",
    }),
}

// NewMockGoldService creates a new instance of the mock gold service
func NewMockGoldService(metrics *prometheus.TestMetrics, logger *logrus.Logger) *MockGoldService {
    // Register metrics
    prometheus.MustRegister(
        mockMetrics.alertCreations,
        mockMetrics.alertUpdates,
        mockMetrics.alertRetrieval,
        mockMetrics.operationLatency,
        mockMetrics.validationErrors,
    )

    return &MockGoldService{
        alerts:            make(map[string]*gold.Alert),
        metrics:          metrics,
        logger:           logger,
        operationLatencies: make(map[string]time.Time),
    }
}

// CreateAlert implements mock alert creation with metrics collection
func (m *MockGoldService) CreateAlert(event *gold.GoldEvent) (*gold.Alert, error) {
    startTime := time.Now()
    m.lock.Lock()
    defer m.lock.Unlock()

    // Validate input
    if event == nil {
        mockMetrics.validationErrors.Inc()
        return nil, errors.NewError("E3001", "event cannot be nil", nil)
    }

    // Create new alert
    alert, err := gold.CreateAlert(event, &gold.SecurityMetadata{
        Classification:   "TEST",
        DataSensitivity: "HIGH",
    })
    if err != nil {
        mockMetrics.validationErrors.Inc()
        m.logger.WithError(err).Error("Failed to create test alert")
        return nil, err
    }

    // Store alert
    m.alerts[alert.AlertID] = alert

    // Record metrics
    mockMetrics.alertCreations.Inc()
    mockMetrics.operationLatency.Observe(time.Since(startTime).Seconds())
    m.operationLatencies[alert.AlertID] = startTime

    m.logger.WithFields(logrus.Fields{
        "alert_id": alert.AlertID,
        "severity": alert.Severity,
        "duration": time.Since(startTime),
    }).Info("Created test alert")

    return alert, nil
}

// UpdateAlertStatus implements mock alert status updates with validation
func (m *MockGoldService) UpdateAlertStatus(alertID string, newStatus string, updateReason string) error {
    startTime := time.Now()
    m.lock.Lock()
    defer m.lock.Unlock()

    // Validate input
    if alertID == "" || newStatus == "" {
        mockMetrics.validationErrors.Inc()
        return errors.NewError("E3001", "invalid input parameters", nil)
    }

    // Check if alert exists
    alert, exists := m.alerts[alertID]
    if !exists {
        mockMetrics.validationErrors.Inc()
        return errors.NewError("E3001", "alert not found", nil)
    }

    // Update status
    alert.Status = newStatus
    alert.UpdatedAt = time.Now().UTC()
    alert.History = append(alert.History, gold.StatusHistory{
        Status:    newStatus,
        Timestamp: time.Now().UTC(),
        UpdatedBy: "TEST",
        Reason:    updateReason,
        Metadata:  map[string]interface{}{"test": true},
    })

    // Record metrics
    mockMetrics.alertUpdates.Inc()
    mockMetrics.operationLatency.Observe(time.Since(startTime).Seconds())

    m.logger.WithFields(logrus.Fields{
        "alert_id":    alertID,
        "new_status": newStatus,
        "duration":   time.Since(startTime),
    }).Info("Updated test alert status")

    return nil
}

// GetAlert implements mock alert retrieval with metrics
func (m *MockGoldService) GetAlert(alertID string) (*gold.Alert, error) {
    startTime := time.Now()
    m.lock.RLock()
    defer m.lock.RUnlock()

    // Validate input
    if alertID == "" {
        mockMetrics.validationErrors.Inc()
        return nil, errors.NewError("E3001", "alert ID cannot be empty", nil)
    }

    // Retrieve alert
    alert, exists := m.alerts[alertID]
    if !exists {
        mockMetrics.validationErrors.Inc()
        return nil, errors.NewError("E3001", "alert not found", nil)
    }

    // Record metrics
    mockMetrics.alertRetrieval.Inc()
    mockMetrics.operationLatency.Observe(time.Since(startTime).Seconds())

    m.logger.WithFields(logrus.Fields{
        "alert_id":  alertID,
        "duration": time.Since(startTime),
    }).Debug("Retrieved test alert")

    return alert, nil
}

// Reset resets the mock service state and metrics
func (m *MockGoldService) Reset() {
    m.lock.Lock()
    defer m.lock.Unlock()

    // Clear state
    m.alerts = make(map[string]*gold.Alert)
    m.operationLatencies = make(map[string]time.Time)

    // Reset metrics
    prometheus.Unregister(mockMetrics.alertCreations)
    prometheus.Unregister(mockMetrics.alertUpdates)
    prometheus.Unregister(mockMetrics.alertRetrieval)
    prometheus.Unregister(mockMetrics.operationLatency)
    prometheus.Unregister(mockMetrics.validationErrors)

    m.logger.Info("Reset mock gold service state")
}

// GetMetrics returns collected test metrics
func (m *MockGoldService) GetMetrics() map[string]interface{} {
    m.lock.RLock()
    defer m.lock.RUnlock()

    metrics := make(map[string]interface{})

    // Calculate success rates
    totalOperations := float64(len(m.alerts))
    if totalOperations > 0 {
        successRate := (totalOperations - float64(mockMetrics.validationErrors.Value())) / totalOperations
        metrics["success_rate"] = successRate
    }

    // Calculate average latencies
    var totalLatency float64
    for _, startTime := range m.operationLatencies {
        totalLatency += time.Since(startTime).Seconds()
    }
    if len(m.operationLatencies) > 0 {
        metrics["avg_latency"] = totalLatency / float64(len(m.operationLatencies))
    }

    // Collect operation counts
    metrics["total_alerts"] = len(m.alerts)
    metrics["alert_creations"] = mockMetrics.alertCreations.Value()
    metrics["alert_updates"] = mockMetrics.alertUpdates.Value()
    metrics["alert_retrievals"] = mockMetrics.alertRetrieval.Value()
    metrics["validation_errors"] = mockMetrics.validationErrors.Value()

    return metrics
}