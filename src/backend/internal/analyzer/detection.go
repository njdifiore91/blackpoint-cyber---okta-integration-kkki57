// Package analyzer implements threat detection algorithms and security event analysis
package analyzer

import (
    "context"
    "sync"
    "time"

    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/silver"
    "github.com/blackpoint/pkg/gold"
    "github.com/blackpoint/metrics"
)

// Global variables for detection management
var (
    // Thread-safe map of detection rules
    detectionRules = make(map[string]DetectionRule)
    ruleLock      sync.RWMutex

    // Detection timeout configuration
    detectionTimeout = 30 * time.Second

    // Resource management
    maxConcurrentDetections = 100
    workerPool             = make(chan struct{}, maxConcurrentDetections)

    // Metrics tags
    metricsTags = map[string]string{
        "component": "analyzer",
        "tier":      "gold",
    }
)

// DetectionRule defines the interface for implementing threat detection rules
type DetectionRule interface {
    // Detect analyzes an event for specific threat patterns
    Detect(event *silver.SilverEvent) (bool, float64, map[string]interface{})
}

// DetectThreats analyzes normalized security events for potential threats
// @metrics.Record
// @audit.Log
func DetectThreats(ctx context.Context, event *silver.SilverEvent) (*gold.Alert, error) {
    // Validate input
    if event == nil {
        return nil, errors.NewError("E3001", "nil event", nil)
    }

    // Apply rate limiting
    select {
    case workerPool <- struct{}{}:
        defer func() { <-workerPool }()
    default:
        return nil, errors.NewError("E4002", "detection capacity exceeded", nil)
    }

    // Start detection metrics
    timer := metrics.NewTimer("detection_latency", metricsTags)
    defer timer.Stop()

    // Create detection context with timeout
    detectionCtx, cancel := context.WithTimeout(ctx, detectionTimeout)
    defer cancel()

    // Apply detection rules
    ruleLock.RLock()
    rules := make([]DetectionRule, 0, len(detectionRules))
    for _, rule := range detectionRules {
        rules = append(rules, rule)
    }
    ruleLock.RUnlock()

    // Track detection results
    var (
        maxSeverity     float64
        detectionData   = make(map[string]interface{})
        threatDetected  bool
    )

    // Process each rule with timeout
    for _, rule := range rules {
        select {
        case <-detectionCtx.Done():
            return nil, errors.NewError("E4002", "detection timeout", map[string]interface{}{
                "timeout": detectionTimeout,
            })
        default:
            detected, severity, metadata := rule.Detect(event)
            if detected {
                threatDetected = true
                if severity > maxSeverity {
                    maxSeverity = severity
                }
                for k, v := range metadata {
                    detectionData[k] = v
                }
            }
        }
    }

    // If no threat detected, return nil
    if !threatDetected {
        metrics.Increment("events_no_threat", metricsTags)
        return nil, nil
    }

    // Create security context for alert
    securityCtx := &gold.SecurityMetadata{
        Classification:   "security_alert",
        ConfidenceScore: maxSeverity,
        ThreatLevel:     calculateThreatLevel(maxSeverity),
        DataSensitivity: "high",
        SecurityTags:    []string{"automated_detection"},
    }

    // Generate alert
    alert, err := gold.CreateAlert(&gold.GoldEvent{
        Severity:         securityCtx.ThreatLevel,
        IntelligenceData: detectionData,
        ComplianceInfo: gold.ComplianceMetadata{
            Standards:     []string{"SOC2", "ISO27001"},
            DataRetention: "90d",
            DataHandling:  "encrypted",
        },
    }, securityCtx)

    if err != nil {
        metrics.Increment("alert_creation_errors", metricsTags)
        return nil, errors.WrapError(err, "failed to create alert", nil)
    }

    metrics.Increment("threats_detected", metricsTags)
    return alert, nil
}

// BatchDetection processes multiple events for threat detection concurrently
// @metrics.RecordBatch
// @audit.LogBatch
func BatchDetection(ctx context.Context, events []*silver.SilverEvent) ([]*gold.Alert, []error) {
    if len(events) == 0 {
        return nil, nil
    }

    // Create worker pool for concurrent processing
    numWorkers := min(len(events), maxConcurrentDetections)
    jobs := make(chan *silver.SilverEvent, len(events))
    results := make(chan struct {
        alert *gold.Alert
        err   error
    }, len(events))

    // Start worker pool
    var wg sync.WaitGroup
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for event := range jobs {
                alert, err := DetectThreats(ctx, event)
                results <- struct {
                    alert *gold.Alert
                    err   error
                }{alert, err}
            }
        }()
    }

    // Send jobs to workers
    for _, event := range events {
        jobs <- event
    }
    close(jobs)

    // Wait for all workers to complete
    go func() {
        wg.Wait()
        close(results)
    }()

    // Collect results
    var (
        alerts []*gold.Alert
        errs   []error
    )

    for result := range results {
        if result.err != nil {
            errs = append(errs, result.err)
        } else if result.alert != nil {
            alerts = append(alerts, result.alert)
        }
    }

    return alerts, errs
}

// calculateThreatLevel converts a severity score to a threat level
func calculateThreatLevel(severity float64) string {
    switch {
    case severity >= 0.8:
        return "critical"
    case severity >= 0.6:
        return "high"
    case severity >= 0.4:
        return "medium"
    case severity >= 0.2:
        return "low"
    default:
        return "info"
    }
}

// min returns the minimum of two integers
func min(a, b int) int {
    if a < b {
        return a
    }
    return b
}