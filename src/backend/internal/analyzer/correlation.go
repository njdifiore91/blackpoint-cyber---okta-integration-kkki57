// Package analyzer implements security event correlation and analysis functionality
package analyzer

import (
    "context"
    "sync"
    "time"

    "github.com/blackpoint/pkg/gold"
    "github.com/blackpoint/pkg/silver"
    "github.com/blackpoint/internal/metrics"
    "github.com/blackpoint/pkg/common/errors"
)

const (
    // Default correlation window for event grouping
    defaultCorrelationWindow = 15 * time.Minute

    // Maximum events to process in a single correlation
    maxEventsPerCorrelation = 1000

    // Worker pool size for parallel correlation
    workerPoolSize = 4
)

// SecurityContext contains security-related metadata for correlation operations
type SecurityContext struct {
    ClientID       string
    Classification string
    DataSensitivity string
    ComplianceReqs []string
}

// CorrelationRule defines the interface for implementing correlation rules
type CorrelationRule interface {
    // Correlate applies the rule to a set of events and returns correlation results
    Correlate(events []*silver.SilverEvent, secCtx SecurityContext) (*gold.Alert, error)
    
    // Validate checks if the rule configuration is valid
    Validate() error
}

// EventCorrelator manages event correlation with enhanced security features
type EventCorrelator struct {
    rules           map[string]CorrelationRule
    correlationWindow time.Duration
    metrics         map[string]*metrics.KubernetesMetric
    securityContext SecurityContext
    mutex           sync.RWMutex
}

// NewEventCorrelator creates a new correlator instance with security context
func NewEventCorrelator(window time.Duration, secCtx SecurityContext) (*EventCorrelator, error) {
    if window <= 0 {
        window = defaultCorrelationWindow
    }

    // Initialize Kubernetes-aware metrics
    correlationMetrics := make(map[string]*metrics.KubernetesMetric)
    metricTypes := []string{"events_processed", "alerts_generated", "correlation_latency"}
    
    for _, mType := range metricTypes {
        metric, err := metrics.NewMetric(
            "correlation_"+mType,
            "counter",
            "Event correlation "+mType,
            []string{"client_id", "rule_id", "severity"},
        )
        if err != nil {
            return nil, errors.WrapError(err, "failed to create correlation metrics", nil)
        }
        correlationMetrics[mType] = metric.(*metrics.KubernetesMetric)
    }

    return &EventCorrelator{
        rules:            make(map[string]CorrelationRule),
        correlationWindow: window,
        metrics:          correlationMetrics,
        securityContext:  secCtx,
    }, nil
}

// RegisterRule adds a new correlation rule with validation
func (ec *EventCorrelator) RegisterRule(ruleID string, rule CorrelationRule) error {
    if err := rule.Validate(); err != nil {
        return errors.WrapError(err, "invalid correlation rule", map[string]interface{}{
            "rule_id": ruleID,
        })
    }

    ec.mutex.Lock()
    defer ec.mutex.Unlock()
    ec.rules[ruleID] = rule
    return nil
}

// CorrelateEvents processes security events and generates alerts
func (ec *EventCorrelator) CorrelateEvents(ctx context.Context, events []*silver.SilverEvent) ([]*gold.Alert, error) {
    if len(events) == 0 {
        return nil, nil
    }

    if len(events) > maxEventsPerCorrelation {
        return nil, errors.NewError("E3001", "event batch size exceeds limit", map[string]interface{}{
            "max_size": maxEventsPerCorrelation,
            "actual_size": len(events),
        })
    }

    // Group events by time window
    eventGroups := ec.groupEventsByWindow(events)

    // Create worker pool for parallel correlation
    type correlationResult struct {
        alerts []*gold.Alert
        err    error
    }

    resultChan := make(chan correlationResult, len(eventGroups))
    workerPool := make(chan struct{}, workerPoolSize)

    // Process event groups concurrently
    var wg sync.WaitGroup
    for _, group := range eventGroups {
        wg.Add(1)
        go func(events []*silver.SilverEvent) {
            defer wg.Done()
            workerPool <- struct{}{} // Acquire worker
            defer func() { <-workerPool }() // Release worker

            alerts, err := ec.correlateEventGroup(ctx, events)
            resultChan <- correlationResult{alerts: alerts, err: err}
        }(group)
    }

    // Wait for all correlations to complete
    go func() {
        wg.Wait()
        close(resultChan)
    }()

    // Collect results
    var alerts []*gold.Alert
    for result := range resultChan {
        if result.err != nil {
            return nil, result.err
        }
        alerts = append(alerts, result.alerts...)
    }

    // Update metrics
    ec.metrics["events_processed"].Inc(map[string]string{
        "client_id": ec.securityContext.ClientID,
    })
    ec.metrics["alerts_generated"].Add(float64(len(alerts)), map[string]string{
        "client_id": ec.securityContext.ClientID,
    })

    return alerts, nil
}

// correlateEventGroup applies correlation rules to a group of events
func (ec *EventCorrelator) correlateEventGroup(ctx context.Context, events []*silver.SilverEvent) ([]*gold.Alert, error) {
    var alerts []*gold.Alert

    ec.mutex.RLock()
    defer ec.mutex.RUnlock()

    for ruleID, rule := range ec.rules {
        select {
        case <-ctx.Done():
            return nil, errors.NewError("E4001", "correlation timeout", nil)
        default:
            alert, err := rule.Correlate(events, ec.securityContext)
            if err != nil {
                return nil, errors.WrapError(err, "rule correlation failed", map[string]interface{}{
                    "rule_id": ruleID,
                })
            }
            if alert != nil {
                alerts = append(alerts, alert)
                ec.metrics["correlation_latency"].Observe(time.Since(events[0].EventTime).Seconds(), map[string]string{
                    "rule_id": ruleID,
                    "severity": alert.Severity,
                })
            }
        }
    }

    return alerts, nil
}

// groupEventsByWindow groups events into time-based windows
func (ec *EventCorrelator) groupEventsByWindow(events []*silver.SilverEvent) [][]*silver.SilverEvent {
    if len(events) == 0 {
        return nil
    }

    var groups [][]*silver.SilverEvent
    currentGroup := []*silver.SilverEvent{events[0]}
    windowStart := events[0].EventTime

    for i := 1; i < len(events); i++ {
        if events[i].EventTime.Sub(windowStart) > ec.correlationWindow {
            groups = append(groups, currentGroup)
            currentGroup = []*silver.SilverEvent{events[i]}
            windowStart = events[i].EventTime
        } else {
            currentGroup = append(currentGroup, events[i])
        }
    }

    if len(currentGroup) > 0 {
        groups = append(groups, currentGroup)
    }

    return groups
}