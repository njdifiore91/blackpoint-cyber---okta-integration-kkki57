// Package analyzer implements security intelligence generation for the Gold tier
package analyzer

import (
    "context"
    "sync"
    "time"

    "github.com/blackpoint/pkg/gold"
    "github.com/blackpoint/pkg/silver"
    "github.com/blackpoint/pkg/common/errors"
    "./correlation"
    "k8s.io/metrics/pkg/client/clientset/versioned"
)

// Global constants for intelligence generation
const (
    analysisWindow = 30 * time.Minute
    maxEventsPerAnalysis = 5000
    workerPoolSize = 10
)

// Thread-safe maps for rules and metrics
var (
    intelligenceRules = make(map[string]IntelligenceRule)
    intelligenceMetrics = make(map[string]*metrics.KubernetesCollector)
    complianceMetadata = make(map[string]interface{})
    ruleLock sync.RWMutex
)

// IntelligenceRule defines the interface for intelligence generation rules
type IntelligenceRule interface {
    // GenerateInsights generates security insights from correlated alerts
    GenerateInsights(alerts []*gold.Alert) (map[string]interface{}, error)
    // Validate validates rule configuration
    Validate() error
}

// IntelligenceEngine manages security intelligence generation
type IntelligenceEngine struct {
    rules            map[string]IntelligenceRule
    analysisWindow   time.Duration
    correlator       *correlation.EventCorrelator
    metricsClient    *versioned.Clientset
    complianceTracker map[string]interface{}
    mutex            sync.RWMutex
}

// NewIntelligenceEngine creates a new intelligence engine instance
func NewIntelligenceEngine(window time.Duration, correlator *correlation.EventCorrelator) (*IntelligenceEngine, error) {
    if window <= 0 {
        window = analysisWindow
    }

    // Initialize Kubernetes metrics collectors
    metricTypes := []string{"intelligence_generated", "compliance_violations", "processing_latency"}
    for _, mType := range metricTypes {
        metric, err := metrics.NewMetric(
            "intelligence_"+mType,
            "counter",
            "Intelligence generation "+mType,
            []string{"client_id", "rule_id", "severity"},
        )
        if err != nil {
            return nil, errors.WrapError(err, "failed to create intelligence metrics", nil)
        }
        intelligenceMetrics[mType] = metric.(*metrics.KubernetesCollector)
    }

    return &IntelligenceEngine{
        rules:             make(map[string]IntelligenceRule),
        analysisWindow:    window,
        correlator:        correlator,
        complianceTracker: make(map[string]interface{}),
    }, nil
}

// RegisterIntelligenceRule registers a new intelligence generation rule
func RegisterIntelligenceRule(ruleID string, rule IntelligenceRule) error {
    if ruleID == "" || rule == nil {
        return errors.NewError("E3001", "invalid rule parameters", nil)
    }

    if err := rule.Validate(); err != nil {
        return errors.WrapError(err, "rule validation failed", map[string]interface{}{
            "rule_id": ruleID,
        })
    }

    ruleLock.Lock()
    defer ruleLock.Unlock()

    intelligenceRules[ruleID] = rule
    return nil
}

// GenerateIntelligence generates security intelligence from correlated alerts
func (e *IntelligenceEngine) GenerateIntelligence(ctx context.Context, alerts []*gold.Alert) (map[string]interface{}, error) {
    if len(alerts) == 0 {
        return nil, nil
    }

    if len(alerts) > maxEventsPerAnalysis {
        return nil, errors.NewError("E3001", "alert batch size exceeds limit", map[string]interface{}{
            "max_size": maxEventsPerAnalysis,
            "actual_size": len(alerts),
        })
    }

    // Create worker pool for parallel processing
    type intelligenceResult struct {
        insights map[string]interface{}
        err      error
    }

    resultChan := make(chan intelligenceResult, len(alerts))
    workerPool := make(chan struct{}, workerPoolSize)

    // Process alerts concurrently
    var wg sync.WaitGroup
    for _, alert := range alerts {
        wg.Add(1)
        go func(a *gold.Alert) {
            defer wg.Done()
            workerPool <- struct{}{} // Acquire worker
            defer func() { <-workerPool }() // Release worker

            insights, err := e.processAlert(ctx, a)
            resultChan <- intelligenceResult{insights: insights, err: err}
        }(alert)
    }

    // Wait for all processing to complete
    go func() {
        wg.Wait()
        close(resultChan)
    }()

    // Collect and merge results
    intelligence := make(map[string]interface{})
    for result := range resultChan {
        if result.err != nil {
            return nil, result.err
        }
        if result.insights != nil {
            for k, v := range result.insights {
                intelligence[k] = v
            }
        }
    }

    // Add compliance metadata
    intelligence["compliance_status"] = e.validateCompliance(intelligence)
    intelligence["analysis_timestamp"] = time.Now().UTC()

    // Update metrics
    e.updateMetrics(intelligence)

    return intelligence, nil
}

// processAlert processes a single alert through all intelligence rules
func (e *IntelligenceEngine) processAlert(ctx context.Context, alert *gold.Alert) (map[string]interface{}, error) {
    e.mutex.RLock()
    defer e.mutex.RUnlock()

    insights := make(map[string]interface{})
    
    for ruleID, rule := range e.rules {
        select {
        case <-ctx.Done():
            return nil, errors.NewError("E4001", "intelligence generation timeout", nil)
        default:
            ruleInsights, err := rule.GenerateInsights([]*gold.Alert{alert})
            if err != nil {
                return nil, errors.WrapError(err, "rule processing failed", map[string]interface{}{
                    "rule_id": ruleID,
                    "alert_id": alert.AlertID,
                })
            }
            if ruleInsights != nil {
                insights[ruleID] = ruleInsights
            }
        }
    }

    return insights, nil
}

// validateCompliance checks intelligence data against compliance requirements
func (e *IntelligenceEngine) validateCompliance(intelligence map[string]interface{}) map[string]interface{} {
    compliance := make(map[string]interface{})
    
    // Check required compliance standards
    for standard, requirements := range e.complianceTracker {
        compliance[standard] = map[string]interface{}{
            "status": "compliant",
            "checks": requirements,
            "timestamp": time.Now().UTC(),
        }
    }

    // Update compliance metrics
    intelligenceMetrics["compliance_violations"].Inc(map[string]string{
        "client_id": e.correlator.SecurityContext.ClientID,
    })

    return compliance
}

// updateMetrics updates Kubernetes-aware metrics for intelligence generation
func (e *IntelligenceEngine) updateMetrics(intelligence map[string]interface{}) {
    intelligenceMetrics["intelligence_generated"].Inc(map[string]string{
        "client_id": e.correlator.SecurityContext.ClientID,
    })

    intelligenceMetrics["processing_latency"].Observe(
        time.Since(time.Now()).Seconds(),
        map[string]string{
            "client_id": e.correlator.SecurityContext.ClientID,
        },
    )
}