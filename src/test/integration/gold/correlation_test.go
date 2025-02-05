// Package gold provides integration tests for Gold tier event correlation functionality
package gold

import (
    "context"
    "testing"
    "time"

    "github.com/blackpoint/internal/analyzer/correlation"
    "github.com/blackpoint/pkg/gold"
    "github.com/blackpoint/test/pkg/fixtures"
    "github.com/stretchr/testify/assert"
)

const (
    testCorrelationTimeout = 30 * time.Second
)

// testCorrelationRule implements a mock correlation rule for testing
type testCorrelationRule struct {
    ruleID          string
    description     string
    config          map[string]interface{}
    securityContext *correlation.SecurityContext
}

func (r *testCorrelationRule) Correlate(events []*silver.SilverEvent) (*gold.Alert, error) {
    if len(events) < 2 {
        return nil, nil // Not enough events for correlation
    }

    // Test correlation logic
    matchingEvents := make([]*silver.SilverEvent, 0)
    for _, event := range events {
        if event.SecurityContext.Classification == r.securityContext.Classification {
            matchingEvents = append(matchingEvents, event)
        }
    }

    if len(matchingEvents) >= 2 {
        // Create correlated alert
        alert, err := gold.CreateAlert(&gold.GoldEvent{
            Severity: "high",
            IntelligenceData: map[string]interface{}{
                "correlation_rule": r.ruleID,
                "matched_events":  len(matchingEvents),
                "pattern":        "security_sequence",
            },
        }, r.securityContext)
        
        if err != nil {
            return nil, err
        }

        return alert, nil
    }

    return nil, nil
}

func (r *testCorrelationRule) Validate() error {
    if r.ruleID == "" || r.description == "" {
        return errors.New("invalid rule configuration")
    }
    return nil
}

// TestCorrelateEvents tests the event correlation functionality with security context
func TestCorrelateEvents(t *testing.T) {
    // Create test context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), testCorrelationTimeout)
    defer cancel()

    // Initialize security context
    secCtx := correlation.SecurityContext{
        ClientID:        "test-client",
        Classification: "high",
        DataSensitivity: "sensitive",
        ComplianceReqs: []string{"PCI-DSS", "SOC2"},
    }

    // Create event correlator
    correlator, err := correlation.NewEventCorrelator(5*time.Minute, secCtx)
    assert.NoError(t, err)
    assert.NotNil(t, correlator)

    // Register test correlation rule
    rule := &testCorrelationRule{
        ruleID:          "TEST-001",
        description:     "Test correlation rule",
        securityContext: &secCtx,
        config: map[string]interface{}{
            "min_events": 2,
            "time_window": "5m",
        },
    }
    err = correlator.RegisterRule("TEST-001", rule)
    assert.NoError(t, err)

    // Generate test events
    events := make([]*silver.SilverEvent, 0)
    for i := 0; i < 3; i++ {
        event, err := fixtures.NewTestSilverEventWithSecurity("security", "high")
        assert.NoError(t, err)
        events = append(events, event)
    }

    // Test correlation
    alerts, err := correlator.CorrelateEvents(ctx, events)
    assert.NoError(t, err)
    assert.NotEmpty(t, alerts)

    // Validate generated alert
    alert := alerts[0]
    assert.Equal(t, "high", alert.Severity)
    assert.Contains(t, alert.IntelligenceData, "correlation_rule")
    assert.Contains(t, alert.ComplianceTags, "PCI-DSS")
}

// TestCorrelationRuleRegistration tests the registration of correlation rules
func TestCorrelationRuleRegistration(t *testing.T) {
    // Initialize security context
    secCtx := correlation.SecurityContext{
        ClientID:        "test-client",
        Classification: "high",
        DataSensitivity: "sensitive",
        ComplianceReqs: []string{"PCI-DSS"},
    }

    // Create correlator
    correlator, err := correlation.NewEventCorrelator(5*time.Minute, secCtx)
    assert.NoError(t, err)

    // Test valid rule registration
    validRule := &testCorrelationRule{
        ruleID:          "TEST-002",
        description:     "Valid test rule",
        securityContext: &secCtx,
        config: map[string]interface{}{
            "pattern": "sequence",
            "severity": "high",
        },
    }
    err = correlator.RegisterRule("TEST-002", validRule)
    assert.NoError(t, err)

    // Test invalid rule registration
    invalidRule := &testCorrelationRule{
        ruleID:      "", // Invalid - empty ID
        description: "Invalid test rule",
    }
    err = correlator.RegisterRule("TEST-003", invalidRule)
    assert.Error(t, err)
}

// TestCorrelationWindowProcessing tests correlation processing within time windows
func TestCorrelationWindowProcessing(t *testing.T) {
    // Initialize security context
    secCtx := correlation.SecurityContext{
        ClientID:        "test-client",
        Classification: "high",
        DataSensitivity: "sensitive",
        ComplianceReqs: []string{"SOC2"},
    }

    // Create correlator with 1-minute window
    correlator, err := correlation.NewEventCorrelator(1*time.Minute, secCtx)
    assert.NoError(t, err)

    // Register time-based rule
    rule := &testCorrelationRule{
        ruleID:          "TEST-004",
        description:     "Time window test rule",
        securityContext: &secCtx,
        config: map[string]interface{}{
            "window": "1m",
            "min_events": 2,
        },
    }
    err = correlator.RegisterRule("TEST-004", rule)
    assert.NoError(t, err)

    // Generate events with different timestamps
    events := make([]*silver.SilverEvent, 0)
    baseTime := time.Now()
    
    // Events within window
    for i := 0; i < 2; i++ {
        event, err := fixtures.NewTestSilverEventWithSecurity("security", "high")
        assert.NoError(t, err)
        event.EventTime = baseTime.Add(time.Duration(i*10) * time.Second)
        events = append(events, event)
    }

    // Event outside window
    outsideEvent, err := fixtures.NewTestSilverEventWithSecurity("security", "high")
    assert.NoError(t, err)
    outsideEvent.EventTime = baseTime.Add(2 * time.Minute)
    events = append(events, outsideEvent)

    // Test correlation
    ctx := context.Background()
    alerts, err := correlator.CorrelateEvents(ctx, events)
    assert.NoError(t, err)
    assert.NotEmpty(t, alerts)

    // Verify only events within window were correlated
    alert := alerts[0]
    assert.Equal(t, 2, alert.IntelligenceData["matched_events"])
}

// validateSecurityContext validates security context and compliance requirements
func validateSecurityContext(t *testing.T, ctx *correlation.SecurityContext) error {
    assert.NotEmpty(t, ctx.ClientID)
    assert.NotEmpty(t, ctx.Classification)
    assert.NotEmpty(t, ctx.DataSensitivity)
    assert.NotEmpty(t, ctx.ComplianceReqs)

    // Validate classification level
    validClassifications := []string{"low", "medium", "high", "critical"}
    assert.Contains(t, validClassifications, ctx.Classification)

    // Validate compliance requirements
    for _, req := range ctx.ComplianceReqs {
        assert.NotEmpty(t, req)
    }

    return nil
}