package gold_test

import (
    "context"
    "testing"
    "time"

    "github.com/blackpoint/pkg/gold"
    "github.com/blackpoint/internal/analyzer"
    "github.com/blackpoint/test/pkg/fixtures"
    "k8s.io/metrics/pkg/client/clientset/versioned"
)

const (
    testTimeout = 30 * time.Second
    testBatchSize = 1000
    accuracyThreshold = 0.80
    securityValidationEnabled = true
    complianceCheckEnabled = true
    metricsCollectionInterval = 5 * time.Second
)

// intelligenceTestSuite encapsulates the test environment
type intelligenceTestSuite struct {
    engine           *analyzer.IntelligenceEngine
    ctx              context.Context
    cancel           context.CancelFunc
    metricsCollector *versioned.Clientset
    securityContext  map[string]interface{}
}

// newTestSuite creates and initializes a test suite
func newTestSuite(t *testing.T) *intelligenceTestSuite {
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    
    // Initialize security context for testing
    securityContext := map[string]interface{}{
        "classification": "test_data",
        "data_sensitivity": "high",
        "compliance_requirements": []string{"SOC2", "GDPR", "PCI"},
    }

    // Create correlator with test security context
    correlator, err := analyzer.NewEventCorrelator(15*time.Minute, analyzer.SecurityContext{
        ClientID: "test_client",
        Classification: "test",
        DataSensitivity: "high",
        ComplianceReqs: []string{"SOC2", "GDPR", "PCI"},
    })
    if err != nil {
        t.Fatalf("Failed to create correlator: %v", err)
    }

    // Initialize intelligence engine
    engine, err := analyzer.NewIntelligenceEngine(30*time.Minute, correlator)
    if err != nil {
        t.Fatalf("Failed to create intelligence engine: %v", err)
    }

    return &intelligenceTestSuite{
        engine:          engine,
        ctx:            ctx,
        cancel:         cancel,
        securityContext: securityContext,
    }
}

// cleanup performs test cleanup
func (s *intelligenceTestSuite) cleanup() {
    s.cancel()
}

// TestIntelligenceGeneration tests end-to-end intelligence generation
func TestIntelligenceGeneration(t *testing.T) {
    suite := newTestSuite(t)
    defer suite.cleanup()

    // Generate test alerts with security context
    alerts, err := fixtures.GenerateTestGoldAlertBatch(testBatchSize, suite.securityContext)
    if err != nil {
        t.Fatalf("Failed to generate test alerts: %v", err)
    }

    // Process alerts through intelligence engine
    intelligence, err := suite.engine.GenerateIntelligence(suite.ctx, alerts)
    if err != nil {
        t.Fatalf("Intelligence generation failed: %v", err)
    }

    // Validate intelligence data
    if intelligence == nil {
        t.Fatal("No intelligence generated")
    }

    // Verify security context preservation
    if intelligence["security_context"] == nil {
        t.Error("Security context not preserved in intelligence data")
    }

    // Validate compliance requirements
    complianceStatus, ok := intelligence["compliance_status"].(map[string]interface{})
    if !ok {
        t.Error("Missing compliance status in intelligence data")
    }

    for _, standard := range []string{"SOC2", "GDPR", "PCI"} {
        if status, exists := complianceStatus[standard]; !exists {
            t.Errorf("Missing compliance status for %s", standard)
        } else {
            statusMap, ok := status.(map[string]interface{})
            if !ok || statusMap["status"] != "compliant" {
                t.Errorf("Invalid compliance status for %s", standard)
            }
        }
    }

    // Verify accuracy metrics
    if accuracy, ok := intelligence["accuracy"].(float64); !ok || accuracy < accuracyThreshold {
        t.Errorf("Accuracy below threshold: got %.2f, want >= %.2f", accuracy, accuracyThreshold)
    }
}

// TestIntelligenceRuleRegistration tests rule registration and validation
func TestIntelligenceRuleRegistration(t *testing.T) {
    suite := newTestSuite(t)
    defer suite.cleanup()

    // Test valid rule registration
    testRule := &struct {
        analyzer.IntelligenceRule
        ruleID string
    }{
        ruleID: "test_rule",
    }

    err := analyzer.RegisterIntelligenceRule(testRule.ruleID, testRule)
    if err != nil {
        t.Errorf("Failed to register valid rule: %v", err)
    }

    // Test invalid rule registration
    err = analyzer.RegisterIntelligenceRule("", nil)
    if err == nil {
        t.Error("Expected error for invalid rule registration")
    }

    // Test duplicate rule registration
    err = analyzer.RegisterIntelligenceRule(testRule.ruleID, testRule)
    if err == nil {
        t.Error("Expected error for duplicate rule registration")
    }

    // Verify security validation
    alerts, _ := fixtures.GenerateTestGoldAlertBatch(1, suite.securityContext)
    intelligence, err := suite.engine.GenerateIntelligence(suite.ctx, alerts)
    if err != nil {
        t.Fatalf("Failed to generate intelligence: %v", err)
    }

    if _, ok := intelligence[testRule.ruleID]; !ok {
        t.Error("Registered rule not applied in intelligence generation")
    }
}

// TestConcurrentIntelligenceProcessing tests concurrent processing capabilities
func TestConcurrentIntelligenceProcessing(t *testing.T) {
    suite := newTestSuite(t)
    defer suite.cleanup()

    // Generate multiple alert batches with different security contexts
    batchCount := 5
    alertBatches := make([][]*gold.Alert, batchCount)
    results := make(chan map[string]interface{}, batchCount)
    errors := make(chan error, batchCount)

    for i := 0; i < batchCount; i++ {
        securityContext := map[string]interface{}{
            "batch_id": i,
            "classification": "test_data",
            "data_sensitivity": "high",
        }
        alerts, err := fixtures.GenerateTestGoldAlertBatch(testBatchSize/batchCount, securityContext)
        if err != nil {
            t.Fatalf("Failed to generate alert batch %d: %v", i, err)
        }
        alertBatches[i] = alerts
    }

    // Process batches concurrently
    for i := 0; i < batchCount; i++ {
        go func(batch []*gold.Alert) {
            intelligence, err := suite.engine.GenerateIntelligence(suite.ctx, batch)
            if err != nil {
                errors <- err
                return
            }
            results <- intelligence
        }(alertBatches[i])
    }

    // Collect and validate results
    for i := 0; i < batchCount; i++ {
        select {
        case err := <-errors:
            t.Errorf("Batch processing error: %v", err)
        case intelligence := <-results:
            // Verify security context isolation
            if intelligence["security_context"] == nil {
                t.Error("Missing security context in concurrent processing")
            }
            // Verify compliance validation
            if intelligence["compliance_status"] == nil {
                t.Error("Missing compliance status in concurrent processing")
            }
        case <-time.After(testTimeout):
            t.Error("Timeout waiting for batch processing")
        }
    }
}