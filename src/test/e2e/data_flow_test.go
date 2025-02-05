// Package e2e provides end-to-end testing for the BlackPoint Security Integration Framework
package e2e

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/require"
    "go.uber.org/zap"

    "../../internal/framework"
    "../../pkg/validation"
    "../../pkg/common"
    "../../pkg/fixtures"
)

// Global test configuration
var testConfig = struct {
    EventCount        int
    ConcurrentClients int
    ValidationThresholds struct {
        Accuracy     float64
        Performance  float64
        Security     float64
    }
    SecurityContext struct {
        Classification    string
        Sensitivity      string
        ComplianceReqs   []string
        EncryptionLevel  string
        AuditLevel       string
    }
}{
    EventCount:        10000,
    ConcurrentClients: 10,
    ValidationThresholds: struct {
        Accuracy     float64
        Performance  float64
        Security     float64
    }{
        Accuracy:    0.80, // 80% minimum accuracy requirement
        Performance: 0.95, // 95% success rate requirement
        Security:    0.90, // 90% security validation requirement
    },
    SecurityContext: struct {
        Classification    string
        Sensitivity      string
        ComplianceReqs   []string
        EncryptionLevel  string
        AuditLevel       string
    }{
        Classification:  "CONFIDENTIAL",
        Sensitivity:     "HIGH",
        ComplianceReqs:  []string{"SOC2", "ISO27001"},
        EncryptionLevel: "AES256",
        AuditLevel:      "DETAILED",
    },
}

// TestDataFlowE2E validates the complete data flow through all tiers
func TestDataFlowE2E(t *testing.T) {
    // Initialize test logger
    logger := common.InitTestLogger(t)
    defer logger.Sync()

    // Create test suite with security context
    suite := framework.NewTestSuite(t, "DataFlowE2E", &framework.TestSuiteConfig{
        Timeout:         30 * time.Minute,
        SecurityEnabled: true,
        MonitoringEnabled: true,
        ValidationConfig: map[string]float64{
            "accuracy":     testConfig.ValidationThresholds.Accuracy,
            "performance": testConfig.ValidationThresholds.Performance,
            "security":    testConfig.ValidationThresholds.Security,
        },
    })

    // Set up test environment
    cleanup := common.SetupTestEnvironment(t, "data-flow-e2e")
    defer cleanup()

    // Create test context
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
    defer cancel()

    // Test Bronze tier processing
    t.Run("BronzeTierProcessing", func(t *testing.T) {
        err := testBronzeTierProcessing(ctx, t)
        require.NoError(t, err, "Bronze tier processing failed")
    })

    // Test Silver tier processing
    t.Run("SilverTierProcessing", func(t *testing.T) {
        err := testSilverTierProcessing(ctx, t)
        require.NoError(t, err, "Silver tier processing failed")
    })

    // Test Gold tier processing
    t.Run("GoldTierProcessing", func(t *testing.T) {
        err := testGoldTierProcessing(ctx, t)
        require.NoError(t, err, "Gold tier processing failed")
    })

    // Run test suite
    err := suite.Run()
    require.NoError(t, err, "Test suite execution failed")
}

// testBronzeTierProcessing validates Bronze tier event processing
func testBronzeTierProcessing(ctx context.Context, t *testing.T) error {
    startTime := time.Now()

    // Generate test events
    events, metrics, err := fixtures.GenerateBronzeEventBatch(testConfig.EventCount, &fixtures.BatchOptions{
        Concurrent:      true,
        WorkerCount:     testConfig.ConcurrentClients,
        SecurityContext: &testConfig.SecurityContext,
    })
    require.NoError(t, err, "Failed to generate Bronze events")

    // Validate events
    validator := validation.NewEventValidator(t, &validation.SecurityContext{
        Classification:   testConfig.SecurityContext.Classification,
        Sensitivity:     testConfig.SecurityContext.Sensitivity,
        ComplianceReqs:  testConfig.SecurityContext.ComplianceReqs,
        EncryptionLevel: testConfig.SecurityContext.EncryptionLevel,
        AuditLevel:      testConfig.SecurityContext.AuditLevel,
    })

    for _, event := range events {
        err := validator.ValidateEventProcessing(t, event, &testConfig.SecurityContext)
        require.NoError(t, err, "Bronze event validation failed")
    }

    // Validate processing latency
    processingTime := time.Since(startTime)
    err = validation.ValidateEventLatency(t, "bronze", processingTime, &validation.SecurityMetrics{
        ProcessingTime:   processingTime,
        SecurityOverhead: metrics.GenerationTime / 10, // Estimated security overhead
    })
    require.NoError(t, err, "Bronze tier latency validation failed")

    // Validate throughput
    eventsPerSecond := float64(len(events)) / processingTime.Seconds()
    require.GreaterOrEqual(t, eventsPerSecond, float64(1000), 
        "Bronze tier throughput below requirement: got %.2f, want >= 1000", eventsPerSecond)

    return nil
}

// testSilverTierProcessing validates Silver tier event processing
func testSilverTierProcessing(ctx context.Context, t *testing.T) error {
    startTime := time.Now()

    // Generate and process Silver events
    bronzeEvents, _, err := fixtures.GenerateBronzeEventBatch(testConfig.EventCount, &fixtures.BatchOptions{
        Concurrent:      true,
        WorkerCount:     testConfig.ConcurrentClients,
        SecurityContext: &testConfig.SecurityContext,
    })
    require.NoError(t, err, "Failed to generate Bronze events for Silver processing")

    // Validate Silver tier processing
    validator := validation.NewEventValidator(t, &validation.SecurityContext{
        Classification:   testConfig.SecurityContext.Classification,
        Sensitivity:     testConfig.SecurityContext.Sensitivity,
        ComplianceReqs:  testConfig.SecurityContext.ComplianceReqs,
        EncryptionLevel: testConfig.SecurityContext.EncryptionLevel,
        AuditLevel:      testConfig.SecurityContext.AuditLevel,
    })

    for _, bronzeEvent := range bronzeEvents {
        // Validate event normalization
        err := validator.ValidateEventProcessing(t, bronzeEvent, &testConfig.SecurityContext)
        require.NoError(t, err, "Silver event normalization failed")

        // Validate schema transformation
        schemaValidator := validation.NewSchemaValidator(t)
        require.True(t, schemaValidator.ValidateSchemaTransformation(bronzeEvent, nil, "silver"),
            "Silver schema transformation validation failed")
    }

    // Validate processing latency
    processingTime := time.Since(startTime)
    err = validation.ValidateEventLatency(t, "silver", processingTime, &validation.SecurityMetrics{
        ProcessingTime:   processingTime,
        SecurityOverhead: processingTime / 5, // Estimated security overhead
    })
    require.NoError(t, err, "Silver tier latency validation failed")

    return nil
}

// testGoldTierProcessing validates Gold tier event processing
func testGoldTierProcessing(ctx context.Context, t *testing.T) error {
    startTime := time.Now()

    // Generate test events through Silver tier
    bronzeEvents, _, err := fixtures.GenerateBronzeEventBatch(testConfig.EventCount, &fixtures.BatchOptions{
        Concurrent:      true,
        WorkerCount:     testConfig.ConcurrentClients,
        SecurityContext: &testConfig.SecurityContext,
    })
    require.NoError(t, err, "Failed to generate events for Gold processing")

    // Validate Gold tier processing
    validator := validation.NewEventValidator(t, &validation.SecurityContext{
        Classification:   testConfig.SecurityContext.Classification,
        Sensitivity:     testConfig.SecurityContext.Sensitivity,
        ComplianceReqs:  testConfig.SecurityContext.ComplianceReqs,
        EncryptionLevel: testConfig.SecurityContext.EncryptionLevel,
        AuditLevel:      testConfig.SecurityContext.AuditLevel,
    })

    for _, bronzeEvent := range bronzeEvents {
        // Validate security intelligence generation
        err := validator.ValidateEventProcessing(t, bronzeEvent, &testConfig.SecurityContext)
        require.NoError(t, err, "Gold event processing failed")

        // Validate schema transformation
        schemaValidator := validation.NewSchemaValidator(t)
        require.True(t, schemaValidator.ValidateSchemaTransformation(bronzeEvent, nil, "gold"),
            "Gold schema transformation validation failed")
    }

    // Validate processing latency
    processingTime := time.Since(startTime)
    err = validation.ValidateEventLatency(t, "gold", processingTime, &validation.SecurityMetrics{
        ProcessingTime:   processingTime,
        SecurityOverhead: processingTime / 3, // Estimated security overhead
    })
    require.NoError(t, err, "Gold tier latency validation failed")

    return nil
}