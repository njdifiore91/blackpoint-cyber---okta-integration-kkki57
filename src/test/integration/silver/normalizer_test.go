// Package silver provides integration tests for the Silver tier normalizer service
package silver

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"

    "../../internal/framework"
    "../../../backend/pkg/bronze/schema"
    "../../../backend/pkg/silver/schema"
    "../../../backend/internal/normalizer"
    "../../pkg/fixtures"
    "../../pkg/metrics"
)

const (
    testTimeout = 5 * time.Minute
    batchSize   = 1000
    minAccuracyThreshold = 0.80
    maxProcessingTime    = 5 * time.Second
    securityValidationTimeout = 30 * time.Second
    maxConcurrentProcessors = 10
    retryAttempts = 3
)

// TestNormalizerIntegration is the main test function for normalizer integration tests
func TestNormalizerIntegration(t *testing.T) {
    // Create test suite with security context
    suite := framework.NewTestSuite(t, "silver-normalizer", &framework.TestSuiteConfig{
        Timeout: testTimeout,
        SecurityEnabled: true,
        MonitoringEnabled: true,
        ValidationConfig: map[string]float64{
            "accuracy":     minAccuracyThreshold,
            "performance": 0.95,
            "security":    0.90,
        },
    })
    require.NotNil(t, suite)

    // Configure security context
    securityCtx := &framework.SecurityContext{
        Level:      "high",
        Compliance: []string{"SOC2", "ISO27001"},
        AuditRequirements: map[string]string{
            "log_level": "debug",
            "retention": "90d",
        },
    }

    // Add test cases
    suite.AddTestCase(framework.NewTestCase(t, "single-event-processing", &framework.TestConfig{
        Timeout: maxProcessingTime,
        SecurityContext: securityCtx,
    }))

    suite.AddTestCase(framework.NewTestCase(t, "batch-event-processing", &framework.TestConfig{
        Timeout: testTimeout,
        SecurityContext: securityCtx,
    }))

    suite.AddTestCase(framework.NewTestCase(t, "error-handling", &framework.TestConfig{
        Timeout: maxProcessingTime,
        SecurityContext: securityCtx,
    }))

    // Run test suite
    err := suite.Run()
    require.NoError(t, err)
}

// testSingleEventProcessing tests processing of a single event through the normalizer
func testSingleEventProcessing(ctx context.Context, t *testing.T) error {
    // Generate secure test event
    bronzeEvent, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
        SecurityLevel: "high",
        AuditLevel:   "detailed",
    })
    require.NoError(t, err)
    require.NotNil(t, bronzeEvent)

    // Initialize normalizer components
    mapper := normalizer.NewFieldMapper(nil, nil)
    transformer := normalizer.NewTransformer(maxProcessingTime)
    processor, err := normalizer.NewProcessor(mapper, transformer, maxProcessingTime)
    require.NoError(t, err)

    // Process event with security validation
    startTime := time.Now()
    silverEvent, err := processor.ProcessSingle(ctx, bronzeEvent)
    processingTime := time.Since(startTime)

    // Validate processing time
    assert.Less(t, processingTime, maxProcessingTime)

    // Validate event transformation
    require.NoError(t, err)
    require.NotNil(t, silverEvent)
    assert.Equal(t, bronzeEvent.ClientID, silverEvent.ClientID)
    assert.Equal(t, bronzeEvent.ID, silverEvent.BronzeEventID)

    // Validate security compliance
    err = silverEvent.ValidateEncryption()
    require.NoError(t, err)

    // Validate schema compliance
    err = silverEvent.Validate()
    require.NoError(t, err)

    return nil
}

// testBatchEventProcessing tests batch processing of multiple events
func testBatchEventProcessing(ctx context.Context, t *testing.T) error {
    // Generate batch of test events
    bronzeEvents, metrics, err := fixtures.GenerateBronzeEventBatch(batchSize, &fixtures.BatchOptions{
        Concurrent: true,
        WorkerCount: maxConcurrentProcessors,
        SecurityContext: &fixtures.SecurityContext{
            Level: "high",
            Compliance: []string{"SOC2", "ISO27001"},
        },
    })
    require.NoError(t, err)
    require.NotNil(t, bronzeEvents)
    require.NotNil(t, metrics)

    // Initialize normalizer components
    mapper := normalizer.NewFieldMapper(nil, nil)
    transformer := normalizer.NewTransformer(maxProcessingTime)
    processor, err := normalizer.NewProcessor(mapper, transformer, maxProcessingTime)
    require.NoError(t, err)

    // Process batch with monitoring
    startTime := time.Now()
    silverEvents, err := processor.Process(ctx, bronzeEvents)
    processingTime := time.Since(startTime)

    // Validate batch processing
    require.NoError(t, err)
    require.NotNil(t, silverEvents)
    assert.Equal(t, len(bronzeEvents), len(silverEvents))

    // Calculate processing metrics
    eventsPerSecond := float64(len(silverEvents)) / processingTime.Seconds()
    assert.GreaterOrEqual(t, eventsPerSecond, float64(1000), "Processing throughput below requirement")

    // Validate accuracy
    accuracyMetrics, err := metrics.CalculateAccuracy(silverEvents, bronzeEvents)
    require.NoError(t, err)
    assert.GreaterOrEqual(t, accuracyMetrics["average_accuracy"], minAccuracyThreshold)

    // Validate security compliance for all events
    for _, event := range silverEvents {
        err = event.ValidateEncryption()
        require.NoError(t, err)
        err = event.Validate()
        require.NoError(t, err)
    }

    return nil
}

// testErrorHandling tests error handling and recovery scenarios
func testErrorHandling(ctx context.Context, t *testing.T) error {
    // Generate invalid test events
    invalidEvent, err := fixtures.GenerateInvalidBronzeEvent("security_violation", &fixtures.SecurityContext{
        Level: "high",
        Violations: []string{"oversized_payload", "invalid_schema"},
    })
    require.NoError(t, err)
    require.NotNil(t, invalidEvent)

    // Initialize normalizer components
    mapper := normalizer.NewFieldMapper(nil, nil)
    transformer := normalizer.NewTransformer(maxProcessingTime)
    processor, err := normalizer.NewProcessor(mapper, transformer, maxProcessingTime)
    require.NoError(t, err)

    // Test processing of invalid event
    _, err = processor.ProcessSingle(ctx, invalidEvent)
    require.Error(t, err)
    assert.Contains(t, err.Error(), "security validation failed")

    // Test retry mechanism
    validEvent, err := fixtures.GenerateValidBronzeEvent(nil)
    require.NoError(t, err)

    // Simulate intermittent failure
    for i := 0; i < retryAttempts; i++ {
        _, err = processor.ProcessSingle(ctx, validEvent)
        if err == nil {
            break
        }
    }
    require.NoError(t, err)

    return nil
}