// Package integration provides integration tests for the BlackPoint Security Integration Framework
package integration

import (
    "context"
    "sync"
    "testing"
    "time"

    "github.com/blackpoint/pkg/bronze"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/internal/collector/validation"
    "github.com/blackpoint/test/pkg/fixtures"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

const (
    // Test configuration constants
    testTimeout          = 30 * time.Second
    testBatchSize       = 1000
    maxLatencyThreshold = time.Second
    minThroughputRate   = 1000.0 // events/second
)

// CollectorTestSuite provides a test suite for collector integration tests
type CollectorTestSuite struct {
    ctx             context.Context
    cancel          context.CancelFunc
    processor       *bronze.EventProcessor
    securityContext *bronze.SecurityContext
    metrics         struct {
        processingTimes []time.Duration
        eventCounts    int
        errorCounts    int
        mutex         sync.Mutex
    }
}

// setupTestSuite initializes the test suite with security context
func setupTestSuite(t *testing.T) *CollectorTestSuite {
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    
    // Initialize security context for testing
    securityCtx := &bronze.SecurityContext{
        ProcessorID: "test-processor",
        SecurityLevel: "enhanced",
        AuditEnabled: true,
    }

    // Create event processor with security configuration
    processor, err := bronze.NewEventProcessor(maxLatencyThreshold, testBatchSize, securityCtx)
    require.NoError(t, err, "Failed to create event processor")

    return &CollectorTestSuite{
        ctx:             ctx,
        cancel:          cancel,
        processor:       processor,
        securityContext: securityCtx,
    }
}

// TestMain handles test suite setup and teardown
func TestMain(m *testing.M) {
    // Global test setup
    if err := setupTestEnvironment(); err != nil {
        panic(err)
    }

    // Run tests
    code := m.Run()

    // Global test cleanup
    cleanupTestEnvironment()

    os.Exit(code)
}

// TestSingleEventProcessing tests individual event processing with security validation
func TestSingleEventProcessing(t *testing.T) {
    suite := setupTestSuite(t)
    defer suite.cancel()

    // Generate valid test event
    event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
        SecurityLevel: "enhanced",
        AuditLevel:   "detailed",
    })
    require.NoError(t, err, "Failed to generate test event")

    // Test event processing with timing
    startTime := time.Now()
    err = suite.processor.ProcessEvent(event, suite.securityContext)
    processingTime := time.Since(startTime)

    // Verify processing success and latency
    assert.NoError(t, err, "Event processing failed")
    assert.Less(t, processingTime, maxLatencyThreshold, 
        "Processing time exceeded threshold: %v", processingTime)

    // Verify event validation
    err = validation.ValidateEvent(suite.ctx, event)
    assert.NoError(t, err, "Event validation failed")

    // Verify security compliance
    err = validation.ValidateSecurityCompliance(event)
    assert.NoError(t, err, "Security compliance validation failed")
}

// TestBatchEventProcessing tests concurrent batch processing with performance monitoring
func TestBatchEventProcessing(t *testing.T) {
    suite := setupTestSuite(t)
    defer suite.cancel()

    // Generate batch of test events
    events, metrics, err := fixtures.GenerateBronzeEventBatch(testBatchSize, &fixtures.BatchOptions{
        Concurrent:      true,
        WorkerCount:     4,
        SecurityContext: suite.securityContext,
    })
    require.NoError(t, err, "Failed to generate event batch")
    require.Len(t, events, testBatchSize, "Incorrect batch size generated")

    // Process batch with timing
    startTime := time.Now()
    errors := suite.processor.BatchProcessEvents(events, suite.securityContext)
    processingTime := time.Since(startTime)

    // Calculate throughput
    throughput := float64(len(events)) / processingTime.Seconds()

    // Verify batch processing success
    assert.Empty(t, errors, "Batch processing produced errors")
    assert.GreaterOrEqual(t, throughput, minThroughputRate, 
        "Throughput below minimum requirement: %.2f events/sec", throughput)

    // Verify batch metrics
    assert.Equal(t, testBatchSize, metrics.TotalEvents, "Incorrect total events count")
    assert.Zero(t, metrics.FailedEvents, "Unexpected failed events")
    assert.Greater(t, metrics.EventsPerSecond, minThroughputRate, 
        "Generation rate below requirement")
}

// TestSecurityCompliance tests security validation and compliance functionality
func TestSecurityCompliance(t *testing.T) {
    suite := setupTestSuite(t)
    defer suite.cancel()

    testCases := []struct {
        name           string
        securityLevel  string
        expectError    bool
        violationType  string
    }{
        {
            name:          "Standard Compliance",
            securityLevel: "standard",
            expectError:   false,
        },
        {
            name:          "Enhanced Security",
            securityLevel: "enhanced",
            expectError:   false,
        },
        {
            name:          "Security Violation",
            securityLevel: "enhanced",
            expectError:   true,
            violationType: "security_violation",
        },
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            var event *bronze.BronzeEvent
            var err error

            if tc.expectError {
                event, err = fixtures.GenerateInvalidBronzeEvent(tc.violationType, 
                    &fixtures.SecurityContext{Level: tc.securityLevel})
            } else {
                event, err = fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
                    SecurityLevel: tc.securityLevel,
                })
            }
            require.NoError(t, err, "Failed to generate test event")

            // Validate security compliance
            err = validation.ValidateSecurityCompliance(event)
            if tc.expectError {
                assert.Error(t, err, "Expected security validation error")
                assert.True(t, errors.IsErrorCode(err, "E1004", "security"), 
                    "Unexpected error type")
            } else {
                assert.NoError(t, err, "Unexpected security validation error")
            }
        })
    }
}

// Helper functions

func setupTestEnvironment() error {
    // Initialize test environment with security configuration
    return nil
}

func cleanupTestEnvironment() {
    // Clean up test resources and sensitive data
}