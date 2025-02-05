// Package silver provides integration tests for Silver tier event transformation
package silver

import (
    "context"
    "sync"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/prometheus/client_golang/prometheus"

    "github.com/blackpoint/pkg/bronze/schema"
    "github.com/blackpoint/pkg/silver/schema"
    "../../pkg/fixtures"
    "../../../backend/internal/normalizer"
)

// Global test constants
const (
    testTimeout           = 30 * time.Second
    testBatchSize        = 1000
    maxConcurrentTransforms = 10
    securityContextTimeout = 5 * time.Second
    maxEncryptionOverhead  = 1 * time.Second
)

// Metrics collectors
var (
    transformationDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "silver_transformation_duration_seconds",
            Help: "Duration of Silver tier event transformations",
            Buckets: []float64{0.1, 0.5, 1, 2, 5},
        },
        []string{"security_level"},
    )

    transformationErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "silver_transformation_errors_total",
            Help: "Total number of Silver tier transformation errors",
        },
        []string{"error_type"},
    )
)

func init() {
    prometheus.MustRegister(transformationDuration)
    prometheus.MustRegister(transformationErrors)
}

// TestTransformEvent tests the transformation of Bronze events into Silver events with security validation
func TestTransformEvent(t *testing.T) {
    // Create test Bronze event with security context
    bronzeEvent, err := fixtures.NewTestSilverEventWithSecurity("security", "high")
    require.NoError(t, err, "Failed to create test Bronze event")

    // Initialize transformer with security configuration
    transformer := normalizer.NewTransformer(testTimeout)
    require.NotNil(t, transformer, "Failed to create transformer")

    // Create security context
    secCtx := &schema.SecurityContext{
        Classification: "high",
        Sensitivity:   "high",
        Compliance:    []string{"pii", "audit-logging"},
        Encryption:    map[string]string{"algorithm": "aes-256-gcm"},
        AccessControl: map[string]string{"level": "restricted"},
    }

    // Transform Bronze event to Silver event
    mappedFields := map[string]interface{}{
        "event_type": "security",
        "severity":   "high",
        "user_id":    "test-user-001",
        "pii_data":   map[string]string{"type": "sensitive"},
    }

    silverEvent, err := transformer.TransformEvent(bronzeEvent, mappedFields, secCtx)
    require.NoError(t, err, "Event transformation failed")
    require.NotNil(t, silverEvent, "Transformed event is nil")

    // Validate transformation result
    assert.Equal(t, bronzeEvent.ClientID, silverEvent.ClientID)
    assert.Equal(t, "security", silverEvent.EventType)
    assert.NotEmpty(t, silverEvent.EventID)
    assert.NotEmpty(t, silverEvent.SecurityContext)
    assert.NotEmpty(t, silverEvent.AuditMetadata)

    // Verify field encryption
    assert.Contains(t, silverEvent.EncryptedFields, "pii_data")
    assert.NotContains(t, silverEvent.NormalizedData, "pii_data")

    // Validate security context preservation
    assert.Equal(t, "high", silverEvent.SecurityContext.Classification)
    assert.Contains(t, silverEvent.SecurityContext.Compliance, "pii")
}

// TestTransformEventPerformance tests the performance of event transformation against SLA requirements
func TestTransformEventPerformance(t *testing.T) {
    transformer := normalizer.NewTransformer(testTimeout)
    require.NotNil(t, transformer, "Failed to create transformer")

    // Create batch of test events
    events := make([]*schema.BronzeEvent, testBatchSize)
    for i := 0; i < testBatchSize; i++ {
        event, err := fixtures.NewTestSilverEventWithSecurity("security", "medium")
        require.NoError(t, err)
        events[i] = event
    }

    // Measure transformation time
    start := time.Now()
    timer := prometheus.NewTimer(transformationDuration.WithLabelValues("medium"))
    defer timer.ObserveDuration()

    for _, event := range events {
        mappedFields := map[string]interface{}{
            "event_type": "security",
            "severity":   "medium",
        }

        _, err := transformer.TransformEvent(event, mappedFields, nil)
        require.NoError(t, err)
    }

    duration := time.Since(start)
    avgDuration := duration / time.Duration(testBatchSize)

    // Verify performance meets SLA
    assert.Less(t, avgDuration, 5*time.Second, "Average transformation time exceeds SLA")
    assert.Less(t, duration, testTimeout, "Batch transformation time exceeds timeout")
}

// TestTransformEventValidation tests validation of transformed events against Silver tier schema
func TestTransformEventValidation(t *testing.T) {
    transformer := normalizer.NewTransformer(testTimeout)
    require.NotNil(t, transformer, "Failed to create transformer")

    testCases := []struct {
        name          string
        securityLevel string
        shouldError   bool
        errorType     string
    }{
        {"ValidHighSecurity", "high", false, ""},
        {"InvalidPII", "critical", true, "encryption_required"},
        {"MissingFields", "medium", true, "missing_required"},
        {"InvalidSchema", "low", true, "schema_validation"},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            event, err := fixtures.NewTestSilverEventWithSecurity("security", tc.securityLevel)
            require.NoError(t, err)

            mappedFields := map[string]interface{}{
                "event_type": "security",
                "severity":   tc.securityLevel,
            }

            _, err = transformer.TransformEvent(event, mappedFields, nil)
            if tc.shouldError {
                assert.Error(t, err)
                transformationErrors.WithLabelValues(tc.errorType).Inc()
            } else {
                assert.NoError(t, err)
            }
        })
    }
}

// TestTransformEventConcurrency tests concurrent transformation of multiple events
func TestTransformEventConcurrency(t *testing.T) {
    transformer := normalizer.NewTransformer(testTimeout)
    require.NotNil(t, transformer, "Failed to create transformer")

    var wg sync.WaitGroup
    errors := make(chan error, maxConcurrentTransforms)

    // Create test events for concurrent processing
    for i := 0; i < maxConcurrentTransforms; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()

            event, err := fixtures.NewTestSilverEventWithSecurity("security", "high")
            if err != nil {
                errors <- err
                return
            }

            mappedFields := map[string]interface{}{
                "event_type": "security",
                "severity":   "high",
                "user_id":    "test-user-001",
            }

            ctx, cancel := context.WithTimeout(context.Background(), securityContextTimeout)
            defer cancel()

            _, err = transformer.TransformEvent(event, mappedFields, nil)
            if err != nil {
                errors <- err
            }
        }()
    }

    // Wait for all transformations to complete
    wg.Wait()
    close(errors)

    // Check for any errors during concurrent processing
    for err := range errors {
        assert.NoError(t, err, "Error during concurrent transformation")
    }
}