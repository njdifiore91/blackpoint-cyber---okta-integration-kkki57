package integration

import (
    "context"
    "testing"
    "time"

    "github.com/blackpoint/internal/analyzer/detection"
    "github.com/blackpoint/internal/analyzer/correlation"
    "github.com/blackpoint/test/pkg/fixtures"
    "github.com/stretchr/testify/assert"
)

// Global test configuration
const (
    testTimeout          = 5 * time.Minute
    testBatchSize       = 1000
    testAccuracyThreshold = 0.80
    testSecurityLevel    = "HIGH"
    testAuditEnabled    = true
    testMetricsInterval = 1 * time.Second
)

// TestMain handles test suite setup and teardown
func TestMain(m *testing.M) {
    // Initialize security context
    ctx := context.Background()
    secCtx := &detection.SecurityContext{
        ClientID:       "test-client-001",
        Classification: "security_test",
        DataSensitivity: "high",
        ComplianceReqs: []string{"SOC2", "ISO27001"},
    }

    // Configure test metrics collection
    metrics.InitTelemetry(&metrics.MetricConfig{
        Namespace:   "blackpoint_test",
        Subsystem:  "analyzer",
        Environment: "test",
        CollectionInterval: int(testMetricsInterval.Seconds()),
    })

    // Run tests with security context
    ctx = context.WithValue(ctx, "security_context", secCtx)
    exitCode := m.Run()

    // Clean up resources
    os.Exit(exitCode)
}

// TestThreatDetection validates threat detection capabilities
func TestThreatDetection(t *testing.T) {
    // Set up test context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    defer cancel()

    // Generate test security events
    events, err := fixtures.GenerateNormalizedEvents(testBatchSize, "security", testSecurityLevel)
    assert.NoError(t, err, "Failed to generate test events")
    assert.Len(t, events, testBatchSize, "Incorrect number of test events generated")

    // Register test detection rules
    rules := []detection.DetectionRule{
        &detection.TestRule{
            Name: "test_rule_1",
            Pattern: "suspicious_login",
            Severity: 0.8,
        },
        &detection.TestRule{
            Name: "test_rule_2",
            Pattern: "failed_auth",
            Severity: 0.6,
        },
    }

    for _, rule := range rules {
        err := detection.RegisterDetectionRule(rule.Name, rule)
        assert.NoError(t, err, "Failed to register detection rule")
    }

    // Initialize metrics collection
    metrics := &detection.DetectionMetrics{}

    // Run threat detection
    alerts, err := detection.BatchDetection(ctx, events)
    assert.NoError(t, err, "Threat detection failed")

    // Validate detection accuracy
    detectedThreats := len(alerts)
    expectedThreats := int(float64(testBatchSize) * 0.1) // Assume 10% of events should trigger alerts
    accuracy := float64(detectedThreats) / float64(expectedThreats)
    assert.GreaterOrEqual(t, accuracy, testAccuracyThreshold, 
        "Detection accuracy below threshold: got %.2f, want >= %.2f", accuracy, testAccuracyThreshold)

    // Validate alert security context
    for _, alert := range alerts {
        assert.NotEmpty(t, alert.SecurityMetadata.Classification, "Alert missing security classification")
        assert.NotEmpty(t, alert.SecurityMetadata.ThreatLevel, "Alert missing threat level")
        assert.NotEmpty(t, alert.ComplianceInfo.Standards, "Alert missing compliance standards")
        assert.True(t, alert.SecurityMetadata.ConfidenceScore > 0, "Alert missing confidence score")
    }

    // Validate performance metrics
    assert.True(t, metrics.ProcessingLatency < 5*time.Second, "Detection latency too high")
    assert.True(t, metrics.ResourceUtilization < 0.8, "Resource utilization too high")
}

// TestEventCorrelation validates event correlation capabilities
func TestEventCorrelation(t *testing.T) {
    // Set up test context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    defer cancel()

    // Generate test security patterns
    patterns, err := fixtures.GenerateSecurityPatterns(5)
    assert.NoError(t, err, "Failed to generate security patterns")

    // Create event correlator with security context
    correlator, err := correlation.NewEventCorrelator(15*time.Minute, correlation.SecurityContext{
        ClientID: "test-client-001",
        Classification: "security_test",
        DataSensitivity: "high",
        ComplianceReqs: []string{"SOC2", "ISO27001"},
    })
    assert.NoError(t, err, "Failed to create event correlator")

    // Register correlation rules
    for _, pattern := range patterns {
        err := correlator.RegisterRule(pattern.ID, &correlation.SecurityPattern{
            Pattern: pattern,
            MinConfidence: 0.7,
            RequiredEvents: 3,
        })
        assert.NoError(t, err, "Failed to register correlation rule")
    }

    // Generate correlated test events
    events, err := fixtures.GenerateNormalizedEvents(testBatchSize, "security", testSecurityLevel)
    assert.NoError(t, err, "Failed to generate test events")

    // Initialize metrics collection
    metrics := &correlation.CorrelationMetrics{}

    // Run event correlation
    alerts, err := correlator.CorrelateEvents(ctx, events)
    assert.NoError(t, err, "Event correlation failed")

    // Validate correlation results
    assert.NotEmpty(t, alerts, "No correlation alerts generated")
    
    // Validate correlation accuracy
    correlatedEvents := 0
    for _, alert := range alerts {
        correlatedEvents += len(alert.SilverEventIDs)
    }
    correlationRate := float64(correlatedEvents) / float64(len(events))
    assert.GreaterOrEqual(t, correlationRate, testAccuracyThreshold,
        "Correlation rate below threshold: got %.2f, want >= %.2f", correlationRate, testAccuracyThreshold)

    // Validate security context
    for _, alert := range alerts {
        assert.NotEmpty(t, alert.SecurityMetadata.Classification, "Alert missing security classification")
        assert.NotEmpty(t, alert.SecurityMetadata.ThreatLevel, "Alert missing threat level")
        assert.True(t, len(alert.SilverEventIDs) >= 2, "Insufficient correlated events")
    }

    // Validate performance metrics
    assert.True(t, metrics.CorrelationLatency < 10*time.Second, "Correlation latency too high")
    assert.True(t, metrics.PatternMatchRate > 0.7, "Pattern match rate too low")
}

// TestBatchProcessing validates batch processing capabilities
func TestBatchProcessing(t *testing.T) {
    // Set up test context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    defer cancel()

    // Generate batch test data
    events, err := fixtures.GenerateNormalizedEvents(testBatchSize, "security", testSecurityLevel)
    assert.NoError(t, err, "Failed to generate test events")

    // Initialize security context
    secCtx := fixtures.NewSecurityContext(testSecurityLevel)
    assert.NotNil(t, secCtx, "Failed to create security context")

    // Configure batch processing
    batchConfig := &detection.BatchConfig{
        MaxBatchSize: testBatchSize,
        Timeout: testTimeout,
        SecurityContext: secCtx,
    }

    // Run batch processing
    startTime := time.Now()
    alerts, errs := detection.BatchDetection(ctx, events)
    processingTime := time.Since(startTime)

    // Validate batch processing results
    assert.NotEmpty(t, alerts, "No alerts generated from batch processing")
    assert.Empty(t, errs, "Batch processing errors occurred")

    // Validate processing performance
    assert.True(t, processingTime < testTimeout/2, "Batch processing too slow")
    assert.True(t, len(alerts) > 0, "No alerts generated")

    // Validate security controls
    for _, alert := range alerts {
        assert.NotEmpty(t, alert.SecurityMetadata.Classification, "Alert missing security classification")
        assert.NotEmpty(t, alert.ComplianceInfo.Standards, "Alert missing compliance standards")
        assert.True(t, alert.SecurityMetadata.ConfidenceScore > 0, "Alert missing confidence score")
    }

    // Validate resource utilization
    metrics := detection.GetBatchMetrics()
    assert.True(t, metrics.CPUUtilization < 0.8, "CPU utilization too high")
    assert.True(t, metrics.MemoryUtilization < 0.8, "Memory utilization too high")
}