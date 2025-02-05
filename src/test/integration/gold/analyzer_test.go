package gold_test

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/blackpoint/internal/analyzer"
    "github.com/blackpoint/test/pkg/validation"
    "github.com/blackpoint/test/pkg/fixtures"
)

// testAnalyzerConfig defines test configuration for analyzer validation
var testAnalyzerConfig = map[string]interface{}{
    "analysis_window": "30m",
    "max_events":     5000,
    "security_context": true,
    "audit_logging":   true,
    "compliance_check": true,
}

// testAccuracyThreshold defines the minimum required accuracy as per specifications
const testAccuracyThreshold = 0.80

// testPerformanceSLA defines the maximum allowed processing time for Gold tier
const testPerformanceSLA = 30 * time.Second

// testSecurityPatterns defines security patterns to validate
var testSecurityPatterns = []string{
    "authentication",
    "authorization",
    "data_access",
    "system_change",
}

// TestAnalyzerIntelligenceGeneration validates the intelligence generation capabilities
// with comprehensive security validation
func TestAnalyzerIntelligenceGeneration(t *testing.T) {
    // Initialize analyzer with security context
    analyzer, err := setupTestAnalyzer()
    assert.NoError(t, err, "Failed to initialize analyzer")

    // Create test alert batch with security patterns
    testAlerts, err := fixtures.GenerateTestGoldAlertBatch(100, map[string]interface{}{
        "security_level": "high",
        "compliance":     []string{"SOC2", "GDPR"},
        "audit_required": true,
    })
    assert.NoError(t, err, "Failed to generate test alerts")

    // Initialize validator with security focus
    validator, err := validation.NewAlertValidator("security", nil, nil)
    assert.NoError(t, err, "Failed to create validator")

    // Process alerts through intelligence engine
    ctx, cancel := context.WithTimeout(context.Background(), testPerformanceSLA)
    defer cancel()

    startTime := time.Now()
    intelligence, err := analyzer.GenerateIntelligence(ctx, testAlerts)
    processingTime := time.Since(startTime)

    // Validate results
    assert.NoError(t, err, "Intelligence generation failed")
    assert.NotNil(t, intelligence, "Intelligence data should not be nil")
    assert.Less(t, processingTime, testPerformanceSLA, "Processing time exceeded SLA")

    // Validate security patterns
    for _, pattern := range testSecurityPatterns {
        assert.Contains(t, intelligence, pattern, "Missing security pattern: %s", pattern)
    }

    // Validate accuracy
    validationResults, err := validator.ValidateAlertBatch(testAlerts, testAlerts)
    assert.NoError(t, err, "Validation failed")

    accuracy := validationResults["average_accuracy"].(float64)
    assert.GreaterOrEqual(t, accuracy, testAccuracyThreshold*100, 
        "Accuracy below required threshold of %.2f%%", testAccuracyThreshold*100)

    // Validate compliance metadata
    assert.Contains(t, intelligence, "compliance_status", "Missing compliance metadata")
    assert.NotEmpty(t, intelligence["compliance_status"], "Empty compliance status")
}

// TestAnalyzerAlertCorrelation validates the alert correlation functionality
// with security validation
func TestAnalyzerAlertCorrelation(t *testing.T) {
    analyzer, err := setupTestAnalyzer()
    assert.NoError(t, err, "Failed to initialize analyzer")

    // Generate related test alerts
    alert1, err := fixtures.NewTestGoldAlert()
    assert.NoError(t, err, "Failed to generate first test alert")

    alert2, err := fixtures.NewTestGoldAlertWithParams(
        alert1.Severity,
        "new",
        map[string]interface{}{
            "correlation_id": alert1.AlertID,
            "threat_type":   alert1.IntelligenceData["threat_type"],
        },
        alert1.SecurityMetadata,
        alert1.ComplianceTags,
    )
    assert.NoError(t, err, "Failed to generate second test alert")

    // Process alerts
    ctx := context.Background()
    results, err := analyzer.GenerateIntelligence(ctx, []*gold.Alert{alert1, alert2})
    assert.NoError(t, err, "Failed to process correlated alerts")

    // Validate correlation results
    assert.Contains(t, results, "correlated_alerts", "Missing correlation data")
    correlations := results["correlated_alerts"].(map[string]interface{})
    assert.Contains(t, correlations, alert1.AlertID, "Missing correlation for first alert")
    assert.Contains(t, correlations, alert2.AlertID, "Missing correlation for second alert")

    // Validate security compliance
    assert.Contains(t, results, "security_validation", "Missing security validation")
    securityResults := results["security_validation"].(map[string]interface{})
    assert.True(t, securityResults["passed"].(bool), "Security validation failed")
}

// TestAnalyzerPerformance validates analyzer performance under load
// with security metrics
func TestAnalyzerPerformance(t *testing.T) {
    analyzer, err := setupTestAnalyzer()
    assert.NoError(t, err, "Failed to initialize analyzer")

    // Generate large batch of test alerts
    testAlerts, err := fixtures.GenerateTestGoldAlertBatch(1000, map[string]interface{}{
        "security_level": "high",
        "performance_test": true,
    })
    assert.NoError(t, err, "Failed to generate test alert batch")

    // Process alerts with monitoring
    ctx := context.Background()
    startTime := time.Now()
    
    results, err := analyzer.GenerateIntelligence(ctx, testAlerts)
    processingTime := time.Since(startTime)

    assert.NoError(t, err, "Batch processing failed")
    assert.NotNil(t, results, "Results should not be nil")

    // Validate performance metrics
    assert.Less(t, processingTime, testPerformanceSLA, 
        "Processing time %v exceeded SLA %v", processingTime, testPerformanceSLA)

    metrics := analyzer.GetMetrics()
    assert.NotNil(t, metrics, "Metrics should not be nil")
    assert.Contains(t, metrics, "events_processed", "Missing events processed metric")
    assert.Contains(t, metrics, "processing_latency", "Missing latency metric")

    // Validate security overhead
    assert.Contains(t, metrics, "security_validation_time", "Missing security validation metric")
    securityOverhead := metrics["security_validation_time"].(float64)
    assert.Less(t, securityOverhead/float64(processingTime), 0.2, 
        "Security validation overhead exceeds 20% of processing time")
}

// setupTestAnalyzer initializes a test analyzer instance with security configuration
func setupTestAnalyzer() (*analyzer.IntelligenceEngine, error) {
    // Create analyzer with test configuration
    engine, err := analyzer.NewIntelligenceEngine(
        30*time.Minute, // analysis window
        correlation.NewEventCorrelator(),
    )
    if err != nil {
        return nil, err
    }

    // Configure security rules
    for _, pattern := range testSecurityPatterns {
        if err := engine.RegisterIntelligenceRule(pattern, NewSecurityRule(pattern)); err != nil {
            return nil, err
        }
    }

    return engine, nil
}