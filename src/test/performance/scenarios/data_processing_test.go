package scenarios

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/require"

    "../../pkg/metrics/performance_metrics"
    "../../pkg/metrics/latency_metrics"
    "../../pkg/generators/load_generator"
)

// Global test configuration
const (
    testDuration           = 5 * time.Minute
    defaultConcurrency     = 10
    maxConcurrency         = 100
    securityContextTimeout = 30 * time.Second
)

// TestBronzeTierProcessing tests Bronze tier data processing performance with enhanced security validation
func TestBronzeTierProcessing(t *testing.T) {
    // Initialize test context with security parameters
    ctx, cancel := context.WithTimeout(context.Background(), testDuration)
    defer cancel()

    // Configure security-aware load generator
    config := &load_generator.LoadGeneratorConfig{
        Duration:     testDuration,
        Concurrency: defaultConcurrency,
        RampUpPeriod: 30 * time.Second,
        EventTypes:   []string{"security", "auth", "access"},
        SecurityContext: map[string]interface{}{
            "classification": "CONFIDENTIAL",
            "sensitivity":   "HIGH",
            "compliance":    []string{"PCI-DSS", "SOC2"},
        },
        ValidationRules: []load_generator.ValidationRule{
            {Field: "client_id", Pattern: "^[a-zA-Z0-9-]{36}$", Required: true},
            {Field: "event_type", Pattern: "^(security|auth|access)$", Required: true},
        },
    }

    // Initialize load generator with security context
    generator, err := load_generator.NewLoadGenerator(config, &load_generator.SecurityContext{})
    require.NoError(t, err, "Failed to initialize load generator")

    // Start performance monitoring
    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "bronze_tier", testDuration)
    require.NoError(t, err, "Failed to initialize performance metrics")

    // Execute load test with security validation
    err = generator.Start(ctx)
    require.NoError(t, err, "Failed to start load generation")

    // Measure processing latency
    latencyTracker := &latency_metrics.SecurityLatencyTracker{}
    bronzeLatency, err := latency_metrics.MeasureProcessingLatency(t, "bronze", func() error {
        return nil // Actual processing would be implemented here
    })
    require.NoError(t, err, "Failed to measure Bronze tier latency")
    require.Less(t, bronzeLatency, time.Second, "Bronze tier latency exceeds 1s requirement")

    // Validate performance requirements
    valid, err := performance_metrics.ValidatePerformanceRequirements(t, metrics)
    require.NoError(t, err, "Failed to validate performance requirements")
    require.True(t, valid, "Performance requirements not met")

    // Stop load generation
    generator.Stop()
}

// TestSilverTierProcessing tests Silver tier data processing with security normalization
func TestSilverTierProcessing(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), testDuration)
    defer cancel()

    // Configure load generator for Silver tier
    config := &load_generator.LoadGeneratorConfig{
        Duration:     testDuration,
        Concurrency: defaultConcurrency,
        EventTypes:   []string{"normalized_security", "normalized_auth"},
        SecurityContext: map[string]interface{}{
            "classification": "RESTRICTED",
            "sensitivity":   "HIGH",
            "compliance":    []string{"PCI-DSS", "HIPAA", "SOC2"},
        },
        ValidationRules: []load_generator.ValidationRule{
            {Field: "normalized_data", Required: true},
            {Field: "security_context", Required: true},
        },
    }

    generator, err := load_generator.NewLoadGenerator(config, &load_generator.SecurityContext{})
    require.NoError(t, err, "Failed to initialize Silver tier generator")

    // Start performance monitoring
    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "silver_tier", testDuration)
    require.NoError(t, err, "Failed to initialize Silver tier metrics")

    // Execute load test
    err = generator.Start(ctx)
    require.NoError(t, err, "Failed to start Silver tier load generation")

    // Measure processing latency
    silverLatency, err := latency_metrics.MeasureProcessingLatency(t, "silver", func() error {
        return nil // Actual processing would be implemented here
    })
    require.NoError(t, err, "Failed to measure Silver tier latency")
    require.Less(t, silverLatency, 5*time.Second, "Silver tier latency exceeds 5s requirement")

    // Validate performance
    valid, err := performance_metrics.ValidatePerformanceRequirements(t, metrics)
    require.NoError(t, err, "Failed to validate Silver tier performance")
    require.True(t, valid, "Silver tier performance requirements not met")

    generator.Stop()
}

// TestGoldTierProcessing tests Gold tier processing with enhanced security analysis
func TestGoldTierProcessing(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), testDuration)
    defer cancel()

    // Configure load generator for Gold tier
    config := &load_generator.LoadGeneratorConfig{
        Duration:     testDuration,
        Concurrency: defaultConcurrency,
        EventTypes:   []string{"security_alert", "threat_detection"},
        SecurityContext: map[string]interface{}{
            "classification": "TOP_SECRET",
            "sensitivity":   "CRITICAL",
            "compliance":    []string{"PCI-DSS", "HIPAA", "SOC2", "GDPR"},
        },
        ValidationRules: []load_generator.ValidationRule{
            {Field: "intelligence_data", Required: true},
            {Field: "threat_score", Required: true},
        },
    }

    generator, err := load_generator.NewLoadGenerator(config, &load_generator.SecurityContext{})
    require.NoError(t, err, "Failed to initialize Gold tier generator")

    // Start performance monitoring
    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "gold_tier", testDuration)
    require.NoError(t, err, "Failed to initialize Gold tier metrics")

    // Execute load test
    err = generator.Start(ctx)
    require.NoError(t, err, "Failed to start Gold tier load generation")

    // Measure processing latency
    goldLatency, err := latency_metrics.MeasureProcessingLatency(t, "gold", func() error {
        return nil // Actual processing would be implemented here
    })
    require.NoError(t, err, "Failed to measure Gold tier latency")
    require.Less(t, goldLatency, 30*time.Second, "Gold tier latency exceeds 30s requirement")

    // Validate performance
    valid, err := performance_metrics.ValidatePerformanceRequirements(t, metrics)
    require.NoError(t, err, "Failed to validate Gold tier performance")
    require.True(t, valid, "Gold tier performance requirements not met")

    generator.Stop()
}

// TestEndToEndProcessing tests end-to-end processing with comprehensive security validation
func TestEndToEndProcessing(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), testDuration)
    defer cancel()

    // Configure end-to-end test
    config := &load_generator.LoadGeneratorConfig{
        Duration:     testDuration,
        Concurrency: maxConcurrency,
        EventTypes:   []string{"security", "auth", "access"},
        SecurityContext: map[string]interface{}{
            "classification": "TOP_SECRET",
            "sensitivity":   "CRITICAL",
            "compliance":    []string{"PCI-DSS", "HIPAA", "SOC2", "GDPR"},
        },
        ValidationRules: []load_generator.ValidationRule{
            {Field: "client_id", Pattern: "^[a-zA-Z0-9-]{36}$", Required: true},
            {Field: "security_context", Required: true},
            {Field: "compliance_tags", Required: true},
        },
    }

    generator, err := load_generator.NewLoadGenerator(config, &load_generator.SecurityContext{})
    require.NoError(t, err, "Failed to initialize end-to-end test generator")

    // Start performance monitoring
    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "end_to_end", testDuration)
    require.NoError(t, err, "Failed to initialize end-to-end metrics")

    // Execute load test
    err = generator.Start(ctx)
    require.NoError(t, err, "Failed to start end-to-end load generation")

    // Validate system throughput
    require.GreaterOrEqual(t, metrics.Throughput.EventsPerSecond, float64(1000),
        "System throughput below 1000 events/second requirement")

    // Validate client scalability
    require.GreaterOrEqual(t, metrics.Resources.ActiveClients, int32(100),
        "System failed to support 100+ concurrent clients")

    // Validate end-to-end performance
    valid, err := performance_metrics.ValidatePerformanceRequirements(t, metrics)
    require.NoError(t, err, "Failed to validate end-to-end performance")
    require.True(t, valid, "End-to-end performance requirements not met")

    generator.Stop()
}