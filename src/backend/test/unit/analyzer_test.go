package analyzer_test

import (
    "context"
    "sync"
    "testing"
    "time"

    "github.com/blackpoint/internal/analyzer"
    "github.com/blackpoint/pkg/silver"
    "github.com/blackpoint/pkg/gold"
    "github.com/blackpoint/pkg/common/errors"
)

// Global test constants
const (
    testTimeout = 30 * time.Second
    testDataSize = 1000
    testConcurrency = 10
    minAccuracyThreshold = 0.80
    maxProcessingLatency = 30 * time.Second
)

// mockDetectionRule implements the DetectionRule interface for testing
type mockDetectionRule struct {
    ruleType string
    shouldDetect bool
    severity float64
    securityControls map[string]interface{}
    complianceRequirements []string
}

func newMockDetectionRule(ruleType string, shouldDetect bool, severity float64, securityControls map[string]interface{}, complianceRequirements []string) *mockDetectionRule {
    return &mockDetectionRule{
        ruleType: ruleType,
        shouldDetect: shouldDetect,
        severity: severity,
        securityControls: securityControls,
        complianceRequirements: complianceRequirements,
    }
}

func (m *mockDetectionRule) Detect(event *silver.SilverEvent) (bool, float64, map[string]interface{}) {
    if m.shouldDetect {
        return true, m.severity, map[string]interface{}{
            "rule_type": m.ruleType,
            "security_controls": m.securityControls,
            "compliance": m.complianceRequirements,
        }
    }
    return false, 0.0, nil
}

// TestDetectThreats tests the threat detection functionality
func TestDetectThreats(t *testing.T) {
    // Create test context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    defer cancel()

    // Test cases
    tests := []struct {
        name string
        events []*silver.SilverEvent
        rules []*mockDetectionRule
        expectedAlerts int
        expectedError error
    }{
        {
            name: "Valid Detection - Single Threat",
            events: generateTestEvents(1),
            rules: []*mockDetectionRule{
                newMockDetectionRule("malware", true, 0.8, map[string]interface{}{
                    "encryption": "AES-256",
                }, []string{"SOC2", "ISO27001"}),
            },
            expectedAlerts: 1,
            expectedError: nil,
        },
        {
            name: "Valid Detection - Multiple Threats",
            events: generateTestEvents(5),
            rules: []*mockDetectionRule{
                newMockDetectionRule("intrusion", true, 0.9, map[string]interface{}{
                    "encryption": "AES-256",
                }, []string{"SOC2"}),
                newMockDetectionRule("malware", true, 0.7, map[string]interface{}{
                    "encryption": "AES-256",
                }, []string{"ISO27001"}),
            },
            expectedAlerts: 10,
            expectedError: nil,
        },
        {
            name: "No Threats Detected",
            events: generateTestEvents(3),
            rules: []*mockDetectionRule{
                newMockDetectionRule("malware", false, 0.0, nil, nil),
            },
            expectedAlerts: 0,
            expectedError: nil,
        },
        {
            name: "Performance Test - Large Batch",
            events: generateTestEvents(testDataSize),
            rules: []*mockDetectionRule{
                newMockDetectionRule("malware", true, 0.8, map[string]interface{}{
                    "encryption": "AES-256",
                }, []string{"SOC2"}),
            },
            expectedAlerts: testDataSize,
            expectedError: nil,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Register test rules
            for _, rule := range tt.rules {
                analyzer.RegisterDetectionRule(rule.ruleType, rule)
            }

            // Start performance timer
            start := time.Now()

            // Process events
            alerts, err := analyzer.DetectThreats(ctx, tt.events[0])

            // Validate processing time
            processingTime := time.Since(start)
            if processingTime > maxProcessingLatency {
                t.Errorf("Processing time exceeded maximum: %v > %v", processingTime, maxProcessingLatency)
            }

            // Validate error
            if (err != nil) != (tt.expectedError != nil) {
                t.Errorf("Expected error: %v, got: %v", tt.expectedError, err)
            }

            // Validate alerts
            if alerts != nil && len(alerts) != tt.expectedAlerts {
                t.Errorf("Expected %d alerts, got %d", tt.expectedAlerts, len(alerts))
            }

            // Validate security controls
            if alerts != nil {
                validateSecurityControls(t, alerts)
            }
        })
    }
}

// TestCorrelateEvents tests the event correlation functionality
func TestCorrelateEvents(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    defer cancel()

    // Initialize correlator with security context
    secCtx := analyzer.SecurityContext{
        ClientID: "test-client",
        Classification: "confidential",
        DataSensitivity: "high",
        ComplianceReqs: []string{"SOC2", "ISO27001"},
    }

    correlator, err := analyzer.NewEventCorrelator(5*time.Minute, secCtx)
    if err != nil {
        t.Fatalf("Failed to create correlator: %v", err)
    }

    // Test cases
    tests := []struct {
        name string
        events []*silver.SilverEvent
        expectedCorrelations int
        expectedError error
    }{
        {
            name: "Single Event Correlation",
            events: generateTestEvents(1),
            expectedCorrelations: 1,
            expectedError: nil,
        },
        {
            name: "Multiple Event Correlation",
            events: generateTestEvents(5),
            expectedCorrelations: 2,
            expectedError: nil,
        },
        {
            name: "Performance Test - Concurrent Correlation",
            events: generateTestEvents(testDataSize),
            expectedCorrelations: testDataSize / 10,
            expectedError: nil,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            start := time.Now()

            // Process correlations
            alerts, err := correlator.CorrelateEvents(ctx, tt.events)

            // Validate processing time
            processingTime := time.Since(start)
            if processingTime > maxProcessingLatency {
                t.Errorf("Correlation time exceeded maximum: %v > %v", processingTime, maxProcessingLatency)
            }

            // Validate error
            if (err != nil) != (tt.expectedError != nil) {
                t.Errorf("Expected error: %v, got: %v", tt.expectedError, err)
            }

            // Validate correlations
            if alerts != nil && len(alerts) != tt.expectedCorrelations {
                t.Errorf("Expected %d correlations, got %d", tt.expectedCorrelations, len(alerts))
            }
        })
    }
}

// BenchmarkAnalyzer runs performance benchmarks for analyzer components
func BenchmarkAnalyzer(b *testing.B) {
    ctx := context.Background()

    // Benchmark threat detection
    b.Run("ThreatDetection", func(b *testing.B) {
        events := generateTestEvents(b.N)
        rule := newMockDetectionRule("benchmark", true, 0.8, nil, nil)
        analyzer.RegisterDetectionRule("benchmark", rule)

        b.ResetTimer()
        for i := 0; i < b.N; i++ {
            analyzer.DetectThreats(ctx, events[i])
        }
    })

    // Benchmark event correlation
    b.Run("EventCorrelation", func(b *testing.B) {
        events := generateTestEvents(b.N)
        correlator, _ := analyzer.NewEventCorrelator(5*time.Minute, analyzer.SecurityContext{
            ClientID: "benchmark",
        })

        b.ResetTimer()
        for i := 0; i < b.N; i++ {
            correlator.CorrelateEvents(ctx, events[i:i+1])
        }
    })
}

// Helper functions

// generateTestEvents creates test security events
func generateTestEvents(count int) []*silver.SilverEvent {
    events := make([]*silver.SilverEvent, count)
    for i := 0; i < count; i++ {
        events[i] = &silver.SilverEvent{
            EventID: fmt.Sprintf("test-event-%d", i),
            ClientID: "test-client",
            EventType: "security_alert",
            EventTime: time.Now().UTC(),
            NormalizedData: map[string]interface{}{
                "source_ip": "192.168.1.1",
                "action": "login_attempt",
                "severity": "high",
            },
            SecurityContext: silver.SecurityContext{
                Classification: "confidential",
                Sensitivity: "high",
                Compliance: []string{"SOC2", "ISO27001"},
            },
        }
    }
    return events
}

// validateSecurityControls validates security controls in alerts
func validateSecurityControls(t *testing.T, alerts []*gold.Alert) {
    for _, alert := range alerts {
        // Validate security metadata
        if alert.SecurityMetadata == nil {
            t.Error("Missing security metadata in alert")
            continue
        }

        // Validate compliance requirements
        if len(alert.ComplianceTags) == 0 {
            t.Error("Missing compliance tags in alert")
        }

        // Validate encryption of sensitive fields
        if len(alert.EncryptedFields) == 0 {
            t.Error("No encrypted fields found in alert")
        }

        // Validate severity calculation
        if alert.Severity == "" {
            t.Error("Missing severity in alert")
        }
    }
}