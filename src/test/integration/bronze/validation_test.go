// Package bronze_test provides integration tests for Bronze tier event processing
package bronze_test

import (
    "testing"
    "time"
    "encoding/json"

    "github.com/blackpoint/pkg/bronze"
    "github.com/blackpoint/test/pkg/fixtures"
    "github.com/stretchr/testify/assert"
)

// Test configuration constants
const (
    testTimeout = 5 * time.Minute
    batchSize = 10000
    maxLatency = time.Second
    minThroughput = 1000
    securityLevel = "HIGH"
    complianceMode = "STRICT"
)

// TestBronzeEventValidation tests the validation of Bronze tier events
func TestBronzeEventValidation(t *testing.T) {
    t.Parallel()

    tests := []struct {
        name string
        event *bronze.BronzeEvent
        wantErr bool
        errorCode string
    }{
        {
            name: "Valid event with security context",
            event: func() *bronze.BronzeEvent {
                event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
                    SecurityLevel: securityLevel,
                    AuditLevel: "detailed",
                    CustomMetadata: map[string]string{
                        "compliance_mode": complianceMode,
                        "test_context": "validation",
                    },
                })
                assert.NoError(t, err)
                return event
            }(),
            wantErr: false,
        },
        {
            name: "Missing client ID",
            event: func() *bronze.BronzeEvent {
                event, err := fixtures.GenerateInvalidBronzeEvent("missing_client", &fixtures.SecurityContext{
                    Level: securityLevel,
                    Compliance: []string{"SOC2", "ISO27001"},
                })
                assert.NoError(t, err)
                return event
            }(),
            wantErr: true,
            errorCode: "E3001",
        },
        {
            name: "Oversized payload",
            event: func() *bronze.BronzeEvent {
                event, err := fixtures.GenerateInvalidBronzeEvent("oversized_payload", &fixtures.SecurityContext{
                    Level: securityLevel,
                    Violations: []string{"max_size_exceeded"},
                })
                assert.NoError(t, err)
                return event
            }(),
            wantErr: true,
            errorCode: "E3001",
        },
        {
            name: "Security policy violation",
            event: func() *bronze.BronzeEvent {
                event, err := fixtures.GenerateInvalidBronzeEvent("security_violation", &fixtures.SecurityContext{
                    Level: securityLevel,
                    Violations: []string{"data_leak"},
                })
                assert.NoError(t, err)
                return event
            }(),
            wantErr: true,
            errorCode: "E3001",
        },
    }

    for _, tt := range tests {
        tt := tt
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()
            err := bronze.ValidateSchema(tt.event)
            
            if tt.wantErr {
                assert.Error(t, err)
                assert.Contains(t, err.Error(), tt.errorCode)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}

// TestBronzeSecurityCompliance tests security compliance aspects
func TestBronzeSecurityCompliance(t *testing.T) {
    t.Parallel()

    // Test security compliance with various security contexts
    securityTests := []struct {
        name string
        securityContext *fixtures.SecurityContext
        wantErr bool
    }{
        {
            name: "Standard compliance",
            securityContext: &fixtures.SecurityContext{
                Level: securityLevel,
                Compliance: []string{"SOC2", "ISO27001"},
                AuditRequirements: map[string]string{
                    "log_level": "debug",
                    "retention": "90d",
                },
            },
            wantErr: false,
        },
        {
            name: "Enhanced security requirements",
            securityContext: &fixtures.SecurityContext{
                Level: "CRITICAL",
                Compliance: []string{"PCI-DSS", "HIPAA"},
                AuditRequirements: map[string]string{
                    "log_level": "trace",
                    "retention": "365d",
                },
            },
            wantErr: false,
        },
    }

    for _, tt := range securityTests {
        tt := tt
        t.Run(tt.name, func(t *testing.T) {
            t.Parallel()

            event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
                SecurityLevel: tt.securityContext.Level,
                CustomMetadata: map[string]string{
                    "compliance": strings.Join(tt.securityContext.Compliance, ","),
                },
            })
            assert.NoError(t, err)

            err = bronze.ValidateSchema(event)
            if tt.wantErr {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}

// TestBronzeProcessingLatency tests processing latency requirements
func TestBronzeProcessingLatency(t *testing.T) {
    // Generate test event batch
    events, metrics, err := fixtures.GenerateBronzeEventBatch(batchSize, &fixtures.BatchOptions{
        Concurrent: true,
        WorkerCount: 4,
        SecurityContext: &fixtures.SecurityContext{
            Level: securityLevel,
            Compliance: []string{"SOC2"},
        },
    })
    assert.NoError(t, err)
    assert.NotNil(t, metrics)

    // Test processing latency for each event
    for _, event := range events {
        start := time.Now()
        err := bronze.ValidateSchema(event)
        processingTime := time.Since(start)

        assert.NoError(t, err)
        assert.Less(t, processingTime, maxLatency, "Processing time exceeded maximum latency")
    }

    // Verify batch processing metrics
    assert.GreaterOrEqual(t, metrics.EventsPerSecond, float64(minThroughput))
    assert.Less(t, metrics.GenerationTime, testTimeout)
}

// TestBronzeThroughputValidation tests system throughput requirements
func TestBronzeThroughputValidation(t *testing.T) {
    // Configure batch processing
    batchOpts := &fixtures.BatchOptions{
        Concurrent: true,
        WorkerCount: 8,
        SecurityContext: &fixtures.SecurityContext{
            Level: securityLevel,
            Compliance: []string{"SOC2", "ISO27001"},
        },
        ProgressCallback: func(current, total int) {
            if current%(total/10) == 0 {
                t.Logf("Processing progress: %d/%d events", current, total)
            }
        },
    }

    // Generate and process large event batch
    start := time.Now()
    events, metrics, err := fixtures.GenerateBronzeEventBatch(batchSize, batchOpts)
    assert.NoError(t, err)
    
    // Validate throughput requirements
    processingTime := time.Since(start)
    eventsPerSecond := float64(len(events)) / processingTime.Seconds()

    assert.GreaterOrEqual(t, eventsPerSecond, float64(minThroughput),
        "System throughput below minimum requirement of %d events/second", minThroughput)
    assert.Less(t, metrics.FailedEvents, len(events)/100,
        "Failed event rate exceeds 1% threshold")
    
    // Verify data accuracy
    for _, event := range events {
        assert.NotEmpty(t, event.ID)
        assert.NotEmpty(t, event.ClientID)
        assert.NotEmpty(t, event.SourcePlatform)
        assert.NotZero(t, event.Timestamp)
        assert.NotNil(t, event.Payload)
        
        // Validate JSON payload
        var payload map[string]interface{}
        err := json.Unmarshal(event.Payload, &payload)
        assert.NoError(t, err, "Invalid JSON payload")
    }
}