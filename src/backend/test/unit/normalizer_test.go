// Package unit provides comprehensive unit tests for the Silver tier normalizer
package unit

import (
    "context"
    "crypto/rand"
    "encoding/json"
    "sync"
    "testing"
    "time"

    "github.com/blackpoint/pkg/bronze/schema"
    "github.com/blackpoint/pkg/silver/schema"
    "github.com/blackpoint/pkg/common/errors"
    "../../internal/normalizer/processor"
    "../../internal/normalizer/mapper"
    "../../internal/normalizer/transformer"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/trace"
)

const (
    testTimeout    = 5 * time.Second
    testBatchSize  = 1000
    testClientID   = "test-client-001"
    perfTestDataSize = 10000
)

var (
    testSecurityContext context.Context
    testEncryptionKey   []byte
)

func init() {
    // Initialize test security context
    testSecurityContext = context.WithValue(context.Background(), "security_level", "high")
    
    // Generate test encryption key
    testEncryptionKey = make([]byte, 32)
    if _, err := rand.Read(testEncryptionKey); err != nil {
        panic("Failed to generate test encryption key")
    }
}

// TestProcessorSecurityValidation validates security controls and encryption
func TestProcessorSecurityValidation(t *testing.T) {
    // Initialize components
    m := mapper.NewFieldMapper(make(map[string]string), nil)
    tr := transformer.NewTransformer(testTimeout)
    p, err := processor.NewProcessor(m, tr, testTimeout)
    if err != nil {
        t.Fatalf("Failed to create processor: %v", err)
    }

    // Test cases for security validation
    tests := []struct {
        name          string
        event         *schema.BronzeEvent
        securityCtx   *schema.SecurityContext
        expectError   bool
        errorCode     string
    }{
        {
            name: "Valid security context",
            event: &schema.BronzeEvent{
                ID:       "test-id-1",
                ClientID: testClientID,
                Payload:  json.RawMessage(`{"sensitive_field":"test123"}`),
            },
            securityCtx: &schema.SecurityContext{
                Classification: "INTERNAL",
                Sensitivity:   "HIGH",
                Compliance:    []string{"PCI", "SOC2"},
            },
            expectError: false,
        },
        {
            name: "Missing security classification",
            event: &schema.BronzeEvent{
                ID:       "test-id-2",
                ClientID: testClientID,
                Payload:  json.RawMessage(`{"field":"value"}`),
            },
            securityCtx: &schema.SecurityContext{
                Sensitivity: "MEDIUM",
            },
            expectError: true,
            errorCode:   "E3001",
        },
        {
            name: "Sensitive data encryption",
            event: &schema.BronzeEvent{
                ID:       "test-id-3",
                ClientID: testClientID,
                Payload:  json.RawMessage(`{"password":"secret123","token":"abc123"}`),
            },
            securityCtx: &schema.SecurityContext{
                Classification: "INTERNAL",
                Sensitivity:   "HIGH",
                Compliance:    []string{"PCI"},
            },
            expectError: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Process event with security context
            result, err := p.ProcessSingle(testSecurityContext, tt.event)

            // Validate results
            if tt.expectError {
                if err == nil {
                    t.Error("Expected error but got none")
                }
                var bpErr *errors.BlackPointError
                if errors.As(err, &bpErr) && bpErr.Code != tt.errorCode {
                    t.Errorf("Expected error code %s, got %s", tt.errorCode, bpErr.Code)
                }
            } else {
                if err != nil {
                    t.Errorf("Unexpected error: %v", err)
                }
                if result != nil {
                    // Verify security context propagation
                    if result.SecurityContext.Classification == "" {
                        t.Error("Security classification not propagated")
                    }
                    // Verify sensitive field encryption
                    for field := range result.NormalizedData {
                        if isSensitiveField(field) && !isEncrypted(result.NormalizedData[field]) {
                            t.Errorf("Sensitive field %s not encrypted", field)
                        }
                    }
                }
            }
        })
    }
}

// TestProcessorPerformance benchmarks processing performance
func TestProcessorPerformance(b *testing.B) {
    // Initialize components
    m := mapper.NewFieldMapper(make(map[string]string), nil)
    tr := transformer.NewTransformer(testTimeout)
    p, err := processor.NewProcessor(m, tr, testTimeout)
    if err != nil {
        b.Fatalf("Failed to create processor: %v", err)
    }

    // Generate test data
    events := generateTestEvents(perfTestDataSize)

    // Benchmark batch processing
    b.Run("BatchProcessing", func(b *testing.B) {
        b.ResetTimer()
        for i := 0; i < b.N; i++ {
            batch := events[i*testBatchSize : (i+1)*testBatchSize]
            _, err := p.Process(testSecurityContext, batch)
            if err != nil {
                b.Fatalf("Batch processing failed: %v", err)
            }
        }
    })

    // Benchmark concurrent processing
    b.Run("ConcurrentProcessing", func(b *testing.B) {
        b.ResetTimer()
        var wg sync.WaitGroup
        for i := 0; i < b.N; i++ {
            wg.Add(1)
            go func(event *schema.BronzeEvent) {
                defer wg.Done()
                _, err := p.ProcessSingle(testSecurityContext, event)
                if err != nil {
                    b.Errorf("Concurrent processing failed: %v", err)
                }
            }(events[i%len(events)])
        }
        wg.Wait()
    })

    // Verify throughput requirements
    b.Run("ThroughputValidation", func(b *testing.B) {
        start := time.Now()
        processed := 0
        for i := 0; i < b.N && processed < 1000; i++ {
            _, err := p.ProcessSingle(testSecurityContext, events[i%len(events)])
            if err != nil {
                b.Fatalf("Processing failed: %v", err)
            }
            processed++
        }
        duration := time.Since(start)
        throughput := float64(processed) / duration.Seconds()
        if throughput < 1000 {
            b.Errorf("Throughput below requirement: %.2f events/second", throughput)
        }
    })
}

// TestFieldMappingAccuracy validates field mapping functionality
func TestFieldMappingAccuracy(t *testing.T) {
    // Initialize mapper with custom mappings
    customMappings := map[string]string{
        "custom_field": "normalized_field",
        "alert_level": "severity",
    }
    m := mapper.NewFieldMapper(customMappings, nil)

    // Test cases for field mapping
    tests := []struct {
        name        string
        input       map[string]interface{}
        expected    map[string]interface{}
        expectError bool
    }{
        {
            name: "Standard field mapping",
            input: map[string]interface{}{
                "source_ip": "192.168.1.1",
                "destination_ip": "10.0.0.1",
                "event_timestamp": "2024-01-20T10:00:00Z",
            },
            expected: map[string]interface{}{
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "event_time": "2024-01-20T10:00:00Z",
            },
            expectError: false,
        },
        {
            name: "Custom field mapping",
            input: map[string]interface{}{
                "custom_field": "test_value",
                "alert_level": "high",
            },
            expected: map[string]interface{}{
                "normalized_field": "test_value",
                "severity": "high",
            },
            expectError: false,
        },
        {
            name: "Invalid field type",
            input: map[string]interface{}{
                "source_ip": 12345,
                "port": "invalid",
            },
            expectError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create test event
            event := &schema.BronzeEvent{
                ID:       "test-id",
                ClientID: testClientID,
                Payload:  mustMarshal(tt.input),
            }

            // Map fields
            result, err := m.MapEvent(event)

            // Validate results
            if tt.expectError {
                if err == nil {
                    t.Error("Expected error but got none")
                }
            } else {
                if err != nil {
                    t.Errorf("Unexpected error: %v", err)
                }
                validateMappedFields(t, result.NormalizedData, tt.expected)
            }
        })
    }
}

// TestTransformationCompliance validates transformation rules
func TestTransformationCompliance(t *testing.T) {
    // Initialize transformer
    tr := transformer.NewTransformer(testTimeout)

    // Register custom transformers
    tr.RegisterTransformer("severity", func(v interface{}) (interface{}, error) {
        if s, ok := v.(string); ok {
            return strings.ToUpper(s), nil
        }
        return nil, errors.NewError("E3001", "invalid severity value", nil)
    })

    // Test cases for transformation
    tests := []struct {
        name        string
        input       map[string]interface{}
        secCtx      *schema.SecurityContext
        validate    func(*testing.T, *schema.SilverEvent)
        expectError bool
    }{
        {
            name: "Valid transformation",
            input: map[string]interface{}{
                "event_type": "security_alert",
                "severity": "high",
                "details": map[string]interface{}{
                    "source": "firewall",
                },
            },
            secCtx: &schema.SecurityContext{
                Classification: "INTERNAL",
                Sensitivity:   "MEDIUM",
                Compliance:    []string{"DEFAULT"},
            },
            validate: func(t *testing.T, e *schema.SilverEvent) {
                if e.EventType != "security_alert" {
                    t.Error("Invalid event type")
                }
                if e.NormalizedData["severity"] != "HIGH" {
                    t.Error("Severity not transformed")
                }
            },
            expectError: false,
        },
        {
            name: "Schema compliance",
            input: map[string]interface{}{
                "event_type": "auth_failure",
                "password": "secret123",
            },
            secCtx: &schema.SecurityContext{
                Classification: "INTERNAL",
                Sensitivity:   "HIGH",
                Compliance:    []string{"PCI"},
            },
            validate: func(t *testing.T, e *schema.SilverEvent) {
                if _, exists := e.NormalizedData["password"]; exists {
                    t.Error("Sensitive field not encrypted")
                }
                if len(e.EncryptedFields) == 0 {
                    t.Error("Missing encrypted fields")
                }
            },
            expectError: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create test event
            bronzeEvent := &schema.BronzeEvent{
                ID:       "test-id",
                ClientID: testClientID,
                Payload:  mustMarshal(tt.input),
            }

            // Transform event
            result, err := tr.TransformEvent(bronzeEvent, tt.input, tt.secCtx)

            // Validate results
            if tt.expectError {
                if err == nil {
                    t.Error("Expected error but got none")
                }
            } else {
                if err != nil {
                    t.Errorf("Unexpected error: %v", err)
                }
                if tt.validate != nil {
                    tt.validate(t, result)
                }
            }
        })
    }
}

// Helper functions

func generateTestEvents(count int) []*schema.BronzeEvent {
    events := make([]*schema.BronzeEvent, count)
    for i := 0; i < count; i++ {
        events[i] = &schema.BronzeEvent{
            ID:       fmt.Sprintf("test-id-%d", i),
            ClientID: testClientID,
            Payload:  mustMarshal(map[string]interface{}{
                "event_type": "test_event",
                "timestamp": time.Now().UTC(),
                "data": fmt.Sprintf("test-data-%d", i),
            }),
        }
    }
    return events
}

func mustMarshal(v interface{}) json.RawMessage {
    data, err := json.Marshal(v)
    if err != nil {
        panic(err)
    }
    return data
}

func validateMappedFields(t *testing.T, actual, expected map[string]interface{}) {
    for k, v := range expected {
        if actual[k] != v {
            t.Errorf("Field %s: expected %v, got %v", k, v, actual[k])
        }
    }
}

func isSensitiveField(field string) bool {
    sensitive := []string{"password", "token", "key", "secret"}
    for _, s := range sensitive {
        if strings.Contains(strings.ToLower(field), s) {
            return true
        }
    }
    return false
}

func isEncrypted(value interface{}) bool {
    // Basic check for encrypted data format
    if data, ok := value.([]byte); ok {
        return len(data) > 0 && data[0] != '{' && data[0] != '['
    }
    return false
}