// Package fixtures provides test data generators for the BlackPoint Security Integration Framework
package fixtures

import (
    "encoding/json"
    "fmt"
    "sync"
    "time"

    "github.com/blackpoint/pkg/bronze"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/utils"
    "github.com/blackpoint/pkg/common/logging"
    "github.com/google/uuid"
    "github.com/stretchr/testify/mock"
)

// Default values for test event generation
const (
    defaultClientID        = "test-client-001"
    defaultSourcePlatform  = "test-platform"
    defaultSchemaVersion  = "1.0"
    maxTestPayloadSize    = 1048576 // 1MB
    maxBatchSize         = 10000
    defaultSecurityLevel = "standard"
    defaultAuditLevel    = "detailed"
)

// GenerateOptions configures test event generation
type GenerateOptions struct {
    ClientID        string
    SourcePlatform  string
    PayloadSize     int
    SecurityLevel   string
    AuditLevel      string
    CustomMetadata  map[string]string
}

// BatchOptions configures batch event generation
type BatchOptions struct {
    Concurrent      bool
    WorkerCount     int
    SecurityContext *SecurityContext
    ProgressCallback func(int, int)
}

// BatchMetrics contains performance data for batch generation
type BatchMetrics struct {
    TotalEvents     int
    GenerationTime  time.Duration
    EventsPerSecond float64
    FailedEvents    int
    AveragePayloadSize int64
}

// SecurityContext represents security test configuration
type SecurityContext struct {
    Level           string
    Compliance      []string
    Violations      []string
    AuditRequirements map[string]string
}

// Sample security test cases
var SecurityTestCases = struct {
    StandardCompliance TestCase
    SecurityViolation TestCase
    AuditRequirement  TestCase
}{
    StandardCompliance: TestCase{
        Name: "Standard Security Compliance",
        SecurityContext: &SecurityContext{
            Level: "standard",
            Compliance: []string{"SOC2", "ISO27001"},
        },
    },
    SecurityViolation: TestCase{
        Name: "Security Policy Violation",
        SecurityContext: &SecurityContext{
            Level: "high",
            Violations: []string{"oversized_payload", "invalid_schema"},
        },
    },
    AuditRequirement: TestCase{
        Name: "Audit Logging Requirement",
        SecurityContext: &SecurityContext{
            Level: "detailed",
            AuditRequirements: map[string]string{
                "log_level": "debug",
                "retention": "90d",
            },
        },
    },
}

// Sample test payloads
var SamplePayloads = struct {
    ValidPayload json.RawMessage
    OversizedPayload json.RawMessage
    MalformedPayload json.RawMessage
    SecurityViolationPayload json.RawMessage
}{
    ValidPayload: json.RawMessage(`{
        "event_type": "security_alert",
        "severity": "high",
        "source": "test-platform",
        "details": {
            "alert_id": "TEST-001",
            "description": "Test security event"
        }
    }`),
    OversizedPayload: generateOversizedPayload(),
    MalformedPayload: json.RawMessage(`{"invalid"json"}`),
    SecurityViolationPayload: json.RawMessage(`{
        "event_type": "security_violation",
        "severity": "critical",
        "sensitive_data": "exposed_credential",
        "violation_type": "data_leak"
    }`),
}

// GenerateValidBronzeEvent creates a valid Bronze tier event for testing
func GenerateValidBronzeEvent(opts *GenerateOptions) (*bronze.BronzeEvent, error) {
    if opts == nil {
        opts = &GenerateOptions{
            ClientID:       defaultClientID,
            SourcePlatform: defaultSourcePlatform,
            SecurityLevel: defaultSecurityLevel,
            AuditLevel:    defaultAuditLevel,
        }
    }

    // Generate unique event ID
    eventID, err := utils.GenerateUUID()
    if err != nil {
        return nil, errors.WrapError(err, "failed to generate event ID", nil)
    }

    // Create security context
    securityContext := map[string]string{
        "level":     opts.SecurityLevel,
        "audit":     opts.AuditLevel,
        "generated": time.Now().UTC().Format(time.RFC3339Nano),
    }

    // Generate test payload
    payload := SamplePayloads.ValidPayload
    if opts.PayloadSize > 0 {
        payload = generateCustomPayload(opts.PayloadSize)
    }

    // Create event with security validation
    event := &bronze.BronzeEvent{
        ID:             eventID,
        ClientID:       opts.ClientID,
        SourcePlatform: opts.SourcePlatform,
        Timestamp:      time.Now().UTC(),
        Payload:        payload,
        SchemaVersion:  defaultSchemaVersion,
        SecurityContext: securityContext,
        AuditMetadata:  opts.CustomMetadata,
    }

    // Validate event
    if err := utils.ValidateJSON(string(payload), utils.ValidationOptions{
        MaxDepth:   20,
        MaxSize:    maxTestPayloadSize,
        StrictMode: true,
    }); err != nil {
        return nil, errors.WrapError(err, "payload validation failed", nil)
    }

    // Log test event generation
    logging.Info("Generated valid test event", map[string]interface{}{
        "event_id": eventID,
        "client_id": opts.ClientID,
        "security_level": opts.SecurityLevel,
    })

    return event, nil
}

// GenerateInvalidBronzeEvent creates an invalid event for testing error handling
func GenerateInvalidBronzeEvent(invalidationType string, securityContext *SecurityContext) (*bronze.BronzeEvent, error) {
    // Start with a valid event
    baseEvent, err := GenerateValidBronzeEvent(nil)
    if err != nil {
        return nil, err
    }

    switch invalidationType {
    case "missing_client":
        baseEvent.ClientID = ""
    case "invalid_platform":
        baseEvent.SourcePlatform = "invalid-platform"
    case "oversized_payload":
        baseEvent.Payload = SamplePayloads.OversizedPayload
    case "malformed_payload":
        baseEvent.Payload = SamplePayloads.MalformedPayload
    case "security_violation":
        baseEvent.Payload = SamplePayloads.SecurityViolationPayload
        if securityContext != nil {
            baseEvent.SecurityContext = securityContext
        }
    default:
        return nil, errors.NewError("E3001", "invalid invalidation type", map[string]interface{}{
            "type": invalidationType,
        })
    }

    // Log invalid test case
    logging.Info("Generated invalid test event", map[string]interface{}{
        "event_id": baseEvent.ID,
        "invalidation_type": invalidationType,
    })

    return baseEvent, nil
}

// GenerateBronzeEventBatch creates a batch of test events with performance metrics
func GenerateBronzeEventBatch(batchSize int, opts *BatchOptions) ([]*bronze.BronzeEvent, *BatchMetrics, error) {
    if batchSize <= 0 || batchSize > maxBatchSize {
        return nil, nil, errors.NewError("E3001", "invalid batch size", map[string]interface{}{
            "max_size": maxBatchSize,
            "requested_size": batchSize,
        })
    }

    startTime := time.Now()
    events := make([]*bronze.BronzeEvent, 0, batchSize)
    metrics := &BatchMetrics{}

    if opts != nil && opts.Concurrent {
        events, metrics = generateConcurrentBatch(batchSize, opts)
    } else {
        for i := 0; i < batchSize; i++ {
            event, err := GenerateValidBronzeEvent(&GenerateOptions{
                SecurityLevel: defaultSecurityLevel,
                AuditLevel:   defaultAuditLevel,
            })
            if err != nil {
                metrics.FailedEvents++
                continue
            }
            events = append(events, event)

            if opts != nil && opts.ProgressCallback != nil {
                opts.ProgressCallback(i+1, batchSize)
            }
        }
    }

    // Calculate metrics
    metrics.TotalEvents = len(events)
    metrics.GenerationTime = time.Since(startTime)
    metrics.EventsPerSecond = float64(metrics.TotalEvents) / metrics.GenerationTime.Seconds()
    metrics.AveragePayloadSize = calculateAveragePayloadSize(events)

    // Log batch generation
    logging.Info("Generated event batch", map[string]interface{}{
        "batch_size": batchSize,
        "generation_time": metrics.GenerationTime,
        "events_per_second": metrics.EventsPerSecond,
    })

    return events, metrics, nil
}

// Helper functions

func generateConcurrentBatch(batchSize int, opts *BatchOptions) ([]*bronze.BronzeEvent, *BatchMetrics) {
    workerCount := opts.WorkerCount
    if workerCount <= 0 {
        workerCount = 4
    }

    var wg sync.WaitGroup
    eventsChan := make(chan *bronze.BronzeEvent, batchSize)
    errorsChan := make(chan error, batchSize)

    // Start workers
    eventsPerWorker := batchSize / workerCount
    for i := 0; i < workerCount; i++ {
        wg.Add(1)
        go func(workerID int) {
            defer wg.Done()
            for j := 0; j < eventsPerWorker; j++ {
                event, err := GenerateValidBronzeEvent(&GenerateOptions{
                    SecurityLevel: defaultSecurityLevel,
                    AuditLevel:   defaultAuditLevel,
                })
                if err != nil {
                    errorsChan <- err
                    continue
                }
                eventsChan <- event
            }
        }(i)
    }

    // Wait for completion
    wg.Wait()
    close(eventsChan)
    close(errorsChan)

    // Collect results
    events := make([]*bronze.BronzeEvent, 0, batchSize)
    metrics := &BatchMetrics{}

    for event := range eventsChan {
        events = append(events, event)
    }

    for range errorsChan {
        metrics.FailedEvents++
    }

    return events, metrics
}

func generateOversizedPayload() json.RawMessage {
    payload := make([]byte, maxTestPayloadSize+1)
    for i := range payload {
        payload[i] = 'x'
    }
    return json.RawMessage(payload)
}

func generateCustomPayload(size int) json.RawMessage {
    if size > maxTestPayloadSize {
        size = maxTestPayloadSize
    }
    
    payload := struct {
        EventType string    `json:"event_type"`
        Timestamp time.Time `json:"timestamp"`
        Data      string    `json:"data"`
    }{
        EventType: "custom_test_event",
        Timestamp: time.Now().UTC(),
        Data:      string(make([]byte, size)),
    }
    
    data, _ := json.Marshal(payload)
    return json.RawMessage(data)
}

func calculateAveragePayloadSize(events []*bronze.BronzeEvent) int64 {
    if len(events) == 0 {
        return 0
    }

    var totalSize int64
    for _, event := range events {
        totalSize += int64(len(event.Payload))
    }
    return totalSize / int64(len(events))
}