// Package integration provides integration tests for the BlackPoint Security Integration Framework
package integration

import (
    "context"
    "encoding/json"
    "sync"
    "testing"
    "time"

    "github.com/blackpoint/internal/normalizer"
    "github.com/blackpoint/pkg/bronze/schema"
    "github.com/blackpoint/pkg/silver/schema"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/stretchr/testify/suite"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
)

// Global test constants
const (
    testTimeout = 30 * time.Second
    testBatchSize = 1000
    processingLatencySLA = 5 * time.Second
    minThroughputSLA = 1000.0 // events/second
    minAccuracySLA = 0.80
)

var testSourceTypes = []string{"aws-security", "azure-ad", "okta"}

// NormalizerTestSuite defines the integration test suite
type NormalizerTestSuite struct {
    suite.Suite
    processor       *normalizer.Processor
    ctx            context.Context
    cancel         context.CancelFunc
    securityContext schema.SecurityContext
}

// SetupSuite initializes the test suite
func (s *NormalizerTestSuite) SetupSuite() {
    // Initialize security context
    s.securityContext = schema.SecurityContext{
        Classification: "INTERNAL",
        Sensitivity:   "MEDIUM",
        Compliance:    []string{"DEFAULT"},
        Encryption:    make(map[string]string),
        AccessControl: make(map[string]string),
    }

    // Create field mapper with test mappings
    mapper := normalizer.NewFieldMapper(map[string]string{
        "source.ip": "src_ip",
        "dest.ip":   "dst_ip",
        "timestamp": "event_time",
        "type":      "event_type",
    }, nil)

    // Create transformer with test timeout
    transformer := normalizer.NewTransformer(5 * time.Second)

    // Initialize processor
    var err error
    s.processor, err = normalizer.NewProcessor(mapper, transformer, processingLatencySLA)
    require.NoError(s.T(), err, "Failed to create processor")

    // Create test context
    s.ctx, s.cancel = context.WithTimeout(context.Background(), testTimeout)
}

// TearDownSuite cleans up test resources
func (s *NormalizerTestSuite) TearDownSuite() {
    s.cancel()
}

// TestNormalizerProcessSingle tests single event normalization
func (s *NormalizerTestSuite) TestNormalizerProcessSingle() {
    // Create test Bronze event
    bronzeEvent := &schema.BronzeEvent{
        ID:             "test-event-1",
        ClientID:       "test-client",
        SourcePlatform: "aws-security",
        Timestamp:      time.Now().UTC(),
        Payload:        json.RawMessage(`{
            "source": {"ip": "192.168.1.1"},
            "dest": {"ip": "10.0.0.1"},
            "timestamp": "2024-01-20T10:00:00Z",
            "type": "SecurityAlert",
            "severity": "HIGH",
            "sensitive_data": "test-secret"
        }`),
        SchemaVersion:  "1.0",
    }

    // Process single event
    startTime := time.Now()
    silverEvent, err := s.processor.ProcessSingle(s.ctx, bronzeEvent)
    processingTime := time.Since(startTime)

    // Validate processing
    require.NoError(s.T(), err, "Single event processing failed")
    require.NotNil(s.T(), silverEvent, "Nil Silver event returned")

    // Validate processing latency
    assert.Less(s.T(), processingTime, processingLatencySLA, 
        "Processing time exceeded SLA: %v", processingTime)

    // Validate field mapping
    assert.Equal(s.T(), "192.168.1.1", silverEvent.NormalizedData["src_ip"])
    assert.Equal(s.T(), "10.0.0.1", silverEvent.NormalizedData["dst_ip"])
    assert.Equal(s.T(), "SecurityAlert", silverEvent.EventType)

    // Validate schema compliance
    err = silverEvent.Validate()
    assert.NoError(s.T(), err, "Silver event schema validation failed")

    // Validate security controls
    assert.NotContains(s.T(), silverEvent.NormalizedData, "sensitive_data", 
        "Sensitive data not properly encrypted")
    assert.NotEmpty(s.T(), silverEvent.EncryptedFields, 
        "No encrypted fields present")
}

// TestNormalizerProcessBatch tests batch event processing
func (s *NormalizerTestSuite) TestNormalizerProcessBatch() {
    // Generate test batch
    bronzeEvents := make([]*schema.BronzeEvent, testBatchSize)
    for i := 0; i < testBatchSize; i++ {
        bronzeEvents[i] = &schema.BronzeEvent{
            ID:             fmt.Sprintf("test-event-%d", i),
            ClientID:       "test-client",
            SourcePlatform: testSourceTypes[i%len(testSourceTypes)],
            Timestamp:      time.Now().UTC(),
            Payload:        json.RawMessage(fmt.Sprintf(`{
                "source": {"ip": "192.168.1.%d"},
                "dest": {"ip": "10.0.0.%d"},
                "timestamp": "%s",
                "type": "SecurityAlert",
                "severity": "MEDIUM",
                "sensitive_data": "secret-%d"
            }`, i%255, i%255, time.Now().UTC().Format(time.RFC3339), i)),
            SchemaVersion:  "1.0",
        }
    }

    // Process batch
    startTime := time.Now()
    silverEvents, err := s.processor.Process(s.ctx, bronzeEvents)
    processingTime := time.Since(startTime)

    // Validate processing
    require.NoError(s.T(), err, "Batch processing failed")
    require.Len(s.T(), silverEvents, testBatchSize, 
        "Not all events processed")

    // Calculate throughput
    throughput := float64(testBatchSize) / processingTime.Seconds()
    assert.GreaterOrEqual(s.T(), throughput, minThroughputSLA,
        "Throughput below SLA: %.2f events/second", throughput)

    // Validate batch results
    var validCount int
    for _, event := range silverEvents {
        // Validate schema
        if err := event.Validate(); err == nil {
            validCount++
        }

        // Validate security controls
        assert.NotContains(s.T(), event.NormalizedData, "sensitive_data",
            "Sensitive data not encrypted in event: %s", event.EventID)
        assert.NotEmpty(s.T(), event.EncryptedFields,
            "Missing encrypted fields in event: %s", event.EventID)
    }

    // Calculate accuracy
    accuracy := float64(validCount) / float64(testBatchSize)
    assert.GreaterOrEqual(s.T(), accuracy, minAccuracySLA,
        "Accuracy below SLA: %.2f", accuracy)
}

// TestNormalizerSecurityControls tests security features
func (s *NormalizerTestSuite) TestNormalizerSecurityControls() {
    // Create test event with sensitive data
    bronzeEvent := &schema.BronzeEvent{
        ID:             "test-security-1",
        ClientID:       "test-client",
        SourcePlatform: "aws-security",
        Timestamp:      time.Now().UTC(),
        Payload:        json.RawMessage(`{
            "source": {"ip": "192.168.1.1"},
            "dest": {"ip": "10.0.0.1"},
            "timestamp": "2024-01-20T10:00:00Z",
            "type": "SecurityAlert",
            "password": "secret123",
            "api_key": "key123",
            "auth_token": "token123"
        }`),
        SchemaVersion:  "1.0",
    }

    // Process event
    silverEvent, err := s.processor.ProcessSingle(s.ctx, bronzeEvent)
    require.NoError(s.T(), err, "Processing failed")

    // Validate sensitive field encryption
    sensitiveFields := []string{"password", "api_key", "auth_token"}
    for _, field := range sensitiveFields {
        assert.NotContains(s.T(), silverEvent.NormalizedData, field,
            "Sensitive field not removed: %s", field)
        assert.Contains(s.T(), silverEvent.EncryptedFields, field,
            "Field not encrypted: %s", field)
    }

    // Validate security context
    assert.NotEmpty(s.T(), silverEvent.SecurityContext.Classification)
    assert.NotEmpty(s.T(), silverEvent.SecurityContext.Sensitivity)
    assert.NotEmpty(s.T(), silverEvent.SecurityContext.Compliance)
}

// TestNormalizerConcurrency tests concurrent processing
func (s *NormalizerTestSuite) TestNormalizerConcurrency() {
    const concurrentBatches = 5
    batchSize := testBatchSize / concurrentBatches

    var wg sync.WaitGroup
    results := make(chan error, concurrentBatches)

    // Process multiple batches concurrently
    for i := 0; i < concurrentBatches; i++ {
        wg.Add(1)
        go func(batchNum int) {
            defer wg.Done()

            // Generate batch
            bronzeEvents := make([]*schema.BronzeEvent, batchSize)
            for j := 0; j < batchSize; j++ {
                bronzeEvents[j] = &schema.BronzeEvent{
                    ID:             fmt.Sprintf("test-concurrent-%d-%d", batchNum, j),
                    ClientID:       fmt.Sprintf("test-client-%d", batchNum),
                    SourcePlatform: testSourceTypes[j%len(testSourceTypes)],
                    Timestamp:      time.Now().UTC(),
                    Payload:        json.RawMessage(fmt.Sprintf(`{
                        "source": {"ip": "192.168.%d.%d"},
                        "dest": {"ip": "10.0.%d.%d"},
                        "timestamp": "%s",
                        "type": "SecurityAlert"
                    }`, batchNum, j%255, batchNum, j%255, time.Now().UTC().Format(time.RFC3339))),
                    SchemaVersion:  "1.0",
                }
            }

            // Process batch
            _, err := s.processor.Process(s.ctx, bronzeEvents)
            results <- err
        }(i)
    }

    // Wait for completion
    wg.Wait()
    close(results)

    // Validate results
    for err := range results {
        assert.NoError(s.T(), err, "Concurrent batch processing failed")
    }
}

// TestMain runs the test suite
func TestMain(m *testing.M) {
    suite.Run(m, new(NormalizerTestSuite))
}