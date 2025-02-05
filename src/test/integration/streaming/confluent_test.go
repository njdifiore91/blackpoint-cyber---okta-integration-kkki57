// Package streaming provides integration tests for Confluent Kafka functionality
package streaming

import (
    "context"
    "encoding/json"
    "sync"
    "testing"
    "time"

    "github.com/stretchr/testify/require"
    "github.com/prometheus/client_golang/prometheus"

    "../../internal/framework/test_suite"
    "../../../backend/internal/streaming/confluent"
    "../../pkg/mocks/confluent"
    "../../pkg/fixtures"
)

// Test configuration constants
const (
    testTimeout = 5 * time.Minute
    defaultTopic = "test-events"
    messageCount = 10000
    maxRetries = 3
    retryDelay = 5 * time.Second
)

// Prometheus metrics
var (
    testLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_kafka_test_latency_seconds",
            Help: "Kafka test execution latency in seconds",
            Buckets: prometheus.ExponentialBuckets(0.01, 2, 10),
        },
        []string{"test_name", "operation"},
    )

    messageProcessingRate = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackpoint_kafka_test_processing_rate",
            Help: "Message processing rate per second",
        },
        []string{"test_name", "operation"},
    )

    testErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_kafka_test_errors_total",
            Help: "Total number of test errors",
        },
        []string{"test_name", "error_type"},
    )
)

func init() {
    // Register metrics
    prometheus.MustRegister(testLatency, messageProcessingRate, testErrors)
}

// TestMain handles test suite setup and teardown
func TestMain(m *testing.M) {
    // Initialize test suite with security context
    suite := test_suite.NewTestSuite(nil, "confluent-integration", &test_suite.TestConfig{
        Timeout: testTimeout,
        SecurityEnabled: true,
        MonitoringEnabled: true,
        ValidationConfig: map[string]float64{
            "accuracy": 80.0,
            "performance": 95.0,
        },
    })

    // Set up metrics collection
    suite.SetupMetrics()

    // Run tests
    code := m.Run()

    // Export final metrics
    suite.ExportMetrics()

    os.Exit(code)
}

// TestConfluentIntegration executes the main integration test suite
func TestConfluentIntegration(t *testing.T) {
    // Create test suite
    suite := NewConfluentTestSuite(t)
    require.NotNil(t, suite)

    // Add test cases
    suite.AddTestCase(&test_suite.TestCase{
        Name: "BasicProduceConsume",
        Exec: suite.TestBasicProduceConsume,
    })

    suite.AddTestCase(&test_suite.TestCase{
        Name: "HighThroughput",
        Exec: suite.TestHighThroughput,
    })

    suite.AddTestCase(&test_suite.TestCase{
        Name: "ErrorHandling",
        Exec: suite.TestErrorHandling,
    })

    // Run test suite
    require.NoError(t, suite.Run())
}

// ConfluentTestSuite provides a structured test suite for Confluent integration
type ConfluentTestSuite struct {
    t *testing.T
    client *confluent.KafkaClient
    mockClient *confluent.MockKafkaClient
    ctx context.Context
    cancel context.CancelFunc
}

// NewConfluentTestSuite creates a new test suite instance
func NewConfluentTestSuite(t *testing.T) *ConfluentTestSuite {
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)

    // Initialize real client
    client, err := confluent.NewKafkaClient(&confluent.KafkaConfig{
        BootstrapServers: "localhost:9092",
        SecurityProtocol: "SASL_SSL",
        SaslMechanism: "PLAIN",
        SaslUsername: "test-user",
        SaslPassword: "test-pass",
        EnableMetrics: true,
    })
    require.NoError(t, err)

    // Initialize mock client
    mockClient, err := confluent.NewMockKafkaClient(t, confluent.MockKafkaConfig{
        MockLatency: 50 * time.Millisecond,
        QueueSize: messageCount,
        SimulateErrors: true,
        ErrorRate: 0.01,
    })
    require.NoError(t, err)

    return &ConfluentTestSuite{
        t: t,
        client: client,
        mockClient: mockClient,
        ctx: ctx,
        cancel: cancel,
    }
}

// TestBasicProduceConsume validates basic message production and consumption
func (s *ConfluentTestSuite) TestBasicProduceConsume() error {
    timer := prometheus.NewTimer(testLatency.WithLabelValues("BasicProduceConsume", "total"))
    defer timer.ObserveDuration()

    // Generate test event
    event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
        SecurityLevel: "standard",
        AuditLevel: "detailed",
    })
    if err != nil {
        return err
    }

    // Produce message
    startProduce := time.Now()
    err = s.mockClient.Produce(defaultTopic, event.Payload)
    if err != nil {
        testErrors.WithLabelValues("BasicProduceConsume", "produce").Inc()
        return err
    }
    testLatency.WithLabelValues("BasicProduceConsume", "produce").Observe(time.Since(startProduce).Seconds())

    // Consume message
    startConsume := time.Now()
    msg, err := s.mockClient.Consume(defaultTopic, 5*time.Second)
    if err != nil {
        testErrors.WithLabelValues("BasicProduceConsume", "consume").Inc()
        return err
    }
    testLatency.WithLabelValues("BasicProduceConsume", "consume").Observe(time.Since(startConsume).Seconds())

    // Validate message
    require.Equal(s.t, event.Payload, msg)

    return nil
}

// TestHighThroughput validates high-throughput message processing
func (s *ConfluentTestSuite) TestHighThroughput() error {
    timer := prometheus.NewTimer(testLatency.WithLabelValues("HighThroughput", "total"))
    defer timer.ObserveDuration()

    var wg sync.WaitGroup
    errors := make(chan error, messageCount)
    
    // Generate test events
    events, metrics, err := fixtures.GenerateBronzeEventBatch(messageCount, &fixtures.BatchOptions{
        Concurrent: true,
        WorkerCount: 4,
        SecurityContext: &fixtures.SecurityContext{
            Level: "standard",
            Compliance: []string{"SOC2", "ISO27001"},
        },
    })
    if err != nil {
        return err
    }

    // Produce messages concurrently
    startTime := time.Now()
    for _, event := range events {
        wg.Add(1)
        go func(e *bronze.BronzeEvent) {
            defer wg.Done()
            if err := s.mockClient.Produce(defaultTopic, e.Payload); err != nil {
                errors <- err
            }
        }(event)
    }

    // Wait for completion
    wg.Wait()
    close(errors)

    // Calculate throughput
    duration := time.Since(startTime)
    throughput := float64(messageCount) / duration.Seconds()
    messageProcessingRate.WithLabelValues("HighThroughput", "produce").Set(throughput)

    // Check for errors
    if len(errors) > 0 {
        for err := range errors {
            testErrors.WithLabelValues("HighThroughput", "produce").Inc()
            s.t.Logf("Production error: %v", err)
        }
        return fmt.Errorf("encountered %d errors during high throughput test", len(errors))
    }

    // Validate throughput meets requirements
    require.GreaterOrEqual(s.t, throughput, float64(1000), "Throughput below minimum requirement")

    return nil
}

// TestErrorHandling validates error handling and recovery
func (s *ConfluentTestSuite) TestErrorHandling() error {
    timer := prometheus.NewTimer(testLatency.WithLabelValues("ErrorHandling", "total"))
    defer timer.ObserveDuration()

    // Test with invalid message
    invalidEvent, err := fixtures.GenerateInvalidBronzeEvent("malformed_payload", nil)
    require.NoError(s.t, err)

    // Expect error for invalid message
    err = s.mockClient.Produce(defaultTopic, invalidEvent.Payload)
    require.Error(s.t, err)
    testErrors.WithLabelValues("ErrorHandling", "validation").Inc()

    // Test with security violation
    securityViolation, err := fixtures.GenerateInvalidBronzeEvent("security_violation", &fixtures.SecurityContext{
        Level: "high",
        Violations: []string{"oversized_payload"},
    })
    require.NoError(s.t, err)

    // Expect error for security violation
    err = s.mockClient.Produce(defaultTopic, securityViolation.Payload)
    require.Error(s.t, err)
    testErrors.WithLabelValues("ErrorHandling", "security").Inc()

    // Test retry logic
    retryEvent, err := fixtures.GenerateValidBronzeEvent(nil)
    require.NoError(s.t, err)

    // Simulate temporary failure with retry
    s.mockClient.SimulateError(true)
    var lastErr error
    for i := 0; i <= maxRetries; i++ {
        if err := s.mockClient.Produce(defaultTopic, retryEvent.Payload); err == nil {
            break
        } else {
            lastErr = err
            time.Sleep(retryDelay)
        }
    }
    require.NoError(s.t, lastErr, "Failed after max retries")

    return nil
}