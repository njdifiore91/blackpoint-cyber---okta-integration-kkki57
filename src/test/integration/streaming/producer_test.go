package streaming_test

import (
    "context"
    "testing"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/stretchr/testify/require"

    "../../pkg/mocks/confluent"
    "../../internal/framework/test_suite"
    "../../../backend/internal/streaming/producer"
    "../../pkg/fixtures"
)

const (
    testTopic     = "test-events"
    testTimeout   = 5 * time.Second
    batchSize     = 1000
    maxRetries    = 3
    retryBackoff  = 100 * time.Millisecond
)

// Prometheus metrics for producer testing
var (
    producerLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_producer_test_latency_seconds",
            Help: "Producer operation latency in seconds",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
        },
        []string{"operation", "status"},
    )

    producerThroughput = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackpoint_producer_test_throughput",
            Help: "Producer throughput in events per second",
        },
        []string{"operation"},
    )

    producerErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_producer_test_errors_total",
            Help: "Total number of producer errors by type",
        },
        []string{"error_type"},
    )
)

func init() {
    // Register metrics
    prometheus.MustRegister(producerLatency, producerThroughput, producerErrors)
}

func TestProducerIntegration(t *testing.T) {
    // Create test suite with security context
    suite := test_suite.NewTestSuite(t, "ProducerIntegration", &test_suite.TestConfig{
        Timeout: 5 * time.Minute,
        SecurityEnabled: true,
        MonitoringEnabled: true,
        ValidationConfig: map[string]float64{
            "accuracy": 80.0,
            "performance": 95.0,
            "security": 90.0,
        },
    })

    // Add test cases
    suite.AddTestCase(&test_suite.TestCase{
        Name: "SingleEventPublish",
        Exec: func(ctx context.Context) error {
            return testSingleEventPublish(ctx, t)
        },
    })

    suite.AddTestCase(&test_suite.TestCase{
        Name: "BatchEventPublish",
        Exec: func(ctx context.Context) error {
            return testBatchEventPublish(ctx, t)
        },
    })

    suite.AddTestCase(&test_suite.TestCase{
        Name: "ProducerReliability",
        Exec: func(ctx context.Context) error {
            return testProducerReliability(ctx, t)
        },
    })

    // Run test suite
    if err := suite.Run(); err != nil {
        t.Fatalf("Test suite failed: %v", err)
    }
}

func testSingleEventPublish(ctx context.Context, t *testing.T) error {
    // Create mock Kafka client with security context
    mockClient, err := confluent.NewMockKafkaClient(t, confluent.MockKafkaConfig{
        MockLatency: 10 * time.Millisecond,
        SimulateErrors: false,
    })
    require.NoError(t, err)
    defer mockClient.Close()

    // Create producer with monitoring
    prod, err := producer.NewProducer(mockClient, testTopic, &producer.ProducerOptions{
        DeliveryTimeout: testTimeout,
        BatchSize: batchSize,
        RetryAttempts: maxRetries,
        BackoffInitial: retryBackoff,
    })
    require.NoError(t, err)
    defer prod.Close()

    // Generate test event
    event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
        SecurityLevel: "high",
        AuditLevel: "detailed",
    })
    require.NoError(t, err)

    // Measure latency
    start := time.Now()
    timer := prometheus.NewTimer(producerLatency.WithLabelValues("single", "success"))
    defer timer.ObserveDuration()

    // Publish event
    eventData, err := event.ToJSON()
    require.NoError(t, err)

    err = prod.Publish(ctx, eventData)
    require.NoError(t, err)

    // Validate latency requirement (<1s for Bronze tier)
    latency := time.Since(start)
    require.Less(t, latency, time.Second, "Bronze tier latency requirement not met")

    return nil
}

func testBatchEventPublish(ctx context.Context, t *testing.T) error {
    // Create mock Kafka client
    mockClient, err := confluent.NewMockKafkaClient(t, confluent.MockKafkaConfig{
        MockLatency: 10 * time.Millisecond,
        QueueSize: batchSize * 2,
    })
    require.NoError(t, err)
    defer mockClient.Close()

    // Create producer
    prod, err := producer.NewProducer(mockClient, testTopic, &producer.ProducerOptions{
        DeliveryTimeout: testTimeout,
        BatchSize: batchSize,
    })
    require.NoError(t, err)
    defer prod.Close()

    // Generate batch of test events
    events, metrics, err := fixtures.GenerateBronzeEventBatch(batchSize, &fixtures.BatchOptions{
        Concurrent: true,
        WorkerCount: 4,
        SecurityContext: &fixtures.SecurityContext{
            Level: "high",
            Compliance: []string{"SOC2", "ISO27001"},
        },
    })
    require.NoError(t, err)

    // Convert events to JSON
    eventBatch := make([][]byte, len(events))
    for i, event := range events {
        data, err := event.ToJSON()
        require.NoError(t, err)
        eventBatch[i] = data
    }

    // Measure throughput
    start := time.Now()
    timer := prometheus.NewTimer(producerLatency.WithLabelValues("batch", "success"))
    defer timer.ObserveDuration()

    // Publish batch
    err = prod.PublishBatch(ctx, eventBatch)
    require.NoError(t, err)

    // Calculate and validate throughput
    duration := time.Since(start)
    throughput := float64(len(events)) / duration.Seconds()
    producerThroughput.WithLabelValues("batch").Set(throughput)

    require.GreaterOrEqual(t, throughput, float64(1000), 
        "Minimum throughput requirement not met: %v events/second", throughput)

    return nil
}

func testProducerReliability(ctx context.Context, t *testing.T) error {
    // Create mock Kafka client with error simulation
    mockClient, err := confluent.NewMockKafkaClient(t, confluent.MockKafkaConfig{
        SimulateErrors: true,
        ErrorRate: 0.2, // 20% error rate
    })
    require.NoError(t, err)
    defer mockClient.Close()

    // Create producer with retry configuration
    prod, err := producer.NewProducer(mockClient, testTopic, &producer.ProducerOptions{
        RetryAttempts: maxRetries,
        BackoffInitial: retryBackoff,
    })
    require.NoError(t, err)
    defer prod.Close()

    // Generate test event
    event, err := fixtures.GenerateValidBronzeEvent(nil)
    require.NoError(t, err)

    eventData, err := event.ToJSON()
    require.NoError(t, err)

    // Test retry mechanism
    start := time.Now()
    err = prod.Publish(ctx, eventData)
    require.NoError(t, err)

    // Validate retry behavior
    metrics := prod.GetMetrics()
    require.NotNil(t, metrics)
    require.GreaterOrEqual(t, metrics["retry_count"], float64(0))
    require.Less(t, metrics["retry_count"], float64(maxRetries))

    // Test circuit breaker
    mockClient.SimulateError("connection_error")
    err = prod.Publish(ctx, eventData)
    require.Error(t, err)
    require.Contains(t, err.Error(), "circuit breaker")

    producerErrors.WithLabelValues("circuit_breaker").Inc()

    return nil
}