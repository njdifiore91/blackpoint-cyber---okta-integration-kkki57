// Package streaming provides integration tests for the Kafka consumer implementation
package streaming

import (
    "context"
    "testing"
    "time"
    "sync/atomic"

    "github.com/stretchr/testify/assert" // v1.8.4
    "github.com/confluentinc/confluent-kafka-go/kafka" // v1.9.2
    "github.com/rcrowley/go-metrics" // v0.0.0-20201227073835-cf1acfcdf475

    "../../internal/framework/test_case"
    "../../pkg/mocks/confluent"
    "../../../backend/internal/streaming/consumer"
)

// Global test constants
const (
    testTimeout = 5 * time.Minute
    testTopic = "test-events"
    messageCount = 10000
    expectedThroughput = 1000 // events/second
    bronzeLatencyThreshold = time.Second
    silverLatencyThreshold = 5 * time.Second
    goldLatencyThreshold = 30 * time.Second
)

// TestMain handles test suite setup and teardown
func TestMain(m *testing.M) {
    // Initialize test metrics registry
    metrics.UseNilMetrics()

    // Run tests
    m.Run()
}

// TestConsumerBasicFunctionality tests the core consumer functionality
func TestConsumerBasicFunctionality(t *testing.T) {
    // Create test case with cleanup
    tc := test_case.NewTestCase(t, "ConsumerBasicFunctionality", &test_case.TestConfig{
        Timeout: testTimeout,
        Labels: map[string]string{
            "component": "consumer",
            "test_type": "integration",
        },
    })

    // Create mock Kafka client
    mockClient, err := confluent.NewMockKafkaClient(t, confluent.MockKafkaConfig{
        MockLatency: 10 * time.Millisecond,
        QueueSize: messageCount * 2,
        SimulateErrors: true,
        ErrorRate: 0.01, // 1% error rate
    })
    assert.NoError(t, err)

    // Configure consumer
    consumerConfig := &kafka.ConfigMap{
        "bootstrap.servers": "mock",
        "group.id": "test-group",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": false,
    }

    // Create consumer instance
    c, err := consumer.NewConsumer(consumerConfig, []string{testTopic}, consumer.ConsumerOptions{
        BatchSize: 100,
        CommitInterval: time.Second,
        EnableMetrics: true,
    })
    assert.NoError(t, err)

    // Add test steps
    tc.AddStep(&test_case.TestStep{
        Name: "Start Consumer",
        Exec: func(ctx context.Context) error {
            return c.Start()
        },
        Cleanup: func(ctx context.Context) error {
            return c.Stop()
        },
        Critical: true,
    })

    // Produce test messages
    var processedCount uint64
    tc.AddStep(&test_case.TestStep{
        Name: "Process Messages",
        Exec: func(ctx context.Context) error {
            // Produce messages across different tiers
            tiers := []string{"bronze", "silver", "gold"}
            for i := 0; i < messageCount; i++ {
                tier := tiers[i%len(tiers)]
                topic := testTopic + "-" + tier
                
                msg := &kafka.Message{
                    TopicPartition: kafka.TopicPartition{
                        Topic: &topic,
                        Partition: 0,
                    },
                    Value: []byte("test message"),
                    Timestamp: time.Now(),
                }

                if err := mockClient.Produce(topic, msg.Value); err != nil {
                    return err
                }

                atomic.AddUint64(&processedCount, 1)
            }
            return nil
        },
        Timeout: 2 * time.Minute,
    })

    // Validate processing metrics
    tc.AddStep(&test_case.TestStep{
        Name: "Validate Metrics",
        Exec: func(ctx context.Context) error {
            metrics := c.GetMetrics()

            // Verify message count
            assert.Equal(t, messageCount, int(metrics.EventsProcessed), 
                "incorrect number of messages processed")

            // Verify throughput
            duration := metrics.ProcessingTime.Seconds()
            throughput := float64(metrics.EventsProcessed) / duration
            assert.GreaterOrEqual(t, throughput, float64(expectedThroughput),
                "throughput below requirement of %d events/second", expectedThroughput)

            // Verify batch sizes
            for _, size := range metrics.BatchSizes {
                assert.LessOrEqual(t, size, 100, "batch size exceeded maximum")
                assert.Greater(t, size, 0, "empty batch detected")
            }

            // Verify error rate
            errorRate := float64(metrics.Errors) / float64(metrics.EventsProcessed)
            assert.LessOrEqual(t, errorRate, 0.02, "error rate exceeded threshold")

            return nil
        },
        Timeout: 30 * time.Second,
    })

    // Run test case
    tc.Run()
}

// TestConsumerErrorHandling tests consumer error handling capabilities
func TestConsumerErrorHandling(t *testing.T) {
    // Create test case
    tc := test_case.NewTestCase(t, "ConsumerErrorHandling", &test_case.TestConfig{
        Timeout: testTimeout,
        Labels: map[string]string{
            "component": "consumer",
            "test_type": "integration",
        },
    })

    // Create mock client with high error rate
    mockClient, err := confluent.NewMockKafkaClient(t, confluent.MockKafkaConfig{
        MockLatency: 10 * time.Millisecond,
        QueueSize: 1000,
        SimulateErrors: true,
        ErrorRate: 0.2, // 20% error rate
    })
    assert.NoError(t, err)

    // Configure consumer
    consumerConfig := &kafka.ConfigMap{
        "bootstrap.servers": "mock",
        "group.id": "test-group",
        "auto.offset.reset": "earliest",
        "enable.auto.commit": false,
    }

    // Create consumer
    c, err := consumer.NewConsumer(consumerConfig, []string{testTopic}, consumer.ConsumerOptions{
        BatchSize: 50,
        CommitInterval: time.Second,
        EnableMetrics: true,
    })
    assert.NoError(t, err)

    // Test error handling
    tc.AddStep(&test_case.TestStep{
        Name: "Handle Errors",
        Exec: func(ctx context.Context) error {
            if err := c.Start(); err != nil {
                return err
            }

            // Produce messages that will generate errors
            for i := 0; i < 1000; i++ {
                msg := &kafka.Message{
                    TopicPartition: kafka.TopicPartition{
                        Topic: &testTopic,
                        Partition: 0,
                    },
                    Value: []byte("error test message"),
                }
                mockClient.Produce(testTopic, msg.Value)
            }

            // Allow time for error processing
            time.Sleep(10 * time.Second)

            metrics := c.GetMetrics()
            assert.Greater(t, metrics.Errors, uint64(0), "no errors detected")
            assert.Less(t, metrics.Errors, uint64(1000), "too many errors")

            return c.Stop()
        },
        Timeout: time.Minute,
    })

    // Run test case
    tc.Run()
}