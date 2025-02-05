// Package mocks provides mock implementations for testing the BlackPoint Security Integration Framework
package mocks

import (
    "github.com/confluentinc/confluent-kafka-go/kafka" // v1.9.2
    "sync"
    "time"
    "testing"

    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/logging"
)

// Default configuration values for mock behavior
const (
    defaultMockLatency = 50 * time.Millisecond
    defaultQueueSize   = 10000
    maxMockLatency    = 5 * time.Second
    minQueueSize      = 1000
)

// MockKafkaConfig defines configurable behavior for the mock Kafka client
type MockKafkaConfig struct {
    MockLatency    time.Duration // Simulated processing latency
    QueueSize      int          // Size of message queues per topic
    SimulateErrors bool         // Enable error simulation
    ErrorRate      float64      // Rate of simulated errors (0.0-1.0)
}

// Validate ensures mock configuration parameters are within acceptable bounds
func (c *MockKafkaConfig) Validate() error {
    if c.MockLatency > maxMockLatency {
        return errors.NewError("E2001", "mock latency exceeds maximum allowed value", map[string]interface{}{
            "max_latency": maxMockLatency,
            "provided_latency": c.MockLatency,
        })
    }

    if c.QueueSize < minQueueSize {
        return errors.NewError("E2001", "queue size below minimum required value", map[string]interface{}{
            "min_size": minQueueSize,
            "provided_size": c.QueueSize,
        })
    }

    if c.ErrorRate < 0.0 || c.ErrorRate > 1.0 {
        return errors.NewError("E2001", "error rate must be between 0.0 and 1.0", map[string]interface{}{
            "provided_rate": c.ErrorRate,
        })
    }

    return nil
}

// MockKafkaClient provides a thread-safe mock implementation of the Confluent Kafka client
type MockKafkaClient struct {
    t            *testing.T
    config       MockKafkaConfig
    messageQueues sync.Map // map[string][]byte for thread-safe message storage
    mockLatency  time.Duration
    closed       bool
    mu           sync.Mutex
    wg           sync.WaitGroup
}

// NewMockKafkaClient creates a new mock Kafka client instance with the specified configuration
func NewMockKafkaClient(t *testing.T, config MockKafkaConfig) (*MockKafkaClient, error) {
    if err := config.Validate(); err != nil {
        return nil, err
    }

    // Use default latency if not specified
    if config.MockLatency == 0 {
        config.MockLatency = defaultMockLatency
    }

    // Use default queue size if not specified
    if config.QueueSize == 0 {
        config.QueueSize = defaultQueueSize
    }

    client := &MockKafkaClient{
        t:           t,
        config:      config,
        mockLatency: config.MockLatency,
    }

    logging.Info("initialized mock Kafka client", map[string]interface{}{
        "mock_latency": config.MockLatency,
        "queue_size":   config.QueueSize,
        "error_simulation": config.SimulateErrors,
    })

    return client, nil
}

// Produce simulates message production to a topic with configurable latency and error injection
func (m *MockKafkaClient) Produce(topic string, message []byte) error {
    m.mu.Lock()
    if m.closed {
        m.mu.Unlock()
        return errors.NewError("E2001", "client is closed", nil)
    }
    m.wg.Add(1)
    m.mu.Unlock()

    defer m.wg.Done()

    // Validate inputs
    if topic == "" {
        return errors.NewError("E2001", "topic cannot be empty", nil)
    }
    if len(message) == 0 {
        return errors.NewError("E2001", "message cannot be empty", nil)
    }

    // Simulate processing latency
    time.Sleep(m.mockLatency)

    // Simulate errors if enabled
    if m.config.SimulateErrors && m.config.ErrorRate > 0 {
        if time.Now().UnixNano()%100 < int64(m.config.ErrorRate*100) {
            return errors.NewError("E2001", "simulated production error", map[string]interface{}{
                "topic": topic,
            })
        }
    }

    // Store message in thread-safe queue
    queue, _ := m.messageQueues.LoadOrStore(topic, make([][]byte, 0, m.config.QueueSize))
    messages := queue.([][]byte)
    
    if len(messages) >= m.config.QueueSize {
        return errors.NewError("E2001", "queue size limit exceeded", map[string]interface{}{
            "topic": topic,
            "queue_size": m.config.QueueSize,
        })
    }

    messages = append(messages, message)
    m.messageQueues.Store(topic, messages)

    logging.Info("produced message to mock topic", map[string]interface{}{
        "topic": topic,
        "message_size": len(message),
    })

    return nil
}

// Consume simulates message consumption from a topic with timeout support
func (m *MockKafkaClient) Consume(topic string, timeout time.Duration) ([]byte, error) {
    m.mu.Lock()
    if m.closed {
        m.mu.Unlock()
        return nil, errors.NewError("E2001", "client is closed", nil)
    }
    m.wg.Add(1)
    m.mu.Unlock()

    defer m.wg.Done()

    // Validate inputs
    if topic == "" {
        return nil, errors.NewError("E2001", "topic cannot be empty", nil)
    }
    if timeout <= 0 {
        return nil, errors.NewError("E2001", "timeout must be positive", nil)
    }

    // Simulate processing latency
    time.Sleep(m.mockLatency)

    // Set up timeout channel
    timeoutChan := time.After(timeout)

    // Try to consume message
    for {
        select {
        case <-timeoutChan:
            return nil, errors.NewError("E2001", "consumption timeout", map[string]interface{}{
                "topic": topic,
                "timeout": timeout,
            })
        default:
            if queue, exists := m.messageQueues.Load(topic); exists {
                messages := queue.([][]byte)
                if len(messages) > 0 {
                    // Remove and return first message
                    message := messages[0]
                    m.messageQueues.Store(topic, messages[1:])

                    logging.Info("consumed message from mock topic", map[string]interface{}{
                        "topic": topic,
                        "message_size": len(message),
                    })

                    return message, nil
                }
            }
            time.Sleep(10 * time.Millisecond) // Prevent tight loop
        }
    }
}

// Close performs cleanup of mock client resources
func (m *MockKafkaClient) Close() error {
    m.mu.Lock()
    if m.closed {
        m.mu.Unlock()
        return errors.NewError("E2001", "client already closed", nil)
    }
    m.closed = true
    m.mu.Unlock()

    // Wait for ongoing operations to complete
    m.wg.Wait()

    // Clear message queues
    m.messageQueues.Range(func(key, value interface{}) bool {
        m.messageQueues.Delete(key)
        return true
    })

    logging.Info("closed mock Kafka client")
    return nil
}