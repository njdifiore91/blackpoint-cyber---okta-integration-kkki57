// Package streaming provides Kafka streaming functionality for the BlackPoint Security Integration Framework
package streaming

import (
    "context"
    "sync"
    "time"

    "github.com/confluentinc/confluent-kafka-go/kafka" // v1.9.2
    "github.com/prometheus/client_golang/prometheus" // v1.16.0
    "../../pkg/common/errors"
    "../../pkg/common/logging"
)

// Default configuration values for the producer
const (
    defaultDeliveryTimeout = 30 * time.Second
    defaultBatchSize = 1000
    defaultRetryAttempts = 3
    defaultBackoffInitial = 100 * time.Millisecond
    defaultBackoffMax = 2 * time.Second
    defaultCircuitBreakerThreshold = 0.5
    defaultCircuitBreakerTimeout = 30 * time.Second
)

// ProducerOptions configures the behavior of the Producer
type ProducerOptions struct {
    DeliveryTimeout time.Duration
    BatchSize int
    RetryAttempts int
    BackoffInitial time.Duration
    BackoffMax time.Duration
    CircuitBreakerThreshold float64
    CircuitBreakerTimeout time.Duration
}

// CircuitBreaker implements circuit breaking for producer operations
type CircuitBreaker struct {
    failures uint64
    total uint64
    threshold float64
    timeout time.Duration
    lastTrip time.Time
    mu sync.RWMutex
}

// Producer implements a high-performance Kafka producer with monitoring and circuit breaking
type Producer struct {
    producer *kafka.Producer
    client *KafkaClient
    topic string
    deliveryTimeout time.Duration
    messagePool *sync.Pool
    circuitBreaker *CircuitBreaker
    metricsRecorder *prometheus.Recorder
}

// NewProducer creates a new Producer instance with optimized configuration
func NewProducer(client *KafkaClient, topic string, opts *ProducerOptions) (*Producer, error) {
    if client == nil {
        return nil, errors.NewError("E2001", "kafka client is required", nil)
    }
    if topic == "" {
        return nil, errors.NewError("E2001", "topic is required", nil)
    }

    // Apply default options if not specified
    if opts == nil {
        opts = &ProducerOptions{}
    }
    if opts.DeliveryTimeout == 0 {
        opts.DeliveryTimeout = defaultDeliveryTimeout
    }
    if opts.BatchSize == 0 {
        opts.BatchSize = defaultBatchSize
    }
    if opts.RetryAttempts == 0 {
        opts.RetryAttempts = defaultRetryAttempts
    }
    if opts.BackoffInitial == 0 {
        opts.BackoffInitial = defaultBackoffInitial
    }
    if opts.BackoffMax == 0 {
        opts.BackoffMax = defaultBackoffMax
    }
    if opts.CircuitBreakerThreshold == 0 {
        opts.CircuitBreakerThreshold = defaultCircuitBreakerThreshold
    }
    if opts.CircuitBreakerTimeout == 0 {
        opts.CircuitBreakerTimeout = defaultCircuitBreakerTimeout
    }

    // Get base configuration from client
    config := client.GetConfig()

    // Configure producer-specific settings
    config.SetKey("enable.idempotence", true)
    config.SetKey("compression.type", "snappy")
    config.SetKey("batch.size", opts.BatchSize)
    config.SetKey("linger.ms", 20)
    config.SetKey("retries", opts.RetryAttempts)
    config.SetKey("delivery.timeout.ms", int(opts.DeliveryTimeout.Milliseconds()))

    // Create Kafka producer
    producer, err := kafka.NewProducer(config)
    if err != nil {
        return nil, errors.WrapError(err, "failed to create kafka producer", nil)
    }

    // Initialize message pool for memory optimization
    messagePool := &sync.Pool{
        New: func() interface{} {
            return &kafka.Message{
                TopicPartition: kafka.TopicPartition{
                    Topic: &topic,
                },
            }
        },
    }

    // Initialize circuit breaker
    circuitBreaker := &CircuitBreaker{
        threshold: opts.CircuitBreakerThreshold,
        timeout: opts.CircuitBreakerTimeout,
    }

    // Initialize metrics recorder
    metricsRecorder := prometheus.NewRecorder(prometheus.RecorderOpts{
        Namespace: "blackpoint",
        Subsystem: "kafka_producer",
    })

    p := &Producer{
        producer: producer,
        client: client,
        topic: topic,
        deliveryTimeout: opts.DeliveryTimeout,
        messagePool: messagePool,
        circuitBreaker: circuitBreaker,
        metricsRecorder: metricsRecorder,
    }

    logging.Info("Kafka producer initialized",
        logging.Field("topic", topic),
        logging.Field("batch_size", opts.BatchSize),
    )

    return p, nil
}

// Publish publishes a single event to Kafka with delivery guarantees
func (p *Producer) Publish(ctx context.Context, event []byte) error {
    if err := p.circuitBreaker.Allow(); err != nil {
        return errors.WrapError(err, "circuit breaker open", nil)
    }

    if len(event) == 0 {
        return errors.NewError("E3001", "event data is required", nil)
    }

    startTime := time.Now()
    msg := p.messagePool.Get().(*kafka.Message)
    defer p.messagePool.Put(msg)

    msg.Value = event
    msg.Timestamp = time.Now()
    msg.Headers = []kafka.Header{
        {
            Key: "source",
            Value: []byte("blackpoint-security"),
        },
    }

    deliveryChan := make(chan kafka.Event, 1)
    if err := p.producer.Produce(msg, deliveryChan); err != nil {
        p.circuitBreaker.RecordFailure()
        return errors.WrapError(err, "failed to produce message", nil)
    }

    select {
    case <-ctx.Done():
        return errors.NewError("E4001", "context cancelled", nil)
    case ev := <-deliveryChan:
        if e, ok := ev.(*kafka.Message); ok {
            if e.TopicPartition.Error != nil {
                p.circuitBreaker.RecordFailure()
                return errors.WrapError(e.TopicPartition.Error, "message delivery failed", nil)
            }
            p.circuitBreaker.RecordSuccess()
            p.recordMetrics("single", time.Since(startTime), 1)
            return nil
        }
        return errors.NewError("E4001", "unexpected delivery event type", nil)
    case <-time.After(p.deliveryTimeout):
        p.circuitBreaker.RecordFailure()
        return errors.NewError("E4001", "delivery timeout exceeded", nil)
    }
}

// PublishBatch efficiently publishes multiple events with parallel delivery tracking
func (p *Producer) PublishBatch(ctx context.Context, events [][]byte) error {
    if err := p.circuitBreaker.Allow(); err != nil {
        return errors.WrapError(err, "circuit breaker open", nil)
    }

    if len(events) == 0 {
        return nil
    }
    if len(events) > defaultBatchSize {
        return errors.NewError("E3001", "batch size exceeds limit", nil)
    }

    startTime := time.Now()
    var wg sync.WaitGroup
    errChan := make(chan error, len(events))
    deliveryChan := make(chan kafka.Event, len(events))

    for _, event := range events {
        if len(event) == 0 {
            continue
        }

        msg := p.messagePool.Get().(*kafka.Message)
        msg.Value = event
        msg.Timestamp = time.Now()
        msg.Headers = []kafka.Header{
            {
                Key: "source",
                Value: []byte("blackpoint-security"),
            },
            {
                Key: "batch",
                Value: []byte("true"),
            },
        }

        wg.Add(1)
        go func(m *kafka.Message) {
            defer wg.Done()
            defer p.messagePool.Put(m)

            if err := p.producer.Produce(m, deliveryChan); err != nil {
                errChan <- errors.WrapError(err, "failed to produce batch message", nil)
                p.circuitBreaker.RecordFailure()
            }
        }(msg)
    }

    // Wait for all messages to be produced
    wg.Wait()
    close(errChan)

    // Collect any production errors
    var errs []error
    for err := range errChan {
        errs = append(errs, err)
    }

    if len(errs) > 0 {
        return errors.WrapError(errs[0], "batch production failed", nil)
    }

    // Wait for deliveries with timeout
    timer := time.NewTimer(p.deliveryTimeout)
    defer timer.Stop()

    deliveredCount := 0
    expectedCount := len(events)

    for deliveredCount < expectedCount {
        select {
        case <-ctx.Done():
            return errors.NewError("E4001", "context cancelled during batch delivery", nil)
        case <-timer.C:
            p.circuitBreaker.RecordFailure()
            return errors.NewError("E4001", "batch delivery timeout exceeded", nil)
        case ev := <-deliveryChan:
            if e, ok := ev.(*kafka.Message); ok {
                if e.TopicPartition.Error != nil {
                    p.circuitBreaker.RecordFailure()
                    return errors.WrapError(e.TopicPartition.Error, "batch message delivery failed", nil)
                }
                deliveredCount++
            }
        }
    }

    p.circuitBreaker.RecordSuccess()
    p.recordMetrics("batch", time.Since(startTime), len(events))
    return nil
}

// Close gracefully shuts down the producer
func (p *Producer) Close() error {
    // Wait for any in-flight deliveries
    p.producer.Flush(int(p.deliveryTimeout.Milliseconds()))
    p.producer.Close()
    return nil
}

// Allow checks if the circuit breaker allows operations
func (c *CircuitBreaker) Allow() error {
    c.mu.RLock()
    defer c.mu.RUnlock()

    if c.lastTrip.IsZero() {
        return nil
    }

    if time.Since(c.lastTrip) > c.timeout {
        c.mu.RUnlock()
        c.mu.Lock()
        c.failures = 0
        c.total = 0
        c.lastTrip = time.Time{}
        c.mu.Unlock()
        c.mu.RLock()
        return nil
    }

    return errors.NewError("E4002", "circuit breaker is open", nil)
}

// RecordSuccess records a successful operation
func (c *CircuitBreaker) RecordSuccess() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.total++
}

// RecordFailure records a failed operation
func (c *CircuitBreaker) RecordFailure() {
    c.mu.Lock()
    defer c.mu.Unlock()
    c.failures++
    c.total++

    if c.total > 0 && float64(c.failures)/float64(c.total) >= c.threshold {
        c.lastTrip = time.Now()
    }
}

// recordMetrics records producer performance metrics
func (p *Producer) recordMetrics(operation string, duration time.Duration, count int) {
    p.metricsRecorder.WithLabelValues(
        "operation", operation,
        "topic", p.topic,
    ).Observe(float64(duration.Milliseconds()))

    p.metricsRecorder.WithLabelValues(
        "messages", "count",
        "topic", p.topic,
    ).Add(float64(count))
}