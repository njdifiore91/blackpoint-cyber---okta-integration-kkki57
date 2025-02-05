// Package streaming provides Kafka streaming functionality for the BlackPoint Security Integration Framework
package streaming

import (
    "context"
    "sync"
    "time"

    "github.com/confluentinc/confluent-kafka-go/kafka" // v1.9.2
    "../../pkg/common/errors"
    "../../pkg/common/logging"
)

// Default configuration values
const (
    defaultPollTimeout    = 1000
    defaultBatchSize     = 100
    defaultCommitInterval = 5 * time.Second
    maxBatchSize        = 1000
    minBatchSize        = 10
    maxRetries         = 3
    retryInterval      = 1 * time.Second
)

// ConsumerOptions defines configuration options for the consumer
type ConsumerOptions struct {
    BatchSize      int
    CommitInterval time.Duration
    PollTimeout    int
    EnableMetrics  bool
}

// Consumer represents an enhanced Kafka consumer with performance monitoring
type Consumer struct {
    consumer       *kafka.Consumer
    topics        []string
    messages      chan *kafka.Message
    ctx           context.Context
    cancel        context.CancelFunc
    monitor       *PerformanceMonitor
    metrics       *MetricsCollector
    options       ConsumerOptions
    mu            sync.RWMutex
}

// MetricsCollector tracks consumer performance metrics
type MetricsCollector struct {
    EventsProcessed uint64
    ProcessingTime  time.Duration
    BatchSizes      []int
    Errors         uint64
    LastUpdated    time.Time
    mu             sync.RWMutex
}

// PerformanceMonitor handles consumer performance monitoring
type PerformanceMonitor struct {
    latencyByTier map[string]time.Duration
    throughput    float64
    lastCheck     time.Time
    mu            sync.RWMutex
}

// NewConsumer creates a new enhanced Kafka consumer instance
func NewConsumer(config *kafka.ConfigMap, topics []string, options ConsumerOptions) (*Consumer, error) {
    if len(topics) == 0 {
        return nil, errors.NewError("E2001", "no topics specified", nil)
    }

    // Set default options
    if options.BatchSize == 0 {
        options.BatchSize = defaultBatchSize
    }
    if options.CommitInterval == 0 {
        options.CommitInterval = defaultCommitInterval
    }
    if options.PollTimeout == 0 {
        options.PollTimeout = defaultPollTimeout
    }

    // Create Kafka consumer
    consumer, err := kafka.NewConsumer(config)
    if err != nil {
        return nil, errors.WrapError(err, "failed to create Kafka consumer", nil)
    }

    // Subscribe to topics
    if err := consumer.SubscribeTopics(topics, nil); err != nil {
        consumer.Close()
        return nil, errors.WrapError(err, "failed to subscribe to topics", nil)
    }

    ctx, cancel := context.WithCancel(context.Background())

    c := &Consumer{
        consumer: consumer,
        topics:   topics,
        messages: make(chan *kafka.Message, options.BatchSize*2),
        ctx:      ctx,
        cancel:   cancel,
        options:  options,
        monitor: &PerformanceMonitor{
            latencyByTier: make(map[string]time.Duration),
            lastCheck:     time.Now(),
        },
        metrics: &MetricsCollector{
            BatchSizes:   make([]int, 0),
            LastUpdated: time.Now(),
        },
    }

    logging.Info("Created new Kafka consumer",
        logging.Field("topics", topics),
        logging.Field("batch_size", options.BatchSize),
    )

    return c, nil
}

// Start begins consuming messages with performance monitoring
func (c *Consumer) Start() error {
    c.mu.Lock()
    defer c.mu.Unlock()

    // Start message polling
    go c.pollMessages()

    // Start batch processing
    go c.processBatches()

    // Start performance monitoring
    go c.monitorPerformance()

    logging.Info("Started Kafka consumer",
        logging.Field("topics", c.topics),
    )

    return nil
}

// Stop gracefully stops the consumer
func (c *Consumer) Stop() error {
    c.mu.Lock()
    defer c.mu.Unlock()

    c.cancel()

    // Wait for in-flight messages
    close(c.messages)

    if err := c.consumer.Close(); err != nil {
        return errors.WrapError(err, "failed to close consumer", nil)
    }

    logging.Info("Stopped Kafka consumer",
        logging.Field("events_processed", c.metrics.EventsProcessed),
    )

    return nil
}

// pollMessages continuously polls for new messages
func (c *Consumer) pollMessages() {
    for {
        select {
        case <-c.ctx.Done():
            return
        default:
            msg, err := c.consumer.ReadMessage(time.Duration(c.options.PollTimeout) * time.Millisecond)
            if err != nil {
                if !err.(kafka.Error).IsTimeout() {
                    logging.Error("Failed to read message",
                        err,
                        logging.Field("topics", c.topics),
                    )
                    c.metrics.mu.Lock()
                    c.metrics.Errors++
                    c.metrics.mu.Unlock()
                }
                continue
            }

            c.messages <- msg
        }
    }
}

// processBatches processes messages in batches
func (c *Consumer) processBatches() {
    batch := make([]*kafka.Message, 0, c.options.BatchSize)
    commitTicker := time.NewTicker(c.options.CommitInterval)
    defer commitTicker.Stop()

    for {
        select {
        case <-c.ctx.Done():
            return
        case msg, ok := <-c.messages:
            if !ok {
                return
            }

            batch = append(batch, msg)
            if len(batch) >= c.options.BatchSize {
                c.processBatch(batch)
                batch = make([]*kafka.Message, 0, c.options.BatchSize)
            }
        case <-commitTicker.C:
            if len(batch) > 0 {
                c.processBatch(batch)
                batch = make([]*kafka.Message, 0, c.options.BatchSize)
            }
        }
    }
}

// processBatch processes a batch of messages
func (c *Consumer) processBatch(batch []*kafka.Message) {
    start := time.Now()

    // Process messages
    for _, msg := range batch {
        // Track processing time by tier
        tier := determineTier(msg)
        processingTime := time.Since(start)
        
        c.monitor.mu.Lock()
        c.monitor.latencyByTier[tier] = processingTime
        c.monitor.mu.Unlock()
    }

    // Commit offsets
    if err := c.consumer.CommitMessage(batch[len(batch)-1]); err != nil {
        logging.Error("Failed to commit offsets",
            err,
            logging.Field("batch_size", len(batch)),
        )
    }

    // Update metrics
    c.metrics.mu.Lock()
    c.metrics.EventsProcessed += uint64(len(batch))
    c.metrics.ProcessingTime += time.Since(start)
    c.metrics.BatchSizes = append(c.metrics.BatchSizes, len(batch))
    c.metrics.LastUpdated = time.Now()
    c.metrics.mu.Unlock()
}

// monitorPerformance monitors consumer performance
func (c *Consumer) monitorPerformance() {
    ticker := time.NewTicker(30 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-c.ctx.Done():
            return
        case <-ticker.C:
            c.checkPerformance()
        }
    }
}

// checkPerformance checks consumer performance metrics
func (c *Consumer) checkPerformance() {
    c.monitor.mu.Lock()
    defer c.monitor.mu.Unlock()

    now := time.Now()
    elapsed := now.Sub(c.monitor.lastCheck)
    c.monitor.lastCheck = now

    c.metrics.mu.RLock()
    throughput := float64(c.metrics.EventsProcessed) / elapsed.Seconds()
    c.metrics.mu.RUnlock()

    c.monitor.throughput = throughput

    // Check tier latencies
    for tier, latency := range c.monitor.latencyByTier {
        threshold := getTierLatencyThreshold(tier)
        if latency > threshold {
            logging.Error("Tier latency threshold exceeded",
                errors.NewError("E2002", "processing latency exceeded threshold", nil),
                logging.Field("tier", tier),
                logging.Field("latency", latency),
                logging.Field("threshold", threshold),
            )
        }
    }
}

// determineTier determines the processing tier for a message
func determineTier(msg *kafka.Message) string {
    // Determine tier based on topic or message headers
    if msg.TopicPartition.Topic != nil {
        topic := *msg.TopicPartition.Topic
        switch {
        case contains(topic, "bronze"):
            return "bronze"
        case contains(topic, "silver"):
            return "silver"
        case contains(topic, "gold"):
            return "gold"
        }
    }
    return "bronze"
}

// getTierLatencyThreshold returns the latency threshold for a tier
func getTierLatencyThreshold(tier string) time.Duration {
    switch tier {
    case "bronze":
        return 1 * time.Second
    case "silver":
        return 5 * time.Second
    case "gold":
        return 30 * time.Second
    default:
        return 1 * time.Second
    }
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
    return len(s) >= len(substr) && s[len(s)-len(substr):] == substr
}

// GetMetrics returns current consumer metrics
func (c *Consumer) GetMetrics() *MetricsCollector {
    c.metrics.mu.RLock()
    defer c.metrics.mu.RUnlock()
    
    return &MetricsCollector{
        EventsProcessed: c.metrics.EventsProcessed,
        ProcessingTime:  c.metrics.ProcessingTime,
        BatchSizes:     append([]int{}, c.metrics.BatchSizes...),
        Errors:         c.metrics.Errors,
        LastUpdated:    c.metrics.LastUpdated,
    }
}