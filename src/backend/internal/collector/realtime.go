// Package collector provides real-time security event collection functionality
package collector

import (
    "context"
    "sync"
    "time"

    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/logging"
    "github.com/blackpoint/pkg/bronze/event"
    "github.com/blackpoint/internal/streaming/producer"
    "github.com/prometheus/client_golang/prometheus" // v1.16.0
)

// Default configuration values
const (
    defaultBufferSize        = 10000
    defaultBatchSize        = 1000
    defaultFlushInterval    = 1 * time.Second
    defaultCollectionTimeout = 5 * time.Second
)

var (
    // Metrics collectors
    metrics = struct {
        eventCollectionTime   *prometheus.HistogramVec
        batchProcessingTime   *prometheus.HistogramVec
        eventBufferSize      *prometheus.GaugeVec
        collectionErrors     *prometheus.CounterVec
        eventsCollected     *prometheus.CounterVec
    }{
        eventCollectionTime: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name: "blackpoint_event_collection_seconds",
                Help: "Time spent collecting individual events",
                Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
            },
            []string{"status"},
        ),
        batchProcessingTime: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name: "blackpoint_batch_processing_seconds",
                Help: "Time spent processing event batches",
                Buckets: []float64{.01, .05, .1, .25, .5, 1, 2.5, 5, 10},
            },
            []string{"status"},
        ),
        eventBufferSize: prometheus.NewGaugeVec(
            prometheus.GaugeOpts{
                Name: "blackpoint_event_buffer_size",
                Help: "Current size of the event buffer",
            },
            []string{"collector_id"},
        ),
        collectionErrors: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "blackpoint_collection_errors_total",
                Help: "Total number of collection errors",
            },
            []string{"error_type"},
        ),
        eventsCollected: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "blackpoint_events_collected_total",
                Help: "Total number of events collected",
            },
            []string{"status"},
        ),
    }
)

// RealtimeCollector manages real-time collection of security events
type RealtimeCollector struct {
    processor     *event.EventProcessor
    producer      *producer.Producer
    eventBuffer   chan []byte
    flushInterval time.Duration
    batchSize     int
    ctx           context.Context
    cancel        context.CancelFunc
    wg            sync.WaitGroup
    collectorID   string
}

// CollectorConfig contains configuration for the RealtimeCollector
type CollectorConfig struct {
    BufferSize    int
    BatchSize     int
    FlushInterval time.Duration
}

// NewRealtimeCollector creates a new RealtimeCollector instance
func NewRealtimeCollector(processor *event.EventProcessor, producer *producer.Producer, config CollectorConfig) (*RealtimeCollector, error) {
    if processor == nil {
        return nil, errors.NewError("E2001", "event processor is required", nil)
    }
    if producer == nil {
        return nil, errors.NewError("E2001", "event producer is required", nil)
    }

    // Apply default configuration if not specified
    if config.BufferSize == 0 {
        config.BufferSize = defaultBufferSize
    }
    if config.BatchSize == 0 {
        config.BatchSize = defaultBatchSize
    }
    if config.FlushInterval == 0 {
        config.FlushInterval = defaultFlushInterval
    }

    // Generate collector ID
    collectorID, err := utils.GenerateUUID()
    if err != nil {
        return nil, errors.WrapError(err, "failed to generate collector ID", nil)
    }

    ctx, cancel := context.WithCancel(context.Background())

    collector := &RealtimeCollector{
        processor:     processor,
        producer:      producer,
        eventBuffer:   make(chan []byte, config.BufferSize),
        flushInterval: config.FlushInterval,
        batchSize:     config.BatchSize,
        ctx:          ctx,
        cancel:       cancel,
        collectorID:  collectorID,
    }

    // Register metrics
    prometheus.MustRegister(
        metrics.eventCollectionTime,
        metrics.batchProcessingTime,
        metrics.eventBufferSize,
        metrics.collectionErrors,
        metrics.eventsCollected,
    )

    logging.Info("Realtime collector initialized",
        logging.Field("collector_id", collector.collectorID),
        logging.Field("buffer_size", config.BufferSize),
        logging.Field("batch_size", config.BatchSize),
    )

    return collector, nil
}

// Start begins the event collection process
func (c *RealtimeCollector) Start() error {
    c.wg.Add(1)
    go c.processBatches()

    logging.Info("Realtime collector started",
        logging.Field("collector_id", c.collectorID),
    )

    return nil
}

// Stop gracefully stops the collector
func (c *RealtimeCollector) Stop() error {
    c.cancel()
    
    // Wait for processing to complete with timeout
    done := make(chan struct{})
    go func() {
        c.wg.Wait()
        close(done)
    }()

    select {
    case <-done:
        logging.Info("Realtime collector stopped gracefully",
            logging.Field("collector_id", c.collectorID),
        )
        return nil
    case <-time.After(defaultCollectionTimeout):
        return errors.NewError("E4001", "collector shutdown timeout exceeded", nil)
    }
}

// CollectEvent collects a single security event
func (c *RealtimeCollector) CollectEvent(ctx context.Context, eventData []byte) error {
    if len(eventData) == 0 {
        metrics.collectionErrors.WithLabelValues("empty_event").Inc()
        return errors.NewError("E3001", "empty event data", nil)
    }

    timer := prometheus.NewTimer(metrics.eventCollectionTime.WithLabelValues("processing"))
    defer timer.ObserveDuration()

    // Validate event data
    if err := validateEvent(eventData); err != nil {
        metrics.collectionErrors.WithLabelValues("validation_error").Inc()
        return err
    }

    // Try to add event to buffer with timeout
    select {
    case c.eventBuffer <- eventData:
        metrics.eventsCollected.WithLabelValues("success").Inc()
        metrics.eventBufferSize.WithLabelValues(c.collectorID).Set(float64(len(c.eventBuffer)))
        return nil
    case <-ctx.Done():
        metrics.collectionErrors.WithLabelValues("context_cancelled").Inc()
        return errors.NewError("E4001", "context cancelled", nil)
    case <-time.After(defaultCollectionTimeout):
        metrics.collectionErrors.WithLabelValues("buffer_full").Inc()
        return errors.NewError("E4001", "event buffer full", nil)
    }
}

// processBatches handles batch processing of collected events
func (c *RealtimeCollector) processBatches() {
    defer c.wg.Done()

    ticker := time.NewTicker(c.flushInterval)
    defer ticker.Stop()

    batch := make([][]byte, 0, c.batchSize)

    for {
        select {
        case <-c.ctx.Done():
            if len(batch) > 0 {
                c.processBatch(batch)
            }
            return
        case event := <-c.eventBuffer:
            batch = append(batch, event)
            if len(batch) >= c.batchSize {
                c.processBatch(batch)
                batch = make([][]byte, 0, c.batchSize)
            }
        case <-ticker.C:
            if len(batch) > 0 {
                c.processBatch(batch)
                batch = make([][]byte, 0, c.batchSize)
            }
        }
    }
}

// processBatch processes a batch of events
func (c *RealtimeCollector) processBatch(events [][]byte) {
    if len(events) == 0 {
        return
    }

    timer := prometheus.NewTimer(metrics.batchProcessingTime.WithLabelValues("processing"))
    defer timer.ObserveDuration()

    // Process events through Bronze tier
    if err := c.producer.PublishBatch(c.ctx, events); err != nil {
        logging.Error("Failed to process event batch",
            err,
            logging.Field("batch_size", len(events)),
            logging.Field("collector_id", c.collectorID),
        )
        metrics.collectionErrors.WithLabelValues("batch_processing").Inc()
        return
    }

    metrics.eventsCollected.WithLabelValues("batch_success").Add(float64(len(events)))
    logging.Info("Batch processed successfully",
        logging.Field("batch_size", len(events)),
        logging.Field("collector_id", c.collectorID),
    )
}

// validateEvent validates incoming security event data
func validateEvent(eventData []byte) error {
    if len(eventData) == 0 {
        return errors.NewError("E3001", "empty event data", nil)
    }

    // Validate event size
    if len(eventData) > event.MaxPayloadSize {
        return errors.NewError("E3001", "event size exceeds limit", map[string]interface{}{
            "max_size": event.MaxPayloadSize,
            "actual_size": len(eventData),
        })
    }

    // Validate event format
    if err := utils.ValidateJSON(string(eventData), utils.ValidationOptions{
        MaxDepth:   20,
        StrictMode: true,
    }); err != nil {
        return errors.WrapError(err, "invalid event format", nil)
    }

    return nil
}

func init() {
    // Initialize metrics with initial values
    metrics.eventBufferSize.WithLabelValues("default").Set(0)
}