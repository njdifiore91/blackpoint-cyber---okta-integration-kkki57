// Package collector provides batch processing functionality for security event collection
package collector

import (
    "context"
    "sync"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/blackpoint/pkg/bronze"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/internal/streaming"
)

// Default configuration values
const (
    defaultBatchSize = 1000
    defaultBatchInterval = 5 * time.Second
    maxBatchSize = 10000
    batchProcessingTimeout = 30 * time.Second
    minBatchSize = 100
    maxRetries = 3
)

var (
    // Metrics collectors
    batchMetrics = struct {
        batchSize *prometheus.HistogramVec
        processingTime *prometheus.HistogramVec
        processingErrors *prometheus.CounterVec
        eventValidations *prometheus.CounterVec
    }{
        batchSize: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name: "blackpoint_batch_size",
                Help: "Size of processed event batches",
                Buckets: []float64{100, 500, 1000, 5000, 10000},
            },
            []string{"status"},
        ),
        processingTime: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name: "blackpoint_batch_processing_seconds",
                Help: "Time spent processing event batches",
                Buckets: []float64{.1, .5, 1, 2.5, 5, 10, 30},
            },
            []string{"operation"},
        ),
        processingErrors: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "blackpoint_batch_errors_total",
                Help: "Total number of batch processing errors",
            },
            []string{"error_type"},
        ),
        eventValidations: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "blackpoint_event_validations_total",
                Help: "Total number of event validations",
            },
            []string{"result"},
        ),
    }
)

// BatchCollector handles batch collection and processing of security events
type BatchCollector struct {
    producer *streaming.Producer
    batchSize int
    batchInterval time.Duration
    eventBuffer []*bronze.BronzeEvent
    bufferMutex sync.Mutex
    cancelFunc context.CancelFunc
    retryCount int
}

// NewBatchCollector creates a new BatchCollector instance
func NewBatchCollector(producer *streaming.Producer, batchSize int, batchInterval time.Duration) (*BatchCollector, error) {
    if producer == nil {
        return nil, errors.NewError("E3001", "producer is required", nil)
    }

    // Validate batch size
    if batchSize <= 0 {
        batchSize = defaultBatchSize
    }
    if batchSize > maxBatchSize {
        return nil, errors.NewError("E3001", "batch size exceeds maximum", map[string]interface{}{
            "max_size": maxBatchSize,
            "provided": batchSize,
        })
    }

    // Validate batch interval
    if batchInterval <= 0 {
        batchInterval = defaultBatchInterval
    }

    collector := &BatchCollector{
        producer:      producer,
        batchSize:     batchSize,
        batchInterval: batchInterval,
        eventBuffer:   make([]*bronze.BronzeEvent, 0, batchSize),
        retryCount:    maxRetries,
    }

    // Start batch processor
    ctx, cancel := context.WithCancel(context.Background())
    collector.cancelFunc = cancel
    go collector.processingLoop(ctx)

    return collector, nil
}

// AddEvent adds a security event to the batch buffer
func (bc *BatchCollector) AddEvent(event *bronze.BronzeEvent) error {
    if event == nil {
        return errors.NewError("E3001", "nil event", nil)
    }

    bc.bufferMutex.Lock()
    defer bc.bufferMutex.Unlock()

    // Validate event
    if err := event.Validate(); err != nil {
        batchMetrics.eventValidations.WithLabelValues("failed").Inc()
        return errors.WrapError(err, "event validation failed", nil)
    }
    batchMetrics.eventValidations.WithLabelValues("success").Inc()

    // Add to buffer
    bc.eventBuffer = append(bc.eventBuffer, event)

    // Process batch if buffer is full
    if len(bc.eventBuffer) >= bc.batchSize {
        return bc.processBatch()
    }

    return nil
}

// processBatch processes the current batch of events
func (bc *BatchCollector) processBatch() error {
    if len(bc.eventBuffer) == 0 {
        return nil
    }

    timer := prometheus.NewTimer(batchMetrics.processingTime.WithLabelValues("process_batch"))
    defer timer.ObserveDuration()

    // Create processing context with timeout
    ctx, cancel := context.WithTimeout(context.Background(), batchProcessingTimeout)
    defer cancel()

    // Create worker pool for parallel validation
    numWorkers := 5
    validationChan := make(chan *bronze.BronzeEvent, len(bc.eventBuffer))
    resultChan := make(chan error, len(bc.eventBuffer))
    var wg sync.WaitGroup

    // Start validation workers
    for i := 0; i < numWorkers; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            for event := range validationChan {
                if err := ValidateEvent(ctx, event); err != nil {
                    resultChan <- err
                    continue
                }
                resultChan <- nil
            }
        }()
    }

    // Send events for validation
    for _, event := range bc.eventBuffer {
        validationChan <- event
    }
    close(validationChan)

    // Wait for validation completion
    wg.Wait()
    close(resultChan)

    // Collect validation results
    validEvents := make([]*bronze.BronzeEvent, 0, len(bc.eventBuffer))
    for i, event := range bc.eventBuffer {
        if err := <-resultChan; err != nil {
            batchMetrics.processingErrors.WithLabelValues("validation").Inc()
            continue
        }
        validEvents = append(validEvents, event)
    }

    // Record batch metrics
    batchMetrics.batchSize.WithLabelValues("processed").Observe(float64(len(validEvents)))

    // Publish valid events
    if len(validEvents) > 0 {
        events := make([][]byte, len(validEvents))
        for i, event := range validEvents {
            data, err := event.ToJSON()
            if err != nil {
                batchMetrics.processingErrors.WithLabelValues("serialization").Inc()
                continue
            }
            events[i] = data
        }

        // Attempt batch publication with retries
        var lastErr error
        for attempt := 0; attempt < bc.retryCount; attempt++ {
            if err := bc.producer.PublishBatch(ctx, events); err != nil {
                lastErr = err
                batchMetrics.processingErrors.WithLabelValues("publication").Inc()
                continue
            }
            lastErr = nil
            break
        }

        if lastErr != nil {
            return errors.WrapError(lastErr, "batch publication failed after retries", nil)
        }
    }

    // Clear the buffer
    bc.eventBuffer = make([]*bronze.BronzeEvent, 0, bc.batchSize)

    return nil
}

// processingLoop handles periodic batch processing
func (bc *BatchCollector) processingLoop(ctx context.Context) {
    ticker := time.NewTicker(bc.batchInterval)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            bc.bufferMutex.Lock()
            if err := bc.processBatch(); err != nil {
                batchMetrics.processingErrors.WithLabelValues("processing_loop").Inc()
            }
            bc.bufferMutex.Unlock()
        }
    }
}

// Stop gracefully stops the batch collector
func (bc *BatchCollector) Stop() error {
    if bc.cancelFunc != nil {
        bc.cancelFunc()
    }

    bc.bufferMutex.Lock()
    defer bc.bufferMutex.Unlock()

    // Process any remaining events
    return bc.processBatch()
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(
        batchMetrics.batchSize,
        batchMetrics.processingTime,
        batchMetrics.processingErrors,
        batchMetrics.eventValidations,
    )
}