// Package bronze provides high-performance, secure event handling functionality for raw security events
package bronze

import (
    "encoding/json"
    "sync"
    "time"

    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/logging"
    "github.com/prometheus/client_golang/prometheus"
)

var (
    // Event pool for memory optimization
    eventPool = sync.Pool{
        New: func() interface{} {
            return &BronzeEvent{}
        },
    }

    // Processing constants
    maxBatchSize     = 1000
    processingTimeout = 1 * time.Second
    maxRetries       = 3

    // Metrics collectors
    metrics = struct {
        processingTime   *prometheus.HistogramVec
        processingErrors *prometheus.CounterVec
        eventSize       *prometheus.HistogramVec
        batchSize       *prometheus.HistogramVec
    }{
        processingTime: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name: "bronze_event_processing_seconds",
                Help: "Time spent processing Bronze events",
                Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
            },
            []string{"status"},
        ),
        processingErrors: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "bronze_event_errors_total",
                Help: "Total number of Bronze event processing errors",
            },
            []string{"error_type"},
        ),
        eventSize: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name: "bronze_event_size_bytes",
                Help: "Size of Bronze events in bytes",
                Buckets: prometheus.ExponentialBuckets(100, 2, 10),
            },
            []string{"source_platform"},
        ),
        batchSize: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name: "bronze_batch_size",
                Help: "Size of Bronze event batches",
                Buckets: []float64{10, 50, 100, 250, 500, 1000},
            },
            []string{"status"},
        ),
    }
)

// EventProcessor handles secure processing of Bronze tier security events
type EventProcessor struct {
    pool           *sync.Pool
    timeout        time.Duration
    batchSize      int
    securityCtx    *SecurityContext
    workerPool     sync.Pool
    metrics        *prometheus.HistogramVec
}

// NewEventProcessor creates a new EventProcessor with security configuration
func NewEventProcessor(timeout time.Duration, batchSize int, ctx *SecurityContext) (*EventProcessor, error) {
    if timeout <= 0 {
        return nil, errors.NewError("E3001", "invalid timeout value", nil)
    }
    if batchSize <= 0 || batchSize > maxBatchSize {
        return nil, errors.NewError("E3001", "invalid batch size", map[string]interface{}{
            "max_size": maxBatchSize,
            "provided": batchSize,
        })
    }

    processor := &EventProcessor{
        pool:        &eventPool,
        timeout:     timeout,
        batchSize:   batchSize,
        securityCtx: ctx,
        metrics:     metrics.processingTime,
    }

    // Initialize worker pool
    processor.workerPool = sync.Pool{
        New: func() interface{} {
            return make(chan *BronzeEvent, batchSize)
        },
    }

    return processor, nil
}

// ProcessEvent processes a single event with comprehensive security validation
func ProcessEvent(event *BronzeEvent, ctx *SecurityContext) error {
    if event == nil {
        return errors.NewError("E3001", "nil event", nil)
    }

    timer := prometheus.NewTimer(metrics.processingTime.WithLabelValues("single"))
    defer timer.ObserveDuration()

    // Validate event schema
    if err := ValidateSchema(event); err != nil {
        metrics.processingErrors.WithLabelValues("schema_validation").Inc()
        return errors.WrapError(err, "schema validation failed", nil)
    }

    // Record event size metrics
    metrics.eventSize.WithLabelValues(event.SourcePlatform).Observe(float64(len(event.Payload)))

    // Process with security context
    if err := processWithSecurity(event, ctx); err != nil {
        metrics.processingErrors.WithLabelValues("security_validation").Inc()
        return err
    }

    logging.SecurityAudit("Event processed successfully", map[string]interface{}{
        "event_id":        event.ID,
        "client_id":       event.ClientID,
        "source_platform": event.SourcePlatform,
    })

    return nil
}

// BatchProcessEvents processes multiple events concurrently with security validation
func BatchProcessEvents(events []*BronzeEvent, ctx *SecurityContext) []error {
    if len(events) == 0 {
        return nil
    }
    if len(events) > maxBatchSize {
        return []error{errors.NewError("E3001", "batch size exceeds limit", map[string]interface{}{
            "max_size": maxBatchSize,
            "provided": len(events),
        })}
    }

    timer := prometheus.NewTimer(metrics.processingTime.WithLabelValues("batch"))
    defer timer.ObserveDuration()

    metrics.batchSize.WithLabelValues("started").Observe(float64(len(events)))

    // Create error channel
    errChan := make(chan error, len(events))
    var wg sync.WaitGroup

    // Process events concurrently
    for _, event := range events {
        wg.Add(1)
        go func(e *BronzeEvent) {
            defer wg.Done()
            if err := ProcessEvent(e, ctx); err != nil {
                errChan <- err
            }
        }(event)
    }

    // Wait for all processors to complete
    wg.Wait()
    close(errChan)

    // Collect errors
    var errors []error
    for err := range errChan {
        errors = append(errors, err)
    }

    metrics.batchSize.WithLabelValues("completed").Observe(float64(len(events)))

    return errors
}

// processWithSecurity applies security validation and enrichment to an event
func processWithSecurity(event *BronzeEvent, ctx *SecurityContext) error {
    // Apply security context
    event.SecurityContext = ctx.String()

    // Add audit metadata
    event.AuditMetadata = map[string]string{
        "process_time": time.Now().UTC().Format(time.RFC3339),
        "processor_id": ctx.ProcessorID,
    }

    // Convert to JSON for storage
    data, err := event.ToJSON()
    if err != nil {
        return errors.WrapError(err, "failed to serialize event", nil)
    }

    // Validate final event size
    if len(data) > maxPayloadSize {
        return errors.NewError("E3001", "processed event size exceeds limit", map[string]interface{}{
            "max_size": maxPayloadSize,
            "actual_size": len(data),
        })
    }

    return nil
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(
        metrics.processingTime,
        metrics.processingErrors,
        metrics.eventSize,
        metrics.batchSize,
    )
}