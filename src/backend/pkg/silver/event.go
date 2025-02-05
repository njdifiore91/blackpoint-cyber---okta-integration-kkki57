// Package silver provides event processing and transformation logic for the Silver tier
package silver

import (
    "context"
    "encoding/json"
    "runtime"
    "sync"
    "time"

    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/utils"
    "github.com/prometheus/client_golang/prometheus"
)

// Global constants for configuration
const (
    maxBatchSize       = 1000
    processingTimeout  = 5 * time.Second
    workerPoolSize     = runtime.NumCPU() * 2
)

// Metrics collectors for monitoring
var (
    processingLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_silver_processing_latency_seconds",
            Help: "Event processing latency in seconds",
            Buckets: []float64{0.1, 0.5, 1, 2, 5},
        },
        []string{"operation", "status"},
    )

    processingErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_silver_processing_errors_total",
            Help: "Number of processing errors by type",
        },
        []string{"error_type"},
    )

    eventCounter = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_silver_events_processed_total",
            Help: "Number of processed events by status",
        },
        []string{"status"},
    )
)

// EventProcessor defines the interface for event processing operations
type EventProcessor interface {
    Process(ctx context.Context, event *schema.SilverEvent) error
}

// Thread-safe processor registry
var (
    eventProcessors = make(map[string]EventProcessor)
    processorLock   sync.RWMutex
)

// ProcessEvent processes a single security event through the Silver tier pipeline
func ProcessEvent(ctx context.Context, event *schema.SilverEvent) error {
    timer := prometheus.NewTimer(processingLatency.WithLabelValues("single", "processing"))
    defer timer.ObserveDuration()

    // Validate context and timeout
    if ctx == nil {
        ctx = context.Background()
    }
    ctx, cancel := context.WithTimeout(ctx, processingTimeout)
    defer cancel()

    // Validate input event
    if event == nil {
        processingErrors.WithLabelValues("nil_event").Inc()
        return errors.NewError("E3001", "nil event", nil)
    }

    // Perform security validation
    if err := schema.ValidateSchema(event); err != nil {
        processingErrors.WithLabelValues("validation_error").Inc()
        return errors.WrapError(err, "event validation failed", map[string]interface{}{
            "event_id": event.EventID,
        })
    }

    // Get appropriate processor for event type
    processorLock.RLock()
    processor, exists := eventProcessors[event.EventType]
    processorLock.RUnlock()

    if !exists {
        processingErrors.WithLabelValues("unknown_event_type").Inc()
        return errors.NewError("E3001", "unknown event type", map[string]interface{}{
            "event_type": event.EventType,
        })
    }

    // Process event with timeout
    errChan := make(chan error, 1)
    go func() {
        errChan <- processor.Process(ctx, event)
    }()

    select {
    case err := <-errChan:
        if err != nil {
            processingErrors.WithLabelValues("processing_error").Inc()
            return errors.WrapError(err, "event processing failed", map[string]interface{}{
                "event_id": event.EventID,
            })
        }
        eventCounter.WithLabelValues("success").Inc()
        return nil

    case <-ctx.Done():
        processingErrors.WithLabelValues("timeout").Inc()
        return errors.NewError("E3001", "processing timeout", map[string]interface{}{
            "event_id": event.EventID,
            "timeout":  processingTimeout,
        })
    }
}

// ProcessBatch processes a batch of security events concurrently
func ProcessBatch(ctx context.Context, events []*schema.SilverEvent) []error {
    timer := prometheus.NewTimer(processingLatency.WithLabelValues("batch", "processing"))
    defer timer.ObserveDuration()

    if len(events) == 0 {
        return nil
    }

    if len(events) > maxBatchSize {
        processingErrors.WithLabelValues("batch_size_exceeded").Inc()
        return []error{errors.NewError("E3001", "batch size exceeds limit", map[string]interface{}{
            "max_size":     maxBatchSize,
            "actual_size": len(events),
        })}
    }

    // Create worker pool
    workers := workerPoolSize
    if workers > len(events) {
        workers = len(events)
    }

    // Initialize channels
    jobs := make(chan *schema.SilverEvent, len(events))
    results := make(chan error, len(events))
    done := make(chan bool)

    // Start workers
    for i := 0; i < workers; i++ {
        go func() {
            for event := range jobs {
                results <- ProcessEvent(ctx, event)
            }
            done <- true
        }()
    }

    // Send jobs
    for _, event := range events {
        jobs <- event
    }
    close(jobs)

    // Wait for workers to finish
    for i := 0; i < workers; i++ {
        <-done
    }
    close(results)

    // Collect errors
    var errs []error
    for err := range results {
        if err != nil {
            errs = append(errs, err)
        }
    }

    // Update metrics
    eventCounter.WithLabelValues("batch_processed").Add(float64(len(events)))
    if len(errs) > 0 {
        processingErrors.WithLabelValues("batch_errors").Add(float64(len(errs)))
    }

    return errs
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(
        processingLatency,
        processingErrors,
        eventCounter,
    )
}