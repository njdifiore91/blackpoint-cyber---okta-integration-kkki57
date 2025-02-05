// Package normalizer provides event normalization services for the Silver tier
package normalizer

import (
    "context"
    "sync"
    "time"

    "github.com/blackpoint/pkg/bronze/schema"
    "github.com/blackpoint/pkg/silver/schema"
    "github.com/blackpoint/pkg/common/errors"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/trace"
    "go.uber.org/zap"
)

// Global constants for processing configuration
const (
    processingTimeout = 5 * time.Second
    maxRetries       = 3
    retryBackoff     = 100 * time.Millisecond
    maxBatchSize     = 1000
    workerPoolSize   = 10
)

// Processor manages event normalization with enhanced security and monitoring
type Processor struct {
    mapper           *FieldMapper
    transformer      *Transformer
    timeout          time.Duration
    logger          *zap.Logger
    tracer          trace.Tracer
    workerPool      chan struct{}
    metrics         *processorMetrics
    mu              sync.RWMutex
}

// processorMetrics tracks performance and operational metrics
type processorMetrics struct {
    eventsProcessed    *zap.Counter
    processingErrors   *zap.Counter
    processingLatency  *zap.Histogram
    retryCount        *zap.Counter
    batchSize         *zap.Gauge
}

// NewProcessor creates a new Processor with security and monitoring configuration
func NewProcessor(mapper *FieldMapper, transformer *Transformer, timeout time.Duration) (*Processor, error) {
    if mapper == nil || transformer == nil {
        return nil, errors.NewError("E4001", "nil dependencies provided", nil)
    }

    if timeout == 0 {
        timeout = processingTimeout
    }

    logger, _ := zap.NewProduction()
    metrics := &processorMetrics{
        eventsProcessed:   zap.NewCounter("events_processed_total"),
        processingErrors:  zap.NewCounter("processing_errors_total"),
        processingLatency: zap.NewHistogram("processing_latency_seconds"),
        retryCount:       zap.NewCounter("processing_retries_total"),
        batchSize:        zap.NewGauge("batch_size_current"),
    }

    return &Processor{
        mapper:      mapper,
        transformer: transformer,
        timeout:     timeout,
        logger:      logger,
        tracer:      otel.Tracer("normalizer.processor"),
        workerPool:  make(chan struct{}, workerPoolSize),
        metrics:     metrics,
    }, nil
}

// Process handles batch processing of Bronze events with concurrent execution
func (p *Processor) Process(ctx context.Context, events []*schema.BronzeEvent) ([]*schema.SilverEvent, error) {
    if len(events) == 0 {
        return nil, nil
    }

    if len(events) > maxBatchSize {
        return nil, errors.NewError("E4001", "batch size exceeds maximum", map[string]interface{}{
            "max_size":     maxBatchSize,
            "actual_size": len(events),
        })
    }

    ctx, span := p.tracer.Start(ctx, "process_batch")
    defer span.End()

    p.metrics.batchSize.Set(float64(len(events)))

    // Create processing channels
    results := make(chan *schema.SilverEvent, len(events))
    errs := make(chan error, len(events))
    var wg sync.WaitGroup

    // Process events concurrently
    for _, event := range events {
        wg.Add(1)
        go func(evt *schema.BronzeEvent) {
            defer wg.Done()

            // Acquire worker from pool
            p.workerPool <- struct{}{}
            defer func() { <-p.workerPool }()

            silverEvent, err := p.ProcessSingle(ctx, evt)
            if err != nil {
                errs <- err
                return
            }
            results <- silverEvent
        }(event)
    }

    // Wait for all processing to complete
    wg.Wait()
    close(results)
    close(errs)

    // Collect results and errors
    var processedEvents []*schema.SilverEvent
    var processingErrors []error

    for err := range errs {
        processingErrors = append(processingErrors, err)
    }

    for result := range results {
        processedEvents = append(processedEvents, result)
    }

    // Handle processing errors
    if len(processingErrors) > 0 {
        p.metrics.processingErrors.Add(float64(len(processingErrors)))
        return processedEvents, errors.NewError("E4001", "batch processing partially failed", map[string]interface{}{
            "total_events": len(events),
            "failed_events": len(processingErrors),
            "first_error": processingErrors[0].Error(),
        })
    }

    p.metrics.eventsProcessed.Add(float64(len(processedEvents)))
    return processedEvents, nil
}

// ProcessSingle handles processing of a single Bronze event with retries
func (p *Processor) ProcessSingle(ctx context.Context, event *schema.BronzeEvent) (*schema.SilverEvent, error) {
    ctx, span := p.tracer.Start(ctx, "process_single")
    defer span.End()

    span.SetAttributes(
        attribute.String("event_id", event.ID),
        attribute.String("client_id", event.ClientID),
    )

    startTime := time.Now()
    defer func() {
        p.metrics.processingLatency.Observe(time.Since(startTime).Seconds())
    }()

    var silverEvent *schema.SilverEvent
    var processingErr error

    // Retry logic with exponential backoff
    for attempt := 0; attempt < maxRetries; attempt++ {
        if attempt > 0 {
            p.metrics.retryCount.Inc()
            time.Sleep(time.Duration(attempt) * retryBackoff)
        }

        silverEvent, processingErr = p.processEventWithTimeout(ctx, event)
        if processingErr == nil {
            break
        }

        p.logger.Warn("Processing attempt failed",
            zap.String("event_id", event.ID),
            zap.Int("attempt", attempt+1),
            zap.Error(processingErr),
        )
    }

    if processingErr != nil {
        p.metrics.processingErrors.Inc()
        return nil, errors.WrapError(processingErr, "processing failed after retries", map[string]interface{}{
            "event_id": event.ID,
            "retries": maxRetries,
        })
    }

    return silverEvent, nil
}

// processEventWithTimeout handles the core event processing with timeout
func (p *Processor) processEventWithTimeout(ctx context.Context, event *schema.BronzeEvent) (*schema.SilverEvent, error) {
    ctx, cancel := context.WithTimeout(ctx, p.timeout)
    defer cancel()

    // Map fields
    mappedFields, err := p.mapper.MapEvent(event)
    if err != nil {
        return nil, errors.WrapError(err, "field mapping failed", nil)
    }

    // Create security context
    securityContext := &schema.SecurityContext{
        Classification: "INTERNAL",
        Sensitivity:   "MEDIUM",
        Compliance:    []string{"DEFAULT"},
        Encryption:    make(map[string]string),
        AccessControl: make(map[string]string),
    }

    // Transform event
    silverEvent, err := p.transformer.TransformEvent(event, mappedFields.NormalizedData, securityContext)
    if err != nil {
        return nil, errors.WrapError(err, "event transformation failed", nil)
    }

    // Validate processed event
    if err := silverEvent.Validate(); err != nil {
        return nil, errors.WrapError(err, "event validation failed", nil)
    }

    return silverEvent, nil
}