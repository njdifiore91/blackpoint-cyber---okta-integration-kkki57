// Package mocks provides test implementations for the BlackPoint Security Integration Framework
package mocks

import (
    "sync"
    "testing"
    "time"

    "github.com/blackpoint/pkg/silver/schema"
    "github.com/blackpoint/pkg/silver/event"
)

// Default configuration values for the mock service
const (
    defaultProcessDelay = 100 * time.Millisecond
    defaultBatchSize = 100
    maxConcurrentBatches = 10
    defaultTimeout = 5 * time.Second
)

// MockSilverService provides a thread-safe mock implementation for testing Silver tier
// event processing functionality with configurable behavior and metrics collection.
type MockSilverService struct {
    t *testing.T
    mu sync.RWMutex
    processedEvents map[string]*schema.SilverEvent
    processingErrors map[string]error
    processDelay time.Duration
    shouldFail bool
    securityCtx *schema.SecurityContext
    metrics *event.ProcessingMetrics
    processingQueue chan struct{}
}

// NewMockSilverService creates a new instance of MockSilverService with the specified
// testing context and security configuration.
func NewMockSilverService(t *testing.T, ctx *schema.SecurityContext) *MockSilverService {
    if ctx == nil {
        t.Fatal("security context cannot be nil")
    }

    return &MockSilverService{
        t:               t,
        processedEvents: make(map[string]*schema.SilverEvent),
        processingErrors: make(map[string]error),
        processDelay:    defaultProcessDelay,
        shouldFail:      false,
        securityCtx:     ctx,
        metrics: &event.ProcessingMetrics{
            EventsProcessed: 0,
            BatchesProcessed: 0,
            ProcessingErrors: 0,
            AverageLatency: 0,
        },
        processingQueue: make(chan struct{}, maxConcurrentBatches),
    }
}

// ProcessEvent mocks the processing of a single security event with configurable
// behavior and metrics collection.
func (m *MockSilverService) ProcessEvent(event *schema.SilverEvent, ctx *schema.SecurityContext) error {
    if event == nil {
        return schema.NewError("E3001", "nil event", nil)
    }

    // Validate security context
    if ctx == nil || ctx.Classification == "" {
        return schema.NewError("E3001", "invalid security context", nil)
    }

    // Record processing start time
    startTime := time.Now()

    // Validate event schema
    if err := schema.ValidateSchema(event); err != nil {
        m.mu.Lock()
        m.metrics.ProcessingErrors++
        m.processingErrors[event.EventID] = err
        m.mu.Unlock()
        return err
    }

    // Simulate processing delay
    time.Sleep(m.processDelay)

    m.mu.Lock()
    defer m.mu.Unlock()

    // Check failure simulation
    if m.shouldFail {
        err := schema.NewError("E3001", "simulated processing failure", nil)
        m.metrics.ProcessingErrors++
        m.processingErrors[event.EventID] = err
        return err
    }

    // Store processed event
    m.processedEvents[event.EventID] = event

    // Update metrics
    m.metrics.EventsProcessed++
    processingTime := time.Since(startTime)
    m.metrics.AverageLatency = (m.metrics.AverageLatency*float64(m.metrics.EventsProcessed-1) + 
        processingTime.Seconds()) / float64(m.metrics.EventsProcessed)

    return nil
}

// ProcessBatch mocks concurrent batch processing of security events with
// configurable behavior and comprehensive metrics collection.
func (m *MockSilverService) ProcessBatch(events []*schema.SilverEvent, ctx *schema.SecurityContext) []error {
    if len(events) == 0 {
        return nil
    }

    if len(events) > defaultBatchSize {
        return []error{schema.NewError("E3001", "batch size exceeds limit", nil)}
    }

    // Create worker pool for concurrent processing
    errors := make([]error, len(events))
    var wg sync.WaitGroup

    for i, event := range events {
        wg.Add(1)
        go func(index int, evt *schema.SilverEvent) {
            defer wg.Done()

            // Acquire processing slot
            m.processingQueue <- struct{}{}
            defer func() {
                <-m.processingQueue
            }()

            // Process event
            if err := m.ProcessEvent(evt, ctx); err != nil {
                errors[index] = err
            }
        }(i, event)
    }

    // Wait for all events to be processed
    wg.Wait()

    // Update batch metrics
    m.mu.Lock()
    m.metrics.BatchesProcessed++
    m.mu.Unlock()

    // Filter out nil errors
    var resultErrors []error
    for _, err := range errors {
        if err != nil {
            resultErrors = append(resultErrors, err)
        }
    }

    return resultErrors
}

// GetMetrics returns a copy of the current processing metrics.
func (m *MockSilverService) GetMetrics() *event.ProcessingMetrics {
    m.mu.RLock()
    defer m.mu.RUnlock()

    // Return a copy to prevent external modification
    return &event.ProcessingMetrics{
        EventsProcessed:  m.metrics.EventsProcessed,
        BatchesProcessed: m.metrics.BatchesProcessed,
        ProcessingErrors: m.metrics.ProcessingErrors,
        AverageLatency:  m.metrics.AverageLatency,
    }
}

// SetProcessDelay configures the simulated processing delay.
func (m *MockSilverService) SetProcessDelay(delay time.Duration) {
    m.mu.Lock()
    m.processDelay = delay
    m.mu.Unlock()
}

// SetShouldFail configures whether the mock service should simulate failures.
func (m *MockSilverService) SetShouldFail(shouldFail bool) {
    m.mu.Lock()
    m.shouldFail = shouldFail
    m.mu.Unlock()
}

// GetProcessedEvent retrieves a processed event by ID.
func (m *MockSilverService) GetProcessedEvent(eventID string) (*schema.SilverEvent, bool) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    event, exists := m.processedEvents[eventID]
    return event, exists
}

// GetProcessingError retrieves a processing error by event ID.
func (m *MockSilverService) GetProcessingError(eventID string) (error, bool) {
    m.mu.RLock()
    defer m.mu.RUnlock()
    
    err, exists := m.processingErrors[eventID]
    return err, exists
}