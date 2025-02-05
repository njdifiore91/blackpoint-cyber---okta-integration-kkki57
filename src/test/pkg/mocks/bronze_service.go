// Package mocks provides mock implementations for testing the BlackPoint Security Integration Framework
package mocks

import (
    "encoding/json"
    "sync"
    "time"

    "github.com/blackpoint/pkg/bronze/schema"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/stretchr/testify/mock"
)

// Default configuration values for mock service
const (
    defaultProcessingDelay = 100 * time.Millisecond
    defaultBatchSize      = 1000
    maxProcessingDelay    = 1 * time.Second
    maxBatchSize         = 5000
)

// MockBronzeService provides a thread-safe mock implementation of the Bronze tier service
type MockBronzeService struct {
    mock.Mock
    configMutex     sync.RWMutex
    processingDelay time.Duration
    batchSize       int
    simulateErrors  bool
    errorRates      map[string]int
}

// NewMockBronzeService creates a new instance of MockBronzeService with default configuration
func NewMockBronzeService() *MockBronzeService {
    service := &MockBronzeService{
        processingDelay: defaultProcessingDelay,
        batchSize:      defaultBatchSize,
        errorRates:     make(map[string]int),
    }

    // Set up default mock expectations
    service.On("ProcessEvent", mock.Anything).Return(nil).Maybe()
    service.On("BatchProcessEvents", mock.Anything).Return([]error{}).Maybe()

    return service
}

// ProcessEvent mocks the processing of a single Bronze tier event
func (m *MockBronzeService) ProcessEvent(event *schema.BronzeEvent) error {
    m.configMutex.RLock()
    delay := m.processingDelay
    simulateErrors := m.simulateErrors
    errorRates := m.errorRates
    m.configMutex.RUnlock()

    // Record the call
    args := m.Called(event)

    // Validate event schema
    if err := schema.ValidateSchema(event); err != nil {
        return errors.WrapError(err, "mock: event validation failed", map[string]interface{}{
            "event_id": event.ID,
        })
    }

    // Simulate processing delay
    time.Sleep(delay)

    // Simulate errors based on configuration
    if simulateErrors {
        if rate, exists := errorRates[event.SourcePlatform]; exists {
            if rate > 0 && (time.Now().UnixNano() % int64(100)) < int64(rate) {
                return errors.NewError("E3001", "mock: simulated processing error", map[string]interface{}{
                    "source_platform": event.SourcePlatform,
                    "error_rate":     rate,
                })
            }
        }
    }

    return args.Error(0)
}

// BatchProcessEvents mocks the batch processing of multiple Bronze tier events
func (m *MockBronzeService) BatchProcessEvents(events []*schema.BronzeEvent) []error {
    m.configMutex.RLock()
    batchSize := m.batchSize
    delay := m.processingDelay
    simulateErrors := m.simulateErrors
    m.configMutex.RUnlock()

    // Record the call
    m.Called(events)

    // Validate batch size
    if len(events) > batchSize {
        return []error{errors.NewError("E3001", "mock: batch size exceeds limit", map[string]interface{}{
            "max_size":     batchSize,
            "actual_size": len(events),
        })}
    }

    results := make([]error, len(events))
    
    // Process each event with configured delay
    for i, event := range events {
        // Simulate batch processing delay
        time.Sleep(delay / time.Duration(len(events)))
        
        // Process individual event
        results[i] = m.ProcessEvent(event)
    }

    return results
}

// SetProcessingDelay configures the simulated processing delay
func (m *MockBronzeService) SetProcessingDelay(delay time.Duration) error {
    if delay > maxProcessingDelay {
        return errors.NewError("E3001", "mock: processing delay exceeds maximum", map[string]interface{}{
            "max_delay":     maxProcessingDelay,
            "actual_delay": delay,
        })
    }

    m.configMutex.Lock()
    m.processingDelay = delay
    m.configMutex.Unlock()

    return nil
}

// SetBatchSize configures the maximum batch size
func (m *MockBronzeService) SetBatchSize(size int) error {
    if size > maxBatchSize {
        return errors.NewError("E3001", "mock: batch size exceeds maximum", map[string]interface{}{
            "max_size":     maxBatchSize,
            "actual_size": size,
        })
    }

    m.configMutex.Lock()
    m.batchSize = size
    m.configMutex.Unlock()

    return nil
}

// ConfigureErrorSimulation configures error simulation patterns and rates
func (m *MockBronzeService) ConfigureErrorSimulation(errorRates map[string]int) error {
    // Validate error rates
    for platform, rate := range errorRates {
        if rate < 0 || rate > 100 {
            return errors.NewError("E3001", "mock: invalid error rate", map[string]interface{}{
                "platform": platform,
                "rate":    rate,
            })
        }
    }

    m.configMutex.Lock()
    m.simulateErrors = len(errorRates) > 0
    m.errorRates = errorRates
    m.configMutex.Unlock()

    return nil
}