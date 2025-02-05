// Package mocks provides mock implementations for testing the BlackPoint Security Integration Framework
package mocks

import (
    "fmt"
    "math/rand"
    "sync"
    "testing"
    "time"

    "github.com/blackpoint/internal/storage"
    "github.com/blackpoint/metrics" // v1.0.0
    "github.com/blackpoint/pkg/common/errors"
)

// Default mock configuration values
const (
    mockStorageDelay = 50 * time.Millisecond
)

// TierStats tracks performance metrics for each storage tier
type TierStats struct {
    OperationCount int64
    LatencySum     time.Duration
    ErrorCount     int64
    LastAccess     time.Time
}

// IndexConfig represents mock index configuration
type IndexConfig struct {
    ShardCount   int
    ReplicaCount int
    RetentionDays int
}

// MockConfig defines configuration for mock behavior
type MockConfig struct {
    MaxEvents      int
    ErrorRate      float64
    LatencyRange   string
    MetricsEnabled bool
    TierLatencies  map[string]time.Duration
}

// Default mock configuration
var defaultMockConfig = MockConfig{
    MaxEvents:      1000,
    ErrorRate:      0.01,
    LatencyRange:   "10ms-100ms",
    MetricsEnabled: true,
    TierLatencies: map[string]time.Duration{
        "bronze": time.Second,
        "silver": 5 * time.Second,
        "gold":   30 * time.Second,
    },
}

// MockChaosSearchClient implements a mock ChaosSearch client for testing
type MockChaosSearchClient struct {
    t               *testing.T
    config          *MockConfig
    mu              sync.RWMutex
    storage         map[string][]interface{}
    indices         map[string]*IndexConfig
    metricsCollector *metrics.Collector
    tierStats       map[string]*TierStats
}

// NewMockChaosSearchClient creates a new mock ChaosSearch client
func NewMockChaosSearchClient(t *testing.T, config *MockConfig) (*MockChaosSearchClient, error) {
    if config == nil {
        config = &defaultMockConfig
    }

    // Validate configuration
    if err := validateMockConfig(config); err != nil {
        return nil, err
    }

    client := &MockChaosSearchClient{
        t:       t,
        config:  config,
        storage: make(map[string][]interface{}),
        indices: make(map[string]*IndexConfig),
        tierStats: make(map[string]*TierStats),
    }

    // Initialize metrics collector if enabled
    if config.MetricsEnabled {
        collector, err := metrics.NewCollector("mock_chaossearch")
        if err != nil {
            return nil, errors.WrapError(err, "failed to initialize metrics collector", nil)
        }
        client.metricsCollector = collector
    }

    // Initialize tier statistics
    for tier := range config.TierLatencies {
        client.tierStats[tier] = &TierStats{
            LastAccess: time.Now(),
        }
    }

    return client, nil
}

// StoreEvent implements storage.ChaosSearchClient interface for event storage
func (m *MockChaosSearchClient) StoreEvent(tier string, event interface{}) error {
    startTime := time.Now()
    defer m.recordOperation(tier, "store", startTime)

    // Simulate configured latency
    if err := m.simulateLatency(tier); err != nil {
        return err
    }

    // Simulate random errors based on configured error rate
    if err := m.simulateError(); err != nil {
        return err
    }

    m.mu.Lock()
    defer m.mu.Unlock()

    // Enforce max events limit
    if len(m.storage[tier]) >= m.config.MaxEvents {
        return errors.NewError("E3001", "storage capacity exceeded", map[string]interface{}{
            "tier": tier,
            "limit": m.config.MaxEvents,
        })
    }

    // Store event with timestamp
    m.storage[tier] = append(m.storage[tier], event)
    
    return nil
}

// QueryEvents implements storage.ChaosSearchClient interface for event querying
func (m *MockChaosSearchClient) QueryEvents(params *storage.QueryParams) ([]interface{}, error) {
    startTime := time.Now()
    defer m.recordOperation(params.Tier, "query", startTime)

    // Simulate configured latency
    if err := m.simulateLatency(params.Tier); err != nil {
        return nil, err
    }

    // Simulate random errors
    if err := m.simulateError(); err != nil {
        return nil, err
    }

    m.mu.RLock()
    defer m.mu.RUnlock()

    // Apply mock filtering
    results := m.filterEvents(params)

    return results, nil
}

// CreateIndex implements storage.ChaosSearchClient interface for index creation
func (m *MockChaosSearchClient) CreateIndex(tier string, config *IndexConfig) error {
    startTime := time.Now()
    defer m.recordOperation(tier, "create_index", startTime)

    if err := m.simulateLatency(tier); err != nil {
        return err
    }

    m.mu.Lock()
    defer m.mu.Unlock()

    m.indices[tier] = config
    m.storage[tier] = make([]interface{}, 0)

    return nil
}

// DeleteIndex implements storage.ChaosSearchClient interface for index deletion
func (m *MockChaosSearchClient) DeleteIndex(tier string) error {
    startTime := time.Now()
    defer m.recordOperation(tier, "delete_index", startTime)

    if err := m.simulateLatency(tier); err != nil {
        return err
    }

    m.mu.Lock()
    defer m.mu.Unlock()

    delete(m.indices, tier)
    delete(m.storage, tier)

    return nil
}

// Helper functions

func (m *MockChaosSearchClient) simulateLatency(tier string) error {
    latency, exists := m.config.TierLatencies[tier]
    if !exists {
        return errors.NewError("E2001", fmt.Sprintf("invalid tier: %s", tier), nil)
    }

    // Add some randomness to latency
    jitter := time.Duration(rand.Int63n(int64(latency) / 2))
    time.Sleep(latency + jitter)

    return nil
}

func (m *MockChaosSearchClient) simulateError() error {
    if rand.Float64() < m.config.ErrorRate {
        return errors.NewError("E4001", "simulated storage error", nil)
    }
    return nil
}

func (m *MockChaosSearchClient) recordOperation(tier, operation string, startTime time.Time) {
    duration := time.Since(startTime)

    m.mu.Lock()
    defer m.mu.Unlock()

    // Update tier statistics
    if stats, exists := m.tierStats[tier]; exists {
        stats.OperationCount++
        stats.LatencySum += duration
        stats.LastAccess = time.Now()
    }

    // Record metrics if enabled
    if m.metricsCollector != nil {
        m.metricsCollector.RecordLatency(fmt.Sprintf("%s_%s", tier, operation), duration)
        m.metricsCollector.IncrementCounter(fmt.Sprintf("%s_%s_total", tier, operation))
    }
}

func (m *MockChaosSearchClient) filterEvents(params *storage.QueryParams) []interface{} {
    if events, exists := m.storage[params.Tier]; exists {
        // Apply time-based filtering if specified
        if params.TimeRange != nil {
            filtered := make([]interface{}, 0)
            for _, event := range events {
                // Add time-based filtering logic here
                filtered = append(filtered, event)
            }
            return filtered
        }
        return events
    }
    return []interface{}{}
}

func validateMockConfig(config *MockConfig) error {
    if config.MaxEvents <= 0 {
        return errors.NewError("E2001", "invalid MaxEvents value", nil)
    }
    if config.ErrorRate < 0 || config.ErrorRate > 1 {
        return errors.NewError("E2001", "invalid ErrorRate value", nil)
    }
    if len(config.TierLatencies) == 0 {
        return errors.NewError("E2001", "TierLatencies configuration required", nil)
    }
    return nil
}