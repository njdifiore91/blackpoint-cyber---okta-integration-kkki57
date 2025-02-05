// Package mocks provides mock implementations for testing the BlackPoint Security Integration Framework
package mocks

import (
	"context"
	"encoding/json"
	"sync"
	"time"
	"testing"

	"github.com/blackpoint/pkg/common" // v1.21
)

// Default configuration values for mock Redis client
const (
	defaultMockTTL     = 15 * time.Minute
	defaultMockTimeout = 5 * time.Second
	maxMockEntries    = 10000
)

// Mock Redis error codes
const (
	ErrKeyNotFound      = "REDIS001"
	ErrKeyExpired      = "REDIS002"
	ErrCapacityExceeded = "REDIS003"
	ErrInvalidKey      = "REDIS004"
	ErrInvalidValue    = "REDIS005"
	ErrLockTimeout     = "REDIS006"
)

// MockOptions configures the behavior of the mock Redis client
type MockOptions struct {
	DefaultTTL  time.Duration
	LockTimeout time.Duration
	MaxEntries  uint64
}

// mockEntry represents a cached item with TTL support
type mockEntry struct {
	data    []byte
	expiry  time.Time
	created time.Time
	size    uint64
}

// perfMetrics tracks performance metrics for mock operations
type perfMetrics struct {
	mu         sync.Mutex
	latencies  map[string]time.Duration
	operations map[string]uint64
	startTime  time.Time
}

// MockRedisClient provides a thread-safe mock implementation of Redis client
type MockRedisClient struct {
	t           *testing.T
	mu          sync.RWMutex
	storage     map[string]mockEntry
	defaultTTL  time.Duration
	lockTimeout time.Duration
	maxEntries  uint64
	metrics     *perfMetrics
}

// NewMockRedisClient creates a new mock Redis client with the specified options
func NewMockRedisClient(t *testing.T, opts *MockOptions) *MockRedisClient {
	if t == nil {
		panic("testing.T reference is required")
	}

	if opts == nil {
		opts = &MockOptions{}
	}

	// Set default values if not specified
	if opts.DefaultTTL == 0 {
		opts.DefaultTTL = defaultMockTTL
	}
	if opts.LockTimeout == 0 {
		opts.LockTimeout = defaultMockTimeout
	}
	if opts.MaxEntries == 0 {
		opts.MaxEntries = maxMockEntries
	}

	client := &MockRedisClient{
		t:           t,
		storage:     make(map[string]mockEntry),
		defaultTTL:  opts.DefaultTTL,
		lockTimeout: opts.LockTimeout,
		maxEntries:  opts.MaxEntries,
		metrics: &perfMetrics{
			latencies:  make(map[string]time.Duration),
			operations: make(map[string]uint64),
			startTime:  time.Now(),
		},
	}

	// Start background cleanup routine
	go client.cleanupExpired()

	return client
}

// Set implements thread-safe mock SET operation with TTL
func (m *MockRedisClient) Set(ctx context.Context, key string, value interface{}, ttl *time.Duration) error {
	start := time.Now()
	defer func() {
		m.trackMetric("set", start)
	}()

	// Validate key
	if key == "" {
		return common.NewError(ErrInvalidKey, "key cannot be empty", nil)
	}

	// Acquire write lock with timeout
	lockChan := make(chan struct{})
	go func() {
		m.mu.Lock()
		close(lockChan)
	}()

	select {
	case <-lockChan:
		defer m.mu.Unlock()
	case <-time.After(m.lockTimeout):
		return common.NewError(ErrLockTimeout, "failed to acquire lock for SET operation", nil)
	case <-ctx.Done():
		return common.NewError(ErrLockTimeout, "context cancelled during SET operation", nil)
	}

	// Check capacity
	if uint64(len(m.storage)) >= m.maxEntries {
		return common.NewError(ErrCapacityExceeded, "mock Redis capacity exceeded", nil)
	}

	// Marshal value
	data, err := json.Marshal(value)
	if err != nil {
		return common.NewError(ErrInvalidValue, "failed to marshal value", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Calculate expiry
	expiry := time.Now().Add(m.defaultTTL)
	if ttl != nil {
		expiry = time.Now().Add(*ttl)
	}

	// Store entry
	m.storage[key] = mockEntry{
		data:    data,
		expiry:  expiry,
		created: time.Now(),
		size:    uint64(len(data)),
	}

	return nil
}

// Get implements thread-safe mock GET operation with expiry check
func (m *MockRedisClient) Get(ctx context.Context, key string, value interface{}) error {
	start := time.Now()
	defer func() {
		m.trackMetric("get", start)
	}()

	// Validate key
	if key == "" {
		return common.NewError(ErrInvalidKey, "key cannot be empty", nil)
	}

	// Acquire read lock with timeout
	lockChan := make(chan struct{})
	go func() {
		m.mu.RLock()
		close(lockChan)
	}()

	select {
	case <-lockChan:
		defer m.mu.RUnlock()
	case <-time.After(m.lockTimeout):
		return common.NewError(ErrLockTimeout, "failed to acquire lock for GET operation", nil)
	case <-ctx.Done():
		return common.NewError(ErrLockTimeout, "context cancelled during GET operation", nil)
	}

	// Check existence and expiry
	entry, exists := m.storage[key]
	if !exists {
		return common.NewError(ErrKeyNotFound, "key not found", nil)
	}

	if time.Now().After(entry.expiry) {
		return common.NewError(ErrKeyExpired, "key has expired", nil)
	}

	// Unmarshal value
	if err := json.Unmarshal(entry.data, value); err != nil {
		return common.NewError(ErrInvalidValue, "failed to unmarshal value", map[string]interface{}{
			"error": err.Error(),
		})
	}

	return nil
}

// Delete implements thread-safe mock DEL operation
func (m *MockRedisClient) Delete(ctx context.Context, key string) error {
	start := time.Now()
	defer func() {
		m.trackMetric("delete", start)
	}()

	// Acquire write lock with timeout
	lockChan := make(chan struct{})
	go func() {
		m.mu.Lock()
		close(lockChan)
	}()

	select {
	case <-lockChan:
		defer m.mu.Unlock()
	case <-time.After(m.lockTimeout):
		return common.NewError(ErrLockTimeout, "failed to acquire lock for DELETE operation", nil)
	case <-ctx.Done():
		return common.NewError(ErrLockTimeout, "context cancelled during DELETE operation", nil)
	}

	delete(m.storage, key)
	return nil
}

// Ping implements mock PING operation for health checks
func (m *MockRedisClient) Ping(ctx context.Context) error {
	start := time.Now()
	defer func() {
		m.trackMetric("ping", start)
	}()
	return nil
}

// Close implements mock cleanup on client shutdown
func (m *MockRedisClient) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.storage = nil
	return nil
}

// GetMetrics returns current performance metrics
func (m *MockRedisClient) GetMetrics() map[string]interface{} {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()

	return map[string]interface{}{
		"operations": m.metrics.operations,
		"latencies":  m.metrics.latencies,
		"uptime":     time.Since(m.metrics.startTime).String(),
	}
}

// cleanupExpired periodically removes expired entries
func (m *MockRedisClient) cleanupExpired() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		m.mu.Lock()
		now := time.Now()
		for key, entry := range m.storage {
			if now.After(entry.expiry) {
				delete(m.storage, key)
			}
		}
		m.mu.Unlock()
	}
}

// trackMetric records operation latency and count
func (m *MockRedisClient) trackMetric(operation string, start time.Time) {
	m.metrics.mu.Lock()
	defer m.metrics.mu.Unlock()

	latency := time.Since(start)
	m.metrics.latencies[operation] = latency
	m.metrics.operations[operation]++
}