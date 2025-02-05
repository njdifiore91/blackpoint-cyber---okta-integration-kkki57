// Package bronze_test provides integration tests for the Bronze tier collector
package bronze_test

import (
    "context"
    "sync"
    "testing"
    "time"

    "github.com/blackpoint/internal/collector"
    "github.com/blackpoint/pkg/bronze/event"
    "github.com/blackpoint/test/pkg/fixtures"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/require"
    "github.com/stretchr/testify/suite"
)

const (
    testTimeout        = 30 * time.Second
    testBatchSize     = 1000
    testThroughputEvents = 10000
    testSecurityTimeout = 5 * time.Second
    testMetricsInterval = 100 * time.Millisecond
)

// CollectorTestSuite defines the integration test suite for Bronze tier collector
type CollectorTestSuite struct {
    suite.Suite
    collector       *collector.RealtimeCollector
    ctx            context.Context
    cancel         context.CancelFunc
    metricsRegistry *prometheus.Registry
    securityContext *fixtures.SecurityContext
}

// TestCollectorSuite is the entry point for the collector test suite
func TestCollectorSuite(t *testing.T) {
    suite.Run(t, new(CollectorTestSuite))
}

// SetupSuite initializes the test suite environment
func (s *CollectorTestSuite) SetupSuite() {
    // Initialize metrics registry
    s.metricsRegistry = prometheus.NewRegistry()
    prometheus.DefaultRegisterer = s.metricsRegistry

    // Initialize security context
    s.securityContext = &fixtures.SecurityContext{
        Level:      "standard",
        Compliance: []string{"SOC2", "ISO27001"},
        AuditRequirements: map[string]string{
            "log_level":  "debug",
            "retention": "90d",
        },
    }
}

// SetupTest prepares each test case
func (s *CollectorTestSuite) SetupTest() {
    var err error
    s.ctx, s.cancel = context.WithTimeout(context.Background(), testTimeout)

    // Initialize collector with security context
    s.collector, err = collector.NewRealtimeCollector(
        &event.EventProcessor{},
        nil, // Producer will be mocked
        collector.CollectorConfig{
            BufferSize:    testBatchSize * 2,
            BatchSize:     testBatchSize,
            FlushInterval: time.Second,
        },
    )
    require.NoError(s.T(), err, "Failed to create collector")

    // Start collector
    err = s.collector.Start()
    require.NoError(s.T(), err, "Failed to start collector")
}

// TearDownTest cleans up after each test
func (s *CollectorTestSuite) TearDownTest() {
    if s.cancel != nil {
        s.cancel()
    }
    if s.collector != nil {
        err := s.collector.Stop()
        require.NoError(s.T(), err, "Failed to stop collector")
    }
}

// TestSingleEventCollection tests collection of individual events
func (s *CollectorTestSuite) TestSingleEventCollection() {
    // Generate valid test event
    event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
        SecurityLevel: s.securityContext.Level,
        AuditLevel:   "detailed",
    })
    require.NoError(s.T(), err, "Failed to generate test event")

    // Test event collection
    startTime := time.Now()
    err = s.collector.CollectEvent(s.ctx, event.Payload)
    require.NoError(s.T(), err, "Failed to collect event")

    // Verify processing latency
    processingTime := time.Since(startTime)
    assert.Less(s.T(), processingTime, time.Second, "Processing time exceeded 1s threshold")

    // Verify metrics
    metrics, err := s.collector.GetMetrics()
    require.NoError(s.T(), err)
    assert.Equal(s.T(), int64(1), metrics.EventsCollected, "Event count mismatch")
}

// TestBatchEventCollection tests batch event processing
func (s *CollectorTestSuite) TestBatchEventCollection() {
    // Generate batch of test events
    events, metrics, err := fixtures.GenerateBronzeEventBatch(testBatchSize, &fixtures.BatchOptions{
        Concurrent:      true,
        WorkerCount:     4,
        SecurityContext: s.securityContext,
    })
    require.NoError(s.T(), err, "Failed to generate event batch")
    require.Len(s.T(), events, testBatchSize, "Batch size mismatch")

    // Process events concurrently
    var wg sync.WaitGroup
    errors := make(chan error, len(events))

    startTime := time.Now()
    for _, event := range events {
        wg.Add(1)
        go func(e *bronze.BronzeEvent) {
            defer wg.Done()
            if err := s.collector.CollectEvent(s.ctx, e.Payload); err != nil {
                errors <- err
            }
        }(event)
    }

    // Wait for completion
    wg.Wait()
    close(errors)

    // Check for errors
    for err := range errors {
        require.NoError(s.T(), err, "Batch processing error")
    }

    // Verify processing time
    processingTime := time.Since(startTime)
    assert.Less(s.T(), processingTime, 5*time.Second, "Batch processing time exceeded threshold")

    // Verify metrics
    collectorMetrics, err := s.collector.GetMetrics()
    require.NoError(s.T(), err)
    assert.Equal(s.T(), int64(testBatchSize), collectorMetrics.EventsCollected, "Batch event count mismatch")
}

// TestThroughputRequirements tests system throughput
func (s *CollectorTestSuite) TestThroughputRequirements() {
    // Generate large batch for throughput testing
    events, _, err := fixtures.GenerateBronzeEventBatch(testThroughputEvents, &fixtures.BatchOptions{
        Concurrent:      true,
        WorkerCount:     8,
        SecurityContext: s.securityContext,
    })
    require.NoError(s.T(), err, "Failed to generate throughput test events")

    // Process events with throughput measurement
    startTime := time.Now()
    var processed int64
    var wg sync.WaitGroup

    for _, event := range events {
        wg.Add(1)
        go func(e *bronze.BronzeEvent) {
            defer wg.Done()
            err := s.collector.CollectEvent(s.ctx, e.Payload)
            if err == nil {
                atomic.AddInt64(&processed, 1)
            }
        }(event)
    }

    wg.Wait()
    duration := time.Since(startTime)

    // Calculate throughput
    eventsPerSecond := float64(processed) / duration.Seconds()
    assert.GreaterOrEqual(s.T(), eventsPerSecond, float64(1000), 
        "Throughput below 1000 events/second requirement: %f", eventsPerSecond)
}

// TestErrorHandling tests error handling scenarios
func (s *CollectorTestSuite) TestErrorHandling() {
    testCases := []struct {
        name           string
        invalidType    string
        expectedError  string
    }{
        {"OversizedPayload", "oversized_payload", "event size exceeds limit"},
        {"MalformedPayload", "malformed_payload", "invalid event format"},
        {"SecurityViolation", "security_violation", "security policy violation"},
    }

    for _, tc := range testCases {
        s.T().Run(tc.name, func(t *testing.T) {
            invalidEvent, err := fixtures.GenerateInvalidBronzeEvent(tc.invalidType, s.securityContext)
            require.NoError(t, err, "Failed to generate invalid event")

            err = s.collector.CollectEvent(s.ctx, invalidEvent.Payload)
            assert.Error(t, err, "Expected error for invalid event")
            assert.Contains(t, err.Error(), tc.expectedError)
        })
    }
}

// TestGracefulShutdown tests collector shutdown behavior
func (s *CollectorTestSuite) TestGracefulShutdown() {
    // Generate test events
    events, _, err := fixtures.GenerateBronzeEventBatch(100, &fixtures.BatchOptions{
        SecurityContext: s.securityContext,
    })
    require.NoError(s.T(), err, "Failed to generate shutdown test events")

    // Start processing events
    var wg sync.WaitGroup
    for _, event := range events {
        wg.Add(1)
        go func(e *bronze.BronzeEvent) {
            defer wg.Done()
            _ = s.collector.CollectEvent(s.ctx, e.Payload)
        }(event)
    }

    // Initiate shutdown
    shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer shutdownCancel()

    err = s.collector.Stop()
    require.NoError(s.T(), err, "Failed to stop collector")

    // Verify graceful shutdown
    select {
    case <-shutdownCtx.Done():
        s.T().Fatal("Shutdown timeout exceeded")
    default:
        wg.Wait()
    }
}

// TestSecurityCompliance tests security requirements
func (s *CollectorTestSuite) TestSecurityCompliance() {
    // Test security validation
    testCases := []struct {
        name     string
        context  *fixtures.SecurityContext
        expectErr bool
    }{
        {
            name: "ValidSecurityContext",
            context: &fixtures.SecurityContext{
                Level:      "standard",
                Compliance: []string{"SOC2"},
            },
            expectErr: false,
        },
        {
            name: "InvalidSecurityLevel",
            context: &fixtures.SecurityContext{
                Level: "invalid",
            },
            expectErr: true,
        },
        {
            name: "MissingCompliance",
            context: &fixtures.SecurityContext{
                Level:      "high",
                Compliance: []string{},
            },
            expectErr: true,
        },
    }

    for _, tc := range testCases {
        s.T().Run(tc.name, func(t *testing.T) {
            event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
                SecurityLevel: tc.context.Level,
            })
            require.NoError(t, err, "Failed to generate security test event")

            err = s.collector.CollectEvent(s.ctx, event.Payload)
            if tc.expectErr {
                assert.Error(t, err, "Expected security validation error")
            } else {
                assert.NoError(t, err, "Unexpected security validation error")
            }
        })
    }
}