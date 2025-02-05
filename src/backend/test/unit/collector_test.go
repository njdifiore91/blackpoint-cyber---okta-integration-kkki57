package unit

import (
    "context"
    "testing"
    "time"
    "sync"

    "github.com/blackpoint/internal/collector"
    "github.com/blackpoint/test/pkg/fixtures"
    "github.com/blackpoint/test/pkg/mocks"
    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

const (
    testTimeout        = 5 * time.Second
    testBatchSize     = 1000
    testClientID      = "test-client-001"
    maxConcurrentTests = 10
)

// collectorTestSuite provides a reusable test environment for collector tests
type collectorTestSuite struct {
    t               *testing.T
    collector       *collector.RealtimeCollector
    mockProducer    *mocks.MockProducer
    securityContext *collector.SecurityContext
    ctx            context.Context
    cancel         context.CancelFunc
}

// newCollectorTestSuite initializes a new test suite with security context
func newCollectorTestSuite(t *testing.T) *collectorTestSuite {
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    
    mockProducer := &mocks.MockProducer{}
    mockProducer.On("PublishBatch", mock.Anything, mock.Anything).Return(nil)
    
    securityContext := &collector.SecurityContext{
        ClientID: testClientID,
        SecurityLevel: "standard",
        AuditEnabled: true,
    }

    config := collector.CollectorConfig{
        BufferSize: testBatchSize,
        BatchSize: testBatchSize,
        FlushInterval: 1 * time.Second,
    }

    col, err := collector.NewRealtimeCollector(nil, mockProducer, config)
    assert.NoError(t, err, "Failed to create collector")

    return &collectorTestSuite{
        t:               t,
        collector:       col,
        mockProducer:    mockProducer,
        securityContext: securityContext,
        ctx:            ctx,
        cancel:         cancel,
    }
}

// TestRealtimeCollector_CollectEvent tests individual event collection with security validation
func TestRealtimeCollector_CollectEvent(t *testing.T) {
    suite := newCollectorTestSuite(t)
    defer suite.cancel()

    tests := []struct {
        name          string
        event         []byte
        expectError   bool
        securityLevel string
    }{
        {
            name:          "Valid event with standard security",
            event:         fixtures.SamplePayloads.ValidPayload,
            expectError:   false,
            securityLevel: "standard",
        },
        {
            name:          "Oversized event",
            event:         fixtures.SamplePayloads.OversizedPayload,
            expectError:   true,
            securityLevel: "standard",
        },
        {
            name:          "Security violation event",
            event:         fixtures.SamplePayloads.SecurityViolationPayload,
            expectError:   true,
            securityLevel: "high",
        },
        {
            name:          "Empty event",
            event:         []byte{},
            expectError:   true,
            securityLevel: "standard",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            suite.securityContext.SecurityLevel = tt.securityLevel
            
            // Test event collection
            startTime := time.Now()
            err := suite.collector.CollectEvent(suite.ctx, tt.event)
            
            // Validate results
            if tt.expectError {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
                // Verify processing latency meets <1s requirement
                assert.Less(t, time.Since(startTime), time.Second)
            }
        })
    }
}

// TestRealtimeCollector_BatchProcessing tests batch event processing with performance validation
func TestRealtimeCollector_BatchProcessing(t *testing.T) {
    suite := newCollectorTestSuite(t)
    defer suite.cancel()

    tests := []struct {
        name        string
        batchSize   int
        concurrent  bool
        expectError bool
    }{
        {
            name:        "Standard batch processing",
            batchSize:   1000,
            concurrent:  false,
            expectError: false,
        },
        {
            name:        "Concurrent batch processing",
            batchSize:   1000,
            concurrent:  true,
            expectError: false,
        },
        {
            name:        "Oversized batch",
            batchSize:   testBatchSize + 1,
            concurrent:  false,
            expectError: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Generate test events
            events, metrics, err := fixtures.GenerateBronzeEventBatch(tt.batchSize, &fixtures.BatchOptions{
                Concurrent:      tt.concurrent,
                SecurityContext: suite.securityContext,
                WorkerCount:    maxConcurrentTests,
            })

            if !tt.expectError {
                assert.NoError(t, err)
                assert.NotNil(t, events)
                assert.NotNil(t, metrics)

                // Verify batch processing performance
                assert.GreaterOrEqual(t, metrics.EventsPerSecond, float64(1000))
                assert.Less(t, metrics.GenerationTime, testTimeout)

                // Process events through collector
                startTime := time.Now()
                for _, event := range events {
                    eventBytes, _ := event.ToJSON()
                    err := suite.collector.CollectEvent(suite.ctx, eventBytes)
                    assert.NoError(t, err)
                }

                // Verify batch processing time
                processingTime := time.Since(startTime)
                assert.Less(t, processingTime, testTimeout)
            } else {
                assert.Error(t, err)
            }
        })
    }
}

// TestCollector_ValidationRules tests event validation and security compliance
func TestCollector_ValidationRules(t *testing.T) {
    suite := newCollectorTestSuite(t)
    defer suite.cancel()

    tests := []struct {
        name        string
        testCase    fixtures.SecurityTestCases
        expectError bool
    }{
        {
            name:        "Standard compliance validation",
            testCase:    fixtures.SecurityTestCases.StandardCompliance,
            expectError: false,
        },
        {
            name:        "Security violation detection",
            testCase:    fixtures.SecurityTestCases.SecurityViolation,
            expectError: true,
        },
        {
            name:        "Audit requirement validation",
            testCase:    fixtures.SecurityTestCases.AuditRequirement,
            expectError: false,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Generate test event with security context
            event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
                SecurityLevel: tt.testCase.SecurityContext.Level,
                AuditLevel:   "detailed",
            })
            assert.NoError(t, err)
            assert.NotNil(t, event)

            // Convert to JSON and validate
            eventBytes, err := event.ToJSON()
            assert.NoError(t, err)

            // Test event collection with security validation
            err = suite.collector.CollectEvent(suite.ctx, eventBytes)
            
            if tt.expectError {
                assert.Error(t, err)
            } else {
                assert.NoError(t, err)
            }
        })
    }
}

// TestCollector_ConcurrentProcessing tests concurrent event processing
func TestCollector_ConcurrentProcessing(t *testing.T) {
    suite := newCollectorTestSuite(t)
    defer suite.cancel()

    // Generate concurrent test events
    eventCount := 1000
    var wg sync.WaitGroup
    errorChan := make(chan error, eventCount)

    // Process events concurrently
    for i := 0; i < eventCount; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()

            event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
                SecurityLevel: "standard",
                AuditLevel:   "detailed",
            })
            if err != nil {
                errorChan <- err
                return
            }

            eventBytes, err := event.ToJSON()
            if err != nil {
                errorChan <- err
                return
            }

            if err := suite.collector.CollectEvent(suite.ctx, eventBytes); err != nil {
                errorChan <- err
            }
        }()
    }

    // Wait for completion
    wg.Wait()
    close(errorChan)

    // Check for errors
    var errors []error
    for err := range errorChan {
        errors = append(errors, err)
    }

    assert.Empty(t, errors, "Concurrent processing produced errors")
}

// TestCollector_Shutdown tests graceful shutdown behavior
func TestCollector_Shutdown(t *testing.T) {
    suite := newCollectorTestSuite(t)
    
    // Start collector
    err := suite.collector.Start()
    assert.NoError(t, err)

    // Generate and collect some events
    events, _, err := fixtures.GenerateBronzeEventBatch(100, nil)
    assert.NoError(t, err)

    for _, event := range events {
        eventBytes, _ := event.ToJSON()
        err := suite.collector.CollectEvent(suite.ctx, eventBytes)
        assert.NoError(t, err)
    }

    // Test graceful shutdown
    err = suite.collector.Stop()
    assert.NoError(t, err)

    // Verify no more events can be collected
    event, _ := fixtures.GenerateValidBronzeEvent(nil)
    eventBytes, _ := event.ToJSON()
    err = suite.collector.CollectEvent(suite.ctx, eventBytes)
    assert.Error(t, err)
}