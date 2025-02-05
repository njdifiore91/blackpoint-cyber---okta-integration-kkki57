// Package bronze provides integration tests for the Bronze tier storage layer
package bronze

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert" // v1.8.4
    
    "github.com/blackpoint/internal/storage"
    "github.com/blackpoint/test/pkg/mocks"
    "github.com/blackpoint/test/internal/framework"
    "github.com/blackpoint/pkg/common/errors"
)

// bronzeStorageTestSuite manages the test suite state and resources
type bronzeStorageTestSuite struct {
    t          *testing.T
    mockClient *mocks.MockChaosSearchClient
    testCase   *framework.TestCase
    ctx        context.Context
    cancel     context.CancelFunc
}

// newBronzeStorageTestSuite initializes a new test suite with monitoring
func newBronzeStorageTestSuite(t *testing.T) *bronzeStorageTestSuite {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
    
    // Initialize test case with monitoring
    testCase := framework.NewTestCase(t, "BronzeStorageIntegration", &framework.TestConfig{
        Timeout:    5 * time.Minute,
        Thresholds: map[string]float64{"accuracy": 0.80},
        Labels: map[string]string{
            "tier": "bronze",
            "type": "storage",
        },
    })

    return &bronzeStorageTestSuite{
        t:        t,
        ctx:      ctx,
        cancel:   cancel,
        testCase: testCase,
    }
}

// TestBronzeStorageBasicOperations validates basic storage operations with monitoring
func TestBronzeStorageBasicOperations(t *testing.T) {
    suite := newBronzeStorageTestSuite(t)
    defer suite.cancel()

    // Initialize mock client with performance tracking
    mockConfig := &mocks.MockConfig{
        MaxEvents:      1000,
        ErrorRate:      0.01,
        MetricsEnabled: true,
        TierLatencies: map[string]time.Duration{
            "bronze": 100 * time.Millisecond,
        },
    }

    client, err := mocks.NewMockChaosSearchClient(t, mockConfig)
    assert.NoError(t, err, "Failed to create mock client")
    suite.mockClient = client

    // Test basic store and retrieve operations
    suite.testCase.AddStep(&framework.TestStep{
        Name: "Store Security Event",
        Exec: func(ctx context.Context) error {
            event := map[string]interface{}{
                "id":        "test-event-1",
                "type":      "security_alert",
                "severity":  "high",
                "timestamp": time.Now().UTC(),
                "source":    "test-integration",
            }
            return suite.mockClient.StoreEvent("bronze", event)
        },
        Critical: true,
    })

    suite.testCase.AddStep(&framework.TestStep{
        Name: "Retrieve Security Event",
        Exec: func(ctx context.Context) error {
            params := &storage.QueryParams{
                Tier: "bronze",
                TimeRange: &storage.TimeRange{
                    Start: time.Now().Add(-1 * time.Hour),
                    End:   time.Now(),
                },
            }
            events, err := suite.mockClient.QueryEvents(params)
            if err != nil {
                return err
            }
            suite.testCase.Assert(func() bool {
                return len(events) > 0
            }, "Expected to retrieve stored event")
            return nil
        },
    })

    suite.testCase.Run()
}

// TestBronzeStoragePerformance validates storage performance requirements
func TestBronzeStoragePerformance(t *testing.T) {
    suite := newBronzeStorageTestSuite(t)
    defer suite.cancel()

    // Configure mock client for performance testing
    mockConfig := &mocks.MockConfig{
        MaxEvents:      10000,
        ErrorRate:      0.01,
        MetricsEnabled: true,
        TierLatencies: map[string]time.Duration{
            "bronze": 50 * time.Millisecond, // Target sub-1s latency
        },
    }

    client, err := mocks.NewMockChaosSearchClient(t, mockConfig)
    assert.NoError(t, err, "Failed to create mock client")
    suite.mockClient = client

    // Test high-volume event ingestion
    suite.testCase.AddStep(&framework.TestStep{
        Name: "High Volume Event Ingestion",
        Exec: func(ctx context.Context) error {
            startTime := time.Now()
            eventCount := 1000 // Test 1000 events/second requirement

            for i := 0; i < eventCount; i++ {
                event := map[string]interface{}{
                    "id":        fmt.Sprintf("perf-event-%d", i),
                    "type":      "security_alert",
                    "timestamp": time.Now().UTC(),
                }
                if err := suite.mockClient.StoreEvent("bronze", event); err != nil {
                    return err
                }
            }

            duration := time.Since(startTime)
            eventsPerSecond := float64(eventCount) / duration.Seconds()

            suite.testCase.Assert(func() bool {
                return eventsPerSecond >= 1000
            }, fmt.Sprintf("Expected >1000 events/second, got %.2f", eventsPerSecond))

            return nil
        },
        Timeout: 30 * time.Second,
    })

    suite.testCase.Run()
}

// TestBronzeStorageRetention validates data retention policies
func TestBronzeStorageRetention(t *testing.T) {
    suite := newBronzeStorageTestSuite(t)
    defer suite.cancel()

    mockConfig := &mocks.MockConfig{
        MaxEvents:      5000,
        MetricsEnabled: true,
        TierLatencies: map[string]time.Duration{
            "bronze": 100 * time.Millisecond,
        },
    }

    client, err := mocks.NewMockChaosSearchClient(t, mockConfig)
    assert.NoError(t, err, "Failed to create mock client")
    suite.mockClient = client

    // Test retention period implementation
    suite.testCase.AddStep(&framework.TestStep{
        Name: "Verify Retention Period",
        Exec: func(ctx context.Context) error {
            // Store events with various ages
            now := time.Now()
            testCases := []struct {
                age      time.Duration
                exists   bool
                message string
            }{
                {25 * 24 * time.Hour, true, "Event within 30-day retention should exist"},
                {35 * 24 * time.Hour, false, "Event beyond 30-day retention should not exist"},
            }

            for _, tc := range testCases {
                event := map[string]interface{}{
                    "id":        fmt.Sprintf("retention-event-%v", tc.age),
                    "timestamp": now.Add(-tc.age),
                }
                err := suite.mockClient.StoreEvent("bronze", event)
                if err != nil {
                    return err
                }
            }

            // Verify retention rules
            for _, tc := range testCases {
                params := &storage.QueryParams{
                    Tier: "bronze",
                    TimeRange: &storage.TimeRange{
                        Start: now.Add(-tc.age),
                        End:   now.Add(-tc.age).Add(time.Hour),
                    },
                }
                events, err := suite.mockClient.QueryEvents(params)
                if err != nil {
                    return err
                }

                suite.testCase.Assert(func() bool {
                    return (len(events) > 0) == tc.exists
                }, tc.message)
            }

            return nil
        },
    })

    suite.testCase.Run()
}

// TestBronzeStorageErrorHandling validates error handling and recovery
func TestBronzeStorageErrorHandling(t *testing.T) {
    suite := newBronzeStorageTestSuite(t)
    defer suite.cancel()

    mockConfig := &mocks.MockConfig{
        MaxEvents:      1000,
        ErrorRate:      0.2, // Higher error rate for testing
        MetricsEnabled: true,
        TierLatencies: map[string]time.Duration{
            "bronze": 100 * time.Millisecond,
        },
    }

    client, err := mocks.NewMockChaosSearchClient(t, mockConfig)
    assert.NoError(t, err, "Failed to create mock client")
    suite.mockClient = client

    suite.testCase.AddStep(&framework.TestStep{
        Name: "Error Recovery",
        Exec: func(ctx context.Context) error {
            successCount := 0
            totalAttempts := 10

            for i := 0; i < totalAttempts; i++ {
                event := map[string]interface{}{
                    "id":        fmt.Sprintf("error-test-%d", i),
                    "timestamp": time.Now(),
                }
                
                err := suite.mockClient.StoreEvent("bronze", event)
                if err == nil {
                    successCount++
                } else {
                    // Verify error is properly structured
                    var bpErr *errors.BlackPointError
                    if !errors.As(err, &bpErr) {
                        return fmt.Errorf("expected BlackPointError, got %T", err)
                    }
                }
            }

            // Verify success rate meets minimum threshold
            successRate := float64(successCount) / float64(totalAttempts)
            suite.testCase.Assert(func() bool {
                return successRate >= 0.7 // Allow for some errors but ensure basic reliability
            }, fmt.Sprintf("Expected success rate >= 70%%, got %.2f%%", successRate*100))

            return nil
        },
        Retries: 3,
    })

    suite.testCase.Run()
}