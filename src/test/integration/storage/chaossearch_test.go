package storage_test

import (
    "context"
    "testing"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/stretchr/testify/require"

    "github.com/blackpoint/internal/storage"
    "github.com/blackpoint/pkg/bronze"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/test/internal/framework"
    "github.com/blackpoint/test/pkg/fixtures"
)

// Global test constants
const (
    testTimeout = 5 * time.Minute
    
    // Performance thresholds from technical spec
    bronzeLatency = 1 * time.Second
    silverLatency = 5 * time.Second
    goldLatency = 30 * time.Second
    minThroughput = 1000 // events/second
    
    // Retention periods from technical spec
    bronzeRetention = 30 * 24 * time.Hour  // 30 days
    silverRetention = 90 * 24 * time.Hour  // 90 days
    goldRetention = 365 * 24 * time.Hour   // 365 days
)

// Prometheus metrics
var (
    storageLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "chaossearch_test_latency_seconds",
            Help: "Storage operation latency by tier",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
        },
        []string{"operation", "tier"},
    )

    throughputGauge = prometheus.NewGauge(
        prometheus.GaugeOpts{
            Name: "chaossearch_test_throughput_events_per_second",
            Help: "Storage throughput in events per second",
        },
    )
)

func TestMain(m *testing.M) {
    // Register metrics
    prometheus.MustRegister(storageLatency, throughputGauge)

    // Run tests
    m.Run()
}

func TestChaosSearchStorage(t *testing.T) {
    // Create test suite
    suite := framework.NewTestSuite(t, "chaossearch-storage", &framework.TestConfig{
        Timeout: testTimeout,
        Parallel: true,
        SecurityEnabled: true,
        MonitoringEnabled: true,
    })

    // Add test cases
    suite.AddTestCase(testStoragePerformance)
    suite.AddTestCase(testRetentionPolicies)
    suite.AddTestCase(testDataAccessPatterns)

    // Run suite
    suite.Run()
}

func testStoragePerformance(t *testing.T) {
    t.Parallel()
    
    ctx := context.Background()
    client, err := storage.NewChaosSearchClient(ctx, getTestConfig())
    require.NoError(t, err)

    // Test Bronze tier write latency
    t.Run("BronzeWriteLatency", func(t *testing.T) {
        events, _, err := fixtures.GenerateBronzeEventBatch(minThroughput, &fixtures.BatchOptions{
            Concurrent: true,
            WorkerCount: 4,
        })
        require.NoError(t, err)

        start := time.Now()
        for _, event := range events {
            err := client.StoreEvent(ctx, "bronze", event)
            require.NoError(t, err)
        }
        duration := time.Since(start)

        // Validate latency
        avgLatency := duration / time.Duration(len(events))
        require.Less(t, avgLatency, bronzeLatency)
        storageLatency.WithLabelValues("write", "bronze").Observe(avgLatency.Seconds())
    })

    // Test Silver tier processing latency
    t.Run("SilverProcessingLatency", func(t *testing.T) {
        start := time.Now()
        events, err := client.QueryEvents(ctx, "silver", map[string]interface{}{
            "time_range": "1h",
            "limit": 1000,
        })
        require.NoError(t, err)
        duration := time.Since(start)

        require.Less(t, duration, silverLatency)
        storageLatency.WithLabelValues("query", "silver").Observe(duration.Seconds())
    })

    // Test Gold tier analytics latency
    t.Run("GoldAnalyticsLatency", func(t *testing.T) {
        start := time.Now()
        _, err := client.QueryEvents(ctx, "gold", map[string]interface{}{
            "time_range": "24h",
            "aggregation": "security_analysis",
        })
        require.NoError(t, err)
        duration := time.Since(start)

        require.Less(t, duration, goldLatency)
        storageLatency.WithLabelValues("analytics", "gold").Observe(duration.Seconds())
    })

    // Test throughput with parallel clients
    t.Run("ParallelThroughput", func(t *testing.T) {
        events, metrics, err := fixtures.GenerateBronzeEventBatch(minThroughput*10, &fixtures.BatchOptions{
            Concurrent: true,
            WorkerCount: 8,
        })
        require.NoError(t, err)

        start := time.Now()
        errChan := make(chan error, len(events))
        
        // Store events in parallel
        for _, event := range events {
            go func(e *bronze.BronzeEvent) {
                errChan <- client.StoreEvent(ctx, "bronze", e)
            }(event)
        }

        // Collect errors
        for i := 0; i < len(events); i++ {
            require.NoError(t, <-errChan)
        }

        duration := time.Since(start)
        throughput := float64(len(events)) / duration.Seconds()
        
        require.GreaterOrEqual(t, throughput, float64(minThroughput))
        throughputGauge.Set(throughput)
    })
}

func testRetentionPolicies(t *testing.T) {
    t.Parallel()
    
    ctx := context.Background()
    client, err := storage.NewChaosSearchClient(ctx, getTestConfig())
    require.NoError(t, err)

    // Test Bronze tier retention
    t.Run("BronzeRetention", func(t *testing.T) {
        policy, err := client.GetRetentionPolicy(ctx, "bronze")
        require.NoError(t, err)
        require.Equal(t, bronzeRetention, policy.Duration)

        // Verify data expiration
        expiredData, err := client.QueryEvents(ctx, "bronze", map[string]interface{}{
            "time_range": "31d",
        })
        require.NoError(t, err)
        require.Empty(t, expiredData)
    })

    // Test Silver tier retention
    t.Run("SilverRetention", func(t *testing.T) {
        policy, err := client.GetRetentionPolicy(ctx, "silver")
        require.NoError(t, err)
        require.Equal(t, silverRetention, policy.Duration)
    })

    // Test Gold tier retention
    t.Run("GoldRetention", func(t *testing.T) {
        policy, err := client.GetRetentionPolicy(ctx, "gold")
        require.NoError(t, err)
        require.Equal(t, goldRetention, policy.Duration)
    })
}

func testDataAccessPatterns(t *testing.T) {
    t.Parallel()
    
    ctx := context.Background()
    client, err := storage.NewChaosSearchClient(ctx, getTestConfig())
    require.NoError(t, err)

    // Test time-based partitioning
    t.Run("TimeBasedPartitioning", func(t *testing.T) {
        events, _, err := fixtures.GenerateBronzeEventBatch(100, nil)
        require.NoError(t, err)

        // Store events
        for _, event := range events {
            err := client.StoreEvent(ctx, "bronze", event)
            require.NoError(t, err)
        }

        // Query by time ranges
        timeRanges := []string{"1h", "24h", "7d"}
        for _, tr := range timeRanges {
            results, err := client.QueryEvents(ctx, "bronze", map[string]interface{}{
                "time_range": tr,
            })
            require.NoError(t, err)
            require.NotEmpty(t, results)
        }
    })

    // Test client-based sharding
    t.Run("ClientBasedSharding", func(t *testing.T) {
        clients := []string{"client1", "client2", "client3"}
        
        // Store events for different clients
        for _, clientID := range clients {
            events, _, err := fixtures.GenerateBronzeEventBatch(50, &fixtures.BatchOptions{
                ClientID: clientID,
            })
            require.NoError(t, err)

            for _, event := range events {
                err := client.StoreEvent(ctx, "bronze", event)
                require.NoError(t, err)
            }
        }

        // Query by client
        for _, clientID := range clients {
            results, err := client.QueryEvents(ctx, "bronze", map[string]interface{}{
                "client_id": clientID,
                "time_range": "1h",
            })
            require.NoError(t, err)
            require.NotEmpty(t, results)
        }
    })
}

// Helper function to get test configuration
func getTestConfig() *storage.ChaosSearchConfig {
    return &storage.ChaosSearchConfig{
        Endpoint: "test-endpoint",
        Region: "us-east-1",
        BucketName: "test-bucket",
        IndexPrefix: "test",
        ShardCount: 3,
        ReplicaCount: 2,
    }
}