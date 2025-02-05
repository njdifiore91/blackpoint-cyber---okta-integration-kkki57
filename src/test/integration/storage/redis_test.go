package storage_test

import (
    "context"
    "encoding/json"
    "testing"
    "time"

    "github.com/blackpoint/internal/storage"
    "github.com/blackpoint/test/internal/framework"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/stretchr/testify/require"
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/wait"
)

// Test configuration constants
const (
    testTimeout       = 5 * time.Minute
    defaultTTL       = 15 * time.Minute
    testKeyPrefix    = "test:blackpoint:"
    testValueSize    = 1024 // 1KB
    testBatchSize    = 1000
    testConcurrency  = 10
)

// Test metrics
var (
    redisOperationDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_redis_operation_duration_seconds",
            Help: "Duration of Redis operations",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
        },
        []string{"operation", "status"},
    )

    redisOperationErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_redis_operation_errors_total",
            Help: "Total number of Redis operation errors",
        },
        []string{"operation", "error_type"},
    )
)

type redisTestSuite struct {
    client          *storage.RedisClient
    ctx             context.Context
    cancel          context.CancelFunc
    container       testcontainers.Container
    metricsRegistry *prometheus.Registry
}

func TestMain(m *testing.M) {
    // Register metrics
    prometheus.MustRegister(redisOperationDuration, redisOperationErrors)
    
    // Run tests
    m.Run()
}

func TestRedisIntegration(t *testing.T) {
    // Create test suite
    suite := framework.NewTestSuite(t, "redis_integration", &framework.TestSuiteConfig{
        Timeout:         testTimeout,
        SecurityEnabled: true,
        MonitoringEnabled: true,
    })

    // Add test cases
    suite.AddTestCase(testBasicOperations(t))
    suite.AddTestCase(testClusterMode(t))
    suite.AddTestCase(testPerformance(t))
    suite.AddTestCase(testSecurityCompliance(t))
    suite.AddTestCase(testMonitoringIntegration(t))

    // Run test suite
    suite.Run()
}

func setupRedisContainer(t *testing.T) (testcontainers.Container, error) {
    req := testcontainers.ContainerRequest{
        Image:        "redis:7.0-alpine",
        ExposedPorts: []string{"6379/tcp"},
        WaitingFor:   wait.ForLog("Ready to accept connections"),
        Env: map[string]string{
            "REDIS_PASSWORD": "test_password",
        },
    }

    container, err := testcontainers.GenericContainer(context.Background(), testcontainers.GenericContainerRequest{
        ContainerRequest: req,
        Started:         true,
    })
    if err != nil {
        return nil, err
    }

    return container, nil
}

func testBasicOperations(t *testing.T) *framework.TestCase {
    return &framework.TestCase{
        Name: "basic_operations",
        Run: func(ctx context.Context) error {
            // Initialize Redis client
            client, err := initRedisClient(t)
            if err != nil {
                return err
            }
            defer client.Close()

            // Test Set operation
            timer := prometheus.NewTimer(redisOperationDuration.WithLabelValues("set", "success"))
            err = client.Set(ctx, testKeyPrefix+"test_key", "test_value", &defaultTTL)
            timer.ObserveDuration()
            if err != nil {
                redisOperationErrors.WithLabelValues("set", "error").Inc()
                return err
            }

            // Test Get operation
            var value string
            timer = prometheus.NewTimer(redisOperationDuration.WithLabelValues("get", "success"))
            err = client.Get(ctx, testKeyPrefix+"test_key", &value)
            timer.ObserveDuration()
            if err != nil {
                redisOperationErrors.WithLabelValues("get", "error").Inc()
                return err
            }
            require.Equal(t, "test_value", value)

            // Test Delete operation
            timer = prometheus.NewTimer(redisOperationDuration.WithLabelValues("delete", "success"))
            err = client.Delete(ctx, testKeyPrefix+"test_key")
            timer.ObserveDuration()
            if err != nil {
                redisOperationErrors.WithLabelValues("delete", "error").Inc()
                return err
            }

            return nil
        },
    }
}

func testClusterMode(t *testing.T) *framework.TestCase {
    return &framework.TestCase{
        Name: "cluster_mode",
        Run: func(ctx context.Context) error {
            // Initialize Redis client in cluster mode
            config := &storage.RedisConfig{
                Addresses:   []string{"localhost:6379"},
                Password:   "test_password",
                ClusterMode: true,
                TLSEnabled: true,
            }

            client, err := storage.NewRedisClient(config)
            if err != nil {
                return err
            }
            defer client.Close()

            // Test cluster operations
            for i := 0; i < testBatchSize; i++ {
                key := fmt.Sprintf("%scluster_test_%d", testKeyPrefix, i)
                value := map[string]interface{}{
                    "index": i,
                    "data":  make([]byte, testValueSize),
                }

                timer := prometheus.NewTimer(redisOperationDuration.WithLabelValues("cluster_set", "success"))
                err := client.Set(ctx, key, value, &defaultTTL)
                timer.ObserveDuration()
                if err != nil {
                    redisOperationErrors.WithLabelValues("cluster_set", "error").Inc()
                    return err
                }
            }

            return nil
        },
    }
}

func testPerformance(t *testing.T) *framework.TestCase {
    return &framework.TestCase{
        Name: "performance",
        Run: func(ctx context.Context) error {
            client, err := initRedisClient(t)
            if err != nil {
                return err
            }
            defer client.Close()

            // Concurrent performance test
            errChan := make(chan error, testConcurrency)
            for i := 0; i < testConcurrency; i++ {
                go func(workerID int) {
                    var err error
                    for j := 0; j < testBatchSize/testConcurrency; j++ {
                        key := fmt.Sprintf("%sperf_test_%d_%d", testKeyPrefix, workerID, j)
                        value := map[string]interface{}{
                            "worker_id": workerID,
                            "index":     j,
                            "data":      make([]byte, testValueSize),
                        }

                        timer := prometheus.NewTimer(redisOperationDuration.WithLabelValues("perf_set", "success"))
                        err = client.Set(ctx, key, value, &defaultTTL)
                        timer.ObserveDuration()
                        if err != nil {
                            redisOperationErrors.WithLabelValues("perf_set", "error").Inc()
                            errChan <- err
                            return
                        }
                    }
                    errChan <- nil
                }(i)
            }

            // Collect results
            for i := 0; i < testConcurrency; i++ {
                if err := <-errChan; err != nil {
                    return err
                }
            }

            return nil
        },
    }
}

func testSecurityCompliance(t *testing.T) *framework.TestCase {
    return &framework.TestCase{
        Name: "security_compliance",
        Run: func(ctx context.Context) error {
            // Test with security configuration
            config := &storage.RedisConfig{
                Addresses:   []string{"localhost:6379"},
                Password:   "test_password",
                TLSEnabled: true,
                CertFile:   "testdata/tls/redis.crt",
                KeyFile:    "testdata/tls/redis.key",
            }

            client, err := storage.NewRedisClient(config)
            if err != nil {
                return err
            }
            defer client.Close()

            // Test secure operations
            sensitiveData := map[string]interface{}{
                "secret": "test_secret",
                "key":    "test_key",
            }

            timer := prometheus.NewTimer(redisOperationDuration.WithLabelValues("secure_set", "success"))
            err = client.Set(ctx, testKeyPrefix+"secure_test", sensitiveData, &defaultTTL)
            timer.ObserveDuration()
            if err != nil {
                redisOperationErrors.WithLabelValues("secure_set", "error").Inc()
                return err
            }

            return nil
        },
    }
}

func testMonitoringIntegration(t *testing.T) *framework.TestCase {
    return &framework.TestCase{
        Name: "monitoring_integration",
        Run: func(ctx context.Context) error {
            client, err := initRedisClient(t)
            if err != nil {
                return err
            }
            defer client.Close()

            // Test metrics collection
            metrics, err := client.GetMetrics()
            if err != nil {
                return err
            }

            // Validate metrics
            require.NotNil(t, metrics)
            require.Contains(t, metrics, "connected_clients")
            require.Contains(t, metrics, "used_memory")
            require.Contains(t, metrics, "total_commands_processed")

            return nil
        },
    }
}

func initRedisClient(t *testing.T) (*storage.RedisClient, error) {
    container, err := setupRedisContainer(t)
    if err != nil {
        return nil, err
    }

    // Get container connection details
    host, err := container.Host(context.Background())
    if err != nil {
        return nil, err
    }

    port, err := container.MappedPort(context.Background(), "6379")
    if err != nil {
        return nil, err
    }

    // Create Redis client
    config := &storage.RedisConfig{
        Addresses: []string{fmt.Sprintf("%s:%s", host, port.Port())},
        Password: "test_password",
    }

    return storage.NewRedisClient(config)
}