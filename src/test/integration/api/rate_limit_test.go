// Package api provides integration tests for API rate limiting functionality
// Version: 1.0.0
package api

import (
    "context"
    "fmt"
    "net/http"
    "sync"
    "testing"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/stretchr/testify/require"

    "../../internal/framework/test_suite"
    "../../pkg/metrics/performance_metrics"
    "../../pkg/fixtures"
)

// Constants for rate limit testing
const (
    bronzeTierRateLimit = 1000 // requests per minute
    silverTierRateLimit = 100  // requests per minute
    goldTierRateLimit   = 50   // requests per minute
    testTimeout        = 5 * time.Minute
    requestInterval    = time.Millisecond
)

// Prometheus metrics for rate limit testing
var (
    rateLimitExceeded = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_rate_limit_exceeded_total",
            Help: "Number of requests that exceeded rate limits",
        },
        []string{"tier", "client_id"},
    )

    requestLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_request_latency_seconds",
            Help: "Request latency by tier",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
        },
        []string{"tier", "status"},
    )
)

// rateLimitTestSuite represents a test suite for rate limit validation
type rateLimitTestSuite struct {
    t               *testing.T
    tier            string
    rateLimit       int
    client          *http.Client
    baseURL         string
    metricsRegistry *prometheus.Registry
    waitGroup       sync.WaitGroup
    ctx             context.Context
    cancel          context.CancelFunc
}

// newRateLimitTestSuite creates a new rate limit test suite instance
func newRateLimitTestSuite(t *testing.T, tier string, rateLimit int) *rateLimitTestSuite {
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)

    // Initialize test suite with security context
    suite := &rateLimitTestSuite{
        t:         t,
        tier:      tier,
        rateLimit: rateLimit,
        client:    &http.Client{Timeout: 10 * time.Second},
        baseURL:   fmt.Sprintf("https://api.blackpoint.security/v1/%s", tier),
        ctx:      ctx,
        cancel:   cancel,
    }

    // Register metrics
    suite.metricsRegistry = prometheus.NewRegistry()
    suite.metricsRegistry.MustRegister(rateLimitExceeded, requestLatency)

    return suite
}

// sendRequests sends HTTP requests at specified rate with metrics collection
func (s *rateLimitTestSuite) sendRequests(requestCount int, interval time.Duration) ([]int, error) {
    statusCodes := make([]int, requestCount)
    metrics := performance_metrics.NewPerformanceMetrics()

    // Generate test event
    event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
        ClientID:       "test-client",
        SourcePlatform: "test-platform",
    })
    if err != nil {
        return nil, fmt.Errorf("failed to generate test event: %v", err)
    }

    for i := 0; i < requestCount; i++ {
        select {
        case <-s.ctx.Done():
            return statusCodes, s.ctx.Err()
        default:
            startTime := time.Now()

            // Send request
            resp, err := s.client.Post(s.baseURL, "application/json", nil)
            if err != nil {
                return statusCodes, fmt.Errorf("request failed: %v", err)
            }

            // Record metrics
            duration := time.Since(startTime)
            requestLatency.WithLabelValues(s.tier, fmt.Sprintf("%d", resp.StatusCode)).Observe(duration.Seconds())

            if resp.StatusCode == http.StatusTooManyRequests {
                rateLimitExceeded.WithLabelValues(s.tier, "test-client").Inc()
            }

            statusCodes[i] = resp.StatusCode
            resp.Body.Close()

            // Wait for next interval
            time.Sleep(interval)
        }
    }

    return statusCodes, nil
}

// TestBronzeTierRateLimits tests rate limiting for Bronze tier API endpoints
func TestBronzeTierRateLimits(t *testing.T) {
    suite := newRateLimitTestSuite(t, "bronze", bronzeTierRateLimit)
    defer suite.cancel()

    // Initialize test metrics
    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "bronze_rate_limit", time.Minute)
    require.NoError(t, err)

    // Send requests at rate exceeding limit
    requestCount := bronzeTierRateLimit * 2
    statusCodes, err := suite.sendRequests(requestCount, requestInterval)
    require.NoError(t, err)

    // Validate rate limiting
    exceededCount := 0
    for _, code := range statusCodes {
        if code == http.StatusTooManyRequests {
            exceededCount++
        }
    }

    // Verify rate limit enforcement
    require.Greater(t, exceededCount, 0, "Rate limit was not enforced")
    require.Less(t, exceededCount, requestCount, "All requests were rate limited")

    // Validate performance metrics
    valid, err := performance_metrics.ValidatePerformanceRequirements(t, metrics)
    require.NoError(t, err)
    require.True(t, valid, "Performance requirements not met")
}

// TestSilverTierRateLimits tests rate limiting for Silver tier API endpoints
func TestSilverTierRateLimits(t *testing.T) {
    suite := newRateLimitTestSuite(t, "silver", silverTierRateLimit)
    defer suite.cancel()

    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "silver_rate_limit", time.Minute)
    require.NoError(t, err)

    requestCount := silverTierRateLimit * 2
    statusCodes, err := suite.sendRequests(requestCount, requestInterval)
    require.NoError(t, err)

    exceededCount := 0
    for _, code := range statusCodes {
        if code == http.StatusTooManyRequests {
            exceededCount++
        }
    }

    require.Greater(t, exceededCount, 0)
    require.Less(t, exceededCount, requestCount)

    valid, err := performance_metrics.ValidatePerformanceRequirements(t, metrics)
    require.NoError(t, err)
    require.True(t, valid)
}

// TestGoldTierRateLimits tests rate limiting for Gold tier API endpoints
func TestGoldTierRateLimits(t *testing.T) {
    suite := newRateLimitTestSuite(t, "gold", goldTierRateLimit)
    defer suite.cancel()

    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "gold_rate_limit", time.Minute)
    require.NoError(t, err)

    requestCount := goldTierRateLimit * 2
    statusCodes, err := suite.sendRequests(requestCount, requestInterval)
    require.NoError(t, err)

    exceededCount := 0
    for _, code := range statusCodes {
        if code == http.StatusTooManyRequests {
            exceededCount++
        }
    }

    require.Greater(t, exceededCount, 0)
    require.Less(t, exceededCount, requestCount)

    valid, err := performance_metrics.ValidatePerformanceRequirements(t, metrics)
    require.NoError(t, err)
    require.True(t, valid)
}

// TestConcurrentClientRateLimits tests rate limiting with multiple concurrent clients
func TestConcurrentClientRateLimits(t *testing.T) {
    clientCount := 5
    suite := newRateLimitTestSuite(t, "bronze", bronzeTierRateLimit)
    defer suite.cancel()

    metrics, err := performance_metrics.CollectPerformanceMetrics(t, "concurrent_rate_limit", time.Minute)
    require.NoError(t, err)

    var wg sync.WaitGroup
    requestCount := bronzeTierRateLimit / clientCount

    for i := 0; i < clientCount; i++ {
        wg.Add(1)
        go func(clientID int) {
            defer wg.Done()
            statusCodes, err := suite.sendRequests(requestCount, requestInterval)
            require.NoError(t, err)

            exceededCount := 0
            for _, code := range statusCodes {
                if code == http.StatusTooManyRequests {
                    exceededCount++
                }
            }

            require.Greater(t, exceededCount, 0)
            require.Less(t, exceededCount, requestCount)
        }(i)
    }

    wg.Wait()

    valid, err := performance_metrics.ValidatePerformanceRequirements(t, metrics)
    require.NoError(t, err)
    require.True(t, valid)
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(rateLimitExceeded, requestLatency)
}