package api_test

import (
    "context"
    "fmt"
    "net/http"
    "testing"
    "time"

    "github.com/prometheus/client_golang/prometheus" // v1.16.0
    "github.com/stretchr/testify/require"

    "../../internal/framework/test_suite"
    "../../pkg/validation/schema_validator"
)

const (
    // Gateway configuration
    gatewayEndpoint = "http://gateway-service:8000"
    testTimeout     = 5 * time.Minute

    // Rate limits per tier (requests per minute)
    bronzeRateLimit = 1000
    silverRateLimit = 100
    goldRateLimit   = 50

    // Test security context
    testSecurityLevel = "high"
)

// Prometheus metrics
var (
    gatewayLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "blackpoint_gateway_test_latency_seconds",
            Help:    "API Gateway test latency in seconds",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
        },
        []string{"tier", "endpoint", "status"},
    )

    rateLimitExceeded = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_gateway_test_ratelimit_exceeded_total",
            Help: "Number of rate limit exceeded errors",
        },
        []string{"tier"},
    )

    authFailures = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_gateway_test_auth_failures_total",
            Help: "Number of authentication failures",
        },
        []string{"tier", "reason"},
    )
)

func init() {
    // Register metrics
    prometheus.MustRegister(gatewayLatency, rateLimitExceeded, authFailures)
}

// TestGatewayIntegration is the main entry point for API Gateway integration tests
func TestGatewayIntegration(t *testing.T) {
    // Create test suite with security context
    suite := test_suite.NewTestSuite(t, "gateway-integration", &test_suite.TestConfig{
        Timeout:         testTimeout,
        SecurityEnabled: true,
        ValidationConfig: map[string]float64{
            "accuracy":    80.0,
            "performance": 95.0,
            "security":    90.0,
        },
    })

    // Configure test environment
    ctx := context.Background()
    validator := schema_validator.NewSchemaValidator(t)

    // Add test cases
    suite.AddTestCase(&test_suite.TestCase{
        Name: "Authentication Tests",
        Exec: func(ctx context.Context) error {
            return testGatewayAuthentication(t, ctx)
        },
    })

    suite.AddTestCase(&test_suite.TestCase{
        Name: "Rate Limiting Tests",
        Exec: func(ctx context.Context) error {
            return testGatewayRateLimiting(t, ctx)
        },
    })

    suite.AddTestCase(&test_suite.TestCase{
        Name: "Routing Tests",
        Exec: func(ctx context.Context) error {
            return testGatewayRouting(t, ctx)
        },
    })

    // Run test suite
    if err := suite.Run(); err != nil {
        t.Fatalf("Gateway integration tests failed: %v", err)
    }
}

// testGatewayAuthentication validates authentication functionality
func testGatewayAuthentication(t *testing.T, ctx context.Context) error {
    client := &http.Client{Timeout: 30 * time.Second}

    // Test missing authentication
    req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/api/v1/bronze/events", gatewayEndpoint), nil)
    require.NoError(t, err)

    resp, err := client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
    authFailures.WithLabelValues("bronze", "missing_token").Inc()

    // Test invalid JWT token
    req.Header.Set("Authorization", "Bearer invalid-token")
    resp, err = client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
    authFailures.WithLabelValues("bronze", "invalid_token").Inc()

    // Test expired JWT token
    expiredToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", expiredToken))
    resp, err = client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusUnauthorized, resp.StatusCode)
    authFailures.WithLabelValues("bronze", "expired_token").Inc()

    // Test valid authentication
    validToken := generateTestToken(t)
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", validToken))
    start := time.Now()
    resp, err = client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusOK, resp.StatusCode)
    gatewayLatency.WithLabelValues("bronze", "/events", "success").Observe(time.Since(start).Seconds())

    return nil
}

// testGatewayRateLimiting validates rate limiting functionality
func testGatewayRateLimiting(t *testing.T, ctx context.Context) error {
    client := &http.Client{Timeout: 30 * time.Second}
    validToken := generateTestToken(t)

    // Test Bronze tier rate limiting
    testTierRateLimit(t, ctx, client, "bronze", bronzeRateLimit, validToken)

    // Test Silver tier rate limiting
    testTierRateLimit(t, ctx, client, "silver", silverRateLimit, validToken)

    // Test Gold tier rate limiting
    testTierRateLimit(t, ctx, client, "gold", goldRateLimit, validToken)

    return nil
}

// testGatewayRouting validates routing and middleware functionality
func testGatewayRouting(t *testing.T, ctx context.Context) error {
    client := &http.Client{Timeout: 30 * time.Second}
    validToken := generateTestToken(t)

    // Test Bronze tier routing
    testEndpoint(t, ctx, client, "bronze", "/events", validToken)
    testEndpoint(t, ctx, client, "bronze", "/events/batch", validToken)

    // Test Silver tier routing
    testEndpoint(t, ctx, client, "silver", "/events", validToken)
    testEndpoint(t, ctx, client, "silver", "/events/normalized", validToken)

    // Test Gold tier routing
    testEndpoint(t, ctx, client, "gold", "/events", validToken)
    testEndpoint(t, ctx, client, "gold", "/intelligence", validToken)

    return nil
}

// Helper functions

func testTierRateLimit(t *testing.T, ctx context.Context, client *http.Client, tier string, limit int, token string) {
    endpoint := fmt.Sprintf("%s/api/v1/%s/events", gatewayEndpoint, tier)
    
    // Send requests up to limit
    for i := 0; i < limit; i++ {
        req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
        require.NoError(t, err)
        req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

        start := time.Now()
        resp, err := client.Do(req)
        require.NoError(t, err)
        require.Equal(t, http.StatusOK, resp.StatusCode)
        gatewayLatency.WithLabelValues(tier, "/events", "success").Observe(time.Since(start).Seconds())
    }

    // Verify rate limit exceeded
    req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
    require.NoError(t, err)
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

    resp, err := client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
    rateLimitExceeded.WithLabelValues(tier).Inc()
}

func testEndpoint(t *testing.T, ctx context.Context, client *http.Client, tier, path, token string) {
    endpoint := fmt.Sprintf("%s/api/v1/%s%s", gatewayEndpoint, tier, path)
    
    req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
    require.NoError(t, err)
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))

    start := time.Now()
    resp, err := client.Do(req)
    require.NoError(t, err)
    require.Equal(t, http.StatusOK, resp.StatusCode)
    gatewayLatency.WithLabelValues(tier, path, "success").Observe(time.Since(start).Seconds())
}

func generateTestToken(t *testing.T) string {
    // Implementation would generate a valid JWT token for testing
    // This is a placeholder that would be replaced with actual token generation
    return "valid-test-token"
}