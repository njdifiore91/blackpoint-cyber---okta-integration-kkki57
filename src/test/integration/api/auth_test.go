// Package api provides integration tests for the BlackPoint Security Integration Framework's authentication system.
// Version: 1.0.0
package api

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert" // v1.8.0
    "github.com/stretchr/testify/require" // v1.8.0
    "golang.org/x/oauth2" // v0.12.0
    "github.com/prometheus/client_golang/prometheus" // v1.14.0

    "github.com/blackpoint/test/internal/framework/test_suite"
    "github.com/blackpoint/backend/internal/auth/jwt"
    "github.com/blackpoint/backend/internal/auth/oauth"
)

// AuthTestSuite provides comprehensive authentication system testing
type AuthTestSuite struct {
    t             *testing.T
    oauthManager  *oauth.OAuthManager
    ctx           context.Context
    authMetrics   *prometheus.CounterVec
    latencyMetrics *prometheus.HistogramVec
    cleanup       func()
}

// NewAuthTestSuite creates a new authentication test suite instance
func NewAuthTestSuite(t *testing.T) *AuthTestSuite {
    // Initialize Prometheus metrics
    authMetrics := prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_auth_test_total",
            Help: "Authentication test execution metrics",
        },
        []string{"test_type", "result"},
    )

    latencyMetrics := prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_auth_test_latency_seconds",
            Help: "Authentication test latency in seconds",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
        },
        []string{"test_type"},
    )

    prometheus.MustRegister(authMetrics, latencyMetrics)

    // Create test suite with security context
    suite := &AuthTestSuite{
        t:             t,
        ctx:          context.Background(),
        authMetrics:   authMetrics,
        latencyMetrics: latencyMetrics,
    }

    return suite
}

// TestOAuthFlow tests the complete OAuth 2.0 authentication flow
func (s *AuthTestSuite) TestOAuthFlow(t *testing.T) {
    startTime := time.Now()
    defer func() {
        s.latencyMetrics.WithLabelValues("oauth_flow").Observe(time.Since(startTime).Seconds())
    }()

    // Initialize OAuth manager with test configuration
    config := oauth.OAuthConfig{
        ClientID:     "test-client",
        ClientSecret: "test-secret",
        RedirectURL:  "http://localhost:8080/callback",
        ProviderURL: "http://localhost:8080/oauth",
        SecurityOptions: oauth.SecurityConfig{
            TokenLifetime:      time.Hour,
            PKCERequired:       true,
            TokenBlacklistTTL:  24 * time.Hour,
            RateLimitPerMinute: 100,
            MaxFailedAttempts:  5,
            FailedAttemptsTTL:  15 * time.Minute,
        },
    }

    oauthManager, err := oauth.InitOAuthManager(config)
    require.NoError(t, err, "Failed to initialize OAuth manager")
    s.oauthManager = oauthManager

    // Test PKCE flow
    state := "test-state"
    authURL, codeVerifier, err := s.oauthManager.GenerateAuthURL(s.ctx, state)
    require.NoError(t, err, "Failed to generate auth URL")
    assert.NotEmpty(t, authURL, "Auth URL should not be empty")
    assert.NotEmpty(t, codeVerifier, "Code verifier should not be empty")

    // Simulate authorization code grant
    code := "test-auth-code"
    token, idToken, err := s.oauthManager.ExchangeAuthCode(s.ctx, code, state)
    require.NoError(t, err, "Failed to exchange auth code")
    assert.NotNil(t, token, "OAuth token should not be nil")
    assert.NotNil(t, idToken, "ID token should not be nil")

    // Validate token contents
    claims, err := jwt.ValidateToken(token.AccessToken)
    require.NoError(t, err, "Failed to validate token")
    assert.Equal(t, "test-client", claims["client_id"], "Invalid client ID in token")

    // Test token revocation
    err = s.oauthManager.RevokeToken(s.ctx, token.AccessToken)
    require.NoError(t, err, "Failed to revoke token")

    // Verify revoked token is invalid
    _, err = jwt.ValidateToken(token.AccessToken)
    assert.Error(t, err, "Revoked token should be invalid")

    s.authMetrics.WithLabelValues("oauth_flow", "success").Inc()
}

// TestJWTTokenLifecycle tests JWT token generation and validation
func (s *AuthTestSuite) TestJWTTokenLifecycle(t *testing.T) {
    startTime := time.Now()
    defer func() {
        s.latencyMetrics.WithLabelValues("jwt_lifecycle").Observe(time.Since(startTime).Seconds())
    }()

    // Generate test claims
    claims := map[string]interface{}{
        "client_id": "test-client",
        "permissions": []string{"read", "write"},
        "metadata": map[string]string{
            "environment": "test",
            "version": "1.0",
        },
    }

    // Generate token
    token, err := jwt.GenerateToken(claims)
    require.NoError(t, err, "Failed to generate token")
    assert.NotEmpty(t, token, "Token should not be empty")

    // Validate token
    validatedClaims, err := jwt.ValidateToken(token)
    require.NoError(t, err, "Failed to validate token")
    assert.Equal(t, claims["client_id"], validatedClaims["client_id"], "Invalid client ID in validated token")

    // Test token refresh
    newToken, err := jwt.RefreshToken(token)
    require.NoError(t, err, "Failed to refresh token")
    assert.NotEqual(t, token, newToken, "Refreshed token should be different")

    // Verify old token is blacklisted
    _, err = jwt.ValidateToken(token)
    assert.Error(t, err, "Old token should be blacklisted")

    s.authMetrics.WithLabelValues("jwt_lifecycle", "success").Inc()
}

// TestAPIAuthentication tests API endpoint authentication
func (s *AuthTestSuite) TestAPIAuthentication(t *testing.T) {
    startTime := time.Now()
    defer func() {
        s.latencyMetrics.WithLabelValues("api_auth").Observe(time.Since(startTime).Seconds())
    }()

    // Test unauthenticated access
    _, err := jwt.ValidateToken("")
    assert.Error(t, err, "Empty token should be invalid")

    // Generate test token
    claims := map[string]interface{}{
        "client_id": "test-client",
        "permissions": []string{"api:read"},
    }
    token, err := jwt.GenerateToken(claims)
    require.NoError(t, err, "Failed to generate token")

    // Test token validation
    validatedClaims, err := jwt.ValidateToken(token)
    require.NoError(t, err, "Failed to validate token")
    assert.Contains(t, validatedClaims["permissions"], "api:read", "Missing required permission")

    // Test expired token
    time.Sleep(time.Second) // Ensure some time passes
    expiredToken, err := jwt.GenerateToken(map[string]interface{}{
        "client_id": "test-client",
        "exp": time.Now().Add(-time.Hour).Unix(),
    })
    require.NoError(t, err, "Failed to generate expired token")
    _, err = jwt.ValidateToken(expiredToken)
    assert.Error(t, err, "Expired token should be invalid")

    s.authMetrics.WithLabelValues("api_auth", "success").Inc()
}

func TestAuth(t *testing.T) {
    suite := NewAuthTestSuite(t)
    
    // Create test suite configuration
    config := &test_suite.TestSuiteConfig{
        Timeout:          5 * time.Minute,
        SecurityEnabled:  true,
        MonitoringEnabled: true,
        ValidationConfig: map[string]float64{
            "accuracy":     0.95,
            "performance": 0.90,
        },
    }

    // Initialize test suite
    testSuite := test_suite.NewTestSuite(t, "AuthenticationTests", config)
    
    // Add test cases
    testSuite.AddTestCase(&test_suite.TestCase{
        Name: "OAuth Flow Test",
        Exec: suite.TestOAuthFlow,
    })
    testSuite.AddTestCase(&test_suite.TestCase{
        Name: "JWT Lifecycle Test",
        Exec: suite.TestJWTTokenLifecycle,
    })
    testSuite.AddTestCase(&test_suite.TestCase{
        Name: "API Authentication Test",
        Exec: suite.TestAPIAuthentication,
    })

    // Run test suite
    err := testSuite.Run()
    require.NoError(t, err, "Test suite execution failed")
}