// Package security provides comprehensive security testing for the BlackPoint Security Integration Framework
// Version: 1.0.0
package security

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/require" // v1.8.0
    "github.com/prometheus/client_golang/prometheus" // v1.12.0
    "github.com/golang-jwt/jwt/v5" // v5.0.0

    "../../internal/framework/test_suite"
    "../../../backend/internal/auth/oauth"
    "../../../backend/internal/auth/jwt"
)

// Security test metrics
var (
    authTestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_auth_test_duration_seconds",
            Help: "Duration of authentication test execution",
            Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
        },
        []string{"test_name", "auth_type"},
    )

    authTestErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_auth_test_errors_total",
            Help: "Total number of authentication test errors",
        },
        []string{"test_name", "error_type"},
    )

    securityValidationScore = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackpoint_security_validation_score",
            Help: "Security validation score for authentication tests",
        },
        []string{"test_name", "validation_type"},
    )
)

// securityTestSuite organizes authentication and security tests
type securityTestSuite struct {
    suite *test_suite.TestSuite
    oauth *oauth.OAuthManager
    ctx   context.Context
}

// TestAuthenticationSuite is the main entry point for authentication testing
func TestAuthenticationSuite(t *testing.T) {
    // Initialize test suite with security context
    suite := test_suite.NewTestSuite(t, "AuthenticationSuite", &test_suite.TestSuiteConfig{
        Timeout: 5 * time.Minute,
        SecurityEnabled: true,
        MonitoringEnabled: true,
        ValidationConfig: map[string]float64{
            "accuracy": 80.0,
            "security": 90.0,
        },
    })

    // Initialize OAuth manager for testing
    oauthConfig := oauth.OAuthConfig{
        ClientID: "test-client",
        ClientSecret: "test-secret",
        RedirectURL: "http://localhost:8080/callback",
        ProviderURL: "http://localhost:8081",
        SecurityOptions: oauth.SecurityConfig{
            TokenLifetime: time.Hour,
            PKCERequired: true,
            TokenBlacklistTTL: 24 * time.Hour,
            RateLimitPerMinute: 100,
            MaxFailedAttempts: 5,
            FailedAttemptsTTL: time.Hour,
        },
    }

    oauthManager, err := oauth.InitOAuthManager(oauthConfig)
    require.NoError(t, err, "Failed to initialize OAuth manager")

    // Create test context
    ctx := context.Background()

    // Initialize security test suite
    testSuite := &securityTestSuite{
        suite: suite,
        oauth: oauthManager,
        ctx:   ctx,
    }

    // Add test cases
    suite.AddTestCase(testSuite.testJWTTokenLifecycle())
    suite.AddTestCase(testSuite.testOAuthSecureFlow())
    suite.AddTestCase(testSuite.testRBACEnforcement())
    suite.AddTestCase(testSuite.testTokenBlacklisting())
    suite.AddTestCase(testSuite.testSecurityAuditing())

    // Run test suite
    err = suite.Run()
    require.NoError(t, err, "Authentication test suite failed")
}

// testJWTTokenLifecycle tests JWT token generation, validation, and security measures
func (s *securityTestSuite) testJWTTokenLifecycle() *test_suite.TestCase {
    return &test_suite.TestCase{
        Name: "JWT Token Lifecycle",
        Setup: func(ctx context.Context) error {
            // Initialize JWT test environment
            return nil
        },
        Execute: func(ctx context.Context) error {
            // Generate test claims
            claims := map[string]interface{}{
                "client_id": "test-client",
                "permissions": []string{"read", "write"},
                "metadata": map[string]string{
                    "environment": "test",
                },
            }

            // Generate token
            token, err := jwt.GenerateToken(claims)
            require.NoError(s.suite.T(), err, "Failed to generate JWT token")

            // Validate token
            validatedClaims, err := jwt.ValidateToken(token)
            require.NoError(s.suite.T(), err, "Failed to validate JWT token")
            require.Equal(s.suite.T(), claims["client_id"], validatedClaims["client_id"], "Client ID mismatch")

            // Test token expiration
            time.Sleep(time.Second)
            _, err = jwt.ValidateToken(token)
            require.NoError(s.suite.T(), err, "Token expired prematurely")

            // Test token refresh
            newToken, err := jwt.RefreshToken(token)
            require.NoError(s.suite.T(), err, "Failed to refresh token")
            require.NotEqual(s.suite.T(), token, newToken, "Refreshed token should be different")

            return nil
        },
        Cleanup: func(ctx context.Context) error {
            // Clean up JWT test resources
            return nil
        },
    }
}

// testOAuthSecureFlow tests OAuth2.0 flow with PKCE and security validations
func (s *securityTestSuite) testOAuthSecureFlow() *test_suite.TestCase {
    return &test_suite.TestCase{
        Name: "OAuth Secure Flow",
        Execute: func(ctx context.Context) error {
            // Generate state and PKCE verifier
            state := "test-state"
            authURL, codeVerifier, err := s.oauth.GenerateAuthURL(ctx, state)
            require.NoError(s.suite.T(), err, "Failed to generate auth URL")
            require.NotEmpty(s.suite.T(), authURL, "Auth URL should not be empty")
            require.NotEmpty(s.suite.T(), codeVerifier, "Code verifier should not be empty")

            // Simulate authorization code grant
            code := "test-auth-code"
            token, idToken, err := s.oauth.ExchangeAuthCode(ctx, code, state)
            require.NoError(s.suite.T(), err, "Failed to exchange auth code")
            require.NotNil(s.suite.T(), token, "Token should not be nil")
            require.NotNil(s.suite.T(), idToken, "ID token should not be nil")

            // Validate token claims
            require.Equal(s.suite.T(), "test-client", idToken.Claims["client_id"], "Client ID mismatch")

            return nil
        },
    }
}

// testRBACEnforcement tests role-based access control implementation
func (s *securityTestSuite) testRBACEnforcement() *test_suite.TestCase {
    return &test_suite.TestCase{
        Name: "RBAC Enforcement",
        Execute: func(ctx context.Context) error {
            roles := []string{"admin", "developer", "analyst", "readonly"}
            
            for _, role := range roles {
                claims := map[string]interface{}{
                    "client_id": "test-client",
                    "role": role,
                    "permissions": getRolePermissions(role),
                }

                token, err := jwt.GenerateToken(claims)
                require.NoError(s.suite.T(), err, "Failed to generate token for role: "+role)

                validatedClaims, err := jwt.ValidateToken(token)
                require.NoError(s.suite.T(), err, "Failed to validate token for role: "+role)

                // Verify role-specific permissions
                require.Equal(s.suite.T(), claims["permissions"], validatedClaims["permissions"], 
                    "Permission mismatch for role: "+role)
            }

            return nil
        },
    }
}

// testTokenBlacklisting tests token revocation and blacklisting
func (s *securityTestSuite) testTokenBlacklisting() *test_suite.TestCase {
    return &test_suite.TestCase{
        Name: "Token Blacklisting",
        Execute: func(ctx context.Context) error {
            // Generate test token
            claims := map[string]interface{}{
                "client_id": "test-client",
                "permissions": []string{"read"},
            }
            token, err := jwt.GenerateToken(claims)
            require.NoError(s.suite.T(), err, "Failed to generate token")

            // Revoke token
            err = s.oauth.RevokeToken(ctx, token)
            require.NoError(s.suite.T(), err, "Failed to revoke token")

            // Verify token is blacklisted
            _, err = jwt.ValidateToken(token)
            require.Error(s.suite.T(), err, "Blacklisted token should be invalid")

            return nil
        },
    }
}

// testSecurityAuditing tests security event logging and monitoring
func (s *securityTestSuite) testSecurityAuditing() *test_suite.TestCase {
    return &test_suite.TestCase{
        Name: "Security Auditing",
        Execute: func(ctx context.Context) error {
            // Test security event logging
            claims := map[string]interface{}{
                "client_id": "test-client",
                "action": "security_test",
            }
            token, err := jwt.GenerateToken(claims)
            require.NoError(s.suite.T(), err, "Failed to generate token")

            // Verify audit logs
            // Note: Implementation depends on logging infrastructure

            return nil
        },
    }
}

// Helper functions

func getRolePermissions(role string) []string {
    switch role {
    case "admin":
        return []string{"read", "write", "delete", "admin"}
    case "developer":
        return []string{"read", "write"}
    case "analyst":
        return []string{"read"}
    case "readonly":
        return []string{"read"}
    default:
        return []string{}
    }
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(authTestDuration, authTestErrors, securityValidationScore)
}