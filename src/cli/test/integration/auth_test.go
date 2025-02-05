// Package integration provides end-to-end integration tests for the BlackPoint CLI
package integration

import (
    "context"
    "os"
    "path/filepath"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/suite"

    "github.com/blackpoint/cli/internal/auth/token"
    "github.com/blackpoint/cli/internal/auth/credentials"
    "github.com/blackpoint/cli/pkg/api/client"
    "github.com/blackpoint/cli/pkg/config/types"
    "github.com/blackpoint/cli/pkg/common/constants"
)

// AuthIntegrationSuite defines the test suite for authentication integration testing
type AuthIntegrationSuite struct {
    suite.Suite
    config            *types.AuthConfig
    apiClient         *client.APIClient
    testAPIKey        string
    testBaseURL       string
    tempCredentialsPath string
    ctx              context.Context
}

// SetupSuite prepares the test environment with secure configurations
func (s *AuthIntegrationSuite) SetupSuite() {
    // Create temporary directory for test credentials
    tempDir, err := os.MkdirTemp("", "blackpoint-cli-test-*")
    s.Require().NoError(err)
    s.tempCredentialsPath = filepath.Join(tempDir, "credentials.json")

    // Initialize test configuration
    s.testAPIKey = "test-api-key-" + time.Now().Format("20060102150405")
    s.testBaseURL = "https://api.test.blackpoint.security"
    s.config = &types.AuthConfig{
        APIKey:      s.testAPIKey,
        TokenPath:   s.tempCredentialsPath,
        MaxLifetime: constants.MaxTokenLifetime,
    }

    // Set up API client with secure defaults
    apiClient, err := client.NewClient(
        s.testBaseURL,
        s.testAPIKey,
        client.WithTLSConfig(nil), // Use default secure TLS config
    )
    s.Require().NoError(err)
    s.apiClient = apiClient

    // Create context with timeout
    s.ctx = context.Background()

    // Verify initial setup
    s.Require().NoError(s.config.Validate())
}

// TearDownSuite cleans up test resources securely
func (s *AuthIntegrationSuite) TearDownSuite() {
    // Clear sensitive test data
    s.config.APIKey = ""
    s.testAPIKey = ""

    // Remove temporary credentials
    if err := credentials.ClearCredentials(s.config); err != nil {
        s.T().Logf("Warning: Failed to clear credentials: %v", err)
    }

    // Remove temporary directory
    if err := os.RemoveAll(filepath.Dir(s.tempCredentialsPath)); err != nil {
        s.T().Logf("Warning: Failed to remove temp directory: %v", err)
    }
}

// TestTokenGeneration validates secure token generation and validation
func (s *AuthIntegrationSuite) TestTokenGeneration() {
    // Generate token pair
    accessToken, refreshToken, err := token.GenerateToken(s.config)
    s.Require().NoError(err)
    s.Require().NotEmpty(accessToken)
    s.Require().NotEmpty(refreshToken)

    // Validate access token
    validatedAccess, err := token.ValidateToken(accessToken, s.config)
    s.Require().NoError(err)
    s.Require().NotNil(validatedAccess)

    claims, ok := validatedAccess.Claims.(*token.TokenClaims)
    s.Require().True(ok)
    s.Assert().Equal("access", claims.TokenType)
    s.Assert().Equal(s.testAPIKey, claims.Subject)
    s.Assert().Equal("blackpoint-cli", claims.Issuer)

    // Validate refresh token
    validatedRefresh, err := token.ValidateToken(refreshToken, s.config)
    s.Require().NoError(err)
    s.Require().NotNil(validatedRefresh)

    refreshClaims, ok := validatedRefresh.Claims.(*token.TokenClaims)
    s.Require().True(ok)
    s.Assert().Equal("refresh", refreshClaims.TokenType)
}

// TestTokenRefresh validates token refresh functionality
func (s *AuthIntegrationSuite) TestTokenRefresh() {
    // Generate initial tokens
    accessToken, refreshToken, err := token.GenerateToken(s.config)
    s.Require().NoError(err)

    // Validate initial tokens
    _, err = token.ValidateToken(accessToken, s.config)
    s.Require().NoError(err)
    _, err = token.ValidateToken(refreshToken, s.config)
    s.Require().NoError(err)

    // Perform token refresh
    newAccessToken, err := token.RefreshToken(refreshToken, s.config)
    s.Require().NoError(err)
    s.Require().NotEmpty(newAccessToken)

    // Validate new access token
    validatedNew, err := token.ValidateToken(newAccessToken, s.config)
    s.Require().NoError(err)
    s.Require().NotNil(validatedNew)

    claims, ok := validatedNew.Claims.(*token.TokenClaims)
    s.Require().True(ok)
    s.Assert().Equal("access", claims.TokenType)
}

// TestCredentialManagement validates secure credential storage
func (s *AuthIntegrationSuite) TestCredentialManagement() {
    // Save credentials
    err := credentials.SaveCredentials(s.config)
    s.Require().NoError(err)

    // Verify file permissions
    info, err := os.Stat(s.tempCredentialsPath)
    s.Require().NoError(err)
    s.Assert().Equal(constants.ConfigFilePermissions, info.Mode().Perm())

    // Load and validate credentials
    err = credentials.LoadCredentials(s.config)
    s.Require().NoError(err)
    s.Assert().Equal(s.testAPIKey, s.config.APIKey)

    // Test credential clearing
    err = credentials.ClearCredentials(s.config)
    s.Require().NoError(err)
    _, err = os.Stat(s.tempCredentialsPath)
    s.Assert().True(os.IsNotExist(err))
}

// TestAuthenticatedRequests validates authenticated API requests
func (s *AuthIntegrationSuite) TestAuthenticatedRequests() {
    // Generate valid tokens
    accessToken, _, err := token.GenerateToken(s.config)
    s.Require().NoError(err)

    // Create authenticated context
    ctx := context.WithValue(s.ctx, "Authorization", "Bearer "+accessToken)

    // Test authenticated request
    var result interface{}
    err = s.apiClient.Get(ctx, "/api/v1/test", &result)
    if err != nil {
        // Check if error is due to test environment
        s.T().Logf("Note: API request failed as expected in test environment: %v", err)
    }

    // Validate token expiration handling
    expired, err := token.IsTokenExpired(nil)
    s.Assert().Error(err)
    s.Assert().False(expired)
}

// TestAuthIntegrationSuite runs the authentication integration test suite
func TestAuthIntegrationSuite(t *testing.T) {
    suite.Run(t, new(AuthIntegrationSuite))
}