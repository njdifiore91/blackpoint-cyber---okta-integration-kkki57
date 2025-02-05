package auth_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/mock"

	"github.com/blackpoint/cli/internal/auth"
	"github.com/blackpoint/cli/pkg/common/constants"
	"github.com/blackpoint/cli/pkg/config/types"
)

// Mock auth configuration for testing
var testAuthConfig = &types.AuthConfig{
	APIKey:      "test-api-key-with-required-entropy-and-length-12345",
	TokenPath:   filepath.Join("testdata", "test_tokens.json"),
	MaxLifetime: time.Hour,
}

// TestGenerateToken tests token generation with comprehensive security validation
func TestGenerateToken(t *testing.T) {
	tests := []struct {
		name    string
		config  *types.AuthConfig
		wantErr bool
	}{
		{
			name:    "Valid token generation",
			config:  testAuthConfig,
			wantErr: false,
		},
		{
			name:    "Nil config",
			config:  nil,
			wantErr: true,
		},
		{
			name: "Invalid API key length",
			config: &types.AuthConfig{
				APIKey:      "short",
				TokenPath:   testAuthConfig.TokenPath,
				MaxLifetime: testAuthConfig.MaxLifetime,
			},
			wantErr: true,
		},
		{
			name: "Invalid token lifetime",
			config: &types.AuthConfig{
				APIKey:      testAuthConfig.APIKey,
				TokenPath:   testAuthConfig.TokenPath,
				MaxLifetime: constants.MaxTokenLifetime + time.Hour,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			accessToken, refreshToken, err := auth.GenerateToken(tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, accessToken)
				assert.Empty(t, refreshToken)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, accessToken)
			assert.NotEmpty(t, refreshToken)

			// Validate access token
			token, err := auth.ValidateToken(accessToken, tt.config)
			require.NoError(t, err)
			claims, ok := token.Claims.(*auth.TokenClaims)
			require.True(t, ok)
			assert.Equal(t, "access", claims.TokenType)
			assert.Equal(t, tt.config.APIKey, claims.Subject)
			assert.True(t, claims.ExpiresAt.After(time.Now()))

			// Validate refresh token
			token, err = auth.ValidateToken(refreshToken, tt.config)
			require.NoError(t, err)
			claims, ok = token.Claims.(*auth.TokenClaims)
			require.True(t, ok)
			assert.Equal(t, "refresh", claims.TokenType)
			assert.Equal(t, tt.config.APIKey, claims.Subject)
			assert.True(t, claims.ExpiresAt.After(time.Now()))
		})
	}
}

// TestValidateToken tests token validation with security focus
func TestValidateToken(t *testing.T) {
	// Generate valid tokens for testing
	accessToken, refreshToken, err := auth.GenerateToken(testAuthConfig)
	require.NoError(t, err)

	tests := []struct {
		name      string
		token     string
		config    *types.AuthConfig
		wantErr   bool
		errString string
	}{
		{
			name:    "Valid access token",
			token:   accessToken,
			config:  testAuthConfig,
			wantErr: false,
		},
		{
			name:    "Valid refresh token",
			token:   refreshToken,
			config:  testAuthConfig,
			wantErr: false,
		},
		{
			name:      "Nil config",
			token:     accessToken,
			config:    nil,
			wantErr:   true,
			errString: "auth config cannot be nil",
		},
		{
			name:      "Invalid token format",
			token:     "invalid-token",
			config:    testAuthConfig,
			wantErr:   true,
			errString: "token validation failed",
		},
		{
			name: "Wrong signing key",
			token: accessToken,
			config: &types.AuthConfig{
				APIKey:      "different-api-key-with-required-entropy-12345",
				TokenPath:   testAuthConfig.TokenPath,
				MaxLifetime: testAuthConfig.MaxLifetime,
			},
			wantErr:   true,
			errString: "token validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := auth.ValidateToken(tt.token, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errString != "" {
					assert.Contains(t, err.Error(), tt.errString)
				}
				assert.Nil(t, token)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, token)
			assert.True(t, token.Valid)
		})
	}
}

// TestRefreshToken tests secure token refresh operations
func TestRefreshToken(t *testing.T) {
	_, refreshToken, err := auth.GenerateToken(testAuthConfig)
	require.NoError(t, err)

	tests := []struct {
		name      string
		token     string
		config    *types.AuthConfig
		wantErr   bool
		errString string
	}{
		{
			name:    "Valid refresh token",
			token:   refreshToken,
			config:  testAuthConfig,
			wantErr: false,
		},
		{
			name:      "Nil config",
			token:     refreshToken,
			config:    nil,
			wantErr:   true,
			errString: "auth config cannot be nil",
		},
		{
			name:      "Invalid refresh token",
			token:     "invalid-token",
			config:    testAuthConfig,
			wantErr:   true,
			errString: "refresh token validation failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newToken, err := auth.RefreshToken(tt.token, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errString != "" {
					assert.Contains(t, err.Error(), tt.errString)
				}
				assert.Empty(t, newToken)
				return
			}

			require.NoError(t, err)
			assert.NotEmpty(t, newToken)

			// Validate new token
			token, err := auth.ValidateToken(newToken, tt.config)
			require.NoError(t, err)
			claims, ok := token.Claims.(*auth.TokenClaims)
			require.True(t, ok)
			assert.Equal(t, "access", claims.TokenType)
			assert.True(t, claims.ExpiresAt.After(time.Now()))
		})
	}
}

// TestAuthConfigSecurity tests security aspects of authentication configuration
func TestAuthConfigSecurity(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "auth_config.json")

	tests := []struct {
		name      string
		config    *types.AuthConfig
		setupFunc func() error
		wantErr   bool
	}{
		{
			name: "Valid config save and load",
			config: &types.AuthConfig{
				APIKey:      testAuthConfig.APIKey,
				TokenPath:   filepath.Join(tempDir, "tokens.json"),
				MaxLifetime: time.Hour,
			},
			setupFunc: func() error {
				return os.MkdirAll(tempDir, 0700)
			},
			wantErr: false,
		},
		{
			name: "Insecure file permissions",
			config: &types.AuthConfig{
				APIKey:      testAuthConfig.APIKey,
				TokenPath:   filepath.Join(tempDir, "tokens.json"),
				MaxLifetime: time.Hour,
			},
			setupFunc: func() error {
				if err := os.MkdirAll(tempDir, 0700); err != nil {
					return err
				}
				return os.Chmod(tempDir, 0777)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				require.NoError(t, tt.setupFunc())
			}

			// Test save config
			err := auth.SaveAuthConfig(tt.config, configPath)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Verify file permissions
			info, err := os.Stat(configPath)
			require.NoError(t, err)
			assert.Equal(t, os.FileMode(0600), info.Mode().Perm())

			// Test load config
			loaded, err := auth.LoadAuthConfig(configPath)
			require.NoError(t, err)
			assert.Equal(t, tt.config.APIKey, loaded.APIKey)
			assert.Equal(t, tt.config.TokenPath, loaded.TokenPath)
			assert.Equal(t, tt.config.MaxLifetime, loaded.MaxLifetime)
		})
	}
}

// TestCredentialSecurity tests secure credential management
func TestCredentialSecurity(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "credentials.json")

	config := &types.AuthConfig{
		APIKey:      testAuthConfig.APIKey,
		TokenPath:   credPath,
		MaxLifetime: time.Hour,
	}

	tests := []struct {
		name      string
		operation func() error
		wantErr   bool
	}{
		{
			name: "Save and load credentials",
			operation: func() error {
				if err := auth.SaveCredentials(config); err != nil {
					return err
				}
				return auth.LoadCredentials(config)
			},
			wantErr: false,
		},
		{
			name: "Clear credentials",
			operation: func() error {
				if err := auth.SaveCredentials(config); err != nil {
					return err
				}
				return auth.ClearCredentials(config)
			},
			wantErr: false,
		},
		{
			name: "Load non-existent credentials",
			operation: func() error {
				return auth.LoadCredentials(&types.AuthConfig{
					TokenPath: filepath.Join(tempDir, "nonexistent.json"),
				})
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.operation()
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)

			// Verify file permissions if file exists
			if _, err := os.Stat(credPath); err == nil {
				info, err := os.Stat(credPath)
				require.NoError(t, err)
				assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
			}
		})
	}
}