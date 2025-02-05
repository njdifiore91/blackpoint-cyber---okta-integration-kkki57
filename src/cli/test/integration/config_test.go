// Package integration provides integration tests for the BlackPoint CLI configuration system
package integration

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/blackpoint/cli/pkg/config/types"
	"github.com/blackpoint/cli/pkg/common/constants"
	"github.com/blackpoint/cli/pkg/common/errors"
	"github.com/blackpoint/cli/internal/config/loader"
	"github.com/blackpoint/cli/internal/config/validator"
)

var (
	testConfigDir = "testdata"
	validTestConfig = `
api:
  endpoint: "https://api.blackpoint.security"
  timeout: 30s
  retryAttempts: 3
  retryDelay: 5s
  version: "v1"
auth:
  apiKey: "abcdef1234567890abcdef1234567890abcd"
  tokenPath: "/tmp/blackpoint/token"
  maxLifetime: 3600s
logging:
  level: "info"
  format: "json"
  outputPath: "/var/log/blackpoint.log"
output:
  format: "json"
  colorEnabled: true
  quiet: false
`
	invalidTestConfig = `
api:
  endpoint: "http://insecure.endpoint"
  timeout: 1s
  retryAttempts: 10
  version: "invalid"
auth:
  apiKey: "tooshort"
  tokenPath: "relative/path"
logging:
  level: "invalid"
  format: "invalid"
output:
  format: "invalid"
`
)

func TestMain(m *testing.M) {
	// Set up test environment
	if err := os.MkdirAll(testConfigDir, 0755); err != nil {
		panic(err)
	}

	// Run tests
	code := m.Run()

	// Clean up
	os.RemoveAll(testConfigDir)
	os.Exit(code)
}

func TestConfigLoadFromFile(t *testing.T) {
	// Create test config file
	configPath := filepath.Join(testConfigDir, "config.yaml")
	err := os.WriteFile(configPath, []byte(validTestConfig), constants.ConfigFilePermissions)
	require.NoError(t, err)

	tests := []struct {
		name        string
		configPath  string
		configData  string
		permissions os.FileMode
		wantErr     bool
		errCode     string
	}{
		{
			name:        "Valid config file",
			configPath:  configPath,
			configData:  validTestConfig,
			permissions: 0600,
			wantErr:     false,
		},
		{
			name:        "Invalid permissions",
			configPath:  filepath.Join(testConfigDir, "insecure.yaml"),
			configData:  validTestConfig,
			permissions: 0666,
			wantErr:     true,
			errCode:     "E1001",
		},
		{
			name:        "Invalid YAML",
			configPath:  filepath.Join(testConfigDir, "invalid.yaml"),
			configData:  "invalid: yaml: content",
			permissions: 0600,
			wantErr:     true,
			errCode:     "E1001",
		},
		{
			name:        "Non-existent file",
			configPath:  "/nonexistent/config.yaml",
			wantErr:     true,
			errCode:     "E1001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.configData != "" {
				err := os.WriteFile(tt.configPath, []byte(tt.configData), tt.permissions)
				require.NoError(t, err)
			}

			config, err := loader.LoadConfig(tt.configPath)
			if tt.wantErr {
				assert.Error(t, err)
				var cliErr *errors.CLIError
				assert.ErrorAs(t, err, &cliErr)
				assert.Equal(t, tt.errCode, cliErr.Code)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, config)
			assert.Equal(t, "https://api.blackpoint.security", config.API.Endpoint)
			assert.Equal(t, 30*time.Second, config.API.Timeout)
		})
	}
}

func TestConfigLoadFromEnvironment(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr bool
		errCode string
	}{
		{
			name: "Valid environment variables",
			envVars: map[string]string{
				"BLACKPOINT_API_ENDPOINT": "https://api.blackpoint.security",
				"BLACKPOINT_API_KEY":      "abcdef1234567890abcdef1234567890abcd",
				"BLACKPOINT_LOG_LEVEL":    "info",
				"BLACKPOINT_OUTPUT_FORMAT": "json",
			},
			wantErr: false,
		},
		{
			name: "Invalid API key length",
			envVars: map[string]string{
				"BLACKPOINT_API_KEY": "tooshort",
			},
			wantErr: true,
			errCode: "E1001",
		},
		{
			name: "Invalid API endpoint",
			envVars: map[string]string{
				"BLACKPOINT_API_ENDPOINT": "http://insecure.endpoint",
			},
			wantErr: true,
			errCode: "E1001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear environment
			os.Clearenv()

			// Set test environment variables
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			config, err := loader.LoadConfig("")
			if tt.wantErr {
				assert.Error(t, err)
				var cliErr *errors.CLIError
				assert.ErrorAs(t, err, &cliErr)
				assert.Equal(t, tt.errCode, cliErr.Code)
				return
			}

			assert.NoError(t, err)
			assert.NotNil(t, config)

			// Verify environment variable overrides
			if endpoint, ok := tt.envVars["BLACKPOINT_API_ENDPOINT"]; ok {
				assert.Equal(t, endpoint, config.API.Endpoint)
			}
		})
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		config  *types.Config
		wantErr bool
		errCode string
	}{
		{
			name: "Valid configuration",
			config: &types.Config{
				API: &types.APIConfig{
					Endpoint:      "https://api.blackpoint.security",
					Timeout:       30 * time.Second,
					RetryAttempts: 3,
					RetryDelay:    5 * time.Second,
					Version:       "v1",
				},
				Auth: &types.AuthConfig{
					APIKey:      "abcdef1234567890abcdef1234567890abcd",
					TokenPath:   "/tmp/blackpoint/token",
					MaxLifetime: time.Hour,
				},
				Logging: &types.LoggingConfig{
					Level:      "info",
					Format:    "json",
					OutputPath: "/var/log/blackpoint.log",
				},
				Output: &types.OutputConfig{
					Format:       "json",
					ColorEnabled: true,
					Quiet:       false,
				},
			},
			wantErr: false,
		},
		{
			name:    "Nil configuration",
			config:  nil,
			wantErr: true,
			errCode: "E1001",
		},
		{
			name: "Invalid API endpoint",
			config: &types.Config{
				API: &types.APIConfig{
					Endpoint: "http://insecure.endpoint",
				},
			},
			wantErr: true,
			errCode: "E1001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validator.ValidateConfig(tt.config)
			if tt.wantErr {
				assert.Error(t, err)
				var cliErr *errors.CLIError
				assert.ErrorAs(t, err, &cliErr)
				assert.Equal(t, tt.errCode, cliErr.Code)
				return
			}

			assert.NoError(t, err)
		})
	}
}

func TestConfigMerging(t *testing.T) {
	// Create base config file
	baseConfig := filepath.Join(testConfigDir, "base.yaml")
	err := os.WriteFile(baseConfig, []byte(validTestConfig), 0600)
	require.NoError(t, err)

	// Set environment overrides
	os.Setenv("BLACKPOINT_API_ENDPOINT", "https://api2.blackpoint.security")
	os.Setenv("BLACKPOINT_LOG_LEVEL", "debug")

	// Load and merge configuration
	config, err := loader.LoadConfig(baseConfig)
	require.NoError(t, err)

	// Verify merged configuration
	assert.Equal(t, "https://api2.blackpoint.security", config.API.Endpoint)
	assert.Equal(t, "debug", config.Logging.Level)
	assert.Equal(t, "abcdef1234567890abcdef1234567890abcd", config.Auth.APIKey)
}