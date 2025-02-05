package config_test

import (
    "testing"
    "time"
    "path/filepath"

    "github.com/blackpoint/cli/pkg/config/types"
    "github.com/blackpoint/cli/pkg/config/validation"
    "github.com/blackpoint/cli/pkg/config/defaults"
    "github.com/blackpoint/cli/pkg/common/constants"
)

// Test constants for consistent test values
const (
    testAPIEndpoint = "https://api.blackpoint.security"
    testAPIKey     = "aB1!cD2@eF3#gH4$iJ5%kL6^mN7&"
)

func TestNewDefaultConfig(t *testing.T) {
    cfg := defaults.NewDefaultConfig()

    // Verify config is not nil
    if cfg == nil {
        t.Fatal("Expected non-nil default configuration")
    }

    // Verify API configuration defaults
    if cfg.API == nil {
        t.Fatal("Expected non-nil API configuration")
    }
    if cfg.API.Endpoint != testAPIEndpoint {
        t.Errorf("Expected API endpoint %s, got %s", testAPIEndpoint, cfg.API.Endpoint)
    }
    if cfg.API.Timeout != constants.DefaultTimeout {
        t.Errorf("Expected timeout %v, got %v", constants.DefaultTimeout, cfg.API.Timeout)
    }
    if cfg.API.RetryAttempts != constants.DefaultRetryAttempts {
        t.Errorf("Expected retry attempts %d, got %d", constants.DefaultRetryAttempts, cfg.API.RetryAttempts)
    }

    // Verify Auth configuration defaults
    if cfg.Auth == nil {
        t.Fatal("Expected non-nil Auth configuration")
    }
    if cfg.Auth.MaxLifetime != constants.MaxTokenLifetime {
        t.Errorf("Expected max lifetime %v, got %v", constants.MaxTokenLifetime, cfg.Auth.MaxLifetime)
    }

    // Verify Logging configuration defaults
    if cfg.Logging == nil {
        t.Fatal("Expected non-nil Logging configuration")
    }
    if cfg.Logging.Level != constants.DefaultLogLevel {
        t.Errorf("Expected log level %s, got %s", constants.DefaultLogLevel, cfg.Logging.Level)
    }
    if cfg.Logging.Format != "json" {
        t.Errorf("Expected log format json, got %s", cfg.Logging.Format)
    }

    // Verify Output configuration defaults
    if cfg.Output == nil {
        t.Fatal("Expected non-nil Output configuration")
    }
    if cfg.Output.Format != constants.DefaultOutputFormat {
        t.Errorf("Expected output format %s, got %s", constants.DefaultOutputFormat, cfg.Output.Format)
    }
}

func TestValidateConfig(t *testing.T) {
    tests := []struct {
        name    string
        cfg     *types.Config
        wantErr bool
    }{
        {
            name: "Valid configuration",
            cfg: &types.Config{
                API: &types.APIConfig{
                    Endpoint:      testAPIEndpoint,
                    Timeout:       30 * time.Second,
                    RetryAttempts: 3,
                    RetryDelay:    5 * time.Second,
                    Version:       "v1",
                },
                Auth: &types.AuthConfig{
                    APIKey:      testAPIKey,
                    TokenPath:   filepath.Join("/", "home", "user", ".blackpoint", "token"),
                    MaxLifetime: 12 * time.Hour,
                },
                Logging: &types.LoggingConfig{
                    Level:      "info",
                    Format:     "json",
                    OutputPath: "",
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
            cfg:     nil,
            wantErr: true,
        },
        {
            name: "Invalid API endpoint (non-HTTPS)",
            cfg: &types.Config{
                API: &types.APIConfig{
                    Endpoint: "http://api.blackpoint.security",
                },
            },
            wantErr: true,
        },
        {
            name: "Invalid API key length",
            cfg: &types.Config{
                Auth: &types.AuthConfig{
                    APIKey: "short",
                },
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validation.ValidateConfig(tt.cfg)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateConfig() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}

func TestValidateAPIConfig(t *testing.T) {
    tests := []struct {
        name    string
        cfg     *types.APIConfig
        wantErr bool
    }{
        {
            name: "Valid API configuration",
            cfg: &types.APIConfig{
                Endpoint:      testAPIEndpoint,
                Timeout:       30 * time.Second,
                RetryAttempts: 3,
                RetryDelay:    5 * time.Second,
                Version:       "v1",
            },
            wantErr: false,
        },
        {
            name: "Invalid timeout",
            cfg: &types.APIConfig{
                Endpoint: testAPIEndpoint,
                Timeout: 301 * time.Second,
            },
            wantErr: true,
        },
        {
            name: "Invalid retry attempts",
            cfg: &types.APIConfig{
                Endpoint:      testAPIEndpoint,
                RetryAttempts: 6,
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validation.ValidateAPIConfig(tt.cfg)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateAPIConfig() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}

func TestValidateAuthConfig(t *testing.T) {
    tests := []struct {
        name    string
        cfg     *types.AuthConfig
        wantErr bool
    }{
        {
            name: "Valid auth configuration",
            cfg: &types.AuthConfig{
                APIKey:      testAPIKey,
                TokenPath:   filepath.Join("/", "home", "user", ".blackpoint", "token"),
                MaxLifetime: 12 * time.Hour,
            },
            wantErr: false,
        },
        {
            name: "Invalid API key (too short)",
            cfg: &types.AuthConfig{
                APIKey: "short",
            },
            wantErr: true,
        },
        {
            name: "Invalid token lifetime",
            cfg: &types.AuthConfig{
                APIKey:      testAPIKey,
                MaxLifetime: 25 * time.Hour,
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validation.ValidateAuthConfig(tt.cfg)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateAuthConfig() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}

func TestValidateLoggingConfig(t *testing.T) {
    tests := []struct {
        name    string
        cfg     *types.LoggingConfig
        wantErr bool
    }{
        {
            name: "Valid logging configuration",
            cfg: &types.LoggingConfig{
                Level:      "info",
                Format:     "json",
                OutputPath: "",
            },
            wantErr: false,
        },
        {
            name: "Invalid log level",
            cfg: &types.LoggingConfig{
                Level:  "invalid",
                Format: "json",
            },
            wantErr: true,
        },
        {
            name: "Invalid log format",
            cfg: &types.LoggingConfig{
                Level:  "info",
                Format: "invalid",
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validation.ValidateLoggingConfig(tt.cfg)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateLoggingConfig() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}

func TestValidateOutputConfig(t *testing.T) {
    tests := []struct {
        name    string
        cfg     *types.OutputConfig
        wantErr bool
    }{
        {
            name: "Valid output configuration",
            cfg: &types.OutputConfig{
                Format:       "json",
                ColorEnabled: true,
                Quiet:       false,
            },
            wantErr: false,
        },
        {
            name: "Invalid output format",
            cfg: &types.OutputConfig{
                Format: "invalid",
            },
            wantErr: true,
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := validation.ValidateOutputConfig(tt.cfg)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateOutputConfig() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}