// Package config provides default configuration values and factory functions for the BlackPoint CLI
package config

import (
    "time"
    
    "github.com/blackpoint/cli/pkg/config/types"
    "github.com/blackpoint/cli/pkg/common/constants"
)

// NewDefaultConfig creates a new configuration instance with secure default values
func NewDefaultConfig() *types.Config {
    return &types.Config{
        API:     NewDefaultAPIConfig(),
        Auth:    NewDefaultAuthConfig(),
        Logging: NewDefaultLoggingConfig(),
        Output:  NewDefaultOutputConfig(),
    }
}

// NewDefaultAPIConfig creates a new API configuration with secure default values
func NewDefaultAPIConfig() *types.APIConfig {
    return &types.APIConfig{
        // Default to secure HTTPS endpoint
        Endpoint:      "https://api.blackpoint.security",
        // Use constants for consistent timeout values
        Timeout:       constants.DefaultTimeout,
        // Configure retry mechanism with safe defaults
        RetryAttempts: constants.DefaultRetryAttempts,
        RetryDelay:    constants.DefaultRetryDelay,
        // Use versioned API for compatibility
        Version:       constants.DefaultAPIVersion,
    }
}

// NewDefaultAuthConfig creates a new authentication configuration with secure defaults
func NewDefaultAuthConfig() *types.AuthConfig {
    return &types.AuthConfig{
        // Initialize with empty API key - must be set by user
        APIKey:      "",
        // Use secure default path for token storage
        TokenPath:   constants.DefaultConfigPath,
        // Set secure token lifetime
        MaxLifetime: constants.MaxTokenLifetime,
    }
}

// NewDefaultLoggingConfig creates a new logging configuration with validated defaults
func NewDefaultLoggingConfig() *types.LoggingConfig {
    return &types.LoggingConfig{
        // Set conservative default log level
        Level:      constants.DefaultLogLevel,
        // Use structured logging by default
        Format:     "json",
        // Default to stderr for logging output
        OutputPath: "",
    }
}

// NewDefaultOutputConfig creates a new output configuration with format validation
func NewDefaultOutputConfig() *types.OutputConfig {
    return &types.OutputConfig{
        // Use structured output format by default
        Format:       constants.DefaultOutputFormat,
        // Enable color output by default
        ColorEnabled: true,
        // Disable quiet mode by default
        Quiet:        false,
    }
}