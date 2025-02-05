// Package config provides validation logic for CLI configuration settings
package config

import (
    "fmt"
    "regexp"
    "time"
    
    "github.com/blackpoint/cli/pkg/config/types"
    "github.com/blackpoint/cli/pkg/common/errors"
)

// Validation constants
const (
    minAPIKeyLength = 32
)

var (
    // Regex patterns for validation
    apiVersionPattern = regexp.MustCompile(`^v\d+$`)
    
    // Valid configuration values
    validLogLevels     = []string{"debug", "info", "warn", "error"}
    validLogFormats    = []string{"text", "json"}
    validOutputFormats = []string{"text", "json", "yaml"}
)

// ValidateConfig performs comprehensive validation of the entire CLI configuration
func ValidateConfig(cfg *types.Config) error {
    if cfg == nil {
        return errors.NewCLIError("E1004", "configuration cannot be nil", nil)
    }

    if err := ValidateAPIConfig(cfg.API); err != nil {
        return errors.WrapError(err, "API configuration validation failed")
    }

    if err := ValidateAuthConfig(cfg.Auth); err != nil {
        return errors.WrapError(err, "authentication configuration validation failed")
    }

    if err := ValidateLoggingConfig(cfg.Logging); err != nil {
        return errors.WrapError(err, "logging configuration validation failed")
    }

    if err := ValidateOutputConfig(cfg.Output); err != nil {
        return errors.WrapError(err, "output configuration validation failed")
    }

    return nil
}

// ValidateAPIConfig validates API-related configuration settings
func ValidateAPIConfig(cfg *types.APIConfig) error {
    if cfg == nil {
        return errors.NewCLIError("E1004", "API configuration cannot be nil", nil)
    }

    // Validate endpoint
    if cfg.Endpoint == "" {
        return errors.NewCLIError("E1004", "API endpoint cannot be empty", nil)
    }

    // Validate API version format
    if !apiVersionPattern.MatchString(cfg.Version) {
        return errors.NewCLIError("E1004", fmt.Sprintf("invalid API version format: must match pattern %s", apiVersionPattern), nil)
    }

    // Validate timeout ranges
    if cfg.Timeout < time.Second || cfg.Timeout > 300*time.Second {
        return errors.NewCLIError("E1004", "timeout must be between 1s and 300s", nil)
    }

    // Validate retry settings
    if cfg.RetryAttempts < 0 || cfg.RetryAttempts > 5 {
        return errors.NewCLIError("E1004", "retry attempts must be between 0 and 5", nil)
    }

    if cfg.RetryDelay < 100*time.Millisecond || cfg.RetryDelay > 5*time.Second {
        return errors.NewCLIError("E1004", "retry delay must be between 100ms and 5s", nil)
    }

    return nil
}

// ValidateAuthConfig validates authentication-related configuration settings
func ValidateAuthConfig(cfg *types.AuthConfig) error {
    if cfg == nil {
        return errors.NewCLIError("E1004", "authentication configuration cannot be nil", nil)
    }

    // Validate API key length and composition
    if len(cfg.APIKey) < minAPIKeyLength {
        return errors.NewCLIError("E1004", fmt.Sprintf("API key must be at least %d characters", minAPIKeyLength), nil)
    }

    // Validate API key character composition
    hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(cfg.APIKey)
    hasLower := regexp.MustCompile(`[a-z]`).MatchString(cfg.APIKey)
    hasNumber := regexp.MustCompile(`[0-9]`).MatchString(cfg.APIKey)
    hasSpecial := regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(cfg.APIKey)

    if !hasUpper || !hasLower || !hasNumber || !hasSpecial {
        return errors.NewCLIError("E1004", "API key must contain uppercase, lowercase, numbers, and special characters", nil)
    }

    // Validate token lifetime
    if cfg.MaxLifetime < 15*time.Minute || cfg.MaxLifetime > 24*time.Hour {
        return errors.NewCLIError("E1004", "token lifetime must be between 15m and 24h", nil)
    }

    return nil
}

// ValidateLoggingConfig validates logging-related configuration settings
func ValidateLoggingConfig(cfg *types.LoggingConfig) error {
    if cfg == nil {
        return errors.NewCLIError("E1004", "logging configuration cannot be nil", nil)
    }

    // Validate log level
    validLevel := false
    for _, level := range validLogLevels {
        if cfg.Level == level {
            validLevel = true
            break
        }
    }
    if !validLevel {
        return errors.NewCLIError("E1004", fmt.Sprintf("invalid log level: must be one of %v", validLogLevels), nil)
    }

    // Validate log format
    validFormat := false
    for _, format := range validLogFormats {
        if cfg.Format == format {
            validFormat = true
            break
        }
    }
    if !validFormat {
        return errors.NewCLIError("E1004", fmt.Sprintf("invalid log format: must be one of %v", validLogFormats), nil)
    }

    // Validate output path if specified
    if cfg.OutputPath != "" {
        if err := validateFilePath(cfg.OutputPath); err != nil {
            return errors.WrapError(err, "invalid log output path")
        }
    }

    return nil
}

// ValidateOutputConfig validates output-related configuration settings
func ValidateOutputConfig(cfg *types.OutputConfig) error {
    if cfg == nil {
        return errors.NewCLIError("E1004", "output configuration cannot be nil", nil)
    }

    // Validate output format
    validFormat := false
    for _, format := range validOutputFormats {
        if cfg.Format == format {
            validFormat = true
            break
        }
    }
    if !validFormat {
        return errors.NewCLIError("E1004", fmt.Sprintf("invalid output format: must be one of %v", validOutputFormats), nil)
    }

    // Validate color settings
    if cfg.ColorEnabled {
        // Check if terminal supports color output
        if !isTerminalSupported() {
            return errors.NewCLIError("E1004", "color output not supported in current terminal", nil)
        }
    }

    return nil
}

// validateFilePath validates if a file path is writable
func validateFilePath(path string) error {
    // Implementation would check file path validity and permissions
    // Omitted for brevity as it requires OS-specific implementations
    return nil
}

// isTerminalSupported checks if the current terminal supports required features
func isTerminalSupported() bool {
    // Implementation would check terminal capabilities
    // Omitted for brevity as it requires OS-specific implementations
    return true
}