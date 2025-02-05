// Package config provides configuration validation for the BlackPoint CLI
package config

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/blackpoint/cli/pkg/common/errors"
	"github.com/blackpoint/cli/pkg/config/types"
)

// Constants for validation
var (
	validLogLevels    = []string{"debug", "info", "warn", "error"}
	validOutputFormats = []string{"json", "yaml", "table", "text"}
	apiVersionPattern = regexp.MustCompile(`^v\d+(\.\d+)?$`)
)

const (
	minAPIKeyLength   = 32
	maxRetryAttempts  = 5
	minRetryDelay     = 1000 // milliseconds
	minTimeout        = 1    // seconds
	maxTimeout        = 60   // seconds
	minTokenLifetime  = 300  // 5 minutes
	maxTokenLifetime  = 86400 // 24 hours
)

// ValidateConfig performs comprehensive validation of the CLI configuration
func ValidateConfig(cfg *types.Config) error {
	if cfg == nil {
		return errors.NewCLIError("1004", "configuration cannot be nil", nil)
	}

	// Validate API configuration
	if err := validateAPIConfig(cfg.API); err != nil {
		return errors.WrapError(err, "API configuration validation failed")
	}

	// Validate Auth configuration
	if err := validateAuthConfig(cfg.Auth); err != nil {
		return errors.WrapError(err, "Auth configuration validation failed")
	}

	// Validate Logging configuration
	if err := validateLoggingConfig(cfg.Logging); err != nil {
		return errors.WrapError(err, "Logging configuration validation failed")
	}

	// Validate Output configuration
	if err := validateOutputConfig(cfg.Output); err != nil {
		return errors.WrapError(err, "Output configuration validation failed")
	}

	return nil
}

// validateAPIConfig validates API-specific configuration settings
func validateAPIConfig(cfg *types.APIConfig) error {
	if cfg == nil {
		return errors.NewCLIError("1004", "API configuration cannot be nil", nil)
	}

	// Validate endpoint
	if cfg.Endpoint == "" {
		return errors.NewCLIError("1004", "API endpoint cannot be empty", nil)
	}

	if !strings.HasPrefix(strings.ToLower(cfg.Endpoint), "https://") {
		return errors.NewCLIError("1004", "API endpoint must use HTTPS protocol", nil)
	}

	// Validate API version format
	if !apiVersionPattern.MatchString(cfg.Version) {
		return errors.NewCLIError("1004", "invalid API version format (must be vX or vX.Y)", nil)
	}

	// Validate timeout bounds
	timeout := int(cfg.Timeout.Seconds())
	if timeout < minTimeout || timeout > maxTimeout {
		return errors.NewCLIError("1004", 
			fmt.Sprintf("timeout must be between %d and %d seconds", minTimeout, maxTimeout), 
			nil)
	}

	// Validate retry settings
	if cfg.RetryAttempts < 0 || cfg.RetryAttempts > maxRetryAttempts {
		return errors.NewCLIError("1004", 
			fmt.Sprintf("retry attempts must be between 0 and %d", maxRetryAttempts), 
			nil)
	}

	if cfg.RetryDelay.Milliseconds() < minRetryDelay {
		return errors.NewCLIError("1004", 
			fmt.Sprintf("retry delay must be at least %d milliseconds", minRetryDelay), 
			nil)
	}

	return nil
}

// validateAuthConfig validates authentication configuration settings
func validateAuthConfig(cfg *types.AuthConfig) error {
	if cfg == nil {
		return errors.NewCLIError("1004", "Auth configuration cannot be nil", nil)
	}

	// Validate API key length
	if len(cfg.APIKey) < minAPIKeyLength {
		return errors.NewCLIError("1004", 
			fmt.Sprintf("API key must be at least %d characters", minAPIKeyLength), 
			nil)
	}

	// Validate token lifetime bounds
	lifetime := int(cfg.MaxLifetime.Seconds())
	if lifetime < minTokenLifetime || lifetime > maxTokenLifetime {
		return errors.NewCLIError("1004", 
			fmt.Sprintf("token lifetime must be between %d and %d seconds", 
				minTokenLifetime, maxTokenLifetime), 
			nil)
	}

	// Validate token path if specified
	if cfg.TokenPath != "" {
		if !strings.HasPrefix(cfg.TokenPath, "/") {
			return errors.NewCLIError("1004", "token path must be absolute", nil)
		}
	}

	return nil
}

// validateLoggingConfig validates logging configuration settings
func validateLoggingConfig(cfg *types.LoggingConfig) error {
	if cfg == nil {
		return errors.NewCLIError("1004", "Logging configuration cannot be nil", nil)
	}

	// Validate log level
	level := strings.ToLower(cfg.Level)
	validLevel := false
	for _, l := range validLogLevels {
		if level == l {
			validLevel = true
			break
		}
	}
	if !validLevel {
		return errors.NewCLIError("1004", 
			fmt.Sprintf("invalid log level: must be one of %v", validLogLevels), 
			nil)
	}

	// Validate log format
	if cfg.Format != "json" && cfg.Format != "text" {
		return errors.NewCLIError("1004", "log format must be 'json' or 'text'", nil)
	}

	// Validate output path if specified
	if cfg.OutputPath != "" {
		if !strings.HasPrefix(cfg.OutputPath, "/") {
			return errors.NewCLIError("1004", "log output path must be absolute", nil)
		}
	}

	return nil
}

// validateOutputConfig validates output configuration settings
func validateOutputConfig(cfg *types.OutputConfig) error {
	if cfg == nil {
		return errors.NewCLIError("1004", "Output configuration cannot be nil", nil)
	}

	// Validate output format
	format := strings.ToLower(cfg.Format)
	validFormat := false
	for _, f := range validOutputFormats {
		if format == f {
			validFormat = true
			break
		}
	}
	if !validFormat {
		return errors.NewCLIError("1004", 
			fmt.Sprintf("invalid output format: must be one of %v", validOutputFormats), 
			nil)
	}

	// No validation needed for boolean fields (ColorEnabled, Quiet)
	// as they can only be true/false

	return nil
}