// Package integration provides configuration and validation for third-party security platform integrations
package integration

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-playground/validator/v10" // v10.11.0
	"gopkg.in/yaml.v3"                      // v3.0.1

	"../../pkg/common/errors"
	"../../pkg/common/logging"
)

// Global constants for configuration validation
var (
	defaultCollectionModes = []string{"realtime", "batch", "hybrid"}
	defaultAuthTypes      = []string{"oauth2", "apikey", "basic", "certificate"}
	defaultBatchSizes    = []int{100, 500, 1000, 5000}
	maxBatchSize        = 10000
	supportedPlatforms  = []string{"aws", "azure", "gcp", "okta", "crowdstrike"}
)

// AuthenticationConfig defines authentication settings for platform integration
type AuthenticationConfig struct {
	Type        string                 `yaml:"type" validate:"required,oneof=oauth2 apikey basic certificate"`
	Credentials map[string]interface{} `yaml:"credentials" validate:"required"`
	ExpiryTime  time.Duration         `yaml:"expiry_time,omitempty"`
	Renewable   bool                  `yaml:"renewable,omitempty"`
}

// DataCollectionConfig defines data collection settings
type DataCollectionConfig struct {
	Mode       string `yaml:"mode" validate:"required,oneof=realtime batch hybrid"`
	BatchSize  int    `yaml:"batch_size,omitempty" validate:"omitempty,min=1,max=10000"`
	Interval   string `yaml:"interval,omitempty" validate:"omitempty,duration"`
	RetryLimit int    `yaml:"retry_limit,omitempty" validate:"omitempty,min=0,max=10"`
}

// ValidationConfig defines validation rules for collected data
type ValidationConfig struct {
	SchemaValidation bool `yaml:"schema_validation"`
	StrictMode      bool `yaml:"strict_mode"`
	ErrorThreshold  int  `yaml:"error_threshold" validate:"omitempty,min=0,max=100"`
}

// IntegrationConfig represents the complete integration configuration
type IntegrationConfig struct {
	PlatformType      string                 `yaml:"platform_type" validate:"required"`
	Name             string                 `yaml:"name" validate:"required,min=3,max=50"`
	Environment      string                 `yaml:"environment" validate:"required,oneof=development staging production"`
	Auth             AuthenticationConfig    `yaml:"auth" validate:"required"`
	Collection       DataCollectionConfig    `yaml:"collection" validate:"required"`
	PlatformSpecific map[string]interface{} `yaml:"platform_specific,omitempty"`
	Validation       ValidationConfig        `yaml:"validation,omitempty"`
}

// Validate performs comprehensive validation of the integration configuration
func (c *IntegrationConfig) Validate() error {
	validate := validator.New()

	// Register custom validation functions
	if err := validate.RegisterValidation("duration", validateDuration); err != nil {
		return errors.NewError("E2001", "failed to register duration validator", map[string]interface{}{
			"error": err.Error(),
		})
	}

	// Perform struct validation
	if err := validate.Struct(c); err != nil {
		return errors.NewError("E2001", "configuration validation failed", map[string]interface{}{
			"validation_errors": err.Error(),
		})
	}

	// Validate platform type
	if err := validatePlatformType(c.PlatformType); err != nil {
		return err
	}

	// Validate collection mode specific requirements
	if err := validateCollectionConfig(c.Collection); err != nil {
		return err
	}

	// Validate authentication configuration
	if err := validateAuthConfig(c.Auth); err != nil {
		return err
	}

	return nil
}

// ValidateConfig validates the complete integration configuration with enhanced validation rules
func ValidateConfig(config *IntegrationConfig) error {
	logger.Info("Validating integration configuration",
		"platform_type", config.PlatformType,
		"environment", config.Environment,
	)

	if err := config.Validate(); err != nil {
		logger.Error("Configuration validation failed",
			err,
			"platform_type", config.PlatformType,
		)
		return err
	}

	return nil
}

// validatePlatformType validates if the platform type is supported
func validatePlatformType(platformType string) error {
	for _, supported := range supportedPlatforms {
		if strings.EqualFold(platformType, supported) {
			return nil
		}
	}

	return errors.NewError("E2001", "unsupported platform type", map[string]interface{}{
		"platform_type": platformType,
		"supported_platforms": supportedPlatforms,
	})
}

// validateCollectionConfig validates collection mode specific requirements
func validateCollectionConfig(config DataCollectionConfig) error {
	// Validate batch configuration
	if config.Mode == "batch" || config.Mode == "hybrid" {
		if config.BatchSize == 0 {
			config.BatchSize = defaultBatchSizes[0]
		}
		if config.BatchSize > maxBatchSize {
			return errors.NewError("E2001", "batch size exceeds maximum limit", map[string]interface{}{
				"batch_size": config.BatchSize,
				"max_size": maxBatchSize,
			})
		}
		if config.Interval == "" {
			return errors.NewError("E2001", "batch interval is required for batch mode", nil)
		}
	}

	return nil
}

// validateAuthConfig validates authentication configuration
func validateAuthConfig(config AuthenticationConfig) error {
	// Validate required credentials based on auth type
	switch config.Type {
	case "oauth2":
		required := []string{"client_id", "client_secret", "token_url"}
		for _, field := range required {
			if _, exists := config.Credentials[field]; !exists {
				return errors.NewError("E2001", fmt.Sprintf("missing required oauth2 credential: %s", field), nil)
			}
		}
	case "apikey":
		if _, exists := config.Credentials["api_key"]; !exists {
			return errors.NewError("E2001", "missing required api_key credential", nil)
		}
	case "basic":
		required := []string{"username", "password"}
		for _, field := range required {
			if _, exists := config.Credentials[field]; !exists {
				return errors.NewError("E2001", fmt.Sprintf("missing required basic auth credential: %s", field), nil)
			}
		}
	case "certificate":
		required := []string{"cert_path", "key_path"}
		for _, field := range required {
			if _, exists := config.Credentials[field]; !exists {
				return errors.NewError("E2001", fmt.Sprintf("missing required certificate credential: %s", field), nil)
			}
		}
	}

	return nil
}

// validateDuration validates duration string format
func validateDuration(fl validator.FieldLevel) bool {
	duration := fl.Field().String()
	_, err := time.ParseDuration(duration)
	return err == nil
}