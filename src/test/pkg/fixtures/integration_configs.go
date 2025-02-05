// Package fixtures provides comprehensive test fixtures for integration configuration testing
package fixtures

import (
	"fmt"
	"os"
	"time"

	"github.com/blackpoint/pkg/integration"
	"gopkg.in/yaml.v3" // v3.0.1
)

// Test constants for configuration generation
var (
	testPlatformTypes = []string{
		"aws", "azure", "okta", "crowdstrike", 
		"sentinel", "splunk", "carbonblack", "paloalto",
	}

	testEnvironments = []string{
		"development", "staging", "production",
	}

	testCollectionModes = []string{
		"real-time", "batch", "hybrid",
	}

	testBatchIntervals = []string{
		"5m", "15m", "1h", "6h", "24h",
	}

	testSecurityLevels = []string{
		"standard", "enhanced", "maximum",
	}
)

// GetTestIntegrationConfig returns a comprehensive test integration configuration
func GetTestIntegrationConfig(platformType, collectionMode string) (*integration.IntegrationConfig, error) {
	// Validate platform type
	validPlatform := false
	for _, p := range testPlatformTypes {
		if p == platformType {
			validPlatform = true
			break
		}
	}
	if !validPlatform {
		return nil, fmt.Errorf("unsupported platform type: %s", platformType)
	}

	// Validate collection mode
	validMode := false
	for _, m := range testCollectionModes {
		if m == collectionMode {
			validMode = true
			break
		}
	}
	if !validMode {
		return nil, fmt.Errorf("unsupported collection mode: %s", collectionMode)
	}

	// Create base configuration
	config := &integration.IntegrationConfig{
		PlatformType: platformType,
		Name:         fmt.Sprintf("%s-integration-test", platformType),
		Environment:  "development",
		Auth: integration.AuthenticationConfig{
			Type: "oauth2",
			Credentials: map[string]interface{}{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"token_url":     "https://test.auth.com/token",
			},
			ExpiryTime: time.Hour,
			Renewable:  true,
		},
		Collection: integration.DataCollectionConfig{
			Mode:       collectionMode,
			RetryLimit: 3,
		},
		PlatformSpecific: map[string]interface{}{
			"region":    "us-west-2",
			"api_version": "v2",
		},
		Validation: integration.ValidationConfig{
			SchemaValidation: true,
			StrictMode:      true,
			ErrorThreshold:  10,
		},
	}

	// Configure batch settings if applicable
	if collectionMode == "batch" || collectionMode == "hybrid" {
		config.Collection.BatchSize = 1000
		config.Collection.Interval = "15m"
	}

	return config, nil
}

// GetInvalidTestConfigs returns an extensive set of invalid configurations
func GetInvalidTestConfigs() ([]*integration.IntegrationConfig, map[string]string) {
	invalidConfigs := make([]*integration.IntegrationConfig, 0)
	expectedErrors := make(map[string]string)

	// Missing platform type
	config1 := &integration.IntegrationConfig{
		Name:        "missing-platform",
		Environment: "development",
	}
	invalidConfigs = append(invalidConfigs, config1)
	expectedErrors["missing-platform"] = "platform_type is required"

	// Invalid auth type
	config2, _ := GetTestIntegrationConfig("aws", "real-time")
	config2.Auth.Type = "invalid"
	invalidConfigs = append(invalidConfigs, config2)
	expectedErrors["aws-integration-test"] = "invalid auth type"

	// Invalid batch size
	config3, _ := GetTestIntegrationConfig("azure", "batch")
	config3.Collection.BatchSize = 20000 // Exceeds maximum
	invalidConfigs = append(invalidConfigs, config3)
	expectedErrors["azure-integration-test"] = "batch size exceeds maximum limit"

	// Missing required oauth2 credentials
	config4, _ := GetTestIntegrationConfig("okta", "real-time")
	config4.Auth.Credentials = map[string]interface{}{
		"client_id": "test-id",
		// Missing client_secret and token_url
	}
	invalidConfigs = append(invalidConfigs, config4)
	expectedErrors["okta-integration-test"] = "missing required oauth2 credentials"

	// Invalid environment
	config5, _ := GetTestIntegrationConfig("splunk", "hybrid")
	config5.Environment = "invalid"
	invalidConfigs = append(invalidConfigs, config5)
	expectedErrors["splunk-integration-test"] = "invalid environment"

	return invalidConfigs, expectedErrors
}

// LoadTestConfigFromFile loads a test configuration from a YAML file
func LoadTestConfigFromFile(filePath string) (*integration.IntegrationConfig, error) {
	// Read file
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse YAML
	config := &integration.IntegrationConfig{}
	if err := yaml.Unmarshal(data, config); err != nil {
		return nil, fmt.Errorf("failed to parse config YAML: %w", err)
	}

	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return config, nil
}

// Helper functions for test configuration generation

// generateTestAuthConfig creates test authentication configuration
func generateTestAuthConfig(authType string) integration.AuthenticationConfig {
	switch authType {
	case "oauth2":
		return integration.AuthenticationConfig{
			Type: "oauth2",
			Credentials: map[string]interface{}{
				"client_id":     "test-client-id",
				"client_secret": "test-client-secret",
				"token_url":     "https://test.auth.com/token",
			},
			ExpiryTime: time.Hour,
			Renewable:  true,
		}
	case "apikey":
		return integration.AuthenticationConfig{
			Type: "apikey",
			Credentials: map[string]interface{}{
				"api_key": "test-api-key",
			},
		}
	default:
		return integration.AuthenticationConfig{
			Type: "basic",
			Credentials: map[string]interface{}{
				"username": "test-user",
				"password": "test-password",
			},
		}
	}
}

// generateTestCollectionConfig creates test collection configuration
func generateTestCollectionConfig(mode string) integration.DataCollectionConfig {
	config := integration.DataCollectionConfig{
		Mode:       mode,
		RetryLimit: 3,
	}

	if mode == "batch" || mode == "hybrid" {
		config.BatchSize = 1000
		config.Interval = "15m"
	}

	return config
}