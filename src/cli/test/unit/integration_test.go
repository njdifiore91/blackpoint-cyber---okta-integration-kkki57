// Package integration_test provides comprehensive unit tests for the BlackPoint CLI integration package
package integration_test

import (
	"crypto/tls"
	"encoding/json"
	"testing"
	"time"

	"../../pkg/integration/types"
	"../../pkg/integration/validation"
	"../../pkg/integration/schema"
	"../../pkg/common/errors"
)

// Test configurations
var (
	// Valid test integration configuration
	testValidIntegration = &types.Integration{
		ID:           "550e8400-e29b-41d4-a716-446655440000",
		Name:         "test-integration",
		PlatformType: "aws",
		Config: &types.IntegrationConfig{
			Environment: "production",
			Auth: &types.AuthConfig{
				Type:         "oauth2",
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret-with-minimum-length-16",
			},
			Collection: &types.CollectionConfig{
				Mode:          "hybrid",
				EventTypes:    []string{"security_alert", "audit_log"},
				BatchSchedule: "*/15 * * * *",
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now().Add(time.Hour),
	}

	// Invalid test configurations
	testInvalidIntegrations = []types.Integration{
		{
			// Invalid name format
			ID:           "550e8400-e29b-41d4-a716-446655440001",
			Name:         "invalid name with spaces",
			PlatformType: "aws",
			Config:       testValidIntegration.Config,
		},
		{
			// Invalid platform type
			ID:           "550e8400-e29b-41d4-a716-446655440002",
			Name:         "test-integration",
			PlatformType: "unsupported-platform",
			Config:       testValidIntegration.Config,
		},
		{
			// Invalid auth config
			ID:           "550e8400-e29b-41d4-a716-446655440003",
			Name:         "test-integration",
			PlatformType: "aws",
			Config: &types.IntegrationConfig{
				Environment: "production",
				Auth: &types.AuthConfig{
					Type: "oauth2",
					// Missing required fields
				},
				Collection: testValidIntegration.Config.Collection,
			},
		},
	}

	// Test authentication configurations
	testAuthConfigs = map[string]*types.AuthConfig{
		"oauth2": {
			Type:         "oauth2",
			ClientID:     "test-oauth2-client",
			ClientSecret: "test-oauth2-secret-with-minimum-length-16",
		},
		"api_key": {
			Type:   "api_key",
			APIKey: "test-api-key-with-minimum-length-of-32-chars",
		},
		"certificate": {
			Type:            "certificate",
			CertificatePath: "/path/to/cert.pem",
		},
	}

	// Test collection configurations
	testCollectionConfigs = map[string]*types.CollectionConfig{
		"realtime": {
			Mode:       "realtime",
			EventTypes: []string{"security_alert"},
		},
		"batch": {
			Mode:          "batch",
			EventTypes:    []string{"audit_log"},
			BatchSchedule: "0 */6 * * *",
		},
		"hybrid": {
			Mode:          "hybrid",
			EventTypes:    []string{"security_alert", "audit_log"},
			BatchSchedule: "*/15 * * * *",
		},
	}
)

// TestIntegrationValidation tests comprehensive integration configuration validation
func TestIntegrationValidation(t *testing.T) {
	// Test valid integration
	err := testValidIntegration.Validate()
	if err != nil {
		t.Errorf("Expected valid integration to pass validation: %v", err)
	}

	// Test invalid integrations
	for _, invalid := range testInvalidIntegrations {
		err := invalid.Validate()
		if err == nil {
			t.Errorf("Expected invalid integration to fail validation: %+v", invalid)
		}
	}

	// Test integration name validation
	invalidNames := []string{
		"",                    // Empty name
		"a",                   // Too short
		"system",             // Reserved name
		"invalid@name",       // Invalid characters
		"very-long-name-that-exceeds-the-maximum-length-limit-of-64-characters",
	}

	for _, name := range invalidNames {
		testValidIntegration.Name = name
		err := testValidIntegration.Validate()
		if err == nil {
			t.Errorf("Expected invalid name to fail validation: %s", name)
		}
	}
}

// TestAuthConfigValidation tests authentication configuration validation
func TestAuthConfigValidation(t *testing.T) {
	// Test valid auth configurations
	for authType, config := range testAuthConfigs {
		err := validation.ValidateAuthConfig(config)
		if err != nil {
			t.Errorf("Expected valid %s auth config to pass validation: %v", authType, err)
		}
	}

	// Test OAuth2 validation
	oauth2Tests := []struct {
		config *types.AuthConfig
		valid  bool
	}{
		{
			config: &types.AuthConfig{
				Type:         "oauth2",
				ClientID:     "",
				ClientSecret: "secret",
			},
			valid: false,
		},
		{
			config: &types.AuthConfig{
				Type:         "oauth2",
				ClientID:     "client",
				ClientSecret: "short",
			},
			valid: false,
		},
	}

	for _, test := range oauth2Tests {
		err := validation.ValidateAuthConfig(test.config)
		if (err == nil) == test.valid {
			t.Errorf("Unexpected OAuth2 validation result for config: %+v", test.config)
		}
	}

	// Test certificate validation
	certTests := []struct {
		config *types.AuthConfig
		valid  bool
	}{
		{
			config: &types.AuthConfig{
				Type:            "certificate",
				CertificatePath: "",
			},
			valid: false,
		},
		{
			config: &types.AuthConfig{
				Type:            "certificate",
				CertificatePath: "/invalid/path/with/spaces and special$chars",
			},
			valid: false,
		},
	}

	for _, test := range certTests {
		err := validation.ValidateAuthConfig(test.config)
		if (err == nil) == test.valid {
			t.Errorf("Unexpected certificate validation result for config: %+v", test.config)
		}
	}
}

// TestCollectionConfigValidation tests data collection configuration validation
func TestCollectionConfigValidation(t *testing.T) {
	// Test valid collection configurations
	for mode, config := range testCollectionConfigs {
		err := validation.ValidateCollectionConfig(config)
		if err != nil {
			t.Errorf("Expected valid %s collection config to pass validation: %v", mode, err)
		}
	}

	// Test invalid event types
	invalidEventTypes := []struct {
		config *types.CollectionConfig
		valid  bool
	}{
		{
			config: &types.CollectionConfig{
				Mode:       "realtime",
				EventTypes: []string{},
			},
			valid: false,
		},
		{
			config: &types.CollectionConfig{
				Mode:       "realtime",
				EventTypes: nil,
			},
			valid: false,
		},
	}

	for _, test := range invalidEventTypes {
		err := validation.ValidateCollectionConfig(test.config)
		if (err == nil) == test.valid {
			t.Errorf("Unexpected event types validation result for config: %+v", test.config)
		}
	}

	// Test batch schedule validation
	batchTests := []struct {
		config *types.CollectionConfig
		valid  bool
	}{
		{
			config: &types.CollectionConfig{
				Mode:          "batch",
				EventTypes:    []string{"audit_log"},
				BatchSchedule: "",
			},
			valid: false,
		},
		{
			config: &types.CollectionConfig{
				Mode:          "batch",
				EventTypes:    []string{"audit_log"},
				BatchSchedule: "invalid cron",
			},
			valid: false,
		},
		{
			config: &types.CollectionConfig{
				Mode:          "realtime",
				EventTypes:    []string{"security_alert"},
				BatchSchedule: "*/15 * * * *", // Should not have schedule in realtime mode
			},
			valid: false,
		},
	}

	for _, test := range batchTests {
		err := validation.ValidateCollectionConfig(test.config)
		if (err == nil) == test.valid {
			t.Errorf("Unexpected batch schedule validation result for config: %+v", test.config)
		}
	}
}

// TestSchemaValidation tests JSON schema validation with version compatibility
func TestSchemaValidation(t *testing.T) {
	// Test valid schema
	validConfig, err := json.Marshal(testValidIntegration)
	if err != nil {
		t.Fatalf("Failed to marshal valid configuration: %v", err)
	}

	err = schema.ValidateConfigurationSchema(validConfig)
	if err != nil {
		t.Errorf("Expected valid schema to pass validation: %v", err)
	}

	// Test invalid schema
	invalidSchemas := []map[string]interface{}{
		{
			// Missing required fields
			"name": "test-integration",
		},
		{
			// Invalid auth type
			"name":         "test-integration",
			"platform_type": "aws",
			"config": map[string]interface{}{
				"environment": "production",
				"auth": map[string]interface{}{
					"type": "unsupported",
				},
			},
		},
		{
			// Invalid collection mode
			"name":         "test-integration",
			"platform_type": "aws",
			"config": map[string]interface{}{
				"environment": "production",
				"auth":       testAuthConfigs["oauth2"],
				"collection": map[string]interface{}{
					"mode":       "invalid",
					"event_types": []string{"security_alert"},
				},
			},
		},
	}

	for _, invalid := range invalidSchemas {
		invalidConfig, err := json.Marshal(invalid)
		if err != nil {
			t.Fatalf("Failed to marshal invalid configuration: %v", err)
		}

		err = schema.ValidateConfigurationSchema(invalidConfig)
		if err == nil {
			t.Errorf("Expected invalid schema to fail validation: %+v", invalid)
		}
	}
}