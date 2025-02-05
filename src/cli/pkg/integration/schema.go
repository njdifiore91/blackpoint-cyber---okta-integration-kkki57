// Package integration provides JSON schema validation for security platform integrations
package integration

import (
    "encoding/json"
    "github.com/xeipuuv/gojsonschema"
    "github.com/blackpoint/cli/pkg/integration/types"
    "github.com/blackpoint/cli/pkg/common/errors"
)

// SchemaVersion defines the current version of the integration schema
const SchemaVersion = "1.0.0"

// Schema definitions for integration configuration validation
var (
    // IntegrationSchema defines the complete JSON schema for integration validation
    IntegrationSchema = map[string]interface{}{
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "BlackPoint Security Integration Schema",
        "type": "object",
        "version": SchemaVersion,
        "required": []string{"name", "platform_type", "config"},
        "properties": {
            "name": {
                "type": "string",
                "pattern": "^[a-zA-Z0-9-_]{3,64}$",
                "description": "Integration name (3-64 characters, alphanumeric with hyphen and underscore)",
            },
            "platform_type": {
                "type": "string",
                "minLength": 1,
                "description": "Security platform type identifier",
            },
            "config": {
                "$ref": "#/definitions/IntegrationConfig",
            },
        },
        "definitions": {
            "IntegrationConfig": {
                "type": "object",
                "required": []string{"environment", "auth", "collection"},
                "properties": {
                    "environment": {
                        "type": "string",
                        "enum": []string{"production", "staging", "development"},
                        "description": "Deployment environment",
                    },
                    "auth": {
                        "$ref": "#/definitions/AuthConfig",
                    },
                    "collection": {
                        "$ref": "#/definitions/CollectionConfig",
                    },
                },
            },
            "AuthConfig": {
                "type": "object",
                "required": []string{"type"},
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": []string{"oauth2", "api_key", "basic", "certificate"},
                        "description": "Authentication method",
                    },
                    "client_id": {
                        "type": "string",
                        "minLength": 1,
                        "description": "OAuth2/Basic auth client ID",
                    },
                    "client_secret": {
                        "type": "string",
                        "minLength": 1,
                        "description": "OAuth2/Basic auth client secret",
                    },
                    "api_key": {
                        "type": "string",
                        "minLength": 32,
                        "description": "API key for authentication",
                    },
                    "certificate_path": {
                        "type": "string",
                        "pattern": "^[\\w\\-\\/\\.]+$",
                        "description": "Path to authentication certificate",
                    },
                },
                "allOf": [
                    {
                        "if": {"properties": {"type": {"const": "oauth2"}}},
                        "then": {"required": ["client_id", "client_secret"]},
                    },
                    {
                        "if": {"properties": {"type": {"const": "api_key"}}},
                        "then": {"required": ["api_key"]},
                    },
                    {
                        "if": {"properties": {"type": {"const": "certificate"}}},
                        "then": {"required": ["certificate_path"]},
                    },
                    {
                        "if": {"properties": {"type": {"const": "basic"}}},
                        "then": {"required": ["client_id", "client_secret"]},
                    },
                ],
            },
            "CollectionConfig": {
                "type": "object",
                "required": []string{"mode", "event_types"},
                "properties": {
                    "mode": {
                        "type": "string",
                        "enum": []string{"realtime", "batch", "hybrid"},
                        "description": "Data collection mode",
                    },
                    "event_types": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "string",
                            "minLength": 1,
                        },
                        "description": "Types of security events to collect",
                    },
                    "batch_schedule": {
                        "type": "string",
                        "pattern": "^(\\*|[0-9,\\-\\*/]+)\\s+(\\*|[0-9,\\-\\*/]+)\\s+(\\*|[0-9,\\-\\*/]+)\\s+(\\*|[0-9,\\-\\*/]+)\\s+(\\*|[0-9,\\-\\*/]+)$",
                        "description": "Cron schedule for batch collection",
                    },
                },
                "allOf": [
                    {
                        "if": {
                            "properties": {"mode": {"enum": ["batch", "hybrid"]}},
                        },
                        "then": {"required": ["batch_schedule"]},
                    },
                ],
            },
        },
    }
)

// GetIntegrationSchema returns the complete JSON schema for integration validation
func GetIntegrationSchema() map[string]interface{} {
    return IntegrationSchema
}

// ValidateConfigurationSchema validates a JSON configuration file against the integration schema
func ValidateConfigurationSchema(configData []byte) error {
    // Parse configuration data
    var config map[string]interface{}
    if err := json.Unmarshal(configData, &config); err != nil {
        return errors.NewCLIError("E1004", "Failed to parse configuration JSON", err)
    }

    // Load schema and configuration for validation
    schemaLoader := gojsonschema.NewGoLoader(IntegrationSchema)
    documentLoader := gojsonschema.NewBytesLoader(configData)

    // Perform validation
    result, err := gojsonschema.Validate(schemaLoader, documentLoader)
    if err != nil {
        return errors.NewCLIError("E1004", "Schema validation failed", err)
    }

    // Check validation results
    if !result.Valid() {
        var validationErrors []string
        for _, err := range result.Errors() {
            validationErrors = append(validationErrors, err.String())
        }
        return errors.NewCLIError("E1004", "Configuration validation failed", 
            errors.WrapError(nil, "Validation errors: "+json.NewEncoder(validationErrors).Encode()))
    }

    // Perform additional security validations
    if err := validateSecurityConstraints(config); err != nil {
        return err
    }

    return nil
}

// validateSecurityConstraints performs additional security-focused validation
func validateSecurityConstraints(config map[string]interface{}) error {
    // Validate auth configuration security
    authConfig, ok := config["config"].(map[string]interface{})["auth"].(map[string]interface{})
    if !ok {
        return errors.NewCLIError("E1004", "Invalid auth configuration structure", nil)
    }

    // Check for sensitive data exposure
    if authType, ok := authConfig["type"].(string); ok {
        switch authType {
        case "oauth2", "basic":
            if _, exists := authConfig["client_secret"]; exists {
                // Ensure client secret is not logged or exposed
                authConfig["client_secret"] = "********"
            }
        case "api_key":
            if _, exists := authConfig["api_key"]; exists {
                // Ensure API key is not logged or exposed
                authConfig["api_key"] = "********"
            }
        }
    }

    // Validate collection configuration security
    collectionConfig, ok := config["config"].(map[string]interface{})["collection"].(map[string]interface{})
    if !ok {
        return errors.NewCLIError("E1004", "Invalid collection configuration structure", nil)
    }

    // Validate batch schedule security (if applicable)
    if mode, ok := collectionConfig["mode"].(string); ok {
        if mode == "batch" || mode == "hybrid" {
            schedule, ok := collectionConfig["batch_schedule"].(string)
            if !ok || schedule == "" {
                return errors.NewCLIError("E1004", "Batch schedule is required for batch/hybrid mode", nil)
            }
        }
    }

    return nil
}