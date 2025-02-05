// Package integration provides validation logic for security platform integrations
package integration

import (
    "encoding/json"
    "fmt"
    "os"

    "../../pkg/integration/types"
    "../../pkg/integration/schema"
    "../../pkg/common/errors"
)

// ValidateIntegrationFile validates an integration configuration file against schema
// and comprehensive business rules including security policies
func ValidateIntegrationFile(filePath string) (*types.Integration, error) {
    // Read and validate file existence and permissions
    fileData, err := os.ReadFile(filePath)
    if err != nil {
        return nil, errors.NewCLIError("E1004", fmt.Sprintf("Failed to read integration file: %s", filePath), err)
    }

    // Validate file size constraints
    if len(fileData) < constants.IntegrationConfigMinSize {
        return nil, errors.NewCLIError("E1004", "Integration configuration file too small", nil)
    }
    if len(fileData) > constants.IntegrationConfigMaxSize {
        return nil, errors.NewCLIError("E1004", "Integration configuration file exceeds maximum size", nil)
    }

    // Validate JSON schema
    if err := schema.ValidateConfigurationSchema(fileData); err != nil {
        return nil, errors.WrapError(err, "Schema validation failed")
    }

    // Unmarshal configuration into Integration struct
    var integration types.Integration
    decoder := json.NewDecoder(bytes.NewReader(fileData))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&integration); err != nil {
        return nil, errors.NewCLIError("E1004", "Failed to parse integration configuration", err)
    }

    // Perform comprehensive validation
    if err := ValidateIntegrationConfig(&integration); err != nil {
        return nil, err
    }

    return &integration, nil
}

// ValidateIntegrationConfig validates an in-memory integration configuration
// against business rules and security policies
func ValidateIntegrationConfig(config *types.Integration) error {
    // Validate basic integration configuration
    if err := config.Validate(); err != nil {
        return errors.WrapError(err, "Integration validation failed")
    }

    // Validate security policies
    if err := validateSecurityPolicies(config); err != nil {
        return errors.WrapError(err, "Security policy validation failed")
    }

    // Validate rate limits and quotas
    if err := validateResourceLimits(config); err != nil {
        return errors.WrapError(err, "Resource limit validation failed")
    }

    return nil
}

// ValidateDeploymentPrerequisites validates all prerequisites before integration deployment
func ValidateDeploymentPrerequisites(integration *types.Integration) error {
    // Validate integration configuration is complete
    if err := ValidateIntegrationConfig(integration); err != nil {
        return errors.WrapError(err, "Prerequisite validation failed")
    }

    // Validate credentials
    if err := validateCredentials(integration); err != nil {
        return errors.WrapError(err, "Credential validation failed")
    }

    // Validate platform-specific requirements
    if err := validatePlatformRequirements(integration); err != nil {
        return errors.WrapError(err, "Platform requirement validation failed")
    }

    // Validate network access
    if err := validateNetworkAccess(integration); err != nil {
        return errors.WrapError(err, "Network access validation failed")
    }

    return nil
}

// validateSecurityPolicies performs security-focused validation of the integration
func validateSecurityPolicies(config *types.Integration) error {
    // Validate authentication security requirements
    if config.Config.Auth == nil {
        return errors.NewCLIError("E1004", "Authentication configuration required", nil)
    }

    // Validate credential strength based on auth type
    switch config.Config.Auth.Type {
    case "oauth2", "basic":
        if len(config.Config.Auth.ClientSecret) < constants.MinPasswordLength {
            return errors.NewCLIError("E1004", "Client secret does not meet minimum length requirement", nil)
        }
    case "api_key":
        if len(config.Config.Auth.APIKey) < constants.APIKeyMinLength {
            return errors.NewCLIError("E1004", "API key does not meet minimum length requirement", nil)
        }
    case "certificate":
        if err := validateCertificate(config.Config.Auth.CertificatePath); err != nil {
            return errors.WrapError(err, "Certificate validation failed")
        }
    }

    // Validate collection security requirements
    if config.Config.Collection.Mode == "batch" || config.Config.Collection.Mode == "hybrid" {
        if err := validateBatchScheduleSecurity(config.Config.Collection.BatchSchedule); err != nil {
            return errors.WrapError(err, "Batch schedule security validation failed")
        }
    }

    return nil
}

// validateCredentials verifies the existence and validity of required credentials
func validateCredentials(integration *types.Integration) error {
    switch integration.Config.Auth.Type {
    case "oauth2":
        if err := validateOAuth2Credentials(integration.Config.Auth); err != nil {
            return err
        }
    case "api_key":
        if err := validateAPIKey(integration.Config.Auth.APIKey); err != nil {
            return err
        }
    case "certificate":
        if err := validateCertificateCredentials(integration.Config.Auth.CertificatePath); err != nil {
            return err
        }
    case "basic":
        if err := validateBasicAuthCredentials(integration.Config.Auth); err != nil {
            return err
        }
    }
    return nil
}

// validateResourceLimits checks integration against system resource limits
func validateResourceLimits(config *types.Integration) error {
    // Validate event size limits
    if config.Config.Collection.Mode == "realtime" {
        if err := validateRealtimeLimits(config); err != nil {
            return err
        }
    }

    // Validate batch processing limits
    if config.Config.Collection.Mode == "batch" || config.Config.Collection.Mode == "hybrid" {
        if err := validateBatchLimits(config); err != nil {
            return err
        }
    }

    return nil
}

// validatePlatformRequirements checks platform-specific integration requirements
func validatePlatformRequirements(integration *types.Integration) error {
    // Validate platform-specific event types
    if err := validateEventTypes(integration.Config.Collection.EventTypes, integration.PlatformType); err != nil {
        return errors.WrapError(err, "Invalid event types for platform")
    }

    // Validate platform-specific authentication
    if err := validatePlatformAuth(integration.Config.Auth, integration.PlatformType); err != nil {
        return errors.WrapError(err, "Invalid authentication for platform")
    }

    return nil
}

// validateNetworkAccess verifies required network connectivity
func validateNetworkAccess(integration *types.Integration) error {
    // Validate platform endpoint accessibility
    if err := validateEndpointAccess(integration.PlatformType); err != nil {
        return errors.WrapError(err, "Platform endpoint not accessible")
    }

    // Validate required ports are accessible
    if err := validatePortAccess(integration.PlatformType); err != nil {
        return errors.WrapError(err, "Required ports not accessible")
    }

    return nil
}