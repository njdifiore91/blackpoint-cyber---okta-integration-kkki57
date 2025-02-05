// Package integration provides validation logic for security platform integrations
package integration

import (
    "regexp"
    "strings"
    "./types"
    "./schema"
    "../common/errors"
)

var (
    // namePattern defines strict validation pattern for integration names
    namePattern = regexp.MustCompile(`^[a-zA-Z][-a-zA-Z0-9_]{2,63}$`)

    // allowedPlatformTypes defines supported security platforms
    allowedPlatformTypes = []string{
        "aws", "azure", "gcp", "okta", "auth0", "crowdstrike",
        "sentinelone", "microsoft365", "cloudflare", "paloalto",
    }

    // allowedEnvironments defines valid deployment environments
    allowedEnvironments = []string{"production", "staging", "development", "dr"}

    // allowedAuthTypes defines supported authentication methods
    allowedAuthTypes = []string{"oauth2", "api_key", "basic", "certificate", "jwt", "saml"}

    // allowedCollectionModes defines valid data collection modes
    allowedCollectionModes = []string{"realtime", "batch", "hybrid"}

    // minPasswordLength defines minimum password/secret length
    minPasswordLength = 16

    // maxBatchDelay defines maximum delay between batch collections in seconds
    maxBatchDelay = 300

    // minEventTypes defines minimum number of event types required
    minEventTypes = 1
)

// ValidateIntegrationName validates integration name against security pattern
func ValidateIntegrationName(name string) error {
    name = strings.TrimSpace(name)
    if !namePattern.MatchString(name) {
        return errors.NewCLIError("E1004", 
            "Integration name must start with a letter and contain only letters, numbers, hyphens, and underscores (2-63 chars)", 
            nil)
    }

    // Check for reserved names
    reservedNames := []string{"system", "admin", "root", "security"}
    for _, reserved := range reservedNames {
        if strings.ToLower(name) == reserved {
            return errors.NewCLIError("E1004", 
                "Integration name cannot use reserved system names", 
                nil)
        }
    }

    return nil
}

// ValidateAuthConfig performs comprehensive authentication configuration validation
func ValidateAuthConfig(config *types.AuthConfig) error {
    if config == nil {
        return errors.NewCLIError("E1004", "Authentication configuration is required", nil)
    }

    // Validate auth type
    validType := false
    for _, authType := range allowedAuthTypes {
        if config.Type == authType {
            validType = true
            break
        }
    }
    if !validType {
        return errors.NewCLIError("E1004", "Invalid authentication type specified", nil)
    }

    // Type-specific validation
    switch config.Type {
    case "oauth2":
        if err := validateOAuth2Config(config); err != nil {
            return err
        }
    case "api_key":
        if err := validateAPIKeyConfig(config); err != nil {
            return err
        }
    case "certificate":
        if err := validateCertificateConfig(config); err != nil {
            return err
        }
    case "basic":
        if err := validateBasicAuthConfig(config); err != nil {
            return err
        }
    case "jwt":
        if err := validateJWTConfig(config); err != nil {
            return err
        }
    case "saml":
        if err := validateSAMLConfig(config); err != nil {
            return err
        }
    }

    return nil
}

// ValidateCollectionConfig validates data collection configuration
func ValidateCollectionConfig(config *types.CollectionConfig) error {
    if config == nil {
        return errors.NewCLIError("E1004", "Collection configuration is required", nil)
    }

    // Validate collection mode
    validMode := false
    for _, mode := range allowedCollectionModes {
        if config.Mode == mode {
            validMode = true
            break
        }
    }
    if !validMode {
        return errors.NewCLIError("E1004", "Invalid collection mode specified", nil)
    }

    // Validate event types
    if len(config.EventTypes) < minEventTypes {
        return errors.NewCLIError("E1004", 
            "At least one event type must be specified", 
            nil)
    }

    // Mode-specific validation
    switch config.Mode {
    case "batch", "hybrid":
        if err := validateBatchConfig(config); err != nil {
            return err
        }
    case "realtime":
        if err := validateRealtimeConfig(config); err != nil {
            return err
        }
    }

    return nil
}

// validateOAuth2Config validates OAuth2.0 specific configuration
func validateOAuth2Config(config *types.AuthConfig) error {
    if config.ClientID == "" || config.ClientSecret == "" {
        return errors.NewCLIError("E1004", 
            "OAuth2 requires both client ID and client secret", 
            nil)
    }
    
    if len(config.ClientSecret) < minPasswordLength {
        return errors.NewCLIError("E1004", 
            "OAuth2 client secret must meet minimum length requirements", 
            nil)
    }

    return nil
}

// validateAPIKeyConfig validates API key specific configuration
func validateAPIKeyConfig(config *types.AuthConfig) error {
    if config.APIKey == "" {
        return errors.NewCLIError("E1004", "API key is required", nil)
    }

    if len(config.APIKey) < minPasswordLength {
        return errors.NewCLIError("E1004", 
            "API key must meet minimum length requirements", 
            nil)
    }

    return nil
}

// validateCertificateConfig validates certificate specific configuration
func validateCertificateConfig(config *types.AuthConfig) error {
    if config.CertificatePath == "" {
        return errors.NewCLIError("E1004", "Certificate path is required", nil)
    }

    // Validate certificate path format
    certPathPattern := regexp.MustCompile(`^[\w\-\/\.]+$`)
    if !certPathPattern.MatchString(config.CertificatePath) {
        return errors.NewCLIError("E1004", 
            "Invalid certificate path format", 
            nil)
    }

    return nil
}

// validateBasicAuthConfig validates basic auth specific configuration
func validateBasicAuthConfig(config *types.AuthConfig) error {
    if config.ClientID == "" || config.ClientSecret == "" {
        return errors.NewCLIError("E1004", 
            "Basic auth requires both username and password", 
            nil)
    }

    if len(config.ClientSecret) < minPasswordLength {
        return errors.NewCLIError("E1004", 
            "Basic auth password must meet minimum length requirements", 
            nil)
    }

    return nil
}

// validateJWTConfig validates JWT specific configuration
func validateJWTConfig(config *types.AuthConfig) error {
    if config.ClientSecret == "" {
        return errors.NewCLIError("E1004", "JWT signing key is required", nil)
    }

    if len(config.ClientSecret) < minPasswordLength {
        return errors.NewCLIError("E1004", 
            "JWT signing key must meet minimum length requirements", 
            nil)
    }

    return nil
}

// validateSAMLConfig validates SAML specific configuration
func validateSAMLConfig(config *types.AuthConfig) error {
    if config.CertificatePath == "" {
        return errors.NewCLIError("E1004", "SAML certificate path is required", nil)
    }

    // Validate certificate path format
    certPathPattern := regexp.MustCompile(`^[\w\-\/\.]+$`)
    if !certPathPattern.MatchString(config.CertificatePath) {
        return errors.NewCLIError("E1004", 
            "Invalid SAML certificate path format", 
            nil)
    }

    return nil
}

// validateBatchConfig validates batch collection specific configuration
func validateBatchConfig(config *types.CollectionConfig) error {
    if config.BatchSchedule == "" {
        return errors.NewCLIError("E1004", 
            "Batch schedule is required for batch/hybrid mode", 
            nil)
    }

    // Validate cron expression format
    cronPattern := regexp.MustCompile(`^(\*|[0-9,\-\*/]+)\s+(\*|[0-9,\-\*/]+)\s+(\*|[0-9,\-\*/]+)\s+(\*|[0-9,\-\*/]+)\s+(\*|[0-9,\-\*/]+)$`)
    if !cronPattern.MatchString(config.BatchSchedule) {
        return errors.NewCLIError("E1004", 
            "Invalid batch schedule format - must be valid cron expression", 
            nil)
    }

    return nil
}

// validateRealtimeConfig validates realtime collection specific configuration
func validateRealtimeConfig(config *types.CollectionConfig) error {
    // Ensure no batch schedule is set for realtime mode
    if config.BatchSchedule != "" {
        return errors.NewCLIError("E1004", 
            "Batch schedule should not be set for realtime collection mode", 
            nil)
    }

    return nil
}