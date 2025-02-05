// Package integration provides configuration management functionality for security platform integrations
package integration

import (
    "fmt"
    "os"
    "path/filepath"
    "gopkg.in/yaml.v3" // v3.0.1
    
    "../../pkg/integration/types"
    "../../pkg/integration/schema"
    "../../pkg/common/errors"
)

const (
    // Default file permissions for configuration files (read/write for owner only)
    configFileMode = os.FileMode(0600)
    
    // Maximum config file size (1MB)
    maxConfigSize = 1048576
    
    // Temporary file suffix
    tempFileSuffix = ".tmp"
    
    // Backup file suffix
    backupFileSuffix = ".bak"
)

// LoadIntegrationConfig loads and validates an integration configuration from a YAML file
func LoadIntegrationConfig(configPath string) (*types.Integration, error) {
    // Validate and clean file path
    absPath, err := filepath.Abs(configPath)
    if err != nil {
        return nil, errors.NewCLIError("E1004", "Invalid configuration file path", err)
    }

    // Check file existence and permissions
    info, err := os.Stat(absPath)
    if err != nil {
        return nil, errors.NewCLIError("E1004", "Configuration file not accessible", err)
    }

    // Validate file size
    if info.Size() > maxConfigSize {
        return nil, errors.NewCLIError("E1004", fmt.Sprintf("Configuration file exceeds maximum size of %d bytes", maxConfigSize), nil)
    }

    // Validate file permissions
    if info.Mode().Perm() != configFileMode {
        return nil, errors.NewCLIError("E1004", "Invalid configuration file permissions", nil)
    }

    // Read configuration file
    data, err := os.ReadFile(absPath)
    if err != nil {
        return nil, errors.NewCLIError("E1004", "Failed to read configuration file", err)
    }

    // Parse YAML into Integration struct
    var config types.Integration
    if err := yaml.Unmarshal(data, &config); err != nil {
        return nil, errors.NewCLIError("E1004", "Failed to parse configuration YAML", err)
    }

    // Validate configuration schema
    if err := schema.ValidateConfigurationSchema(data); err != nil {
        return nil, errors.WrapError(err, "Schema validation failed")
    }

    // Validate integration configuration
    if err := config.Validate(); err != nil {
        return nil, errors.WrapError(err, "Integration validation failed")
    }

    return &config, nil
}

// SaveIntegrationConfig securely saves an integration configuration to a YAML file
func SaveIntegrationConfig(config *types.Integration, configPath string) error {
    // Validate configuration before saving
    if err := config.Validate(); err != nil {
        return errors.WrapError(err, "Invalid integration configuration")
    }

    // Create configuration directory if it doesn't exist
    configDir := filepath.Dir(configPath)
    if err := os.MkdirAll(configDir, configFileMode); err != nil {
        return errors.NewCLIError("E1004", "Failed to create configuration directory", err)
    }

    // Marshal configuration to YAML
    data, err := yaml.Marshal(config)
    if err != nil {
        return errors.NewCLIError("E1004", "Failed to marshal configuration to YAML", err)
    }

    // Create temporary file for atomic write
    tempPath := configPath + tempFileSuffix
    if err := os.WriteFile(tempPath, data, configFileMode); err != nil {
        return errors.NewCLIError("E1004", "Failed to write temporary configuration file", err)
    }

    // Create backup of existing configuration if it exists
    if _, err := os.Stat(configPath); err == nil {
        backupPath := configPath + backupFileSuffix
        if err := os.Rename(configPath, backupPath); err != nil {
            os.Remove(tempPath)
            return errors.NewCLIError("E1004", "Failed to create backup configuration", err)
        }
    }

    // Perform atomic rename
    if err := os.Rename(tempPath, configPath); err != nil {
        os.Remove(tempPath)
        return errors.NewCLIError("E1004", "Failed to save configuration file", err)
    }

    return nil
}

// ValidateConfigFile performs comprehensive validation of an integration configuration file
func ValidateConfigFile(configPath string) error {
    // Load and validate configuration
    config, err := LoadIntegrationConfig(configPath)
    if err != nil {
        return err
    }

    // Perform additional security validation
    if err := validateSecurityConstraints(config); err != nil {
        return errors.WrapError(err, "Security validation failed")
    }

    return nil
}

// validateSecurityConstraints performs additional security-focused validation
func validateSecurityConstraints(config *types.Integration) error {
    if config.Config == nil || config.Config.Auth == nil {
        return errors.NewCLIError("E1004", "Missing authentication configuration", nil)
    }

    // Validate authentication configuration security
    switch config.Config.Auth.Type {
    case "oauth2", "basic":
        if config.Config.Auth.ClientSecret == "" {
            return errors.NewCLIError("E1004", "Missing client secret for OAuth2/Basic authentication", nil)
        }
    case "api_key":
        if config.Config.Auth.APIKey == "" {
            return errors.NewCLIError("E1004", "Missing API key", nil)
        }
    case "certificate":
        if config.Config.Auth.CertificatePath == "" {
            return errors.NewCLIError("E1004", "Missing certificate path", nil)
        }
        // Validate certificate file existence and permissions
        if _, err := os.Stat(config.Config.Auth.CertificatePath); err != nil {
            return errors.NewCLIError("E1004", "Certificate file not accessible", err)
        }
    }

    return nil
}