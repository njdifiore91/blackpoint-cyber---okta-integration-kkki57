// Package config provides secure configuration loading functionality for the BlackPoint CLI
package config

import (
    "crypto/tls"
    "fmt"
    "os"
    "path/filepath"
    
    "gopkg.in/yaml.v3"
    
    "github.com/blackpoint/cli/pkg/config/types"
    "github.com/blackpoint/cli/pkg/config/defaults"
    "github.com/blackpoint/cli/pkg/common/errors"
    "github.com/blackpoint/cli/pkg/common/constants"
)

// LoadConfig securely loads the CLI configuration from multiple sources
// with comprehensive validation and security checks
func LoadConfig(configPath string) (*types.Config, error) {
    // Initialize with secure defaults
    config := defaults.NewDefaultConfig()
    
    // Load from config file if provided
    if configPath != "" {
        if err := loadFromFile(configPath, config); err != nil {
            return nil, errors.NewCLIError("E1001", 
                fmt.Sprintf("failed to load config file: %s", configPath), err)
        }
    }
    
    // Override with environment variables
    if err := loadFromEnv(config); err != nil {
        return nil, errors.NewCLIError("E1001", 
            "failed to load environment configuration", err)
    }
    
    // Perform comprehensive validation
    if err := validateConfig(config); err != nil {
        return nil, err
    }
    
    return config, nil
}

// loadFromFile securely loads configuration from a YAML file
func loadFromFile(path string, config *types.Config) error {
    // Verify file exists
    if _, err := os.Stat(path); err != nil {
        return errors.NewCLIError("E1001", 
            fmt.Sprintf("config file not accessible: %s", path), err)
    }
    
    // Verify file permissions (owner read/write only)
    info, err := os.Stat(path)
    if err != nil {
        return errors.NewCLIError("E1001", 
            "failed to get file info", err)
    }
    
    if info.Mode().Perm() > constants.ConfigFilePermissions {
        return errors.NewCLIError("E1001", 
            fmt.Sprintf("insecure file permissions: %s", path), nil)
    }
    
    // Read file contents
    data, err := os.ReadFile(path)
    if err != nil {
        return errors.NewCLIError("E1001", 
            "failed to read config file", err)
    }
    
    // Validate YAML structure
    if err := yaml.Unmarshal(data, config); err != nil {
        return errors.NewCLIError("E1001", 
            "invalid YAML configuration", err)
    }
    
    return nil
}

// loadFromEnv securely loads configuration from environment variables
func loadFromEnv(config *types.Config) error {
    // API Configuration
    if endpoint := os.Getenv("BLACKPOINT_API_ENDPOINT"); endpoint != "" {
        config.API.Endpoint = endpoint
    }
    
    // Auth Configuration
    if apiKey := os.Getenv("BLACKPOINT_API_KEY"); apiKey != "" {
        if len(apiKey) < constants.APIKeyMinLength {
            return errors.NewCLIError("E1001", 
                "API key from environment is too short", nil)
        }
        config.Auth.APIKey = apiKey
    }
    
    // Logging Configuration
    if level := os.Getenv("BLACKPOINT_LOG_LEVEL"); level != "" {
        config.Logging.Level = level
    }
    
    // Output Configuration
    if format := os.Getenv("BLACKPOINT_OUTPUT_FORMAT"); format != "" {
        config.Output.Format = format
    }
    
    return nil
}

// validateConfig performs comprehensive configuration validation
func validateConfig(config *types.Config) error {
    if config == nil {
        return errors.NewCLIError("E1001", 
            "configuration cannot be nil", nil)
    }
    
    // Validate API configuration
    if err := validateAPIConfig(config.API); err != nil {
        return err
    }
    
    // Validate Auth configuration
    if err := validateAuthConfig(config.Auth); err != nil {
        return err
    }
    
    // Validate Logging configuration
    if err := validateLoggingConfig(config.Logging); err != nil {
        return err
    }
    
    // Validate Output configuration
    if err := validateOutputConfig(config.Output); err != nil {
        return err
    }
    
    return nil
}

// validateAPIConfig validates API-specific configuration
func validateAPIConfig(config *types.APIConfig) error {
    if config == nil {
        return errors.NewCLIError("E1001", 
            "API configuration cannot be nil", nil)
    }
    
    // Validate TLS configuration
    if _, err := tls.X509KeyPair([]byte{}, []byte{}); err != nil {
        return errors.NewCLIError("E1001", 
            "invalid TLS configuration", err)
    }
    
    // Validate endpoint URL
    if config.Endpoint == "" {
        return errors.NewCLIError("E1001", 
            "API endpoint cannot be empty", nil)
    }
    
    // Validate timeouts
    if config.Timeout < constants.DefaultConnectionTimeout {
        return errors.NewCLIError("E1001", 
            "API timeout is too short", nil)
    }
    
    return nil
}

// validateAuthConfig validates authentication configuration
func validateAuthConfig(config *types.AuthConfig) error {
    if config == nil {
        return errors.NewCLIError("E1001", 
            "Auth configuration cannot be nil", nil)
    }
    
    // Validate API key
    if len(config.APIKey) < constants.APIKeyMinLength {
        return errors.NewCLIError("E1001", 
            "API key is too short", nil)
    }
    
    // Validate token path
    if config.TokenPath != "" {
        if !filepath.IsAbs(config.TokenPath) {
            return errors.NewCLIError("E1001", 
                "token path must be absolute", nil)
        }
    }
    
    return nil
}

// validateLoggingConfig validates logging configuration
func validateLoggingConfig(config *types.LoggingConfig) error {
    if config == nil {
        return errors.NewCLIError("E1001", 
            "Logging configuration cannot be nil", nil)
    }
    
    // Validate log path permissions if specified
    if config.OutputPath != "" {
        dir := filepath.Dir(config.OutputPath)
        if _, err := os.Stat(dir); err != nil {
            return errors.NewCLIError("E1001", 
                "log directory does not exist", err)
        }
    }
    
    return nil
}

// validateOutputConfig validates output configuration
func validateOutputConfig(config *types.OutputConfig) error {
    if config == nil {
        return errors.NewCLIError("E1001", 
            "Output configuration cannot be nil", nil)
    }
    
    validFormats := []string{"json", "yaml", "table", "text"}
    formatValid := false
    for _, format := range validFormats {
        if config.Format == format {
            formatValid = true
            break
        }
    }
    
    if !formatValid {
        return errors.NewCLIError("E1001", 
            fmt.Sprintf("invalid output format: must be one of %v", validFormats), nil)
    }
    
    return nil
}