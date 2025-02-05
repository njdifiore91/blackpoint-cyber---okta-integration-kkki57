// Package config provides configuration types and validation for the BlackPoint CLI
package config

import (
    "fmt"
    "os"
    "time"
    "net/url"
    "path/filepath"
    "strings"
    
    "github.com/blackpoint/cli/pkg/common/constants"
)

// Config represents the main CLI configuration structure
type Config struct {
    API     *APIConfig     `json:"api" yaml:"api"`
    Auth    *AuthConfig    `json:"auth" yaml:"auth"`
    Logging *LoggingConfig `json:"logging" yaml:"logging"`
    Output  *OutputConfig  `json:"output" yaml:"output"`
}

// APIConfig contains settings for API communication
type APIConfig struct {
    Endpoint      string        `json:"endpoint" yaml:"endpoint"`
    Timeout       time.Duration `json:"timeout" yaml:"timeout"`
    RetryAttempts int          `json:"retryAttempts" yaml:"retryAttempts"`
    RetryDelay    time.Duration `json:"retryDelay" yaml:"retryDelay"`
    Version       string        `json:"version" yaml:"version"`
}

// AuthConfig contains authentication settings
type AuthConfig struct {
    APIKey      string        `json:"apiKey" yaml:"apiKey"`
    TokenPath   string        `json:"tokenPath" yaml:"tokenPath"`
    MaxLifetime time.Duration `json:"maxLifetime" yaml:"maxLifetime"`
}

// LoggingConfig contains logging settings
type LoggingConfig struct {
    Level      string `json:"level" yaml:"level"`
    Format     string `json:"format" yaml:"format"`
    OutputPath string `json:"outputPath" yaml:"outputPath"`
}

// OutputConfig contains CLI output formatting settings
type OutputConfig struct {
    Format       string `json:"format" yaml:"format"`
    ColorEnabled bool   `json:"colorEnabled" yaml:"colorEnabled"`
    Quiet        bool   `json:"quiet" yaml:"quiet"`
}

// Validate performs comprehensive validation of the Config structure
func (c *Config) Validate() error {
    if c == nil {
        return fmt.Errorf("configuration cannot be nil")
    }

    if err := c.API.Validate(); err != nil {
        return fmt.Errorf("api config validation failed: %w", err)
    }

    if err := c.Auth.Validate(); err != nil {
        return fmt.Errorf("auth config validation failed: %w", err)
    }

    if err := c.Logging.Validate(); err != nil {
        return fmt.Errorf("logging config validation failed: %w", err)
    }

    if err := c.Output.Validate(); err != nil {
        return fmt.Errorf("output config validation failed: %w", err)
    }

    return nil
}

// Validate performs validation of APIConfig settings
func (c *APIConfig) Validate() error {
    if c == nil {
        return fmt.Errorf("api configuration cannot be nil")
    }

    // Validate endpoint
    if c.Endpoint == "" {
        return fmt.Errorf("api endpoint cannot be empty")
    }

    u, err := url.Parse(c.Endpoint)
    if err != nil {
        return fmt.Errorf("invalid api endpoint URL: %w", err)
    }

    if u.Scheme != "https" {
        return fmt.Errorf("api endpoint must use HTTPS")
    }

    // Validate timeout
    if c.Timeout < constants.DefaultConnectionTimeout || c.Timeout > constants.DefaultIntegrationTimeout {
        return fmt.Errorf("invalid timeout value: must be between %v and %v", 
            constants.DefaultConnectionTimeout, constants.DefaultIntegrationTimeout)
    }

    // Validate retry settings
    if c.RetryAttempts < 0 || c.RetryAttempts > constants.MaxIntegrationRetries {
        return fmt.Errorf("invalid retry attempts: must be between 0 and %d", 
            constants.MaxIntegrationRetries)
    }

    if c.RetryDelay < 0 || c.RetryDelay > constants.DefaultIntegrationTimeout {
        return fmt.Errorf("invalid retry delay: must be between 0 and %v", 
            constants.DefaultIntegrationTimeout)
    }

    return nil
}

// Validate performs validation of AuthConfig settings
func (c *AuthConfig) Validate() error {
    if c == nil {
        return fmt.Errorf("auth configuration cannot be nil")
    }

    // Validate API key
    if len(c.APIKey) < constants.APIKeyMinLength {
        return fmt.Errorf("api key must be at least %d characters", constants.APIKeyMinLength)
    }

    // Validate token path
    if c.TokenPath != "" {
        if !filepath.IsAbs(c.TokenPath) {
            return fmt.Errorf("token path must be absolute")
        }
        
        dir := filepath.Dir(c.TokenPath)
        if _, err := os.Stat(dir); err != nil {
            return fmt.Errorf("token directory does not exist: %w", err)
        }
    }

    // Validate token lifetime
    if c.MaxLifetime <= 0 || c.MaxLifetime > constants.MaxTokenLifetime {
        return fmt.Errorf("invalid token lifetime: must be between 0 and %v", 
            constants.MaxTokenLifetime)
    }

    return nil
}

// Validate performs validation of LoggingConfig settings
func (c *LoggingConfig) Validate() error {
    if c == nil {
        return fmt.Errorf("logging configuration cannot be nil")
    }

    // Validate log level
    validLevels := []string{"debug", "info", "warn", "error"}
    levelValid := false
    for _, level := range validLevels {
        if strings.ToLower(c.Level) == level {
            levelValid = true
            break
        }
    }
    if !levelValid {
        return fmt.Errorf("invalid log level: must be one of %v", validLevels)
    }

    // Validate log format
    validFormats := []string{"json", "text"}
    formatValid := false
    for _, format := range validFormats {
        if strings.ToLower(c.Format) == format {
            formatValid = true
            break
        }
    }
    if !formatValid {
        return fmt.Errorf("invalid log format: must be one of %v", validFormats)
    }

    // Validate output path
    if c.OutputPath != "" {
        dir := filepath.Dir(c.OutputPath)
        if _, err := os.Stat(dir); err != nil {
            return fmt.Errorf("log output directory does not exist: %w", err)
        }
    }

    return nil
}

// Validate performs validation of OutputConfig settings
func (c *OutputConfig) Validate() error {
    if c == nil {
        return fmt.Errorf("output configuration cannot be nil")
    }

    // Validate output format
    validFormats := []string{"json", "yaml", "table", "text"}
    formatValid := false
    for _, format := range validFormats {
        if strings.ToLower(c.Format) == format {
            formatValid = true
            break
        }
    }
    if !formatValid {
        return fmt.Errorf("invalid output format: must be one of %v", validFormats)
    }

    return nil
}