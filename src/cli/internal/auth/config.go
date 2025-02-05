// Package auth provides secure authentication configuration management for the BlackPoint CLI
package auth

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/json"
    "fmt"
    "io"
    "os"
    "path/filepath"
    "time"

    "github.com/blackpoint/cli/pkg/common/constants"
    "github.com/blackpoint/cli/pkg/common/errors"
    "github.com/blackpoint/cli/pkg/config/types"
)

const (
    defaultAuthConfigFile       = "auth.json"
    defaultAuthConfigPermissions = 0600
    defaultConfigVersion        = "1.0"
    defaultTokenExpiryDuration  = time.Hour
)

// encryptedData represents sensitive data with encryption metadata
type encryptedData struct {
    Data      []byte `json:"data"`
    Nonce     []byte `json:"nonce"`
    Version   string `json:"version"`
    Timestamp int64  `json:"timestamp"`
}

// LoadAuthConfig securely loads and validates authentication configuration
func LoadAuthConfig(configPath string) (*types.AuthConfig, error) {
    if configPath == "" {
        configPath = GetDefaultAuthConfigPath()
    }

    // Check file permissions
    info, err := os.Stat(configPath)
    if err != nil {
        if os.IsNotExist(err) {
            return nil, errors.NewCLIError("E1001", "Auth config file does not exist", err)
        }
        return nil, errors.NewCLIError("E1001", "Failed to access auth config file", err)
    }

    // Verify file permissions are secure
    if info.Mode().Perm() != defaultAuthConfigPermissions {
        return nil, errors.NewCLIError("E1001", fmt.Sprintf(
            "Insecure auth config file permissions: %v", info.Mode().Perm()), nil)
    }

    // Read config file
    data, err := os.ReadFile(configPath)
    if err != nil {
        return nil, errors.NewCLIError("E1001", "Failed to read auth config file", err)
    }

    var config types.AuthConfig
    if err := json.Unmarshal(data, &config); err != nil {
        return nil, errors.NewCLIError("E1001", "Failed to parse auth config", err)
    }

    // Validate loaded configuration
    if err := ValidateAuthConfig(&config); err != nil {
        return nil, err
    }

    return &config, nil
}

// SaveAuthConfig securely saves authentication configuration
func SaveAuthConfig(config *types.AuthConfig, configPath string) error {
    if err := ValidateAuthConfig(config); err != nil {
        return err
    }

    if configPath == "" {
        configPath = GetDefaultAuthConfigPath()
    }

    // Ensure config directory exists with secure permissions
    configDir := filepath.Dir(configPath)
    if err := os.MkdirAll(configDir, 0700); err != nil {
        return errors.NewCLIError("E1001", "Failed to create config directory", err)
    }

    // Marshal config with proper formatting
    data, err := json.MarshalIndent(config, "", "  ")
    if err != nil {
        return errors.NewCLIError("E1001", "Failed to marshal auth config", err)
    }

    // Write file with secure permissions
    if err := os.WriteFile(configPath, data, defaultAuthConfigPermissions); err != nil {
        return errors.NewCLIError("E1001", "Failed to write auth config file", err)
    }

    // Verify file contents and permissions
    if err := verifyConfigFile(configPath, data); err != nil {
        return errors.NewCLIError("E1001", "Config file verification failed", err)
    }

    return nil
}

// ValidateAuthConfig performs comprehensive validation of authentication configuration
func ValidateAuthConfig(config *types.AuthConfig) error {
    if config == nil {
        return errors.NewCLIError("E1001", "Auth config cannot be nil", nil)
    }

    // Validate API key if present
    if config.APIKey != "" {
        if len(config.APIKey) < constants.APIKeyMinLength {
            return errors.NewCLIError("E1001", fmt.Sprintf(
                "API key must be at least %d characters", constants.APIKeyMinLength), nil)
        }
    }

    // Validate token path if present
    if config.TokenPath != "" {
        if !filepath.IsAbs(config.TokenPath) {
            return errors.NewCLIError("E1001", "Token path must be absolute", nil)
        }

        // Check directory permissions
        dir := filepath.Dir(config.TokenPath)
        info, err := os.Stat(dir)
        if err != nil {
            return errors.NewCLIError("E1001", "Token directory does not exist", err)
        }

        if info.Mode().Perm() > 0700 {
            return errors.NewCLIError("E1001", "Insecure token directory permissions", nil)
        }
    }

    // Validate token lifetime
    if config.MaxLifetime <= 0 || config.MaxLifetime > constants.MaxTokenLifetime {
        return errors.NewCLIError("E1001", fmt.Sprintf(
            "Invalid token lifetime: must be between 0 and %v", constants.MaxTokenLifetime), nil)
    }

    return nil
}

// GetDefaultAuthConfigPath returns the secure default path for authentication configuration
func GetDefaultAuthConfigPath() string {
    homeDir, err := os.UserHomeDir()
    if err != nil {
        // Fallback to current directory if home directory cannot be determined
        homeDir = "."
    }

    return filepath.Join(homeDir, ".blackpoint", "cli", defaultAuthConfigFile)
}

// verifyConfigFile verifies the integrity of the written config file
func verifyConfigFile(path string, expectedData []byte) error {
    // Read back the file
    data, err := os.ReadFile(path)
    if err != nil {
        return err
    }

    // Verify content matches
    if string(data) != string(expectedData) {
        return fmt.Errorf("config file content verification failed")
    }

    // Verify permissions
    info, err := os.Stat(path)
    if err != nil {
        return err
    }

    if info.Mode().Perm() != defaultAuthConfigPermissions {
        return fmt.Errorf("config file has incorrect permissions")
    }

    return nil
}

// encryptSensitiveData encrypts sensitive configuration data
func encryptSensitiveData(data []byte, key []byte) (*encryptedData, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, err
    }

    encrypted := gcm.Seal(nil, nonce, data, nil)
    return &encryptedData{
        Data:      encrypted,
        Nonce:     nonce,
        Version:   defaultConfigVersion,
        Timestamp: time.Now().Unix(),
    }, nil
}

// decryptSensitiveData decrypts sensitive configuration data
func decryptSensitiveData(encData *encryptedData, key []byte) ([]byte, error) {
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, err
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, err
    }

    return gcm.Open(nil, encData.Nonce, encData.Data, nil)
}