// Package auth provides secure credential management for the BlackPoint CLI
package auth

import (
    "crypto/aes"
    "crypto/rand"
    "encoding/json"
    "errors"
    "log"
    "os"
    "path/filepath"

    "github.com/blackpoint/cli/pkg/common/constants"
    "github.com/blackpoint/cli/pkg/config/types"
    "github.com/blackpoint/cli/internal/auth/token"
)

// Error definitions for credential management
var (
    ErrInvalidAPIKey        = errors.New("invalid API key format or length")
    ErrCredentialsNotFound  = errors.New("credentials file not found")
    ErrInvalidCredentials   = errors.New("invalid credentials format")
    ErrEncryptionFailed    = errors.New("failed to encrypt credentials")
    ErrDecryptionFailed    = errors.New("failed to decrypt credentials")
)

// credentialsFile represents the structure of stored credentials
type credentialsFile struct {
    APIKey      string `json:"apiKey"`
    AccessToken string `json:"accessToken"`
    RefreshToken string `json:"refreshToken"`
    Encrypted   bool   `json:"encrypted"`
}

// LoadCredentials loads and decrypts credentials from the configured credentials file
func LoadCredentials(config *types.AuthConfig) error {
    if config == nil {
        return ErrInvalidCredentials
    }

    // Check if credentials file exists
    if _, err := os.Stat(config.TokenPath); err != nil {
        return ErrCredentialsNotFound
    }

    // Verify file permissions
    info, err := os.Stat(config.TokenPath)
    if err != nil {
        return err
    }
    if info.Mode().Perm() != constants.ConfigFilePermissions {
        return errors.New("invalid credentials file permissions")
    }

    // Read credentials file
    data, err := os.ReadFile(config.TokenPath)
    if err != nil {
        return err
    }

    var creds credentialsFile
    if err := json.Unmarshal(data, &creds); err != nil {
        return ErrInvalidCredentials
    }

    // Decrypt credentials if encrypted
    if creds.Encrypted {
        decryptedKey, err := decryptCredentials(creds.APIKey, config)
        if err != nil {
            return ErrDecryptionFailed
        }
        creds.APIKey = decryptedKey
    }

    // Validate API key
    if err := ValidateAPIKey(creds.APIKey); err != nil {
        return err
    }

    // Update config with loaded credentials
    config.APIKey = creds.APIKey

    // Log credential access (excluding sensitive data)
    log.Printf("Credentials loaded successfully from: %s", config.TokenPath)

    return nil
}

// SaveCredentials encrypts and saves credentials to the configured credentials file
func SaveCredentials(config *types.AuthConfig) error {
    if config == nil || config.APIKey == "" {
        return ErrInvalidCredentials
    }

    // Validate API key before saving
    if err := ValidateAPIKey(config.APIKey); err != nil {
        return err
    }

    // Create credentials directory if it doesn't exist
    dir := filepath.Dir(config.TokenPath)
    if err := os.MkdirAll(dir, constants.ConfigFilePermissions); err != nil {
        return err
    }

    // Generate new tokens
    accessToken, refreshToken, err := token.GenerateToken(config)
    if err != nil {
        return err
    }

    // Encrypt credentials
    encryptedKey, err := encryptCredentials(config.APIKey, config)
    if err != nil {
        return ErrEncryptionFailed
    }

    creds := credentialsFile{
        APIKey:      encryptedKey,
        AccessToken: accessToken,
        RefreshToken: refreshToken,
        Encrypted:   true,
    }

    // Marshal credentials to JSON
    data, err := json.MarshalIndent(creds, "", "  ")
    if err != nil {
        return err
    }

    // Write to temporary file first
    tempFile := config.TokenPath + ".tmp"
    if err := os.WriteFile(tempFile, data, constants.ConfigFilePermissions); err != nil {
        return err
    }

    // Atomically rename to final location
    if err := os.Rename(tempFile, config.TokenPath); err != nil {
        os.Remove(tempFile) // Clean up on error
        return err
    }

    // Log credential update (excluding sensitive data)
    log.Printf("Credentials saved successfully to: %s", config.TokenPath)

    return nil
}

// ValidateAPIKey validates the format and security requirements of an API key
func ValidateAPIKey(apiKey string) error {
    if apiKey == "" {
        return ErrInvalidAPIKey
    }

    if len(apiKey) < constants.APIKeyMinLength {
        return ErrInvalidAPIKey
    }

    // Check API key format (alphanumeric + special chars)
    for _, char := range apiKey {
        if !isValidAPIKeyChar(char) {
            return ErrInvalidAPIKey
        }
    }

    return nil
}

// ClearCredentials securely removes stored credentials
func ClearCredentials(config *types.AuthConfig) error {
    if config == nil || config.TokenPath == "" {
        return ErrInvalidCredentials
    }

    // Check if file exists
    if _, err := os.Stat(config.TokenPath); err != nil {
        return nil // Already cleared
    }

    // Securely overwrite file contents before deletion
    zeros := make([]byte, 1024)
    if err := os.WriteFile(config.TokenPath, zeros, constants.ConfigFilePermissions); err != nil {
        return err
    }

    // Remove the file
    if err := os.Remove(config.TokenPath); err != nil {
        return err
    }

    // Log credential removal
    log.Printf("Credentials cleared successfully from: %s", config.TokenPath)

    return nil
}

// Helper functions

func encryptCredentials(data string, config *types.AuthConfig) (string, error) {
    key := make([]byte, 32)
    if _, err := rand.Read(key); err != nil {
        return "", err
    }

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    ciphertext := make([]byte, len(data))
    block.Encrypt(ciphertext, []byte(data))

    return string(ciphertext), nil
}

func decryptCredentials(data string, config *types.AuthConfig) (string, error) {
    key := make([]byte, 32)
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    plaintext := make([]byte, len(data))
    block.Decrypt(plaintext, []byte(data))

    return string(plaintext), nil
}

func isValidAPIKeyChar(c rune) bool {
    return (c >= 'a' && c <= 'z') ||
           (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') ||
           c == '-' || c == '_' || c == '.'
}