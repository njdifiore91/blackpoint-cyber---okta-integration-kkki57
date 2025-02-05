// Package config provides secure configuration writing functionality for the BlackPoint CLI
package config

import (
    "fmt"
    "os"
    "path/filepath"
    "time"
    "gopkg.in/yaml.v3" // v3.0.1
    "io/ioutil"

    "github.com/blackpoint/cli/pkg/config/types"
    "github.com/blackpoint/cli/pkg/common/errors"
)

const (
    // Maximum path length for configuration files
    maxPathLength = 4096
    // Secure file permissions for configuration files
    secureFilePerms = 0600
    // Secure directory permissions
    secureDirPerms = 0700
    // Temporary file suffix
    tempSuffix = ".tmp"
    // Backup file suffix format
    backupSuffixFmt = ".%s.bak"
)

// WriteConfig securely writes configuration to a YAML file with validation and atomic operations
func WriteConfig(config *types.Config, path string) error {
    // Validate configuration
    if err := config.Validate(); err != nil {
        return errors.NewCLIError("E1001", "configuration validation failed", err)
    }

    // Validate and normalize path
    if err := validatePath(path); err != nil {
        return err
    }

    // Ensure directory exists with secure permissions
    if err := ensureDirectory(path); err != nil {
        return err
    }

    // Create backup of existing config if present
    if err := backupConfig(path); err != nil {
        return err
    }

    // Create temporary file for atomic write
    tempPath := path + tempSuffix
    tempFile, err := os.OpenFile(tempPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, secureFilePerms)
    if err != nil {
        return errors.NewCLIError("E1003", "failed to create temporary file", err)
    }
    defer func() {
        tempFile.Close()
        os.Remove(tempPath) // Clean up temp file in case of failure
    }()

    // Marshal configuration to YAML
    yamlData, err := yaml.Marshal(config)
    if err != nil {
        return errors.NewCLIError("E1004", "failed to marshal configuration", err)
    }

    // Write YAML to temporary file
    if _, err := tempFile.Write(yamlData); err != nil {
        return errors.NewCLIError("E1005", "failed to write configuration", err)
    }

    // Ensure all data is written to disk
    if err := tempFile.Sync(); err != nil {
        return errors.NewCLIError("E1006", "failed to sync configuration to disk", err)
    }

    // Close temporary file before rename
    if err := tempFile.Close(); err != nil {
        return errors.NewCLIError("E1007", "failed to close temporary file", err)
    }

    // Atomically rename temporary file to target path
    if err := os.Rename(tempPath, path); err != nil {
        return errors.NewCLIError("E1008", "failed to save configuration", err)
    }

    return nil
}

// validatePath validates and secures the configuration file path
func validatePath(path string) error {
    if path == "" {
        return errors.NewCLIError("E1009", "configuration path cannot be empty", nil)
    }

    // Clean and normalize path
    cleanPath := filepath.Clean(path)

    // Verify absolute path
    if !filepath.IsAbs(cleanPath) {
        return errors.NewCLIError("E1010", "configuration path must be absolute", nil)
    }

    // Check path length
    if len(cleanPath) > maxPathLength {
        return errors.NewCLIError("E1011", fmt.Sprintf("path exceeds maximum length of %d", maxPathLength), nil)
    }

    // Verify parent directory exists and is writable
    dir := filepath.Dir(cleanPath)
    if err := verifyDirectoryAccess(dir); err != nil {
        return err
    }

    return nil
}

// ensureDirectory creates and secures the configuration directory
func ensureDirectory(path string) error {
    dir := filepath.Dir(path)

    // Create directory if it doesn't exist
    if err := os.MkdirAll(dir, secureDirPerms); err != nil {
        return errors.NewCLIError("E1012", "failed to create configuration directory", err)
    }

    // Verify directory permissions
    info, err := os.Stat(dir)
    if err != nil {
        return errors.NewCLIError("E1013", "failed to verify directory permissions", err)
    }

    // Ensure directory has secure permissions
    if info.Mode().Perm() != secureDirPerms {
        if err := os.Chmod(dir, secureDirPerms); err != nil {
            return errors.NewCLIError("E1014", "failed to set directory permissions", err)
        }
    }

    return nil
}

// backupConfig creates a backup of existing configuration
func backupConfig(path string) error {
    // Check if existing config exists
    if _, err := os.Stat(path); os.IsNotExist(err) {
        return nil
    }

    // Generate backup file name with timestamp
    timestamp := time.Now().UTC().Format("20060102150405")
    backupPath := path + fmt.Sprintf(backupSuffixFmt, timestamp)

    // Copy existing config to backup
    input, err := ioutil.ReadFile(path)
    if err != nil {
        return errors.NewCLIError("E1015", "failed to read existing configuration", err)
    }

    if err := ioutil.WriteFile(backupPath, input, secureFilePerms); err != nil {
        return errors.NewCLIError("E1016", "failed to create configuration backup", err)
    }

    return nil
}

// verifyDirectoryAccess checks if a directory exists and is writable
func verifyDirectoryAccess(dir string) error {
    // Check if directory exists
    info, err := os.Stat(dir)
    if err != nil {
        if os.IsNotExist(err) {
            return errors.NewCLIError("E1017", "directory does not exist", err)
        }
        return errors.NewCLIError("E1018", "failed to access directory", err)
    }

    // Verify it's a directory
    if !info.IsDir() {
        return errors.NewCLIError("E1019", "path is not a directory", nil)
    }

    // Check write permission by attempting to create a temporary file
    tmpFile := filepath.Join(dir, ".write_test")
    if err := ioutil.WriteFile(tmpFile, []byte{}, secureFilePerms); err != nil {
        return errors.NewCLIError("E1020", "directory is not writable", err)
    }
    os.Remove(tmpFile)

    return nil
}