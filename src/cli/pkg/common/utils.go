// Package common provides shared utilities for the BlackPoint CLI application
package common

import (
    "context"
    "math/rand"
    "os"
    "path/filepath"
    "time"
)

// RetryWithBackoff executes an operation with exponential backoff and jitter
func RetryWithBackoff(ctx context.Context, operation func() error, maxAttempts int, initialDelay time.Duration) error {
    if maxAttempts <= 0 {
        maxAttempts = DefaultRetryAttempts
    }
    if initialDelay <= 0 {
        initialDelay = DefaultRetryDelay
    }

    var lastErr error
    for attempt := 1; attempt <= maxAttempts; attempt++ {
        select {
        case <-ctx.Done():
            return WrapError(ctx.Err(), "operation cancelled")
        default:
            logging.Debug("Executing retry attempt", map[string]interface{}{
                "attempt": attempt,
                "max_attempts": maxAttempts,
            })

            if err := operation(); err != nil {
                lastErr = err
                if !IsRetryable(err) {
                    logging.Error("Non-retryable error encountered", err, map[string]interface{}{
                        "attempt": attempt,
                    })
                    return err
                }

                if attempt == maxAttempts {
                    logging.Error("Max retry attempts reached", err, map[string]interface{}{
                        "max_attempts": maxAttempts,
                    })
                    return WrapError(err, "max retry attempts reached")
                }

                // Calculate exponential backoff with jitter
                backoff := initialDelay * time.Duration(1<<uint(attempt-1))
                jitter := time.Duration(rand.Float64() * float64(backoff) * 0.2) // 20% jitter
                sleepDuration := backoff + jitter

                logging.Debug("Retrying operation", map[string]interface{}{
                    "attempt": attempt,
                    "backoff": sleepDuration.String(),
                })

                select {
                case <-ctx.Done():
                    return WrapError(ctx.Err(), "operation cancelled during backoff")
                case <-time.After(sleepDuration):
                    continue
                }
            }

            logging.Debug("Operation completed successfully", map[string]interface{}{
                "attempts_used": attempt,
            })
            return nil
        }
    }

    return lastErr
}

// ExpandPath expands a file path with security validation
func ExpandPath(path string) (string, error) {
    if path == "" {
        return "", NewCLIError("E1004", "empty path provided", nil)
    }

    // Handle home directory expansion
    if len(path) >= 2 && path[:2] == "~/" {
        home, err := os.UserHomeDir()
        if err != nil {
            return "", WrapError(err, "failed to get user home directory")
        }
        path = filepath.Join(home, path[2:])
    }

    // Convert to absolute path
    absPath, err := filepath.Abs(path)
    if err != nil {
        return "", WrapError(err, "failed to get absolute path")
    }

    // Clean and normalize path
    cleanPath := filepath.Clean(absPath)

    // Validate no path traversal
    if !filepath.IsAbs(cleanPath) {
        return "", NewCLIError("E1004", "path traversal detected", nil)
    }

    return cleanPath, nil
}

// EnsureDirectory ensures a directory exists with proper permissions
func EnsureDirectory(path string, perm os.FileMode, recursive bool) error {
    expandedPath, err := ExpandPath(path)
    if err != nil {
        return err
    }

    logging.Debug("Ensuring directory exists", map[string]interface{}{
        "path": expandedPath,
        "permissions": perm,
        "recursive": recursive,
    })

    // Check if directory already exists
    info, err := os.Stat(expandedPath)
    if err == nil {
        if !info.IsDir() {
            return NewCLIError("E1004", "path exists but is not a directory", nil)
        }
        // Validate permissions
        if info.Mode().Perm() != perm {
            if err := os.Chmod(expandedPath, perm); err != nil {
                return WrapError(err, "failed to set directory permissions")
            }
        }
        return nil
    }

    if !os.IsNotExist(err) {
        return WrapError(err, "failed to check directory")
    }

    // Create directory
    if recursive {
        err = os.MkdirAll(expandedPath, perm)
    } else {
        err = os.Mkdir(expandedPath, perm)
    }

    if err != nil {
        return WrapError(err, "failed to create directory")
    }

    logging.Debug("Directory created successfully", map[string]interface{}{
        "path": expandedPath,
        "permissions": perm,
    })

    return nil
}

// ValidateFilePath validates if a file path is accessible and secure
func ValidateFilePath(path string, requiredPerm os.FileMode, allowSymlinks bool) error {
    expandedPath, err := ExpandPath(path)
    if err != nil {
        return err
    }

    logging.Debug("Validating file path", map[string]interface{}{
        "path": expandedPath,
        "required_permissions": requiredPerm,
        "allow_symlinks": allowSymlinks,
    })

    // Get file info, following symlinks if allowed
    var info os.FileInfo
    if allowSymlinks {
        info, err = os.Stat(expandedPath)
    } else {
        info, err = os.Lstat(expandedPath)
    }

    if err != nil {
        if os.IsNotExist(err) {
            return NewCLIError("E1004", "file does not exist", err)
        }
        return WrapError(err, "failed to get file info")
    }

    // Check file type
    if !allowSymlinks && info.Mode()&os.ModeSymlink != 0 {
        return NewCLIError("E1004", "symlinks not allowed", nil)
    }

    // Validate permissions
    if info.Mode().Perm()&requiredPerm != requiredPerm {
        return NewCLIError("E1004", "insufficient file permissions", nil)
    }

    // Validate parent directory permissions
    parentDir := filepath.Dir(expandedPath)
    parentInfo, err := os.Stat(parentDir)
    if err != nil {
        return WrapError(err, "failed to check parent directory")
    }

    if !parentInfo.IsDir() {
        return NewCLIError("E1004", "parent path is not a directory", nil)
    }

    logging.Debug("File path validation successful", map[string]interface{}{
        "path": expandedPath,
        "file_mode": info.Mode().String(),
    })

    return nil
}