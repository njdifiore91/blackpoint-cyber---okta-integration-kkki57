// Package common provides shared utilities for the BlackPoint CLI application
package common

import (
    "fmt"
    "errors"
    "runtime"
    "strings"
)

// CLIError represents a custom error type for CLI operations with enhanced context
type CLIError struct {
    Code       string
    Message    string
    Cause      error
    StackTrace []uintptr
    retryable  bool
}

// Pre-defined CLI errors with standard codes and messages
var (
    ErrInvalidConfig = &CLIError{
        Code:      "E1001",
        Message:   "Invalid configuration provided",
        retryable: false,
    }
    ErrAuthenticationFailed = &CLIError{
        Code:      "E1002",
        Message:   "Authentication failed - please check credentials",
        retryable: true,
    }
    ErrConnectionFailed = &CLIError{
        Code:      "E1003",
        Message:   "Connection failed - check network connectivity",
        retryable: true,
    }
    ErrValidationFailed = &CLIError{
        Code:      "E1004",
        Message:   "Validation failed - check input parameters",
        retryable: false,
    }
    ErrOperationTimeout = &CLIError{
        Code:      "E1005",
        Message:   "Operation timed out - try again later",
        retryable: true,
    }
)

// retryableCodes defines which error codes support retry operations
var retryableCodes = map[string]bool{
    "E1002": true, // Authentication failures
    "E1003": true, // Connection issues
    "E1005": true, // Timeouts
}

// Error implements the error interface for CLIError
func (e *CLIError) Error() string {
    msg := fmt.Sprintf("[%s] %s", e.Code, e.Message)
    if e.Cause != nil {
        msg = fmt.Sprintf("%s: %v", msg, e.Cause)
    }
    return msg
}

// Unwrap implements error unwrapping for error chains
func (e *CLIError) Unwrap() error {
    return e.Cause
}

// StackTraceString returns a formatted stack trace for debugging
func (e *CLIError) StackTraceString() string {
    if len(e.StackTrace) == 0 {
        return ""
    }

    frames := runtime.CallersFrames(e.StackTrace)
    var trace strings.Builder
    trace.WriteString("\nStack Trace:\n")

    for {
        frame, more := frames.Next()
        // Skip runtime and standard library frames
        if !strings.Contains(frame.File, "runtime/") {
            trace.WriteString(fmt.Sprintf("\t%s:%d - %s\n", frame.File, frame.Line, frame.Function))
        }
        if !more {
            break
        }
    }
    return trace.String()
}

// NewCLIError creates a new CLI error with code, message, stack trace and optional cause
func NewCLIError(code string, message string, cause error) *CLIError {
    // Validate error code format
    if !strings.HasPrefix(code, "E") {
        code = "E" + code
    }

    // Create error instance
    cliErr := &CLIError{
        Code:      code,
        Message:   message,
        Cause:     cause,
        retryable: retryableCodes[code],
    }

    // Capture stack trace
    const depth = 32
    var pcs [depth]uintptr
    n := runtime.Callers(2, pcs[:])
    cliErr.StackTrace = pcs[0:n]

    return cliErr
}

// WrapError wraps an existing error with additional context while preserving the error chain
func WrapError(err error, message string) error {
    if err == nil {
        return nil
    }

    // Check if original error is a CLIError
    var cliErr *CLIError
    if errors.As(err, &cliErr) {
        // Preserve the original error code and retryable status
        return NewCLIError(cliErr.Code, fmt.Sprintf("%s: %s", message, cliErr.Message), err)
    }

    // Create new CLIError for non-CLI errors
    return NewCLIError("E1000", fmt.Sprintf("%s: %v", message, err), err)
}

// IsRetryable determines if an error can be retried based on error type and code
func IsRetryable(err error) bool {
    if err == nil {
        return false
    }

    // Unwrap error chain to find CLIError
    var cliErr *CLIError
    if errors.As(err, &cliErr) {
        return cliErr.retryable
    }

    // Non-CLI errors are not retryable by default
    return false
}