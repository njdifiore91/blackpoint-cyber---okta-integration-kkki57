// Package api provides API client functionality for the BlackPoint CLI
package api

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/blackpoint/cli/pkg/common/errors"
)

// APIError represents a custom error type for API operations with HTTP status context
type APIError struct {
	Code       string // Error code for classification
	Message    string // User-facing error message
	StatusCode int    // HTTP status code
	Cause      error  // Underlying error cause
}

// Pre-defined API errors with standard codes and messages
var (
	ErrInvalidRequest = &APIError{
		Code:       "API1001",
		Message:    "Invalid API request",
		StatusCode: http.StatusBadRequest,
	}
	ErrUnauthorized = &APIError{
		Code:       "API1002",
		Message:    "Unauthorized access",
		StatusCode: http.StatusUnauthorized,
	}
	ErrForbidden = &APIError{
		Code:       "API1003",
		Message:    "Access forbidden",
		StatusCode: http.StatusForbidden,
	}
	ErrNotFound = &APIError{
		Code:       "API1004",
		Message:    "Resource not found",
		StatusCode: http.StatusNotFound,
	}
	ErrServerError = &APIError{
		Code:       "API1005",
		Message:    "Internal server error",
		StatusCode: http.StatusInternalServerError,
	}
)

// Error implements the error interface for APIError with secure message formatting
func (e *APIError) Error() string {
	msg := fmt.Sprintf("[%s] %s (Status: %d)", e.Code, e.Message, e.StatusCode)
	if e.Cause != nil {
		// Ensure sensitive information is not leaked in error messages
		causeMsg := e.Cause.Error()
		if !strings.Contains(causeMsg, "token") && !strings.Contains(causeMsg, "password") {
			msg = fmt.Sprintf("%s: %v", msg, causeMsg)
		}
	}
	return msg
}

// Unwrap implements error unwrapping for error cause chain access
func (e *APIError) Unwrap() error {
	return e.Cause
}

// NewAPIError creates a new API error with code, message, status code and optional cause
func NewAPIError(code string, message string, statusCode int, cause error) *APIError {
	// Validate error code format
	if !strings.HasPrefix(code, "API") {
		code = "API" + code
	}

	// Validate status code range
	if statusCode < 100 || statusCode > 599 {
		statusCode = http.StatusInternalServerError
	}

	// Create error instance with security-conscious message
	apiErr := &APIError{
		Code:       code,
		Message:    sanitizeErrorMessage(message),
		StatusCode: statusCode,
		Cause:      cause,
	}

	return apiErr
}

// FromHTTPResponse creates an APIError from an HTTP response
func FromHTTPResponse(resp *http.Response) *APIError {
	if resp == nil {
		return ErrServerError
	}

	// Read response body with size limit to prevent memory exhaustion
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
	if err != nil {
		return NewAPIError("API1006", "Failed to read error response", resp.StatusCode, err)
	}
	defer resp.Body.Close()

	// Map HTTP status code to appropriate error
	var baseErr *APIError
	switch {
	case resp.StatusCode == http.StatusBadRequest:
		baseErr = ErrInvalidRequest
	case resp.StatusCode == http.StatusUnauthorized:
		baseErr = ErrUnauthorized
	case resp.StatusCode == http.StatusForbidden:
		baseErr = ErrForbidden
	case resp.StatusCode == http.StatusNotFound:
		baseErr = ErrNotFound
	case resp.StatusCode >= 500:
		baseErr = ErrServerError
	default:
		baseErr = NewAPIError("API1007", "Unexpected API response", resp.StatusCode, nil)
	}

	// Create new error with response context
	return NewAPIError(
		baseErr.Code,
		fmt.Sprintf("%s: %s", baseErr.Message, sanitizeErrorMessage(string(body))),
		resp.StatusCode,
		errors.WrapError(baseErr, "API request failed"),
	)
}

// IsClientError checks if the error represents a client-side error (4xx range)
func IsClientError(err error) bool {
	var apiErr *APIError
	if err == nil {
		return false
	}
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 400 && apiErr.StatusCode < 500
	}
	return false
}

// IsServerError checks if the error represents a server-side error (5xx range)
func IsServerError(err error) bool {
	var apiErr *APIError
	if err == nil {
		return false
	}
	if errors.As(err, &apiErr) {
		return apiErr.StatusCode >= 500 && apiErr.StatusCode < 600
	}
	return false
}

// sanitizeErrorMessage removes potentially sensitive information from error messages
func sanitizeErrorMessage(message string) string {
	// List of patterns to sanitize
	sensitivePatterns := []string{
		"token=",
		"password=",
		"secret=",
		"key=",
		"authorization:",
		"auth:",
	}

	// Convert to lowercase for case-insensitive matching
	messageLower := strings.ToLower(message)
	
	// Check for sensitive information
	for _, pattern := range sensitivePatterns {
		if strings.Contains(messageLower, pattern) {
			return "Error details redacted for security"
		}
	}

	return message
}