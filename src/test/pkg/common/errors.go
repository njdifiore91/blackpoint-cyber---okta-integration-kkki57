// Package common provides shared utilities for the BlackPoint Security Integration Framework testing suite.
// Version: 1.0.0
package common

import (
	"fmt" // v1.21
	"strings"
	"testing" // v1.21
	"time"

	"github.com/stretchr/testify/assert" // v1.8.0
)

// TestErrorCodes defines standardized error codes for test scenarios
var TestErrorCodes = map[string]string{
	"TEST_TIMEOUT":       "E1001",
	"INVALID_EVENT":      "E1002",
	"PROCESSING_ERROR":   "E1003",
	"VALIDATION_ERROR":   "E1004",
	"CONFIG_ERROR":       "E1005",
	"INTEGRATION_ERROR":  "E1006",
	"DATA_ACCURACY_ERROR": "E1007",
	"ASSERTION_ERROR":    "E1008",
}

// TestErrorMessages provides detailed message templates for each error code
var TestErrorMessages = map[string]string{
	"E1001": "Test operation timed out after specified duration",
	"E1002": "Invalid event structure or data format",
	"E1003": "Event processing failed with details: %s",
	"E1004": "Validation check failed: %s",
	"E1005": "Configuration error: %s",
	"E1006": "Integration operation failed: %s",
	"E1007": "Data accuracy below threshold: %s",
	"E1008": "Assertion failed: %s",
}

// testError represents a structured test error with code and message
type testError struct {
	code    string
	message string
}

// Error implements the error interface for testError
func (e *testError) Error() string {
	return fmt.Sprintf("[%s] %s", e.code, e.message)
}

// NewTestError creates a new test error with standardized formatting
func NewTestError(code string, details string, args ...interface{}) error {
	// Validate error code exists
	errorCode, exists := TestErrorCodes[code]
	if !exists {
		return fmt.Errorf("invalid error code: %s", code)
	}

	// Get message template and format with details
	msgTemplate, exists := TestErrorMessages[errorCode]
	if !exists {
		return fmt.Errorf("missing message template for code: %s", errorCode)
	}

	// Format the message with provided details and args
	var message string
	if len(args) > 0 {
		message = fmt.Sprintf(msgTemplate, fmt.Sprintf(details, args...))
	} else {
		message = fmt.Sprintf(msgTemplate, details)
	}

	return &testError{
		code:    errorCode,
		message: message,
	}
}

// AssertErrorCode validates that an error matches the expected error code
func AssertErrorCode(t *testing.T, err error, expectedCode string) bool {
	t.Helper()

	if err == nil {
		t.Errorf("expected error with code %s, got nil", expectedCode)
		return false
	}

	// Handle wrapped errors
	var testErr *testError
	switch e := err.(type) {
	case *testError:
		testErr = e
	default:
		t.Errorf("error is not a testError: %v", err)
		return false
	}

	// Use testify/assert for comparison with detailed logging
	result := assert.Equal(t, expectedCode, testErr.code,
		"error code mismatch\nexpected: %s\nactual: %s\nmessage: %s",
		expectedCode, testErr.code, testErr.message)

	return result
}

// IsTestTimeout checks if an error is a test timeout error
func IsTestTimeout(err error) bool {
	if err == nil {
		return false
	}

	testErr, ok := err.(*testError)
	if !ok {
		return false
	}

	return testErr.code == TestErrorCodes["TEST_TIMEOUT"]
}

// WrapTestError wraps an existing error with additional test context
func WrapTestError(err error, context string, args ...interface{}) error {
	if err == nil {
		return nil
	}

	// Extract original error information
	var originalErr *testError
	var code string
	var originalMsg string

	switch e := err.(type) {
	case *testError:
		originalErr = e
		code = e.code
		originalMsg = e.message
	default:
		// For non-test errors, use PROCESSING_ERROR code
		code = TestErrorCodes["PROCESSING_ERROR"]
		originalMsg = err.Error()
	}

	// Format new context
	newContext := fmt.Sprintf(context, args...)
	
	// Combine original message with new context
	message := fmt.Sprintf("%s: %s", newContext, originalMsg)

	return &testError{
		code:    code,
		message: message,
	}
}

// ValidateTimeout checks if an operation completed within the specified timeout
func ValidateTimeout(start time.Time, timeout time.Duration) error {
	if time.Since(start) > timeout {
		return NewTestError("TEST_TIMEOUT",
			fmt.Sprintf("operation exceeded timeout of %v", timeout))
	}
	return nil
}

// ExtractErrorCode extracts the error code from a test error
func ExtractErrorCode(err error) string {
	if err == nil {
		return ""
	}

	testErr, ok := err.(*testError)
	if !ok {
		return ""
	}

	return testErr.code
}