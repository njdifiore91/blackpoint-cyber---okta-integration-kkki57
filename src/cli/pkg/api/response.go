// Package api provides API client functionality for the BlackPoint CLI
package api

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "sync"

    "github.com/blackpoint/cli/pkg/common/errors"
)

// Response represents a thread-safe generic response structure for API operations
type Response struct {
    Success   bool        `json:"success"`
    Data      interface{} `json:"data,omitempty"`
    Message   string      `json:"message,omitempty"`
    ErrorCode string      `json:"error_code,omitempty"`
    mutex     sync.RWMutex
}

// NewResponse creates a new thread-safe Response instance
func NewResponse() *Response {
    return &Response{
        Success: false,
        mutex:   sync.RWMutex{},
    }
}

// IsSuccess performs a thread-safe check if response indicates success
func (r *Response) IsSuccess() bool {
    r.mutex.RLock()
    defer r.mutex.RUnlock()
    return r.Success && r.ErrorCode == ""
}

// GetData performs thread-safe data extraction with type validation
func (r *Response) GetData(target interface{}) error {
    r.mutex.Lock()
    defer r.mutex.Unlock()

    if r.Data == nil {
        return errors.NewCLIError("E1004", "No data available in response", nil)
    }

    // Convert data to JSON then unmarshal to target type
    jsonData, err := json.Marshal(r.Data)
    if err != nil {
        return errors.WrapError(err, "Failed to marshal response data")
    }

    if err := json.Unmarshal(jsonData, target); err != nil {
        return errors.WrapError(err, "Failed to unmarshal response data to target type")
    }

    return nil
}

// ParseResponse parses an HTTP response into the provided result type with comprehensive error handling
func ParseResponse(resp *http.Response, result interface{}) error {
    if resp == nil {
        return errors.NewCLIError("E1004", "Nil response received", nil)
    }
    defer resp.Body.Close()

    // Check for HTTP error status codes
    if resp.StatusCode >= 400 {
        return HandleError(resp)
    }

    // Initialize response body reader with buffering
    bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
    if err != nil {
        return errors.WrapError(err, "Failed to read response body")
    }

    // Validate response structure and parse JSON
    if err := json.Unmarshal(bodyBytes, result); err != nil {
        return errors.WrapError(err, "Failed to parse response JSON")
    }

    return nil
}

// ExtractData extracts data from a successful response into a structured format with validation
func ExtractData(resp *http.Response) (map[string]interface{}, error) {
    if resp == nil {
        return nil, errors.NewCLIError("E1004", "Nil response received", nil)
    }
    defer resp.Body.Close()

    // Read response body with memory limits
    bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024)) // 1MB limit
    if err != nil {
        return nil, errors.WrapError(err, "Failed to read response body")
    }

    // Parse JSON response
    var result map[string]interface{}
    decoder := json.NewDecoder(bytes.NewReader(bodyBytes))
    decoder.UseNumber() // Preserve number formats

    if err := decoder.Decode(&result); err != nil {
        return nil, errors.WrapError(err, "Failed to parse response JSON")
    }

    // Validate response structure
    if result == nil {
        return nil, errors.NewCLIError("E1004", "Empty response data", nil)
    }

    return result, nil
}

// HandleError processes error responses with secure messaging and proper context
func HandleError(resp *http.Response) error {
    // Create API error from response
    apiErr := FromHTTPResponse(resp)

    // Map API error to CLI error
    var code string
    switch {
    case resp.StatusCode == http.StatusUnauthorized:
        code = "E1002" // Authentication error
    case resp.StatusCode == http.StatusBadRequest:
        code = "E1004" // Validation error
    case resp.StatusCode >= 500:
        code = "E1003" // Connection/server error
    default:
        code = "E1000" // Generic error
    }

    return errors.NewCLIError(code, apiErr.Message, apiErr)
}