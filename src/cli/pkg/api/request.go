// Package api provides HTTP request handling and construction for the BlackPoint CLI API client
package api

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/sync/semaphore"

	"github.com/blackpoint/cli/pkg/common/constants"
	"github.com/blackpoint/cli/pkg/common/errors"
)

// AuthType represents the authentication method to be used
type AuthType int

const (
	// AuthNone represents no authentication
	AuthNone AuthType = iota
	// AuthOAuth represents OAuth2.0 authentication
	AuthOAuth
	// AuthAPIKey represents API key authentication
	AuthAPIKey
)

// RequestConfig holds configuration for HTTP requests
type RequestConfig struct {
	RetryAttempts     int
	RetryDelay        time.Duration
	Timeout           time.Duration
	Headers           map[string]string
	AuthMethod        AuthType
	TLSConfig         *tls.Config
	EnableCompression bool
	OAuth2Config      *oauth2.Config
	APIKey           string
}

// defaultHeaders contains standard headers added to all requests
var defaultHeaders = map[string]string{
	"Accept":           "application/json",
	"Content-Type":     "application/json",
	"User-Agent":       "blackpoint-cli/1.0",
	"X-Client-Version": "1.0.0",
}

// requestSemaphore limits concurrent requests
var requestSemaphore = semaphore.NewWeighted(int64(constants.MaxConcurrentRequests))

// NewRequestConfig creates a new request configuration with secure defaults
func NewRequestConfig() *RequestConfig {
	return &RequestConfig{
		RetryAttempts:     constants.DefaultRetryAttempts,
		RetryDelay:        constants.DefaultRetryDelay,
		Timeout:           constants.DefaultTimeout,
		Headers:           make(map[string]string),
		AuthMethod:        AuthNone,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
		EnableCompression: true,
	}
}

// validate checks the request configuration for security and performance
func (c *RequestConfig) validate() error {
	if c.RetryAttempts < 0 {
		return errors.NewCLIError("1004", "retry attempts must be non-negative", nil)
	}
	if c.Timeout < 0 {
		return errors.NewCLIError("1004", "timeout must be non-negative", nil)
	}
	if c.AuthMethod == AuthOAuth && c.OAuth2Config == nil {
		return errors.NewCLIError("1004", "OAuth2 config required for OAuth authentication", nil)
	}
	if c.AuthMethod == AuthAPIKey && len(c.APIKey) < constants.APIKeyMinLength {
		return errors.NewCLIError("1004", "invalid API key length", nil)
	}
	return nil
}

// RequestOption represents a function that modifies a RequestConfig
type RequestOption func(*RequestConfig)

// WithTimeout sets the request timeout
func WithTimeout(timeout time.Duration) RequestOption {
	return func(c *RequestConfig) {
		c.Timeout = timeout
	}
}

// WithRetry sets retry parameters
func WithRetry(attempts int, delay time.Duration) RequestOption {
	return func(c *RequestConfig) {
		c.RetryAttempts = attempts
		c.RetryDelay = delay
	}
}

// WithOAuth2 sets OAuth2.0 authentication
func WithOAuth2(config *oauth2.Config) RequestOption {
	return func(c *RequestConfig) {
		c.AuthMethod = AuthOAuth
		c.OAuth2Config = config
	}
}

// WithAPIKey sets API key authentication
func WithAPIKey(apiKey string) RequestOption {
	return func(c *RequestConfig) {
		c.AuthMethod = AuthAPIKey
		c.APIKey = apiKey
	}
}

// NewRequest creates a new HTTP request with standard headers and security features
func NewRequest(ctx context.Context, method, url string, body interface{}, opts ...RequestOption) (*http.Request, error) {
	config := NewRequestConfig()
	for _, opt := range opts {
		opt(config)
	}

	if err := config.validate(); err != nil {
		return nil, errors.WrapError(err, "invalid request configuration")
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, config.Timeout)
	defer cancel()

	var bodyReader io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, errors.WrapError(err, "failed to marshal request body")
		}
		bodyReader = bytes.NewReader(jsonBody)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return nil, errors.WrapError(err, "failed to create request")
	}

	// Add default headers
	for k, v := range defaultHeaders {
		req.Header.Set(k, v)
	}
	for k, v := range config.Headers {
		req.Header.Set(k, v)
	}

	// Apply authentication
	switch config.AuthMethod {
	case AuthOAuth:
		token, err := config.OAuth2Config.TokenSource(ctx).Token()
		if err != nil {
			return nil, errors.WrapError(err, "failed to get OAuth token")
		}
		token.SetAuthHeader(req)
	case AuthAPIKey:
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", config.APIKey))
	}

	// Enable compression if requested
	if config.EnableCompression {
		req.Header.Set("Accept-Encoding", "gzip")
	}

	return req, nil
}

// DoRequest executes an HTTP request with retry logic and error handling
func DoRequest(req *http.Request, opts ...RequestOption) (*http.Response, error) {
	config := NewRequestConfig()
	for _, opt := range opts {
		opt(config)
	}

	// Acquire semaphore slot
	if err := requestSemaphore.Acquire(req.Context(), 1); err != nil {
		return nil, errors.WrapError(err, "failed to acquire request slot")
	}
	defer requestSemaphore.Release(1)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: config.TLSConfig,
		},
	}

	var lastErr error
	for attempt := 0; attempt <= config.RetryAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-req.Context().Done():
				return nil, errors.WrapError(req.Context().Err(), "request cancelled")
			case <-time.After(config.RetryDelay):
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = errors.WrapError(err, "request failed")
			if !errors.IsRetryable(lastErr) {
				return nil, lastErr
			}
			continue
		}

		// Handle compression
		if resp.Header.Get("Content-Encoding") == "gzip" {
			reader, err := gzip.NewReader(resp.Body)
			if err != nil {
				resp.Body.Close()
				return nil, errors.WrapError(err, "failed to create gzip reader")
			}
			resp.Body = reader
		}

		// Check for error status codes
		if resp.StatusCode >= 400 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			lastErr = errors.NewCLIError(
				fmt.Sprintf("E%d", resp.StatusCode),
				fmt.Sprintf("request failed with status %d: %s", resp.StatusCode, string(body)),
				nil,
			)
			if !errors.IsRetryable(lastErr) || attempt == config.RetryAttempts {
				return nil, lastErr
			}
			continue
		}

		return resp, nil
	}

	return nil, lastErr
}