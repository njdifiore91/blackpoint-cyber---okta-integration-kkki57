// Package api provides API client functionality for the BlackPoint CLI
package api

import (
    "context"
    "crypto/tls"
    "fmt"
    "net"
    "net/http"
    "sync"
    "time"

    "github.com/blackpoint/cli/pkg/common/constants"
    "github.com/blackpoint/cli/pkg/common/errors"
)

// APIClient provides a thread-safe HTTP client for BlackPoint API operations
type APIClient struct {
    baseURL          string
    apiKey           string
    httpClient       *http.Client
    mu               sync.RWMutex
    config           *RequestConfig
    tlsConfig        *tls.Config
    metricsCollector MetricsCollector
}

// ClientOption defines a function type for configuring the APIClient
type ClientOption func(*APIClient)

// WithTLSConfig sets a custom TLS configuration for the client
func WithTLSConfig(tlsConfig *tls.Config) ClientOption {
    return func(c *APIClient) {
        c.tlsConfig = tlsConfig
    }
}

// WithMetricsCollector sets a custom metrics collector
func WithMetricsCollector(collector MetricsCollector) ClientOption {
    return func(c *APIClient) {
        c.metricsCollector = collector
    }
}

// NewClient creates a new API client with secure defaults
func NewClient(baseURL, apiKey string, opts ...ClientOption) (*APIClient, error) {
    if baseURL == "" || apiKey == "" {
        return nil, errors.NewCLIError("E1001", "baseURL and apiKey are required", nil)
    }

    // Create default TLS config with secure settings
    defaultTLSConfig := &tls.Config{
        MinVersion:               tls.VersionTLS12,
        PreferServerCipherSuites: true,
        CipherSuites:            secureCipherSuites(),
    }

    client := &APIClient{
        baseURL:   baseURL,
        apiKey:    apiKey,
        tlsConfig: defaultTLSConfig,
        config:    NewRequestConfig(),
    }

    // Apply custom options
    for _, opt := range opts {
        opt(client)
    }

    // Configure HTTP client with secure defaults
    transport := &http.Transport{
        TLSClientConfig:       client.tlsConfig,
        MaxIdleConns:         100,
        MaxIdleConnsPerHost:  10,
        MaxConnsPerHost:      100,
        IdleConnTimeout:      constants.DefaultKeepAliveInterval,
        TLSHandshakeTimeout:  10 * time.Second,
        ExpectContinueTimeout: 1 * time.Second,
        DialContext: (&net.Dialer{
            Timeout:   constants.DefaultConnectionTimeout,
            KeepAlive: constants.DefaultKeepAliveInterval,
        }).DialContext,
    }

    client.httpClient = &http.Client{
        Transport: transport,
        Timeout:   constants.DefaultHTTPTimeout,
    }

    return client, nil
}

// Get performs a secure HTTP GET request with retry logic
func (c *APIClient) Get(ctx context.Context, endpoint string, result interface{}) error {
    c.mu.RLock()
    defer c.mu.RUnlock()

    startTime := time.Now()
    defer func() {
        if c.metricsCollector != nil {
            c.metricsCollector.RecordRequestDuration("GET", endpoint, time.Since(startTime))
        }
    }()

    req, err := NewRequest(ctx, http.MethodGet, 
        fmt.Sprintf("%s/%s", c.baseURL, endpoint),
        nil,
        WithAPIKey(c.apiKey),
        WithTimeout(constants.DefaultTimeout),
        WithRetry(constants.DefaultRetryAttempts, constants.DefaultRetryDelay),
    )
    if err != nil {
        return errors.WrapError(err, "failed to create GET request")
    }

    resp, err := DoRequest(req)
    if err != nil {
        return errors.WrapError(err, "GET request failed")
    }

    return ParseResponse(resp, result)
}

// Post performs a secure HTTP POST request with retry logic
func (c *APIClient) Post(ctx context.Context, endpoint string, body, result interface{}) error {
    c.mu.RLock()
    defer c.mu.RUnlock()

    startTime := time.Now()
    defer func() {
        if c.metricsCollector != nil {
            c.metricsCollector.RecordRequestDuration("POST", endpoint, time.Since(startTime))
        }
    }()

    req, err := NewRequest(ctx, http.MethodPost,
        fmt.Sprintf("%s/%s", c.baseURL, endpoint),
        body,
        WithAPIKey(c.apiKey),
        WithTimeout(constants.DefaultTimeout),
        WithRetry(constants.DefaultRetryAttempts, constants.DefaultRetryDelay),
    )
    if err != nil {
        return errors.WrapError(err, "failed to create POST request")
    }

    resp, err := DoRequest(req)
    if err != nil {
        return errors.WrapError(err, "POST request failed")
    }

    return ParseResponse(resp, result)
}

// Put performs a secure HTTP PUT request with retry logic
func (c *APIClient) Put(ctx context.Context, endpoint string, body, result interface{}) error {
    c.mu.RLock()
    defer c.mu.RUnlock()

    startTime := time.Now()
    defer func() {
        if c.metricsCollector != nil {
            c.metricsCollector.RecordRequestDuration("PUT", endpoint, time.Since(startTime))
        }
    }()

    req, err := NewRequest(ctx, http.MethodPut,
        fmt.Sprintf("%s/%s", c.baseURL, endpoint),
        body,
        WithAPIKey(c.apiKey),
        WithTimeout(constants.DefaultTimeout),
        WithRetry(constants.DefaultRetryAttempts, constants.DefaultRetryDelay),
    )
    if err != nil {
        return errors.WrapError(err, "failed to create PUT request")
    }

    resp, err := DoRequest(req)
    if err != nil {
        return errors.WrapError(err, "PUT request failed")
    }

    return ParseResponse(resp, result)
}

// Delete performs a secure HTTP DELETE request with retry logic
func (c *APIClient) Delete(ctx context.Context, endpoint string) error {
    c.mu.RLock()
    defer c.mu.RUnlock()

    startTime := time.Now()
    defer func() {
        if c.metricsCollector != nil {
            c.metricsCollector.RecordRequestDuration("DELETE", endpoint, time.Since(startTime))
        }
    }()

    req, err := NewRequest(ctx, http.MethodDelete,
        fmt.Sprintf("%s/%s", c.baseURL, endpoint),
        nil,
        WithAPIKey(c.apiKey),
        WithTimeout(constants.DefaultTimeout),
        WithRetry(constants.DefaultRetryAttempts, constants.DefaultRetryDelay),
    )
    if err != nil {
        return errors.WrapError(err, "failed to create DELETE request")
    }

    resp, err := DoRequest(req)
    if err != nil {
        return errors.WrapError(err, "DELETE request failed")
    }

    return ParseResponse(resp, nil)
}

// MetricsCollector defines the interface for collecting API metrics
type MetricsCollector interface {
    RecordRequestDuration(method, endpoint string, duration time.Duration)
}

// secureCipherSuites returns a list of secure TLS cipher suites
func secureCipherSuites() []uint16 {
    return []uint16{
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
        tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
        tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    }
}