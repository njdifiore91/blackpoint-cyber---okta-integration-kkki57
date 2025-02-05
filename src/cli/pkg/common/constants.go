// Package common provides shared constants and utilities used throughout the BlackPoint CLI application.
// Version: 1.0.0
package common

import (
	"os"
	"time"
)

// Configuration file constants
const (
	// DefaultConfigPath specifies the default location for the CLI configuration file
	DefaultConfigPath = "~/.blackpoint/config.yaml"

	// DefaultLogLevel defines the default logging verbosity
	DefaultLogLevel = "info"

	// DefaultOutputFormat specifies the default output format for CLI commands
	DefaultOutputFormat = "json"
)

// API and request constants
const (
	// DefaultAPIVersion specifies the API version for backend service communication
	DefaultAPIVersion = "v1"

	// APIKeyMinLength defines the minimum required length for API keys
	APIKeyMinLength = 32

	// MaxEventSize defines the maximum allowed size in bytes for individual security events
	MaxEventSize = 1048576 // 1MB

	// DefaultBatchSize defines the optimal size for batch operations
	DefaultBatchSize = 1000

	// MaxConcurrentRequests limits the number of concurrent API requests
	MaxConcurrentRequests = 100
)

// Time-related constants
var (
	// DefaultTimeout defines the maximum duration to wait for API operations
	DefaultTimeout = time.Second * 30

	// DefaultRetryDelay specifies the delay between retry attempts
	DefaultRetryDelay = time.Second * 5
)

// Retry and error handling constants
const (
	// DefaultRetryAttempts defines the number of retry attempts for failed operations
	DefaultRetryAttempts = 3
)

// File permission constants
var (
	// ConfigFilePermissions defines secure file permissions for configuration files
	// 0600 ensures read/write for owner only
	ConfigFilePermissions = os.FileMode(0600)
)

// Exit codes for CLI operations
const (
	// ExitCodeSuccess indicates successful command execution
	ExitCodeSuccess = 0

	// ExitCodeError indicates command execution failure
	ExitCodeError = 1

	// ExitCodeConfigError indicates configuration-related errors
	ExitCodeConfigError = 2

	// ExitCodeAPIError indicates API communication errors
	ExitCodeAPIError = 3
)

// HTTP-related constants
const (
	// DefaultHTTPTimeout defines the timeout for HTTP requests
	DefaultHTTPTimeout = time.Second * 30

	// DefaultConnectionTimeout defines the timeout for establishing connections
	DefaultConnectionTimeout = time.Second * 10

	// DefaultKeepAliveInterval defines the interval for connection keep-alive
	DefaultKeepAliveInterval = time.Second * 30
)

// Integration-related constants
const (
	// DefaultIntegrationTimeout defines the timeout for integration operations
	DefaultIntegrationTimeout = time.Minute * 5

	// MaxIntegrationRetries defines the maximum number of retries for integration operations
	MaxIntegrationRetries = 5

	// IntegrationConfigMinSize defines the minimum size for integration configuration files
	IntegrationConfigMinSize = 50 // bytes

	// IntegrationConfigMaxSize defines the maximum size for integration configuration files
	IntegrationConfigMaxSize = 1048576 // 1MB
)

// Security-related constants
const (
	// MinPasswordLength defines the minimum length for passwords
	MinPasswordLength = 12

	// MaxPasswordLength defines the maximum length for passwords
	MaxPasswordLength = 128

	// MaxTokenLifetime defines the maximum lifetime for authentication tokens
	MaxTokenLifetime = time.Hour * 24
)