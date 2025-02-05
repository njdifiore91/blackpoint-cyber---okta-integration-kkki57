// Package bronze provides request validation and security enforcement for Bronze tier API endpoints
package bronze

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/blackpoint/pkg/bronze/schema"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/logging"
    "github.com/blackpoint/pkg/common/middleware"
    "github.com/prometheus/client_golang/prometheus"
)

// Validation constants
const (
    maxRequestSize    int64 = 1048576 // 1MB max request size
    requestRateLimit  int   = 1000    // requests per minute
    validationTimeout       = 500 * time.Millisecond
)

// Error codes for validation failures
var validationErrorCodes = map[string]string{
    "INVALID_REQUEST":      "BR001",
    "SCHEMA_VIOLATION":     "BR002",
    "SIZE_EXCEEDED":        "BR003",
    "INVALID_CLIENT":       "BR004",
    "INVALID_PLATFORM":     "BR005",
    "RATE_LIMIT_EXCEEDED":  "BR006",
    "SECURITY_VIOLATION":   "BR007",
}

// Validation metrics
var (
    validationLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_bronze_validation_latency_seconds",
            Help: "Latency of Bronze tier request validation",
            Buckets: []float64{0.1, 0.25, 0.5, 1.0},
        },
        []string{"status"},
    )

    validationErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_bronze_validation_errors_total",
            Help: "Total number of validation errors by type",
        },
        []string{"error_code"},
    )
)

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(validationLatency, validationErrors)
}

// ValidateRequest performs comprehensive validation of incoming Bronze tier requests
// with security checks and performance monitoring
func ValidateRequest(r *http.Request) (*schema.BronzeEvent, error) {
    timer := prometheus.NewTimer(validationLatency.WithLabelValues("processing"))
    defer timer.ObserveDuration()

    // Validate request size
    if r.ContentLength > maxRequestSize {
        validationErrors.WithLabelValues("SIZE_EXCEEDED").Inc()
        return nil, errors.NewError(validationErrorCodes["SIZE_EXCEEDED"], 
            "Request size exceeds maximum allowed", map[string]interface{}{
                "max_size": maxRequestSize,
                "actual_size": r.ContentLength,
            })
    }

    // Validate client ID
    clientID, err := ValidateClientID(r)
    if err != nil {
        return nil, err
    }

    // Parse and validate request body
    var requestData map[string]interface{}
    if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
        validationErrors.WithLabelValues("INVALID_REQUEST").Inc()
        return nil, errors.NewError(validationErrorCodes["INVALID_REQUEST"], 
            "Invalid request format", nil)
    }

    // Validate source platform
    platform, ok := requestData["source_platform"].(string)
    if !ok || platform == "" {
        validationErrors.WithLabelValues("INVALID_PLATFORM").Inc()
        return nil, errors.NewError(validationErrorCodes["INVALID_PLATFORM"], 
            "Missing or invalid source platform", nil)
    }

    if valid, err := ValidateSourcePlatform(platform); !valid {
        return nil, err
    }

    // Create and validate Bronze event
    payload, err := json.Marshal(requestData["payload"])
    if err != nil {
        validationErrors.WithLabelValues("INVALID_REQUEST").Inc()
        return nil, errors.NewError(validationErrorCodes["INVALID_REQUEST"], 
            "Invalid payload format", nil)
    }

    event, err := schema.NewBronzeEvent(clientID, platform, payload)
    if err != nil {
        validationErrors.WithLabelValues("SCHEMA_VIOLATION").Inc()
        return nil, errors.WrapError(err, "Failed to create Bronze event", nil)
    }

    // Perform schema validation
    if err := schema.ValidateSchema(event); err != nil {
        validationErrors.WithLabelValues("SCHEMA_VIOLATION").Inc()
        return nil, err
    }

    // Log successful validation
    logging.SecurityAudit("Bronze request validation successful", map[string]interface{}{
        "client_id": clientID,
        "platform": platform,
        "event_id": event.ID,
        "validation_time": timer.ObserveDuration().Seconds(),
    })

    return event, nil
}

// ValidateClientID validates the client ID with security checks and rate limiting
func ValidateClientID(r *http.Request) (string, error) {
    claims, ok := r.Context().Value("claims").(map[string]interface{})
    if !ok {
        validationErrors.WithLabelValues("INVALID_CLIENT").Inc()
        return "", errors.NewError(validationErrorCodes["INVALID_CLIENT"], 
            "Missing client authentication", nil)
    }

    clientID, ok := claims["client_id"].(string)
    if !ok || clientID == "" {
        validationErrors.WithLabelValues("INVALID_CLIENT").Inc()
        return "", errors.NewError(validationErrorCodes["INVALID_CLIENT"], 
            "Invalid client ID format", nil)
    }

    // Check rate limits
    if !middleware.CheckRateLimit(clientID, requestRateLimit) {
        validationErrors.WithLabelValues("RATE_LIMIT_EXCEEDED").Inc()
        return "", errors.NewError(validationErrorCodes["RATE_LIMIT_EXCEEDED"], 
            "Rate limit exceeded", map[string]interface{}{
                "client_id": clientID,
                "limit": requestRateLimit,
            })
    }

    logging.SecurityAudit("Client validation successful", map[string]interface{}{
        "client_id": clientID,
        "remote_addr": r.RemoteAddr,
    })

    return clientID, nil
}

// ValidateSourcePlatform validates the security platform source
func ValidateSourcePlatform(platform string) (bool, error) {
    allowedPlatforms := map[string]bool{
        "aws":    true,
        "azure":  true,
        "gcp":    true,
        "okta":   true,
    }

    if !allowedPlatforms[platform] {
        validationErrors.WithLabelValues("INVALID_PLATFORM").Inc()
        return false, errors.NewError(validationErrorCodes["INVALID_PLATFORM"], 
            "Unsupported security platform", map[string]interface{}{
                "platform": platform,
                "allowed_platforms": allowedPlatforms,
            })
    }

    logging.SecurityAudit("Platform validation successful", map[string]interface{}{
        "platform": platform,
    })

    return true, nil
}