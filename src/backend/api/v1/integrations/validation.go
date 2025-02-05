// Package integrations provides validation logic for integration API requests
package integrations

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "sync"

    "github.com/go-playground/validator/v10" // v10.11.0
    "github.com/prometheus/client_golang/prometheus" // v1.12.0

    "../../../pkg/integration/config"
    "../../../pkg/common/errors"
    "../../../pkg/common/logging"
)

var (
    // Global validator instance
    validate = validator.New()

    // Error code for validation failures
    validationErrorCode = "VALIDATION_ERROR"

    // Validation metrics
    validationMetrics = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "integration_validation_total",
            Help: "Total number of integration validation attempts by result",
        },
        []string{"platform_type", "result"},
    )

    // Platform-specific validators
    platformValidators = make(map[string]PlatformValidator)
    platformValidatorsMutex sync.RWMutex
)

// ValidationError represents a validation error with security context
type ValidationError struct {
    Field           string
    Message         string
    SecurityContext struct {
        ValidationRule string
        Severity      string
        Context       map[string]interface{}
    }
}

// Error implements the error interface
func (e *ValidationError) Error() string {
    return fmt.Sprintf("validation error on field '%s': %s", e.Field, e.Message)
}

// PlatformValidator defines platform-specific validation rules
type PlatformValidator interface {
    ValidateConfig(*config.IntegrationConfig) error
    ValidateUpdate(*config.IntegrationConfig, *config.IntegrationConfig) error
}

// init registers custom validators and initializes metrics
func init() {
    prometheus.MustRegister(validationMetrics)

    // Register custom validators
    validate.RegisterValidation("platform_type", validatePlatformType)
    validate.RegisterValidation("environment", validateEnvironment)
}

// ValidateIntegrationRequest validates an incoming integration API request
func ValidateIntegrationRequest(r *http.Request) (*config.IntegrationConfig, error) {
    // Read and parse request body
    body, err := io.ReadAll(r.Body)
    if err != nil {
        return nil, errors.NewError("E3001", "failed to read request body", nil)
    }
    defer r.Body.Close()

    var cfg config.IntegrationConfig
    if err := json.Unmarshal(body, &cfg); err != nil {
        return nil, errors.NewError("E3001", "invalid request format", map[string]interface{}{
            "error": err.Error(),
        })
    }

    // Validate basic structure
    if err := validate.Struct(&cfg); err != nil {
        validationMetrics.WithLabelValues(cfg.PlatformType, "failed").Inc()
        return nil, createValidationError(err)
    }

    // Apply platform-specific validation
    platformValidatorsMutex.RLock()
    validator, exists := platformValidators[cfg.PlatformType]
    platformValidatorsMutex.RUnlock()

    if exists {
        if err := validator.ValidateConfig(&cfg); err != nil {
            validationMetrics.WithLabelValues(cfg.PlatformType, "failed").Inc()
            return nil, err
        }
    }

    // Validate configuration
    if err := cfg.Validate(); err != nil {
        validationMetrics.WithLabelValues(cfg.PlatformType, "failed").Inc()
        return nil, err
    }

    validationMetrics.WithLabelValues(cfg.PlatformType, "success").Inc()
    logging.Info("Integration configuration validated successfully",
        "platform_type", cfg.PlatformType,
        "environment", cfg.Environment,
    )

    return &cfg, nil
}

// ValidateUpdateRequest validates an integration update request
func ValidateUpdateRequest(r *http.Request, integrationID string) (*config.IntegrationConfig, error) {
    // Read and parse update request
    body, err := io.ReadAll(r.Body)
    if err != nil {
        return nil, errors.NewError("E3001", "failed to read update request body", nil)
    }
    defer r.Body.Close()

    var updateCfg config.IntegrationConfig
    if err := json.Unmarshal(body, &updateCfg); err != nil {
        return nil, errors.NewError("E3001", "invalid update request format", map[string]interface{}{
            "error": err.Error(),
        })
    }

    // Validate basic structure
    if err := validate.Struct(&updateCfg); err != nil {
        validationMetrics.WithLabelValues(updateCfg.PlatformType, "update_failed").Inc()
        return nil, createValidationError(err)
    }

    // Apply platform-specific update validation
    platformValidatorsMutex.RLock()
    validator, exists := platformValidators[updateCfg.PlatformType]
    platformValidatorsMutex.RUnlock()

    if exists {
        if err := validator.ValidateUpdate(&updateCfg, nil); err != nil {
            validationMetrics.WithLabelValues(updateCfg.PlatformType, "update_failed").Inc()
            return nil, err
        }
    }

    validationMetrics.WithLabelValues(updateCfg.PlatformType, "update_success").Inc()
    logging.Info("Integration update validated successfully",
        "integration_id", integrationID,
        "platform_type", updateCfg.PlatformType,
    )

    return &updateCfg, nil
}

// RegisterPlatformValidator registers a platform-specific validator
func RegisterPlatformValidator(platformType string, validator PlatformValidator) {
    platformValidatorsMutex.Lock()
    defer platformValidatorsMutex.Unlock()
    platformValidators[platformType] = validator
}

// validatePlatformType validates the platform type
func validatePlatformType(fl validator.FieldLevel) bool {
    platformType := fl.Field().String()
    platformValidatorsMutex.RLock()
    _, exists := platformValidators[platformType]
    platformValidatorsMutex.RUnlock()
    return exists
}

// validateEnvironment validates the environment field
func validateEnvironment(fl validator.FieldLevel) bool {
    env := fl.Field().String()
    validEnvs := map[string]bool{
        "development": true,
        "staging":     true,
        "production": true,
    }
    return validEnvs[env]
}

// createValidationError creates a structured validation error
func createValidationError(err error) error {
    if validationErrors, ok := err.(validator.ValidationErrors); ok {
        var details []ValidationError
        for _, e := range validationErrors {
            details = append(details, ValidationError{
                Field:   e.Field(),
                Message: fmt.Sprintf("failed on '%s' validation", e.Tag()),
                SecurityContext: struct {
                    ValidationRule string
                    Severity      string
                    Context       map[string]interface{}
                }{
                    ValidationRule: e.Tag(),
                    Severity:      "error",
                    Context: map[string]interface{}{
                        "field":     e.Field(),
                        "value":     e.Value(),
                        "namespace": e.Namespace(),
                    },
                },
            })
        }
        return errors.NewError(validationErrorCode, "validation failed", map[string]interface{}{
            "validation_errors": details,
        })
    }
    return err
}