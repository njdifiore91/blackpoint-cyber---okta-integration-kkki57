// Package integration provides validation logic for third-party security platform integrations
package integration

import (
    "context"
    "sync"
    "time"

    "github.com/go-playground/validator/v10" // v10.11.0
    "github.com/prometheus/client_golang/prometheus" // v1.12.0

    "../../pkg/integration/config"
    "../../pkg/integration/platform"
    "../../pkg/common/errors"
)

// Validation metrics
var (
    validationDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "blackpoint_integration_validation_duration_seconds",
            Help:    "Duration of integration validation operations",
            Buckets: prometheus.ExponentialBuckets(0.01, 2, 10),
        },
        []string{"platform_type", "validation_type"},
    )

    validationErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_integration_validation_errors_total",
            Help: "Total number of validation errors by type",
        },
        []string{"platform_type", "error_type"},
    )

    validationCacheHits = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_integration_validation_cache_hits_total",
            Help: "Total number of validation cache hits",
        },
        []string{"platform_type"},
    )
)

func init() {
    prometheus.MustRegister(validationDuration)
    prometheus.MustRegister(validationErrors)
    prometheus.MustRegister(validationCacheHits)
}

// IntegrationValidator provides thread-safe validation with caching
type IntegrationValidator struct {
    validator *validator.Validate
    cache    *sync.Map
    rules    map[string]string
}

// ValidationResult represents the outcome of a validation operation
type ValidationResult struct {
    Valid    bool
    Errors   []error
    Metadata map[string]interface{}
    CacheKey string
}

// NewIntegrationValidator creates a new validator instance with enhanced features
func NewIntegrationValidator() *IntegrationValidator {
    v := &IntegrationValidator{
        validator: validator.New(),
        cache:    &sync.Map{},
        rules:    make(map[string]string),
    }

    // Register custom validation functions
    v.validator.RegisterValidation("platform_type", validatePlatformType)
    v.validator.RegisterValidation("auth_config", validateAuthConfig)
    v.validator.RegisterValidation("collection_config", validateCollectionConfig)

    return v
}

// ValidateIntegration performs comprehensive validation of integration configuration
func (v *IntegrationValidator) ValidateIntegration(ctx context.Context, cfg *config.IntegrationConfig) error {
    timer := prometheus.NewTimer(validationDuration.WithLabelValues(cfg.PlatformType, "full"))
    defer timer.ObserveDuration()

    // Generate cache key
    cacheKey := generateCacheKey(cfg)

    // Check validation cache
    if result, ok := v.cache.Load(cacheKey); ok {
        validationCacheHits.WithLabelValues(cfg.PlatformType).Inc()
        if validResult, ok := result.(ValidationResult); ok && validResult.Valid {
            return nil
        }
    }

    // Basic structure validation
    if err := v.validator.Struct(cfg); err != nil {
        validationErrors.WithLabelValues(cfg.PlatformType, "structure").Inc()
        return errors.NewError("E2001", "invalid integration configuration structure", map[string]interface{}{
            "validation_errors": err.Error(),
            "platform_type":    cfg.PlatformType,
        })
    }

    // Platform-specific validation
    if err := v.validatePlatformSpecific(ctx, cfg); err != nil {
        validationErrors.WithLabelValues(cfg.PlatformType, "platform_specific").Inc()
        return err
    }

    // Authentication validation
    if err := v.validateAuth(cfg.Auth, cfg.PlatformType); err != nil {
        validationErrors.WithLabelValues(cfg.PlatformType, "auth").Inc()
        return err
    }

    // Data collection validation
    if err := v.validateCollection(cfg.Collection, cfg.PlatformType); err != nil {
        validationErrors.WithLabelValues(cfg.PlatformType, "collection").Inc()
        return err
    }

    // Cache successful validation
    v.cache.Store(cacheKey, ValidationResult{
        Valid:    true,
        Metadata: map[string]interface{}{
            "validated_at": time.Now().UTC(),
            "platform_type": cfg.PlatformType,
        },
        CacheKey: cacheKey,
    })

    return nil
}

// validatePlatformSpecific performs platform-specific validation
func (v *IntegrationValidator) validatePlatformSpecific(ctx context.Context, cfg *config.IntegrationConfig) error {
    timer := prometheus.NewTimer(validationDuration.WithLabelValues(cfg.PlatformType, "platform_specific"))
    defer timer.ObserveDuration()

    // Validate platform type
    if !isPlatformSupported(cfg.PlatformType) {
        return errors.NewError("E2001", "unsupported platform type", map[string]interface{}{
            "platform_type": cfg.PlatformType,
            "supported_platforms": platform.SupportedPlatforms,
        })
    }

    // Validate platform-specific configuration
    if cfg.PlatformSpecific != nil {
        if rule, exists := v.rules[cfg.PlatformType]; exists {
            if err := v.validator.Var(cfg.PlatformSpecific, rule); err != nil {
                return errors.NewError("E2001", "invalid platform-specific configuration", map[string]interface{}{
                    "platform_type": cfg.PlatformType,
                    "validation_errors": err.Error(),
                })
            }
        }
    }

    return nil
}

// validateAuth performs enhanced authentication configuration validation
func (v *IntegrationValidator) validateAuth(auth config.AuthenticationConfig, platformType string) error {
    timer := prometheus.NewTimer(validationDuration.WithLabelValues(platformType, "auth"))
    defer timer.ObserveDuration()

    // Validate auth type compatibility
    if !isAuthTypeSupported(auth.Type, platformType) {
        return errors.NewError("E2001", "unsupported authentication type for platform", map[string]interface{}{
            "auth_type": auth.Type,
            "platform_type": platformType,
        })
    }

    // Validate credentials
    if err := validateCredentials(auth.Credentials, auth.Type); err != nil {
        return err
    }

    // Validate token expiry and renewal
    if auth.ExpiryTime > 0 {
        if auth.ExpiryTime < time.Hour {
            return errors.NewError("E2001", "token expiry time too short", map[string]interface{}{
                "min_expiry": "1h",
                "provided_expiry": auth.ExpiryTime,
            })
        }
    }

    return nil
}

// validateCollection performs data collection configuration validation
func (v *IntegrationValidator) validateCollection(collection config.DataCollectionConfig, platformType string) error {
    timer := prometheus.NewTimer(validationDuration.WithLabelValues(platformType, "collection"))
    defer timer.ObserveDuration()

    // Validate collection mode
    if !isCollectionModeSupported(collection.Mode, platformType) {
        return errors.NewError("E2001", "unsupported collection mode for platform", map[string]interface{}{
            "mode": collection.Mode,
            "platform_type": platformType,
        })
    }

    // Validate batch configuration
    if collection.Mode == "batch" || collection.Mode == "hybrid" {
        if err := validateBatchConfig(collection); err != nil {
            return err
        }
    }

    return nil
}

// AddValidationRule adds a custom validation rule for a platform
func (v *IntegrationValidator) AddValidationRule(platformType string, rule string) error {
    if !isPlatformSupported(platformType) {
        return errors.NewError("E2001", "cannot add rule for unsupported platform", map[string]interface{}{
            "platform_type": platformType,
        })
    }

    // Validate rule syntax
    if err := v.validator.RegisterValidation(platformType+"_rule", func(fl validator.FieldLevel) bool {
        return true // Placeholder for actual rule validation
    }); err != nil {
        return errors.WrapError(err, "invalid validation rule syntax", map[string]interface{}{
            "platform_type": platformType,
            "rule": rule,
        })
    }

    v.rules[platformType] = rule
    
    // Clear cache entries for this platform
    v.clearPlatformCache(platformType)

    return nil
}

// Helper functions

func generateCacheKey(cfg *config.IntegrationConfig) string {
    // Implementation of cache key generation
    return cfg.PlatformType + "_" + cfg.Name
}

func isPlatformSupported(platformType string) bool {
    for _, p := range platform.SupportedPlatforms {
        if p == platformType {
            return true
        }
    }
    return false
}

func isAuthTypeSupported(authType string, platformType string) bool {
    // Implementation of auth type support check
    return true // Placeholder
}

func validateCredentials(credentials map[string]interface{}, authType string) error {
    // Implementation of credential validation
    return nil // Placeholder
}

func isCollectionModeSupported(mode string, platformType string) bool {
    // Implementation of collection mode support check
    return true // Placeholder
}

func validateBatchConfig(collection config.DataCollectionConfig) error {
    // Implementation of batch configuration validation
    return nil // Placeholder
}

func (v *IntegrationValidator) clearPlatformCache(platformType string) {
    v.cache.Range(func(key, value interface{}) bool {
        if vr, ok := value.(ValidationResult); ok {
            if vr.Metadata["platform_type"] == platformType {
                v.cache.Delete(key)
            }
        }
        return true
    })
}