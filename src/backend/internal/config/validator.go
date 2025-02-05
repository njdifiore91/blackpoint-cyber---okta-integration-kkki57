// Package config provides configuration validation functionality for the BlackPoint Security Integration Framework
package config

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"reflect"
	"strings"
	"sync"

	"github.com/go-playground/validator/v10" // v10.11.0
	"github.com/prometheus/client_golang/prometheus" // v1.12.0
	"../../pkg/common/errors"
	"../../pkg/common/logging"
)

// ValidationRule defines a custom validation rule function
type ValidationRule func(interface{}) error

// SecurityRule defines a security-specific validation rule
type SecurityRule func(interface{}) error

// ConfigValidator provides enhanced configuration validation with security features
type ConfigValidator struct {
	validator     *validator.Validate
	customRules   map[string]ValidationRule
	securityRules map[string]SecurityRule
	metrics       *prometheus.CounterVec
	mu           sync.RWMutex
}

var (
	// Default validator instance
	defaultValidator *ConfigValidator

	// Validation metrics
	validationMetrics = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blackpoint_config_validation",
			Help: "Configuration validation metrics",
		},
		[]string{"result", "type"},
	)
)

func init() {
	prometheus.MustRegister(validationMetrics)
	defaultValidator = NewConfigValidator()
}

// NewConfigValidator creates a new ConfigValidator instance with security features
func NewConfigValidator() *ConfigValidator {
	v := &ConfigValidator{
		validator:     validator.New(),
		customRules:   make(map[string]ValidationRule),
		securityRules: make(map[string]SecurityRule),
		metrics:      validationMetrics,
	}

	// Register default security validation rules
	v.registerDefaultSecurityRules()

	return v
}

// ValidateConfig performs comprehensive configuration validation with security checks
func ValidateConfig(config interface{}) error {
	return defaultValidator.Validate(config)
}

// Validate performs configuration validation with security checks
func (cv *ConfigValidator) Validate(config interface{}) error {
	if config == nil {
		return errors.NewError("E2001", "configuration cannot be nil", nil)
	}

	cv.mu.RLock()
	defer cv.mu.RUnlock()

	// Start validation metrics recording
	timer := prometheus.NewTimer(prometheus.ObserverVec{})
	defer timer.ObserveDuration()

	// Perform struct validation
	if err := cv.validator.Struct(config); err != nil {
		cv.metrics.WithLabelValues("failure", "struct").Inc()
		return errors.WrapError(err, "struct validation failed", nil)
	}

	// Apply custom validation rules
	if err := cv.applyCustomRules(config); err != nil {
		cv.metrics.WithLabelValues("failure", "custom").Inc()
		return err
	}

	// Apply security validation rules
	if err := cv.applySecurityRules(config); err != nil {
		cv.metrics.WithLabelValues("failure", "security").Inc()
		return err
	}

	cv.metrics.WithLabelValues("success", "total").Inc()
	logging.Info("Configuration validation successful",
		"config_type", reflect.TypeOf(config).String(),
	)

	return nil
}

// RegisterSecurityRule registers a new security validation rule
func (cv *ConfigValidator) RegisterSecurityRule(name string, rule SecurityRule) {
	cv.mu.Lock()
	defer cv.mu.Unlock()
	cv.securityRules[name] = rule
}

// registerDefaultSecurityRules registers default security validation rules
func (cv *ConfigValidator) registerDefaultSecurityRules() {
	// TLS Configuration Validation
	cv.RegisterSecurityRule("tls", func(config interface{}) error {
		val := reflect.ValueOf(config)
		tlsField := val.FieldByName("TLS")
		if !tlsField.IsValid() {
			return nil
		}

		tlsConfig, ok := tlsField.Interface().(*tls.Config)
		if !ok {
			return errors.NewError("E2001", "invalid TLS configuration type", nil)
		}

		if tlsConfig.MinVersion < tls.VersionTLS12 {
			return errors.NewError("E2001", "TLS version must be 1.2 or higher", nil)
		}

		return nil
	})

	// Authentication Configuration Validation
	cv.RegisterSecurityRule("auth", func(config interface{}) error {
		val := reflect.ValueOf(config)
		authField := val.FieldByName("Auth")
		if !authField.IsValid() {
			return nil
		}

		authType := authField.FieldByName("Type").String()
		if !strings.Contains("OAuth2,JWT,mTLS", authType) {
			return errors.NewError("E2001", "unsupported authentication type", nil)
		}

		return nil
	})

	// Encryption Configuration Validation
	cv.RegisterSecurityRule("encryption", func(config interface{}) error {
		val := reflect.ValueOf(config)
		encField := val.FieldByName("Encryption")
		if !encField.IsValid() {
			return nil
		}

		if keySize := encField.FieldByName("KeySize").Int(); keySize < 256 {
			return errors.NewError("E2001", "encryption key size must be at least 256 bits", nil)
		}

		return nil
	})
}

// applyCustomRules applies registered custom validation rules
func (cv *ConfigValidator) applyCustomRules(config interface{}) error {
	for name, rule := range cv.customRules {
		if err := rule(config); err != nil {
			return errors.WrapError(err, "custom validation failed", map[string]interface{}{
				"rule": name,
			})
		}
	}
	return nil
}

// applySecurityRules applies registered security validation rules
func (cv *ConfigValidator) applySecurityRules(config interface{}) error {
	for name, rule := range cv.securityRules {
		if err := rule(config); err != nil {
			logging.SecurityAudit("Security validation failed",
				"rule", name,
				"error", err.Error(),
			)
			return errors.WrapError(err, "security validation failed", map[string]interface{}{
				"rule": name,
			})
		}
	}
	return nil
}

// validateCertificate validates X.509 certificate configuration
func validateCertificate(certPEM []byte) error {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return errors.NewError("E2001", "failed to decode certificate PEM", nil)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return errors.WrapError(err, "failed to parse certificate", nil)
	}

	// Validate certificate attributes
	if cert.NotAfter.Before(time.Now()) {
		return errors.NewError("E2001", "certificate has expired", nil)
	}

	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.NewError("E2001", "certificate missing required key usage", nil)
	}

	return nil
}