// Package generators provides test scenario generators for the BlackPoint Security Integration Framework
// Version: 1.0.0
package generators

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"../../pkg/common/errors"
	"../../pkg/common/logging"
	"../../pkg/common/utils"
	"../../pkg/fixtures/bronze_events"
)

// SecurityScenarioTypes defines available security test scenario types
var SecurityScenarioTypes = map[string]string{
	"AUTH_BYPASS":      "Authentication bypass attempt scenarios",
	"UNAUTH_ACCESS":    "Unauthorized access attempt patterns",
	"DATA_LEAK":        "Data leakage and exposure scenarios",
	"ENCRYPTION_BYPASS": "Encryption bypass and weakness tests",
	"INVALID_CERT":     "Invalid certificate and chain scenarios",
	"INVALID_SIG":      "Invalid signature and tampering tests",
	"INCIDENT_RESPONSE": "Security incident response scenarios",
	"COMPLIANCE_CHECK": "Security compliance validation tests",
}

// defaultTestCertConfig defines standard test certificate configuration
var defaultTestCertConfig = map[string]interface{}{
	"keySize":            2048,
	"validity":           24 * time.Hour,
	"algorithm":          "RSA",
	"signatureAlgorithm": "SHA256WithRSA",
	"keyUsage":          x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	"extKeyUsage":       []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
}

// AuthConfig configures authentication test scenarios
type AuthConfig struct {
	OAuthConfig     *OAuthTestConfig
	APIKeyConfig    *APIKeyTestConfig
	MTLSConfig      *MTLSTestConfig
	HMACConfig      *HMACTestConfig
	ValidationRules map[string]interface{}
}

// OAuthTestConfig defines OAuth test parameters
type OAuthTestConfig struct {
	Issuer     string
	Audience   string
	ValidRoles []string
	ExpiryTime time.Duration
}

// APIKeyTestConfig defines API key test parameters
type APIKeyTestConfig struct {
	KeyPrefix    string
	KeyLength    int
	ValidScopes  []string
	RotationTime time.Duration
}

// MTLSTestConfig defines mTLS test parameters
type MTLSTestConfig struct {
	CAConfig     *x509.Certificate
	ClientConfig *tls.Config
	ValidDomains []string
}

// HMACTestConfig defines HMAC signature test parameters
type HMACTestConfig struct {
	Algorithm  string
	SecretKey  []byte
	Timestamp  time.Time
	ValidityWindow time.Duration
}

// GenerateAuthBypassScenario generates comprehensive authentication bypass test scenarios
func GenerateAuthBypassScenario(t *testing.T, config AuthConfig) (map[string]interface{}, error) {
	logging.LogTestInfo(t, "Generating auth bypass scenarios", map[string]interface{}{
		"scenario_type": "AUTH_BYPASS",
		"config":        fmt.Sprintf("%+v", config),
	})

	scenarios := make(map[string]interface{})

	// Generate OAuth bypass scenarios
	if config.OAuthConfig != nil {
		oauthScenarios, err := generateOAuthBypassScenarios(t, config.OAuthConfig)
		if err != nil {
			return nil, errors.WrapTestError(err, "failed to generate OAuth scenarios")
		}
		scenarios["oauth_bypass"] = oauthScenarios
	}

	// Generate API key bypass scenarios
	if config.APIKeyConfig != nil {
		apiKeyScenarios, err := generateAPIKeyBypassScenarios(t, config.APIKeyConfig)
		if err != nil {
			return nil, errors.WrapTestError(err, "failed to generate API key scenarios")
		}
		scenarios["api_key_bypass"] = apiKeyScenarios
	}

	// Generate mTLS bypass scenarios
	if config.MTLSConfig != nil {
		mtlsScenarios, err := generateMTLSBypassScenarios(t, config.MTLSConfig)
		if err != nil {
			return nil, errors.WrapTestError(err, "failed to generate mTLS scenarios")
		}
		scenarios["mtls_bypass"] = mtlsScenarios
	}

	// Generate HMAC signature bypass scenarios
	if config.HMACConfig != nil {
		hmacScenarios, err := generateHMACBypassScenarios(t, config.HMACConfig)
		if err != nil {
			return nil, errors.WrapTestError(err, "failed to generate HMAC scenarios")
		}
		scenarios["hmac_bypass"] = hmacScenarios
	}

	return scenarios, nil
}

// GenerateDataLeakScenario generates data leakage and encryption test scenarios
func GenerateDataLeakScenario(t *testing.T, dataType string, config map[string]interface{}) (map[string]interface{}, error) {
	logging.LogTestInfo(t, "Generating data leak scenarios", map[string]interface{}{
		"scenario_type": "DATA_LEAK",
		"data_type":     dataType,
	})

	// Generate test event with sensitive data
	event, err := bronze_events.GenerateValidBronzeEvent(&bronze_events.GenerateOptions{
		SecurityLevel: "high",
		AuditLevel:   "detailed",
	})
	if err != nil {
		return nil, errors.WrapTestError(err, "failed to generate test event")
	}

	scenarios := map[string]interface{}{
		"unencrypted_transmission": generateUnencryptedTransmissionScenario(event),
		"weak_encryption":          generateWeakEncryptionScenario(event),
		"missing_field_encryption": generateMissingFieldEncryptionScenario(event),
		"encryption_key_exposure":  generateKeyExposureScenario(event),
		"data_validation":         map[string]interface{}{
			"event":    event,
			"rules":    config["validation_rules"],
			"expected": "fail",
		},
	}

	return scenarios, nil
}

// ValidateSecurityScenario validates security test scenario execution results
func ValidateSecurityScenario(t *testing.T, scenario map[string]interface{}, results map[string]interface{}, config map[string]interface{}) error {
	logging.LogTestInfo(t, "Validating security scenario", map[string]interface{}{
		"scenario_type": scenario["type"],
		"validation_rules": config["validation_rules"],
	})

	// Validate scenario execution
	if err := validateScenarioExecution(scenario, results); err != nil {
		return errors.WrapTestError(err, "scenario execution validation failed")
	}

	// Validate security controls
	if err := validateSecurityControls(scenario, results, config); err != nil {
		return errors.WrapTestError(err, "security control validation failed")
	}

	// Validate compliance requirements
	if err := validateComplianceRequirements(scenario, results, config); err != nil {
		return errors.WrapTestError(err, "compliance validation failed")
	}

	return nil
}

// Helper functions for scenario generation

func generateOAuthBypassScenarios(t *testing.T, config *OAuthTestConfig) (map[string]interface{}, error) {
	scenarios := map[string]interface{}{
		"expired_token": generateExpiredToken(config),
		"invalid_signature": generateInvalidSignature(config),
		"wrong_audience": generateWrongAudience(config),
		"insufficient_scope": generateInsufficientScope(config),
		"tampered_claims": generateTamperedClaims(config),
	}
	return scenarios, nil
}

func generateAPIKeyBypassScenarios(t *testing.T, config *APIKeyTestConfig) (map[string]interface{}, error) {
	scenarios := map[string]interface{}{
		"invalid_key": generateInvalidAPIKey(config),
		"expired_key": generateExpiredAPIKey(config),
		"wrong_scope": generateWrongScopeAPIKey(config),
		"revoked_key": generateRevokedAPIKey(config),
	}
	return scenarios, nil
}

func generateMTLSBypassScenarios(t *testing.T, config *MTLSTestConfig) (map[string]interface{}, error) {
	scenarios := map[string]interface{}{
		"invalid_cert": generateInvalidCertificate(config),
		"expired_cert": generateExpiredCertificate(config),
		"wrong_domain": generateWrongDomainCertificate(config),
		"revoked_cert": generateRevokedCertificate(config),
	}
	return scenarios, nil
}

func generateHMACBypassScenarios(t *testing.T, config *HMACTestConfig) (map[string]interface{}, error) {
	scenarios := map[string]interface{}{
		"invalid_signature": generateInvalidHMACSignature(config),
		"expired_signature": generateExpiredHMACSignature(config),
		"replay_attack": generateReplayAttackScenario(config),
		"tampered_payload": generateTamperedPayloadScenario(config),
	}
	return scenarios, nil
}

// Helper functions for scenario validation

func validateScenarioExecution(scenario, results map[string]interface{}) error {
	expectedResult := scenario["expected"].(string)
	actualResult := results["result"].(string)

	if expectedResult != actualResult {
		return errors.NewTestError("VALIDATION_ERROR", fmt.Sprintf(
			"scenario execution mismatch: expected %s, got %s",
			expectedResult, actualResult))
	}
	return nil
}

func validateSecurityControls(scenario, results, config map[string]interface{}) error {
	controls := config["security_controls"].(map[string]interface{})
	for control, expected := range controls {
		actual, exists := results[control]
		if !exists {
			return errors.NewTestError("VALIDATION_ERROR", fmt.Sprintf(
				"missing security control validation: %s", control))
		}
		if actual != expected {
			return errors.NewTestError("VALIDATION_ERROR", fmt.Sprintf(
				"security control mismatch for %s: expected %v, got %v",
				control, expected, actual))
		}
	}
	return nil
}

func validateComplianceRequirements(scenario, results, config map[string]interface{}) error {
	requirements := config["compliance_requirements"].(map[string]interface{})
	for req, expected := range requirements {
		actual, exists := results[req]
		if !exists {
			return errors.NewTestError("VALIDATION_ERROR", fmt.Sprintf(
				"missing compliance requirement: %s", req))
		}
		if actual != expected {
			return errors.NewTestError("VALIDATION_ERROR", fmt.Sprintf(
				"compliance requirement not met for %s: expected %v, got %v",
				req, expected, actual))
		}
	}
	return nil
}