// Package fixtures provides test fixtures for the BlackPoint Security Integration Framework
package fixtures

import (
	"crypto/aes" // v1.21
	"encoding/json"
	"fmt"
	"time"

	"github.com/blackpoint/security" // v1.0.0
	"github.com/blackpoint/metrics" // v1.0.0
	"github.com/stretchr/testify/assert" // v1.8.4
	"../../../backend/pkg/silver/schema"
)

// Test constants for generating consistent test data
const (
	testClientID      = "test-client-001"
	testSchemaVersion = "1.0"
)

// Supported event types for test data generation
var supportedEventTypes = []string{
	"auth",
	"access",
	"security",
	"system",
	"compliance",
	"audit",
}

// Security levels for test data classification
var securityLevels = []string{
	"low",
	"medium",
	"high",
	"critical",
}

// NewTestSilverEventWithSecurity creates a new SilverEvent instance with test data and security context
func NewTestSilverEventWithSecurity(eventType string, securityLevel string) (*schema.SilverEvent, error) {
	// Validate input parameters
	if !isValidEventType(eventType) {
		return nil, fmt.Errorf("invalid event type: %s", eventType)
	}
	if !isValidSecurityLevel(securityLevel) {
		return nil, fmt.Errorf("invalid security level: %s", securityLevel)
	}

	// Generate test event ID
	eventID := fmt.Sprintf("test-event-%s-%d", eventType, time.Now().UnixNano())

	// Create normalized test data
	normalizedData, err := generateNormalizedTestData(eventType)
	if err != nil {
		return nil, fmt.Errorf("failed to generate normalized data: %w", err)
	}

	// Generate security context
	securityContext := schema.SecurityContext{
		Classification: securityLevel,
		Sensitivity:   securityLevel,
		Compliance:    getComplianceRequirements(securityLevel),
		Encryption:    getEncryptionConfig(securityLevel),
		AccessControl: getAccessControlConfig(securityLevel),
	}

	// Create audit metadata
	auditMetadata := schema.AuditMetadata{
		CreatedAt:     time.Now().UTC(),
		CreatedBy:     "test-framework",
		NormalizedAt:  time.Now().UTC(),
		NormalizedBy:  "test-normalizer",
		SchemaVersion: testSchemaVersion,
		SourceEventID: fmt.Sprintf("bronze-event-%s", eventID),
	}

	// Create test event
	event := &schema.SilverEvent{
		EventID:        eventID,
		ClientID:       testClientID,
		EventType:      eventType,
		EventTime:      time.Now().UTC(),
		NormalizedData: normalizedData,
		SchemaVersion:  testSchemaVersion,
		SecurityContext: securityContext,
		AuditMetadata:  auditMetadata,
		EncryptedFields: make(map[string][]byte),
	}

	// Apply field-level encryption if required
	if securityLevel == "high" || securityLevel == "critical" {
		if err := encryptSensitiveFields(event); err != nil {
			return nil, fmt.Errorf("failed to encrypt sensitive fields: %w", err)
		}
	}

	// Record test metrics
	metrics.RecordTestEvent("silver_event_created", map[string]string{
		"event_type":     eventType,
		"security_level": securityLevel,
	})

	return event, nil
}

// GenerateSecurityTestData generates test data for security validation scenarios
func GenerateSecurityTestData(securityLevel string) (map[string]interface{}, error) {
	if !isValidSecurityLevel(securityLevel) {
		return nil, fmt.Errorf("invalid security level: %s", securityLevel)
	}

	// Generate base test data
	testData := map[string]interface{}{
		"timestamp":       time.Now().UTC(),
		"security_level": securityLevel,
		"test_scenario":  fmt.Sprintf("security-validation-%s", securityLevel),
		"metadata": map[string]interface{}{
			"framework_version": testSchemaVersion,
			"test_mode":        true,
		},
	}

	// Add security-level specific test data
	switch securityLevel {
	case "low":
		testData["access_controls"] = []string{"public"}
		testData["encryption_required"] = false
	case "medium":
		testData["access_controls"] = []string{"internal", "authenticated"}
		testData["encryption_required"] = true
		testData["encryption_fields"] = []string{"metadata"}
	case "high":
		testData["access_controls"] = []string{"restricted", "mfa-required"}
		testData["encryption_required"] = true
		testData["encryption_fields"] = []string{"metadata", "content", "user_data"}
		testData["compliance_checks"] = []string{"pii", "audit-logging"}
	case "critical":
		testData["access_controls"] = []string{"highly-restricted", "mfa-required", "approval-required"}
		testData["encryption_required"] = true
		testData["encryption_fields"] = []string{"metadata", "content", "user_data", "system_data"}
		testData["compliance_checks"] = []string{"pii", "audit-logging", "field-level-encryption"}
	}

	// Add compliance markers
	testData["compliance_markers"] = generateComplianceMarkers(securityLevel)

	return testData, nil
}

// Helper functions

func isValidEventType(eventType string) bool {
	for _, t := range supportedEventTypes {
		if t == eventType {
			return true
		}
	}
	return false
}

func isValidSecurityLevel(level string) bool {
	for _, l := range securityLevels {
		if l == level {
			return true
		}
	}
	return false
}

func generateNormalizedTestData(eventType string) (map[string]interface{}, error) {
	data := map[string]interface{}{
		"event_type":     eventType,
		"timestamp":      time.Now().UTC(),
		"test_data":      true,
		"client_id":      testClientID,
		"schema_version": testSchemaVersion,
	}

	// Add event type specific test data
	switch eventType {
	case "auth":
		data["auth_type"] = "test-auth"
		data["user_id"] = "test-user-001"
		data["auth_method"] = "test-method"
	case "access":
		data["resource_id"] = "test-resource-001"
		data["access_type"] = "test-access"
		data["user_id"] = "test-user-001"
	case "security":
		data["alert_id"] = "test-alert-001"
		data["severity"] = "medium"
		data["category"] = "test-category"
	case "system":
		data["system_id"] = "test-system-001"
		data["action"] = "test-action"
		data["status"] = "success"
	case "compliance":
		data["policy_id"] = "test-policy-001"
		data["compliance_type"] = "test-compliance"
		data["status"] = "compliant"
	case "audit":
		data["audit_id"] = "test-audit-001"
		data["action"] = "test-audit-action"
		data["result"] = "success"
	}

	return data, nil
}

func getComplianceRequirements(securityLevel string) []string {
	switch securityLevel {
	case "low":
		return []string{"basic-logging"}
	case "medium":
		return []string{"basic-logging", "data-retention"}
	case "high":
		return []string{"basic-logging", "data-retention", "encryption", "access-control"}
	case "critical":
		return []string{"basic-logging", "data-retention", "encryption", "access-control", "audit-trail", "pii-protection"}
	default:
		return []string{"basic-logging"}
	}
}

func getEncryptionConfig(securityLevel string) map[string]string {
	config := make(map[string]string)
	switch securityLevel {
	case "low":
		config["transport"] = "tls-1.2"
	case "medium":
		config["transport"] = "tls-1.3"
		config["storage"] = "aes-256"
	case "high":
		config["transport"] = "tls-1.3"
		config["storage"] = "aes-256"
		config["field"] = "aes-256-gcm"
	case "critical":
		config["transport"] = "tls-1.3"
		config["storage"] = "aes-256"
		config["field"] = "aes-256-gcm"
		config["key_rotation"] = "enabled"
	}
	return config
}

func getAccessControlConfig(securityLevel string) map[string]string {
	config := make(map[string]string)
	switch securityLevel {
	case "low":
		config["read"] = "authenticated"
	case "medium":
		config["read"] = "authenticated"
		config["write"] = "authorized"
	case "high":
		config["read"] = "authorized"
		config["write"] = "mfa-required"
	case "critical":
		config["read"] = "mfa-required"
		config["write"] = "approval-required"
	}
	return config
}

func generateComplianceMarkers(securityLevel string) []string {
	markers := []string{"test-framework"}
	switch securityLevel {
	case "low":
		markers = append(markers, "basic-validation")
	case "medium":
		markers = append(markers, "basic-validation", "encryption-check")
	case "high":
		markers = append(markers, "basic-validation", "encryption-check", "access-control-check")
	case "critical":
		markers = append(markers, "basic-validation", "encryption-check", "access-control-check", "pii-check")
	}
	return markers
}

func encryptSensitiveFields(event *schema.SilverEvent) error {
	sensitiveFields := []string{"user_id", "credentials", "pii_data"}
	for _, field := range sensitiveFields {
		if value, exists := event.NormalizedData[field]; exists {
			encrypted, err := security.EncryptField(value)
			if err != nil {
				return fmt.Errorf("failed to encrypt field %s: %w", field, err)
			}
			event.EncryptedFields[field] = encrypted
			delete(event.NormalizedData, field)
		}
	}
	return nil
}