// Package fixtures provides test fixtures for the BlackPoint Security Integration Framework
package fixtures

import (
	"crypto/rand"
	"encoding/json"
	"time"

	"github.com/blackpoint/pkg/common/utils"
	"github.com/blackpoint/pkg/gold"
)

// Test data constants for Gold tier alerts
var (
	testAlertSeverities = []string{"critical", "high", "medium", "low", "info"}
	testAlertStatuses   = []string{"new", "acknowledged", "investigating", "resolved", "closed"}
	testComplianceTags  = []string{"SOC2", "GDPR", "PCI", "HIPAA"}
	testSecurityContexts = []string{"internal", "external", "third_party", "customer"}
)

const defaultTestAlertCount = 100

// NewTestGoldAlert creates a new test Gold alert with predefined test data and security metadata
func NewTestGoldAlert() (*gold.Alert, error) {
	// Generate cryptographically secure alert ID
	alertID, err := utils.GenerateUUID()
	if err != nil {
		return nil, err
	}

	// Generate random severity using crypto/rand
	severityIndex, err := secureRandomIndex(len(testAlertSeverities))
	if err != nil {
		return nil, err
	}

	// Generate test intelligence data
	intelligenceData := map[string]interface{}{
		"detection_source": "test_fixture",
		"threat_type":     "test_threat",
		"indicators":      []string{"test_indicator_1", "test_indicator_2"},
		"confidence":      0.85,
		"timestamp":      time.Now().UTC().Format(time.RFC3339),
	}

	// Generate security metadata
	securityMetadata := map[string]interface{}{
		"classification":    "test_data",
		"data_sensitivity": "medium",
		"security_zone":    "test",
		"encryption_level": "high",
	}

	// Create test alert with security validation
	alert := &gold.Alert{
		AlertID:          alertID,
		Status:           "new",
		Severity:         testAlertSeverities[severityIndex],
		IntelligenceData: intelligenceData,
		SecurityMetadata: securityMetadata,
		ComplianceTags:   []string{"SOC2", "GDPR"},
		AuditTrail: []gold.AuditEntry{{
			Action:    "created",
			Timestamp: time.Now().UTC(),
			Actor:     "test_fixture",
			Context:   "test_generation",
		}},
	}

	// Validate security context
	if err := utils.ValidateSecurityContext(alert); err != nil {
		return nil, err
	}

	return alert, nil
}

// NewTestGoldAlertWithParams creates a new test Gold alert with specified parameters
func NewTestGoldAlertWithParams(severity string, status string, intelligenceData map[string]interface{}, 
	securityMetadata map[string]interface{}, complianceTags []string) (*gold.Alert, error) {
	
	// Validate input parameters
	if !isValidSeverity(severity) || !isValidStatus(status) {
		return nil, fmt.Errorf("invalid severity or status")
	}

	// Generate secure alert ID
	alertID, err := utils.GenerateUUID()
	if err != nil {
		return nil, err
	}

	// Create alert with specified parameters
	alert := &gold.Alert{
		AlertID:          alertID,
		Status:           status,
		Severity:         severity,
		IntelligenceData: intelligenceData,
		SecurityMetadata: securityMetadata,
		ComplianceTags:   complianceTags,
		AuditTrail: []gold.AuditEntry{{
			Action:    "created",
			Timestamp: time.Now().UTC(),
			Actor:     "test_fixture",
			Context:   "parameterized_test",
		}},
	}

	// Validate security context
	if err := utils.ValidateSecurityContext(alert); err != nil {
		return nil, err
	}

	return alert, nil
}

// GenerateTestGoldAlertBatch generates a batch of test Gold alerts with security validation
func GenerateTestGoldAlertBatch(count int, securityContext map[string]interface{}) ([]*gold.Alert, error) {
	if count <= 0 {
		count = defaultTestAlertCount
	}

	alerts := make([]*gold.Alert, count)
	errChan := make(chan error, count)
	alertChan := make(chan *gold.Alert, count)

	// Generate alerts concurrently
	for i := 0; i < count; i++ {
		go func() {
			alert, err := NewTestGoldAlert()
			if err != nil {
				errChan <- err
				return
			}

			// Add batch-specific security context
			if securityContext != nil {
				alert.SecurityMetadata["batch_context"] = securityContext
			}

			alertChan <- alert
		}()
	}

	// Collect results
	for i := 0; i < count; i++ {
		select {
		case err := <-errChan:
			return nil, err
		case alert := <-alertChan:
			alerts[i] = alert
		}
	}

	return alerts, nil
}

// Helper functions

// secureRandomIndex generates a cryptographically secure random index
func secureRandomIndex(max int) (int, error) {
	b := make([]byte, 1)
	_, err := rand.Read(b)
	if err != nil {
		return 0, err
	}
	return int(b[0]) % max, nil
}

// isValidSeverity checks if the severity level is valid
func isValidSeverity(severity string) bool {
	for _, s := range testAlertSeverities {
		if s == severity {
			return true
		}
	}
	return false
}

// isValidStatus checks if the status is valid
func isValidStatus(status string) bool {
	for _, s := range testAlertStatuses {
		if s == status {
			return true
		}
	}
	return false
}