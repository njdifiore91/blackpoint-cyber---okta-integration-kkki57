// Package gold implements the Gold tier schema and validation for security intelligence events
package gold

import (
	"encoding/json"
	"time"
	"crypto/aes"

	"github.com/blackpoint/pkg/common/errors"
	"github.com/blackpoint/pkg/common/utils"
)

// Schema version for Gold tier events
const schemaVersion = "2.0"

// Maximum field length for string values
const maxFieldLength = 8192

// Required fields for Gold tier events
var requiredFields = []string{
	"alert_id",
	"client_id", 
	"severity",
	"detection_time",
	"intelligence_data",
	"silver_event_ids",
	"security_context",
	"audit_metadata",
}

// Allowed severity levels
var severityLevels = []string{
	"critical",
	"high", 
	"medium",
	"low",
	"info",
}

// Fields requiring encryption
var encryptedFields = []string{
	"pii_data",
	"credentials",
	"sensitive_indicators",
}

// SecurityMetadata contains security-related metadata for Gold events
type SecurityMetadata struct {
	Classification    string            `json:"classification"`
	ConfidenceScore  float64           `json:"confidence_score"`
	ThreatLevel      string            `json:"threat_level"`
	DataSensitivity  string            `json:"data_sensitivity"`
	SecurityTags     []string          `json:"security_tags"`
	EncryptionInfo   map[string]string `json:"encryption_info"`
}

// AuditMetadata contains audit trail information
type AuditMetadata struct {
	CreatedBy    string    `json:"created_by"`
	CreatedAt    time.Time `json:"created_at"`
	ModifiedBy   string    `json:"modified_by"`
	ModifiedAt   time.Time `json:"modified_at"`
	AccessLog    []string  `json:"access_log"`
	ValidationID string    `json:"validation_id"`
}

// ComplianceMetadata contains compliance-related information
type ComplianceMetadata struct {
	Standards     []string          `json:"standards"`
	Requirements  map[string]string `json:"requirements"`
	DataRetention string           `json:"data_retention"`
	DataHandling  string           `json:"data_handling"`
}

// GoldEvent represents a security intelligence event in the Gold tier
type GoldEvent struct {
	AlertID          string                 `json:"alert_id"`
	ClientID         string                 `json:"client_id"`
	Severity         string                 `json:"severity"`
	DetectionTime    time.Time             `json:"detection_time"`
	IntelligenceData map[string]interface{} `json:"intelligence_data"`
	SilverEventIDs   []string              `json:"silver_event_ids"`
	SchemaVersion    string                `json:"schema_version"`
	SecurityMetadata SecurityMetadata      `json:"security_context"`
	AuditMetadata    AuditMetadata        `json:"audit_metadata"`
	EncryptedFields  map[string][]byte    `json:"encrypted_fields"`
	ComplianceInfo   ComplianceMetadata   `json:"compliance_metadata"`
}

// ValidateWithSecurity performs comprehensive validation of a Gold event with security checks
func (e *GoldEvent) ValidateWithSecurity() error {
	return ValidateSecuritySchema(e)
}

// ValidateSecuritySchema validates a security intelligence event against the Gold tier schema
func ValidateSecuritySchema(event *GoldEvent) error {
	if event == nil {
		return errors.NewSecurityError("E3001", "event cannot be nil", nil)
	}

	// Validate required fields
	for _, field := range requiredFields {
		switch field {
		case "alert_id":
			if event.AlertID == "" {
				return errors.NewSecurityError("E3001", "alert_id is required", nil)
			}
			if !utils.ValidateSecurityPattern(event.AlertID, "^[a-zA-Z0-9-]{36}$") {
				return errors.NewSecurityError("E3001", "invalid alert_id format", nil)
			}
		case "client_id":
			if event.ClientID == "" {
				return errors.NewSecurityError("E3001", "client_id is required", nil)
			}
			if !utils.ValidateSecurityPattern(event.ClientID, "^[a-zA-Z0-9-]{36}$") {
				return errors.NewSecurityError("E3001", "invalid client_id format", nil)
			}
		case "severity":
			if event.Severity == "" {
				return errors.NewSecurityError("E3001", "severity is required", nil)
			}
			validSeverity := false
			for _, s := range severityLevels {
				if event.Severity == s {
					validSeverity = true
					break
				}
			}
			if !validSeverity {
				return errors.NewSecurityError("E3001", "invalid severity level", nil)
			}
		}
	}

	// Validate timestamps
	if !utils.ValidateTimestamp(event.DetectionTime) {
		return errors.NewSecurityError("E3001", "invalid detection_time", nil)
	}
	if !utils.ValidateTimestamp(event.AuditMetadata.CreatedAt) {
		return errors.NewSecurityError("E3001", "invalid audit creation timestamp", nil)
	}

	// Validate intelligence data
	if event.IntelligenceData == nil {
		return errors.NewSecurityError("E3001", "intelligence_data is required", nil)
	}
	intelligenceJSON, err := json.Marshal(event.IntelligenceData)
	if err != nil {
		return errors.WrapSecurityError(err, "failed to validate intelligence_data", nil)
	}
	if len(intelligenceJSON) > maxFieldLength {
		return errors.NewSecurityError("E3001", "intelligence_data exceeds maximum size", nil)
	}

	// Validate silver event references
	if len(event.SilverEventIDs) == 0 {
		return errors.NewSecurityError("E3001", "at least one silver_event_id is required", nil)
	}
	for _, id := range event.SilverEventIDs {
		if !utils.ValidateSecurityPattern(id, "^[a-zA-Z0-9-]{36}$") {
			return errors.NewSecurityError("E3001", "invalid silver_event_id format", nil)
		}
	}

	// Validate schema version
	if event.SchemaVersion != schemaVersion {
		return errors.NewSecurityError("E3001", "unsupported schema version", nil)
	}

	// Validate security metadata
	if event.SecurityMetadata.ConfidenceScore < 0 || event.SecurityMetadata.ConfidenceScore > 1 {
		return errors.NewSecurityError("E3001", "confidence score must be between 0 and 1", nil)
	}

	// Validate encrypted fields
	for field := range event.EncryptedFields {
		isEncrypted := false
		for _, ef := range encryptedFields {
			if field == ef {
				isEncrypted = true
				break
			}
		}
		if !isEncrypted {
			return errors.NewSecurityError("E3001", "invalid encrypted field", nil)
		}
	}

	// Validate compliance metadata
	if len(event.ComplianceInfo.Standards) == 0 {
		return errors.NewSecurityError("E3001", "at least one compliance standard is required", nil)
	}

	return nil
}