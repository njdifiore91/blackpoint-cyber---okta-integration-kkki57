// Package silver provides schema definitions and validation for normalized security events
package silver

import (
    "encoding/json"
    "time"

    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/utils"
    "../bronze/schema"
)

// Schema version for Silver tier events
const schemaVersion = "1.0"

// Maximum field length for string values
const maxFieldLength = 4096

// Required fields for Silver tier events
var requiredFields = []string{
    "event_id",
    "client_id",
    "event_type",
    "event_time",
    "normalized_data",
    "security_context",
    "audit_metadata",
}

// Fields requiring encryption
var sensitiveFields = []string{
    "pii",
    "credentials",
    "auth_tokens",
}

// SecurityContext represents the security metadata for an event
type SecurityContext struct {
    Classification string            `json:"classification"`
    Sensitivity    string            `json:"sensitivity"`
    Compliance     []string          `json:"compliance"`
    Encryption     map[string]string `json:"encryption"`
    AccessControl  map[string]string `json:"access_control"`
}

// AuditMetadata represents audit trail information
type AuditMetadata struct {
    CreatedAt     time.Time `json:"created_at"`
    CreatedBy     string    `json:"created_by"`
    NormalizedAt  time.Time `json:"normalized_at"`
    NormalizedBy  string    `json:"normalized_by"`
    SchemaVersion string    `json:"schema_version"`
    SourceEventID string    `json:"source_event_id"`
}

// SilverEvent represents a normalized security event with enhanced security features
type SilverEvent struct {
    EventID        string                 `json:"event_id"`
    ClientID       string                 `json:"client_id"`
    EventType      string                 `json:"event_type"`
    EventTime      time.Time              `json:"event_time"`
    NormalizedData map[string]interface{} `json:"normalized_data"`
    SchemaVersion  string                 `json:"schema_version"`
    BronzeEventID  string                 `json:"bronze_event_id"`
    SecurityContext SecurityContext        `json:"security_context"`
    AuditMetadata  AuditMetadata         `json:"audit_metadata"`
    EncryptedFields map[string][]byte     `json:"encrypted_fields,omitempty"`
}

// NewSilverEvent creates a new SilverEvent with security context
func NewSilverEvent(clientID string, eventType string, normalizedData map[string]interface{}, securityContext SecurityContext) (*SilverEvent, error) {
    eventID, err := utils.GenerateUUID()
    if err != nil {
        return nil, errors.WrapError(err, "failed to generate event ID", nil)
    }

    event := &SilverEvent{
        EventID:        eventID,
        ClientID:       clientID,
        EventType:      eventType,
        EventTime:      time.Now().UTC(),
        NormalizedData: normalizedData,
        SchemaVersion:  schemaVersion,
        SecurityContext: securityContext,
        AuditMetadata: AuditMetadata{
            CreatedAt:     time.Now().UTC(),
            CreatedBy:     "system",
            NormalizedAt:  time.Now().UTC(),
            NormalizedBy:  "normalizer",
            SchemaVersion: schemaVersion,
        },
        EncryptedFields: make(map[string][]byte),
    }

    // Encrypt sensitive fields
    if err := event.encryptSensitiveFields(); err != nil {
        return nil, err
    }

    // Validate the new event
    if err := event.Validate(); err != nil {
        return nil, err
    }

    return event, nil
}

// FromBronzeEvent creates a Silver event from a Bronze event
func (s *SilverEvent) FromBronzeEvent(bronzeEvent *schema.BronzeEvent, normalizedData map[string]interface{}, securityContext SecurityContext) error {
    if bronzeEvent == nil {
        return errors.NewError("E3001", "nil bronze event", nil)
    }

    s.BronzeEventID = bronzeEvent.ID
    s.ClientID = bronzeEvent.ClientID
    s.NormalizedData = normalizedData
    s.SecurityContext = securityContext
    s.AuditMetadata.SourceEventID = bronzeEvent.ID

    // Encrypt sensitive fields
    if err := s.encryptSensitiveFields(); err != nil {
        return err
    }

    return s.Validate()
}

// Validate performs comprehensive validation of the SilverEvent
func (s *SilverEvent) Validate() error {
    if s == nil {
        return errors.NewError("E3001", "nil event", nil)
    }

    // Validate required fields
    for _, field := range requiredFields {
        if !s.hasRequiredField(field) {
            return errors.NewError("E3001", "missing required field", map[string]interface{}{
                "field": field,
            })
        }
    }

    // Validate field lengths
    if err := s.validateFieldLengths(); err != nil {
        return err
    }

    // Validate security context
    if err := s.validateSecurityContext(); err != nil {
        return err
    }

    // Validate normalized data structure
    if err := utils.ValidateJSON(string(s.marshalNormalizedData()), utils.ValidationOptions{
        MaxDepth:   20,
        MaxSize:    int64(maxFieldLength),
        StrictMode: true,
    }); err != nil {
        return errors.WrapError(err, "invalid normalized data format", nil)
    }

    return nil
}

// ToJSON converts the SilverEvent to JSON with security handling
func (s *SilverEvent) ToJSON() ([]byte, error) {
    // Create a sanitized copy for JSON conversion
    sanitizedEvent := *s

    // Temporarily decrypt fields for JSON conversion
    if err := sanitizedEvent.decryptFields(); err != nil {
        return nil, err
    }

    // Marshal to JSON
    data, err := json.Marshal(sanitizedEvent)
    if err != nil {
        return nil, errors.WrapError(err, "failed to marshal event to JSON", nil)
    }

    // Re-encrypt fields
    if err := sanitizedEvent.encryptSensitiveFields(); err != nil {
        return nil, err
    }

    return data, nil
}

// ValidateSchema performs validation of a SilverEvent against the schema
func ValidateSchema(event *SilverEvent) error {
    if event == nil {
        return errors.NewError("E3001", "nil event", nil)
    }

    return event.Validate()
}

// Helper functions

func (s *SilverEvent) hasRequiredField(field string) bool {
    switch field {
    case "event_id":
        return s.EventID != ""
    case "client_id":
        return s.ClientID != ""
    case "event_type":
        return s.EventType != ""
    case "event_time":
        return !s.EventTime.IsZero()
    case "normalized_data":
        return s.NormalizedData != nil
    case "security_context":
        return s.SecurityContext.Classification != ""
    case "audit_metadata":
        return !s.AuditMetadata.CreatedAt.IsZero()
    default:
        return false
    }
}

func (s *SilverEvent) validateFieldLengths() error {
    if len(s.EventID) > maxFieldLength {
        return errors.NewError("E3001", "event ID exceeds maximum length", nil)
    }
    if len(s.ClientID) > maxFieldLength {
        return errors.NewError("E3001", "client ID exceeds maximum length", nil)
    }
    if len(s.EventType) > maxFieldLength {
        return errors.NewError("E3001", "event type exceeds maximum length", nil)
    }
    return nil
}

func (s *SilverEvent) validateSecurityContext() error {
    if s.SecurityContext.Classification == "" {
        return errors.NewError("E3001", "missing security classification", nil)
    }
    if s.SecurityContext.Sensitivity == "" {
        return errors.NewError("E3001", "missing sensitivity level", nil)
    }
    if len(s.SecurityContext.Compliance) == 0 {
        return errors.NewError("E3001", "missing compliance requirements", nil)
    }
    return nil
}

func (s *SilverEvent) encryptSensitiveFields() error {
    for _, field := range sensitiveFields {
        if value, ok := s.NormalizedData[field]; ok {
            encrypted, err := utils.EncryptField(value)
            if err != nil {
                return errors.WrapError(err, "failed to encrypt sensitive field", map[string]interface{}{
                    "field": field,
                })
            }
            s.EncryptedFields[field] = encrypted
            delete(s.NormalizedData, field)
        }
    }
    return nil
}

func (s *SilverEvent) decryptFields() error {
    for field, encrypted := range s.EncryptedFields {
        decrypted, err := utils.DecryptField(encrypted)
        if err != nil {
            return errors.WrapError(err, "failed to decrypt field", map[string]interface{}{
                "field": field,
            })
        }
        s.NormalizedData[field] = decrypted
    }
    return nil
}

func (s *SilverEvent) marshalNormalizedData() []byte {
    data, _ := json.Marshal(s.NormalizedData)
    return data
}