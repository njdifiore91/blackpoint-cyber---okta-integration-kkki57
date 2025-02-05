// Package bronze provides schema definitions and validation for raw security events
package bronze

import (
    "encoding/json"
    "time"

    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/utils"
    "github.com/blackpoint/pkg/common/logging"
)

// Schema version for Bronze tier events
const schemaVersion = "1.0"

// Maximum size for raw event payload (1MB)
const maxPayloadSize = 1048576

// Allowed security platforms for event sources
var allowedSourcePlatforms = []string{
    "aws",
    "azure",
    "gcp",
    "okta",
}

// Maximum age allowed for event timestamps
const maxTimestampAge = 24 * time.Hour

// BronzeEvent represents a raw security event in the Bronze tier
type BronzeEvent struct {
    ID              string          `json:"id"`
    ClientID        string          `json:"client_id"`
    SourcePlatform  string          `json:"source_platform"`
    Timestamp       time.Time       `json:"timestamp"`
    Payload         json.RawMessage `json:"payload"`
    SchemaVersion   string          `json:"schema_version"`
    SecurityContext string          `json:"security_context,omitempty"`
    AuditMetadata   map[string]string `json:"audit_metadata,omitempty"`
}

// NewBronzeEvent creates a new BronzeEvent with enhanced security features
func NewBronzeEvent(clientID string, sourcePlatform string, payload json.RawMessage) (*BronzeEvent, error) {
    // Generate secure UUID for event ID
    eventID, err := utils.GenerateUUID()
    if err != nil {
        logging.Error("Failed to generate event ID", err)
        return nil, errors.WrapError(err, "event ID generation failed", nil)
    }

    // Create event with current timestamp
    event := &BronzeEvent{
        ID:             eventID,
        ClientID:       clientID,
        SourcePlatform: sourcePlatform,
        Timestamp:      time.Now().UTC(),
        Payload:        payload,
        SchemaVersion:  schemaVersion,
        AuditMetadata:  make(map[string]string),
    }

    // Validate the new event
    if err := event.Validate(); err != nil {
        return nil, err
    }

    // Log security audit event
    logging.SecurityAudit("Created new Bronze event", map[string]interface{}{
        "event_id":        eventID,
        "client_id":       clientID,
        "source_platform": sourcePlatform,
        "payload_size":    len(payload),
    })

    return event, nil
}

// Validate performs comprehensive validation of the BronzeEvent
func (e *BronzeEvent) Validate() error {
    // Check for required fields
    if e.ID == "" {
        return errors.NewError("E3001", "missing event ID", nil)
    }
    if e.ClientID == "" {
        return errors.NewError("E3001", "missing client ID", nil)
    }
    if e.SourcePlatform == "" {
        return errors.NewError("E3001", "missing source platform", nil)
    }
    if e.Payload == nil {
        return errors.NewError("E3001", "missing payload", nil)
    }

    // Validate event ID format
    if err := utils.ValidateJSON(e.ID, utils.ValidationOptions{
        MaxDepth:   1,
        StrictMode: true,
    }); err != nil {
        return errors.WrapError(err, "invalid event ID format", nil)
    }

    // Validate source platform
    validPlatform := false
    for _, platform := range allowedSourcePlatforms {
        if e.SourcePlatform == platform {
            validPlatform = true
            break
        }
    }
    if !validPlatform {
        return errors.NewError("E3001", "invalid source platform", map[string]interface{}{
            "platform": e.SourcePlatform,
            "allowed":  allowedSourcePlatforms,
        })
    }

    // Validate timestamp
    if e.Timestamp.IsZero() {
        return errors.NewError("E3001", "missing timestamp", nil)
    }
    age := time.Since(e.Timestamp)
    if age > maxTimestampAge {
        return errors.NewError("E3001", "event timestamp too old", map[string]interface{}{
            "max_age": maxTimestampAge,
            "age":     age,
        })
    }

    // Validate payload size
    if len(e.Payload) > maxPayloadSize {
        return errors.NewError("E3001", "payload size exceeds limit", map[string]interface{}{
            "max_size":    maxPayloadSize,
            "actual_size": len(e.Payload),
        })
    }

    // Validate payload JSON structure
    if err := utils.ValidateJSON(string(e.Payload), utils.ValidationOptions{
        MaxDepth:    20,
        MaxSize:     int64(maxPayloadSize),
        AllowNulls:  false,
        StrictMode:  true,
    }); err != nil {
        return errors.WrapError(err, "invalid payload format", nil)
    }

    // Sanitize payload data
    sanitizedPayload := utils.SanitizeString(string(e.Payload), utils.SanitizationOptions{
        MaxLength:  maxPayloadSize,
        StripHTML:  true,
        TrimSpace: true,
    })
    e.Payload = json.RawMessage(sanitizedPayload)

    return nil
}

// ToJSON converts the BronzeEvent to JSON format with security sanitization
func (e *BronzeEvent) ToJSON() ([]byte, error) {
    // Create a sanitized copy for JSON conversion
    sanitizedEvent := *e

    // Sanitize sensitive fields
    sanitizedEvent.SecurityContext = utils.SanitizeString(e.SecurityContext, utils.SanitizationOptions{
        MaxLength:  1000,
        StripHTML:  true,
        TrimSpace: true,
    })

    // Marshal to JSON
    data, err := json.Marshal(sanitizedEvent)
    if err != nil {
        return nil, errors.WrapError(err, "failed to marshal event to JSON", nil)
    }

    // Log audit event
    logging.SecurityAudit("Converted Bronze event to JSON", map[string]interface{}{
        "event_id": e.ID,
        "size":     len(data),
    })

    return data, nil
}

// ValidateSchema performs validation of a BronzeEvent against the schema
func ValidateSchema(event *BronzeEvent) error {
    if event == nil {
        return errors.NewError("E3001", "nil event", nil)
    }

    // Perform schema validation
    if err := event.Validate(); err != nil {
        logging.Error("Schema validation failed", err, map[string]interface{}{
            "event_id": event.ID,
        })
        return err
    }

    // Log successful validation
    logging.SecurityAudit("Schema validation successful", map[string]interface{}{
        "event_id":        event.ID,
        "client_id":       event.ClientID,
        "source_platform": event.SourcePlatform,
        "schema_version": schemaVersion,
    })

    return nil
}