// Package gold implements enhanced request validation and data sanitization for Gold tier API endpoints
package gold

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "regexp"
    "time"

    "github.com/blackpoint/pkg/gold/schema"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/utils"
    "github.com/blackpoint/security"  // v1.0.0
    "github.com/blackpoint/monitoring" // v1.0.0
    "go.opentelemetry.io/otel"        // v1.0.0
    "go.opentelemetry.io/otel/trace"
)

// Maximum request size for Gold tier API endpoints (10MB)
const maxRequestSize int64 = 10485760

// Validation error codes with descriptions
var validationErrorCodes = map[string]string{
    "invalid_request": "GOLD-VAL-001",
    "schema_violation": "GOLD-VAL-002",
    "invalid_correlation": "GOLD-VAL-003",
    "security_pattern_violation": "GOLD-VAL-004",
    "threat_intelligence_violation": "GOLD-VAL-005",
}

// Security pattern validation for common attack vectors
var securityPatterns = map[string]string{
    "sql_injection": `(?i)(\b(select|insert|update|delete|drop|union|exec)\b)`,
    "xss": `(<script|javascript:|vbscript:|livescript:)`,
    "command_injection": `(\b(cmd|powershell|bash|sh|wget|curl)\b)`,
}

// ValidateCreateAlertRequest validates a request to create a new security intelligence alert
func ValidateCreateAlertRequest(r *http.Request, ti *security.ThreatIntelligence) (*schema.GoldEvent, error) {
    ctx := r.Context()
    tracer := otel.Tracer("gold-validation")
    ctx, span := tracer.Start(ctx, "ValidateCreateAlertRequest")
    defer span.End()

    // Initialize validation metrics
    monitoring.RecordValidationAttempt("gold", "create_alert")
    defer monitoring.RecordValidationDuration("gold", time.Now())

    // Validate request size
    if r.ContentLength > maxRequestSize {
        monitoring.RecordValidationError("gold", "size_exceeded")
        return nil, errors.NewError(validationErrorCodes["invalid_request"], 
            fmt.Sprintf("request size exceeds maximum allowed size of %d bytes", maxRequestSize), nil)
    }

    // Read and parse request body
    body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestSize))
    if err != nil {
        monitoring.RecordValidationError("gold", "read_error")
        return nil, errors.WrapError(err, "failed to read request body", nil)
    }

    // Validate JSON structure
    var rawEvent map[string]interface{}
    if err := json.Unmarshal(body, &rawEvent); err != nil {
        monitoring.RecordValidationError("gold", "invalid_json")
        return nil, errors.WrapError(err, "invalid JSON format", nil)
    }

    // Security pattern validation
    if err := validateSecurityPatterns(body); err != nil {
        monitoring.RecordValidationError("gold", "security_pattern")
        return nil, err
    }

    // Create GoldEvent instance
    event := &schema.GoldEvent{}
    if err := json.Unmarshal(body, event); err != nil {
        monitoring.RecordValidationError("gold", "schema_violation")
        return nil, errors.WrapError(err, "failed to parse event data", nil)
    }

    // Validate schema
    if err := event.ValidateWithSecurity(); err != nil {
        monitoring.RecordValidationError("gold", "schema_validation")
        return nil, errors.WrapError(err, "schema validation failed", nil)
    }

    // Validate client authorization
    if err := validateClientAuthorization(r, event.ClientID); err != nil {
        monitoring.RecordValidationError("gold", "authorization")
        return nil, err
    }

    // Threat intelligence validation
    if err := validateThreatIntelligence(event, ti); err != nil {
        monitoring.RecordValidationError("gold", "threat_intelligence")
        return nil, err
    }

    // Record successful validation
    monitoring.RecordValidationSuccess("gold", "create_alert")
    span.SetAttributes(trace.StringAttribute("event.id", event.AlertID))

    return event, nil
}

// ValidateUpdateAlertRequest validates a request to update an existing security intelligence alert
func ValidateUpdateAlertRequest(r *http.Request, alertID string, ti *security.ThreatIntelligence) (*schema.GoldEvent, error) {
    ctx := r.Context()
    tracer := otel.Tracer("gold-validation")
    ctx, span := tracer.Start(ctx, "ValidateUpdateAlertRequest")
    defer span.End()

    // Initialize validation metrics
    monitoring.RecordValidationAttempt("gold", "update_alert")
    defer monitoring.RecordValidationDuration("gold", time.Now())

    // Validate alert ID format
    if !utils.ValidateSecurityPattern(alertID, "^[a-zA-Z0-9-]{36}$") {
        monitoring.RecordValidationError("gold", "invalid_alert_id")
        return nil, errors.NewError(validationErrorCodes["invalid_request"], "invalid alert ID format", nil)
    }

    // Validate request size
    if r.ContentLength > maxRequestSize {
        monitoring.RecordValidationError("gold", "size_exceeded")
        return nil, errors.NewError(validationErrorCodes["invalid_request"], 
            fmt.Sprintf("request size exceeds maximum allowed size of %d bytes", maxRequestSize), nil)
    }

    // Read and parse request body
    body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestSize))
    if err != nil {
        monitoring.RecordValidationError("gold", "read_error")
        return nil, errors.WrapError(err, "failed to read request body", nil)
    }

    // Validate JSON structure
    var rawEvent map[string]interface{}
    if err := json.Unmarshal(body, &rawEvent); err != nil {
        monitoring.RecordValidationError("gold", "invalid_json")
        return nil, errors.WrapError(err, "invalid JSON format", nil)
    }

    // Security pattern validation
    if err := validateSecurityPatterns(body); err != nil {
        monitoring.RecordValidationError("gold", "security_pattern")
        return nil, err
    }

    // Create GoldEvent instance
    event := &schema.GoldEvent{}
    if err := json.Unmarshal(body, event); err != nil {
        monitoring.RecordValidationError("gold", "schema_violation")
        return nil, errors.WrapError(err, "failed to parse event data", nil)
    }

    // Validate alert ID matches
    if event.AlertID != alertID {
        monitoring.RecordValidationError("gold", "alert_id_mismatch")
        return nil, errors.NewError(validationErrorCodes["invalid_request"], "alert ID mismatch", nil)
    }

    // Validate schema
    if err := event.ValidateWithSecurity(); err != nil {
        monitoring.RecordValidationError("gold", "schema_validation")
        return nil, errors.WrapError(err, "schema validation failed", nil)
    }

    // Validate client authorization
    if err := validateClientAuthorization(r, event.ClientID); err != nil {
        monitoring.RecordValidationError("gold", "authorization")
        return nil, err
    }

    // Threat intelligence validation
    if err := validateThreatIntelligence(event, ti); err != nil {
        monitoring.RecordValidationError("gold", "threat_intelligence")
        return nil, err
    }

    // Record successful validation
    monitoring.RecordValidationSuccess("gold", "update_alert")
    span.SetAttributes(trace.StringAttribute("event.id", event.AlertID))

    return event, nil
}

// validateSecurityPatterns checks for common security attack patterns
func validateSecurityPatterns(data []byte) error {
    dataStr := string(data)
    for patternName, pattern := range securityPatterns {
        re := regexp.MustCompile(pattern)
        if re.MatchString(dataStr) {
            return errors.NewError(validationErrorCodes["security_pattern_violation"],
                fmt.Sprintf("detected potential %s attack pattern", patternName),
                map[string]interface{}{"pattern": patternName})
        }
    }
    return nil
}

// validateClientAuthorization validates client authorization for the request
func validateClientAuthorization(r *http.Request, clientID string) error {
    authHeader := r.Header.Get("Authorization")
    if authHeader == "" {
        return errors.NewError(validationErrorCodes["invalid_request"], "missing authorization header", nil)
    }

    // Validate client credentials and permissions
    if !security.ValidateClientAccess(authHeader, clientID, "gold:write") {
        return errors.NewError(validationErrorCodes["invalid_request"], "unauthorized client access", nil)
    }

    return nil
}

// validateThreatIntelligence performs threat intelligence validation on the event
func validateThreatIntelligence(event *schema.GoldEvent, ti *security.ThreatIntelligence) error {
    if ti == nil {
        return errors.NewError(validationErrorCodes["threat_intelligence_violation"], 
            "threat intelligence service unavailable", nil)
    }

    // Validate against threat intelligence data
    score, err := ti.AnalyzeEvent(event)
    if err != nil {
        return errors.WrapError(err, "threat intelligence analysis failed", nil)
    }

    // Check threat score threshold
    if score > 0.7 {
        return errors.NewError(validationErrorCodes["threat_intelligence_violation"],
            "event exceeded threat intelligence threshold",
            map[string]interface{}{"threat_score": score})
    }

    return nil
}