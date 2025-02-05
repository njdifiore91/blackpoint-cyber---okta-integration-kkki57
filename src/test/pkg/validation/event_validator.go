// Package validation provides comprehensive event validation testing utilities
package validation

import (
    "testing"
    "time"

    "../common"
    "../fixtures"
    "./schema_validator"
)

// ValidationErrorCodes defines error codes for validation failures
var ValidationErrorCodes = map[string]string{
    "SCHEMA_ERROR":          "V1001",
    "LATENCY_ERROR":        "V1002", 
    "THROUGHPUT_ERROR":     "V1003",
    "ACCURACY_ERROR":       "V1004",
    "SECURITY_CONTEXT_ERROR": "V1005",
    "ENCRYPTION_ERROR":     "V1006",
    "COMPLIANCE_ERROR":     "V1007",
}

// ValidationThresholds defines validation thresholds per technical specifications
var ValidationThresholds = struct {
    MaxBronzeLatency time.Duration
    MaxSilverLatency time.Duration
    MaxGoldLatency   time.Duration
    MinThroughput    int
    MinAccuracy      float64
    MinSecurityScore float64
}{
    MaxBronzeLatency: time.Second,
    MaxSilverLatency: 5 * time.Second,
    MaxGoldLatency:   30 * time.Second,
    MinThroughput:    1000,
    MinAccuracy:      0.8,
    MinSecurityScore: 0.95,
}

// SecurityContext represents security validation context
type SecurityContext struct {
    Classification    string
    Sensitivity      string
    ComplianceReqs   []string
    EncryptionLevel  string
    AuditLevel       string
}

// SecurityMetrics tracks security validation metrics
type SecurityMetrics struct {
    ProcessingTime   time.Duration
    SecurityOverhead time.Duration
    EncryptionTime   time.Duration
    ComplianceChecks int
    SecurityScore    float64
}

// EventValidator provides validation utilities for security events
type EventValidator struct {
    t               *testing.T
    schemaValidator *schema_validator.SchemaValidator
    securityContext *SecurityContext
    metrics         *SecurityMetrics
}

// NewEventValidator creates a new EventValidator instance
func NewEventValidator(t *testing.T, securityCtx *SecurityContext) *EventValidator {
    return &EventValidator{
        t:               t,
        schemaValidator: schema_validator.NewSchemaValidator(t),
        securityContext: securityCtx,
        metrics:         &SecurityMetrics{},
    }
}

// ValidateEventProcessing validates complete event processing including security
func ValidateEventProcessing(t *testing.T, event interface{}, securityCtx *SecurityContext) error {
    startTime := time.Now()
    defer func() {
        processingTime := time.Since(startTime)
        t.Logf("Event processing validation completed in %v", processingTime)
    }()

    validator := NewEventValidator(t, securityCtx)

    // Validate event schema and security context
    if err := validator.validateEventSchema(event); err != nil {
        return common.NewTestError("SCHEMA_ERROR", "Schema validation failed: %v", err)
    }

    // Validate field-level encryption
    if err := validator.validateEncryption(event); err != nil {
        return common.NewTestError("ENCRYPTION_ERROR", "Encryption validation failed: %v", err)
    }

    // Validate processing latency with security overhead
    if err := validator.validateProcessingLatency(event); err != nil {
        return common.NewTestError("LATENCY_ERROR", "Latency validation failed: %v", err)
    }

    // Validate data transformation accuracy
    if err := validator.validateAccuracy(event); err != nil {
        return common.NewTestError("ACCURACY_ERROR", "Accuracy validation failed: %v", err)
    }

    // Validate compliance requirements
    if err := validator.validateCompliance(event); err != nil {
        return common.NewTestError("COMPLIANCE_ERROR", "Compliance validation failed: %v", err)
    }

    return nil
}

// ValidateEventLatency validates processing latency for an event tier
func ValidateEventLatency(t *testing.T, tier string, latency time.Duration, securityMetrics *SecurityMetrics) error {
    // Determine tier-specific threshold
    var threshold time.Duration
    switch tier {
    case "bronze":
        threshold = ValidationThresholds.MaxBronzeLatency
    case "silver":
        threshold = ValidationThresholds.MaxSilverLatency
    case "gold":
        threshold = ValidationThresholds.MaxGoldLatency
    default:
        return common.NewTestError("LATENCY_ERROR", "Invalid tier specified: %s", tier)
    }

    // Account for security processing overhead
    totalLatency := latency
    if securityMetrics != nil {
        totalLatency += securityMetrics.SecurityOverhead
    }

    if totalLatency > threshold {
        return common.NewTestError("LATENCY_ERROR", 
            "Processing latency %v exceeds threshold %v for tier %s",
            totalLatency, threshold, tier)
    }

    return nil
}

// validateEventSchema validates event schema with security context
func (v *EventValidator) validateEventSchema(event interface{}) error {
    startTime := time.Now()
    defer func() {
        v.metrics.ProcessingTime = time.Since(startTime)
    }()

    // Validate base schema
    if !v.schemaValidator.ValidateEventSchema(event, getTierFromEvent(event)) {
        return common.NewTestError("SCHEMA_ERROR", "Invalid event schema")
    }

    // Validate security context
    if err := v.validateSecurityContext(event); err != nil {
        return err
    }

    return nil
}

// validateSecurityContext validates event security context
func (v *EventValidator) validateSecurityContext(event interface{}) error {
    if v.securityContext == nil {
        return common.NewTestError("SECURITY_CONTEXT_ERROR", "Missing security context")
    }

    // Validate classification
    if v.securityContext.Classification == "" {
        return common.NewTestError("SECURITY_CONTEXT_ERROR", "Missing security classification")
    }

    // Validate compliance requirements
    if len(v.securityContext.ComplianceReqs) == 0 {
        return common.NewTestError("SECURITY_CONTEXT_ERROR", "Missing compliance requirements")
    }

    // Validate encryption level
    if v.securityContext.EncryptionLevel == "" {
        return common.NewTestError("SECURITY_CONTEXT_ERROR", "Missing encryption level")
    }

    return nil
}

// validateEncryption validates field-level encryption
func (v *EventValidator) validateEncryption(event interface{}) error {
    startTime := time.Now()
    defer func() {
        v.metrics.EncryptionTime = time.Since(startTime)
    }()

    // Implementation depends on event type and encryption requirements
    switch e := event.(type) {
    case *fixtures.BronzeEvent:
        return v.validateBronzeEncryption(e)
    // Add cases for Silver and Gold events
    default:
        return common.NewTestError("ENCRYPTION_ERROR", "Unsupported event type for encryption validation")
    }
}

// validateProcessingLatency validates event processing latency
func (v *EventValidator) validateProcessingLatency(event interface{}) error {
    tier := getTierFromEvent(event)
    return ValidateEventLatency(v.t, tier, v.metrics.ProcessingTime, v.metrics)
}

// validateAccuracy validates data transformation accuracy
func (v *EventValidator) validateAccuracy(event interface{}) error {
    // Calculate accuracy score based on field correctness
    accuracyScore := calculateAccuracyScore(event)
    
    if accuracyScore < ValidationThresholds.MinAccuracy {
        return common.NewTestError("ACCURACY_ERROR", 
            "Accuracy score %.2f below threshold %.2f",
            accuracyScore, ValidationThresholds.MinAccuracy)
    }

    return nil
}

// validateCompliance validates compliance requirements
func (v *EventValidator) validateCompliance(event interface{}) error {
    v.metrics.ComplianceChecks++

    if v.securityContext == nil || len(v.securityContext.ComplianceReqs) == 0 {
        return common.NewTestError("COMPLIANCE_ERROR", "Missing compliance requirements")
    }

    // Validate against each compliance requirement
    for _, req := range v.securityContext.ComplianceReqs {
        if err := validateComplianceRequirement(event, req); err != nil {
            return err
        }
    }

    return nil
}

// Helper functions

func getTierFromEvent(event interface{}) string {
    switch event.(type) {
    case *fixtures.BronzeEvent:
        return "bronze"
    // Add cases for Silver and Gold events
    default:
        return "unknown"
    }
}

func calculateAccuracyScore(event interface{}) float64 {
    // Implementation depends on validation requirements
    // Returns a score between 0 and 1
    return 1.0 // Placeholder
}

func validateComplianceRequirement(event interface{}, requirement string) error {
    // Implementation depends on specific compliance requirements
    return nil // Placeholder
}