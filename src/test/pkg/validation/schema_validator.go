// Package validation provides comprehensive schema validation testing utilities
package validation

import (
    "encoding/json"
    "testing"
    "time"

    "github.com/blackpoint/pkg/bronze"
    "github.com/blackpoint/pkg/silver"
    "github.com/blackpoint/pkg/gold"
    "github.com/blackpoint/pkg/metrics" // v1.0.0
)

// SchemaValidator provides test utilities for schema validation across tiers
type SchemaValidator struct {
    t *testing.T
    metricsCollector *metrics.Collector
}

// NewSchemaValidator creates a new SchemaValidator instance
func NewSchemaValidator(t *testing.T) *SchemaValidator {
    collector, err := metrics.NewCollector("schema_validation")
    if err != nil {
        t.Fatalf("Failed to create metrics collector: %v", err)
    }

    return &SchemaValidator{
        t:               t,
        metricsCollector: collector,
    }
}

// ValidateBronzeSchema validates Bronze tier event schemas with enhanced error reporting
func ValidateBronzeSchema(t *testing.T, event *bronze.BronzeEvent) bool {
    startTime := time.Now()
    defer func() {
        metrics.RecordLatency("bronze_validation", time.Since(startTime))
    }()

    if event == nil {
        t.Error("Bronze event cannot be nil")
        metrics.IncrementCounter("bronze_validation_errors", map[string]string{"type": "nil_event"})
        return false
    }

    err := bronze.ValidateSchema(event)
    if err != nil {
        t.Errorf("Bronze schema validation failed: %v", err)
        metrics.IncrementCounter("bronze_validation_errors", map[string]string{
            "type": "schema_error",
            "client_id": event.ClientID,
        })
        return false
    }

    // Additional validation checks
    if len(event.Payload) == 0 {
        t.Error("Bronze event payload cannot be empty")
        metrics.IncrementCounter("bronze_validation_errors", map[string]string{"type": "empty_payload"})
        return false
    }

    if event.SchemaVersion == "" {
        t.Error("Bronze event schema version cannot be empty")
        metrics.IncrementCounter("bronze_validation_errors", map[string]string{"type": "missing_version"})
        return false
    }

    metrics.IncrementCounter("bronze_validation_success", map[string]string{"client_id": event.ClientID})
    return true
}

// ValidateSilverSchema validates Silver tier event schemas with enhanced error reporting
func ValidateSilverSchema(t *testing.T, event *silver.SilverEvent) bool {
    startTime := time.Now()
    defer func() {
        metrics.RecordLatency("silver_validation", time.Since(startTime))
    }()

    if event == nil {
        t.Error("Silver event cannot be nil")
        metrics.IncrementCounter("silver_validation_errors", map[string]string{"type": "nil_event"})
        return false
    }

    err := silver.ValidateSchema(event)
    if err != nil {
        t.Errorf("Silver schema validation failed: %v", err)
        metrics.IncrementCounter("silver_validation_errors", map[string]string{
            "type": "schema_error",
            "client_id": event.ClientID,
        })
        return false
    }

    // Validate security context
    if event.SecurityContext.Classification == "" {
        t.Error("Silver event security classification cannot be empty")
        metrics.IncrementCounter("silver_validation_errors", map[string]string{"type": "missing_classification"})
        return false
    }

    // Validate normalized data structure
    if len(event.NormalizedData) == 0 {
        t.Error("Silver event normalized data cannot be empty")
        metrics.IncrementCounter("silver_validation_errors", map[string]string{"type": "empty_normalized_data"})
        return false
    }

    metrics.IncrementCounter("silver_validation_success", map[string]string{"client_id": event.ClientID})
    return true
}

// ValidateGoldSchema validates Gold tier event schemas with enhanced error reporting
func ValidateGoldSchema(t *testing.T, event *gold.GoldEvent) bool {
    startTime := time.Now()
    defer func() {
        metrics.RecordLatency("gold_validation", time.Since(startTime))
    }()

    if event == nil {
        t.Error("Gold event cannot be nil")
        metrics.IncrementCounter("gold_validation_errors", map[string]string{"type": "nil_event"})
        return false
    }

    err := gold.ValidateSecuritySchema(event)
    if err != nil {
        t.Errorf("Gold schema validation failed: %v", err)
        metrics.IncrementCounter("gold_validation_errors", map[string]string{
            "type": "schema_error",
            "client_id": event.ClientID,
        })
        return false
    }

    // Validate intelligence data
    if len(event.IntelligenceData) == 0 {
        t.Error("Gold event intelligence data cannot be empty")
        metrics.IncrementCounter("gold_validation_errors", map[string]string{"type": "empty_intelligence_data"})
        return false
    }

    // Validate severity level
    validSeverity := false
    for _, s := range []string{"critical", "high", "medium", "low", "info"} {
        if event.Severity == s {
            validSeverity = true
            break
        }
    }
    if !validSeverity {
        t.Errorf("Invalid Gold event severity level: %s", event.Severity)
        metrics.IncrementCounter("gold_validation_errors", map[string]string{"type": "invalid_severity"})
        return false
    }

    metrics.IncrementCounter("gold_validation_success", map[string]string{"client_id": event.ClientID})
    return true
}

// ValidateSchemaTransformation validates schema transformations between tiers
func ValidateSchemaTransformation(t *testing.T, sourceEvent interface{}, transformedEvent interface{}, tier string) bool {
    startTime := time.Now()
    defer func() {
        metrics.RecordLatency("transformation_validation", time.Since(startTime))
    }()

    // Validate source event exists
    if sourceEvent == nil {
        t.Error("Source event cannot be nil")
        metrics.IncrementCounter("transformation_errors", map[string]string{"type": "nil_source"})
        return false
    }

    // Validate transformed event exists
    if transformedEvent == nil {
        t.Error("Transformed event cannot be nil")
        metrics.IncrementCounter("transformation_errors", map[string]string{"type": "nil_transformed"})
        return false
    }

    // Validate based on tier
    switch tier {
    case "silver":
        bronzeEvent, ok := sourceEvent.(*bronze.BronzeEvent)
        if !ok {
            t.Error("Invalid source event type for Silver tier")
            return false
        }
        silverEvent, ok := transformedEvent.(*silver.SilverEvent)
        if !ok {
            t.Error("Invalid transformed event type for Silver tier")
            return false
        }
        
        // Verify Bronze to Silver transformation
        if silverEvent.BronzeEventID != bronzeEvent.ID {
            t.Error("Bronze event ID not preserved in Silver transformation")
            return false
        }

    case "gold":
        silverEvent, ok := sourceEvent.(*silver.SilverEvent)
        if !ok {
            t.Error("Invalid source event type for Gold tier")
            return false
        }
        goldEvent, ok := transformedEvent.(*gold.GoldEvent)
        if !ok {
            t.Error("Invalid transformed event type for Gold tier")
            return false
        }

        // Verify Silver to Gold transformation
        found := false
        for _, id := range goldEvent.SilverEventIDs {
            if id == silverEvent.EventID {
                found = true
                break
            }
        }
        if !found {
            t.Error("Silver event ID not preserved in Gold transformation")
            return false
        }
    
    default:
        t.Errorf("Unsupported transformation tier: %s", tier)
        return false
    }

    metrics.IncrementCounter("transformation_success", map[string]string{"tier": tier})
    return true
}

// ValidateEventSchema validates event schema for any tier with enhanced error reporting
func (v *SchemaValidator) ValidateEventSchema(event interface{}, tier string) bool {
    switch tier {
    case "bronze":
        if bronzeEvent, ok := event.(*bronze.BronzeEvent); ok {
            return ValidateBronzeSchema(v.t, bronzeEvent)
        }
    case "silver":
        if silverEvent, ok := event.(*silver.SilverEvent); ok {
            return ValidateSilverSchema(v.t, silverEvent)
        }
    case "gold":
        if goldEvent, ok := event.(*gold.GoldEvent); ok {
            return ValidateGoldSchema(v.t, goldEvent)
        }
    }
    
    v.t.Errorf("Invalid event type for tier: %s", tier)
    return false
}

// AssertValidSchema asserts that an event has a valid schema
func (v *SchemaValidator) AssertValidSchema(event interface{}, tier string) {
    if !v.ValidateEventSchema(event, tier) {
        v.t.Fatalf("Schema validation failed for %s tier event", tier)
    }
}