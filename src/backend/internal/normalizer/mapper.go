// Package normalizer provides field mapping functionality for security event normalization
package normalizer

import (
    "encoding/json"
    "strings"
    "sync"
    "time"

    "github.com/blackpoint/pkg/bronze/schema"
    "github.com/blackpoint/pkg/silver/schema"
    "github.com/blackpoint/pkg/common/errors"
    "go.uber.org/zap"
)

// Standard field name mappings for common security event fields
var standardFieldNames = map[string]string{
    "source_ip": "src_ip",
    "destination_ip": "dst_ip",
    "source_port": "src_port",
    "destination_port": "dst_port",
    "event_timestamp": "event_time",
    "alert_severity": "severity",
    "alert_type": "event_type",
    "source_user": "src_user",
    "target_user": "dst_user",
}

// Required fields for normalized events
var requiredFields = []string{
    "event_type",
    "event_time",
    "src_ip",
    "dst_ip",
}

// Field type validations for data integrity
var fieldTypeValidations = map[string]string{
    "src_ip": "ipv4",
    "dst_ip": "ipv4",
    "event_time": "timestamp",
    "severity": "enum",
    "port": "uint16",
}

// FieldMapper handles field mapping operations with performance optimization
type FieldMapper struct {
    standardMappings map[string]string
    customMappings   map[string]string
    requiredFields   []string
    pathCache       sync.Map
    logger         *zap.Logger
    metrics        *fieldMapperMetrics
}

// fieldMapperMetrics tracks performance metrics
type fieldMapperMetrics struct {
    mappingDuration   *zap.Timer
    cacheHits         *zap.Counter
    validationErrors  *zap.Counter
    eventsProcessed   *zap.Counter
}

// NewFieldMapper creates a new FieldMapper with configuration
func NewFieldMapper(customMappings map[string]string, logger *zap.Logger) *FieldMapper {
    metrics := &fieldMapperMetrics{
        mappingDuration:   zap.NewTimer("field_mapping_duration"),
        cacheHits:         zap.NewCounter("field_mapping_cache_hits"),
        validationErrors:  zap.NewCounter("field_mapping_validation_errors"),
        eventsProcessed:   zap.NewCounter("events_processed_total"),
    }

    return &FieldMapper{
        standardMappings: standardFieldNames,
        customMappings:   customMappings,
        requiredFields:   requiredFields,
        logger:          logger,
        metrics:         metrics,
    }
}

// MapEvent maps a Bronze event to Silver format with optimizations
func (fm *FieldMapper) MapEvent(bronzeEvent *schema.BronzeEvent) (*schema.SilverEvent, error) {
    if bronzeEvent == nil {
        return nil, errors.NewError("E3001", "nil bronze event", nil)
    }

    defer fm.metrics.mappingDuration.Start().Stop()
    fm.metrics.eventsProcessed.Inc()

    // Parse bronze event payload
    var rawData map[string]interface{}
    if err := json.Unmarshal(bronzeEvent.Payload, &rawData); err != nil {
        fm.metrics.validationErrors.Inc()
        return nil, errors.WrapError(err, "failed to parse bronze event payload", nil)
    }

    // Map fields with caching
    normalizedData, err := fm.mapFields(rawData)
    if err != nil {
        return nil, err
    }

    // Create security context
    securityContext := schema.SecurityContext{
        Classification: "normalized",
        Sensitivity:    "medium",
        Compliance:     []string{"default"},
        Encryption:     make(map[string]string),
        AccessControl:  make(map[string]string),
    }

    // Create Silver event
    silverEvent, err := schema.NewSilverEvent(
        bronzeEvent.ClientID,
        normalizedData["event_type"].(string),
        normalizedData,
        securityContext,
    )
    if err != nil {
        return nil, err
    }

    // Set Bronze event reference
    silverEvent.BronzeEventID = bronzeEvent.ID

    return silverEvent, nil
}

// mapFields performs the actual field mapping with performance optimization
func (fm *FieldMapper) mapFields(rawData map[string]interface{}) (map[string]interface{}, error) {
    normalizedData := make(map[string]interface{}, len(rawData))

    // Apply standard mappings first
    for sourceField, targetField := range fm.standardMappings {
        if value, exists := rawData[sourceField]; exists {
            if err := fm.validateField(targetField, value); err != nil {
                fm.metrics.validationErrors.Inc()
                return nil, err
            }
            normalizedData[targetField] = value
        }
    }

    // Apply custom mappings
    for sourceField, targetField := range fm.customMappings {
        if value, exists := rawData[sourceField]; exists {
            // Check cache for complex field paths
            if cachedValue, ok := fm.pathCache.Load(sourceField); ok {
                fm.metrics.cacheHits.Inc()
                normalizedData[targetField] = cachedValue
                continue
            }

            if err := fm.validateField(targetField, value); err != nil {
                fm.metrics.validationErrors.Inc()
                return nil, err
            }
            normalizedData[targetField] = value
            fm.pathCache.Store(sourceField, value)
        }
    }

    // Validate required fields
    if err := fm.validateRequiredFields(normalizedData); err != nil {
        fm.metrics.validationErrors.Inc()
        return nil, err
    }

    return normalizedData, nil
}

// validateField performs type validation for specific fields
func (fm *FieldMapper) validateField(fieldName string, value interface{}) error {
    if validationType, exists := fieldTypeValidations[fieldName]; exists {
        switch validationType {
        case "ipv4":
            if _, ok := value.(string); !ok {
                return errors.NewError("E3001", "invalid IP address format", map[string]interface{}{
                    "field": fieldName,
                    "value": value,
                })
            }
        case "timestamp":
            switch v := value.(type) {
            case string:
                if _, err := time.Parse(time.RFC3339, v); err != nil {
                    return errors.NewError("E3001", "invalid timestamp format", map[string]interface{}{
                        "field": fieldName,
                        "value": v,
                    })
                }
            case float64:
                // Unix timestamp validation
                if v < 0 {
                    return errors.NewError("E3001", "invalid timestamp value", nil)
                }
            default:
                return errors.NewError("E3001", "invalid timestamp type", nil)
            }
        case "enum":
            if _, ok := value.(string); !ok {
                return errors.NewError("E3001", "invalid enum value", map[string]interface{}{
                    "field": fieldName,
                    "value": value,
                })
            }
        case "uint16":
            switch v := value.(type) {
            case float64:
                if v < 0 || v > 65535 {
                    return errors.NewError("E3001", "port number out of range", nil)
                }
            default:
                return errors.NewError("E3001", "invalid port number type", nil)
            }
        }
    }
    return nil
}

// validateRequiredFields ensures all required fields are present
func (fm *FieldMapper) validateRequiredFields(data map[string]interface{}) error {
    for _, field := range fm.requiredFields {
        if _, exists := data[field]; !exists {
            return errors.NewError("E3001", "missing required field", map[string]interface{}{
                "field": field,
            })
        }
    }
    return nil
}

// AddCustomMapping adds or updates a custom field mapping
func (fm *FieldMapper) AddCustomMapping(sourceField, targetField string) {
    fm.customMappings[sourceField] = targetField
    fm.pathCache.Delete(sourceField) // Clear cache for updated mapping
}

// ClearCache clears the field path cache
func (fm *FieldMapper) ClearCache() {
    fm.pathCache = sync.Map{}
}