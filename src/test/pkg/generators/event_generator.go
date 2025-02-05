// Package generators provides test data generation capabilities for the BlackPoint Security Integration Framework
package generators

import (
    "encoding/json"
    "fmt"
    "sync"
    "time"

    "github.com/google/uuid" // v1.3.0

    "github.com/blackpoint/pkg/bronze/schema"
    "github.com/blackpoint/pkg/silver/schema"
    "github.com/blackpoint/pkg/gold/alert"
    "github.com/blackpoint/pkg/common/errors"
)

// Global constants for event generation
const (
    defaultBatchSize     = 1000
    maxBatchSize        = 10000
    maxConcurrentBatches = 50
    defaultErrorRate    = 0.1
)

// Supported event types and severities
var (
    supportedEventTypes = []string{"auth", "access", "security", "system"}
    supportedSeverities = []string{"critical", "high", "medium", "low", "info"}
)

// Compliance rules for test data generation
var complianceRules = map[string][]string{
    "PCI-DSS": {"data_encryption", "access_control", "audit_logging"},
    "HIPAA":   {"phi_protection", "access_monitoring", "breach_notification"},
    "SOC2":    {"security_monitoring", "incident_response", "change_management"},
    "GDPR":    {"data_privacy", "consent_management", "data_protection"},
}

// GeneratorConfig defines configuration for the event generator
type GeneratorConfig struct {
    BatchSize          int
    ErrorRate         float64
    ComplianceEnabled bool
    SecurityContext   map[string]interface{}
    ValidationRules   []ValidationRule
    PerformanceParams PerformanceParams
}

// ValidationRule defines a rule for validating generated events
type ValidationRule struct {
    Field     string
    Pattern   string
    Required  bool
    Validator func(interface{}) bool
}

// PerformanceParams defines performance-related parameters
type PerformanceParams struct {
    ConcurrentBatches int
    BatchTimeout      time.Duration
    RateLimit        int
    BufferSize       int
}

// EventGenerator handles generation of test events across all tiers
type EventGenerator struct {
    config         *GeneratorConfig
    templates      map[string]interface{}
    errorPatterns  map[string]ErrorPattern
    metrics        *GeneratorMetrics
    mutex          sync.RWMutex
    complianceRules map[string][]string
}

// GeneratorMetrics tracks event generation statistics
type GeneratorMetrics struct {
    EventsGenerated    uint64
    ValidationErrors   uint64
    ComplianceErrors   uint64
    ProcessingTime     time.Duration
    BatchesCompleted   uint64
}

// ErrorPattern defines patterns for generating test errors
type ErrorPattern struct {
    Probability float64
    ErrorType   string
    Payload     interface{}
}

// NewEventGenerator creates a new event generator instance
func NewEventGenerator(config *GeneratorConfig) (*EventGenerator, error) {
    if config == nil {
        return nil, errors.NewError("E3001", "generator config is required", nil)
    }

    // Apply default configuration if needed
    if config.BatchSize <= 0 {
        config.BatchSize = defaultBatchSize
    }
    if config.BatchSize > maxBatchSize {
        return nil, errors.NewError("E3001", "batch size exceeds maximum", nil)
    }
    if config.ErrorRate < 0 || config.ErrorRate > 1 {
        config.ErrorRate = defaultErrorRate
    }

    // Initialize generator
    gen := &EventGenerator{
        config:         config,
        templates:      make(map[string]interface{}),
        errorPatterns:  initializeErrorPatterns(),
        metrics:        &GeneratorMetrics{},
        complianceRules: complianceRules,
    }

    // Initialize event templates
    if err := gen.initializeTemplates(); err != nil {
        return nil, err
    }

    return gen, nil
}

// GenerateEvent generates a single event for the specified tier
func (g *EventGenerator) GenerateEvent(tier string, eventType string, securityContext map[string]interface{}) (interface{}, error) {
    g.mutex.Lock()
    defer g.mutex.Unlock()

    switch tier {
    case "bronze":
        return g.generateBronzeEvent(eventType, securityContext)
    case "silver":
        return g.generateSilverEvent(eventType, securityContext)
    case "gold":
        return g.generateGoldEvent(eventType, securityContext)
    default:
        return nil, errors.NewError("E3001", "unsupported tier", nil)
    }
}

// GenerateBatch generates a batch of events with parallel processing
func (g *EventGenerator) GenerateBatch(tier string, count int) ([]interface{}, error) {
    if count <= 0 || count > maxBatchSize {
        return nil, errors.NewError("E3001", "invalid batch size", nil)
    }

    results := make([]interface{}, count)
    errors := make([]error, count)
    var wg sync.WaitGroup

    // Calculate optimal batch size for parallel processing
    batchSize := g.config.BatchSize
    if batchSize > count {
        batchSize = count
    }

    // Process batches in parallel
    for i := 0; i < count; i += batchSize {
        wg.Add(1)
        go func(start int) {
            defer wg.Done()
            end := start + batchSize
            if end > count {
                end = count
            }

            for j := start; j < end; j++ {
                event, err := g.GenerateEvent(tier, g.randomEventType(), g.generateSecurityContext())
                results[j] = event
                errors[j] = err
            }
        }(i)
    }

    wg.Wait()

    // Check for errors
    for _, err := range errors {
        if err != nil {
            return nil, err
        }
    }

    return results, nil
}

// GenerateTestScenario generates a complete test scenario across all tiers
func (g *EventGenerator) GenerateTestScenario(scenarioConfig map[string]interface{}) (*TestScenario, error) {
    scenario := &TestScenario{
        BronzeEvents: make([]*schema.BronzeEvent, 0),
        SilverEvents: make([]*schema.SilverEvent, 0),
        GoldAlerts:   make([]*alert.Alert, 0),
    }

    // Generate Bronze events
    bronzeCount := scenarioConfig["bronze_count"].(int)
    bronzeEvents, err := g.GenerateBatch("bronze", bronzeCount)
    if err != nil {
        return nil, err
    }

    // Convert and validate Bronze events
    for _, event := range bronzeEvents {
        if bronzeEvent, ok := event.(*schema.BronzeEvent); ok {
            scenario.BronzeEvents = append(scenario.BronzeEvents, bronzeEvent)
        }
    }

    // Generate corresponding Silver events
    for _, bronzeEvent := range scenario.BronzeEvents {
        silverEvent, err := g.generateSilverFromBronze(bronzeEvent)
        if err != nil {
            continue // Skip failed conversions in test scenarios
        }
        scenario.SilverEvents = append(scenario.SilverEvents, silverEvent)
    }

    // Generate Gold alerts from correlated events
    if len(scenario.SilverEvents) > 0 {
        alerts, err := g.generateGoldAlerts(scenario.SilverEvents)
        if err != nil {
            return nil, err
        }
        scenario.GoldAlerts = alerts
    }

    return scenario, nil
}

// Helper functions

func (g *EventGenerator) generateBronzeEvent(eventType string, securityContext map[string]interface{}) (*schema.BronzeEvent, error) {
    clientID := uuid.New().String()
    payload := g.generateEventPayload(eventType)

    event, err := schema.NewBronzeEvent(clientID, "test_platform", payload)
    if err != nil {
        return nil, err
    }

    // Add security context
    if securityContext != nil {
        event.SecurityContext = securityContext
    }

    return event, nil
}

func (g *EventGenerator) generateSilverEvent(eventType string, securityContext map[string]interface{}) (*schema.SilverEvent, error) {
    normalizedData := g.generateNormalizedData(eventType)
    secCtx := schema.SecurityContext{
        Classification: "CONFIDENTIAL",
        Sensitivity:    "HIGH",
        Compliance:     []string{"PCI-DSS", "SOC2"},
    }

    event, err := schema.NewSilverEvent(uuid.New().String(), eventType, normalizedData, secCtx)
    if err != nil {
        return nil, err
    }

    return event, nil
}

func (g *EventGenerator) generateGoldEvent(eventType string, securityContext map[string]interface{}) (*alert.Alert, error) {
    ctx := &alert.SecurityMetadata{
        Classification: "RESTRICTED",
        DataSensitivity: "HIGH",
    }

    event := &schema.GoldEvent{
        Severity: g.randomSeverity(),
        IntelligenceData: g.generateIntelligenceData(),
    }

    alert, err := alert.CreateAlert(event, ctx)
    if err != nil {
        return nil, err
    }

    return alert, nil
}

// TestScenario represents a complete test scenario across all tiers
type TestScenario struct {
    BronzeEvents []*schema.BronzeEvent
    SilverEvents []*schema.SilverEvent
    GoldAlerts   []*alert.Alert
}

func (g *EventGenerator) randomEventType() string {
    return supportedEventTypes[time.Now().UnixNano()%int64(len(supportedEventTypes))]
}

func (g *EventGenerator) randomSeverity() string {
    return supportedSeverities[time.Now().UnixNano()%int64(len(supportedSeverities))]
}

func (g *EventGenerator) generateSecurityContext() map[string]interface{} {
    return map[string]interface{}{
        "classification": "CONFIDENTIAL",
        "sensitivity":    "HIGH",
        "compliance":     []string{"PCI-DSS", "SOC2"},
    }
}

func (g *EventGenerator) generateEventPayload(eventType string) json.RawMessage {
    payload := map[string]interface{}{
        "event_type": eventType,
        "timestamp":  time.Now().UTC(),
        "source_ip":  "192.168.1.1",
        "user_id":    uuid.New().String(),
    }
    data, _ := json.Marshal(payload)
    return data
}

func (g *EventGenerator) generateNormalizedData(eventType string) map[string]interface{} {
    return map[string]interface{}{
        "event_type":    eventType,
        "normalized_at": time.Now().UTC(),
        "metadata":      map[string]string{"source": "test_generator"},
    }
}

func (g *EventGenerator) generateIntelligenceData() map[string]interface{} {
    return map[string]interface{}{
        "threat_score":   0.85,
        "confidence":     0.9,
        "detection_rule": "TEST-001",
    }
}

func initializeErrorPatterns() map[string]ErrorPattern {
    return map[string]ErrorPattern{
        "validation": {
            Probability: 0.1,
            ErrorType:   "E3001",
            Payload:     "validation error",
        },
        "security": {
            Probability: 0.05,
            ErrorType:   "E1001",
            Payload:     "security violation",
        },
    }
}

func (g *EventGenerator) initializeTemplates() error {
    // Initialize templates for each event type
    for _, eventType := range supportedEventTypes {
        g.templates[eventType] = g.generateEventPayload(eventType)
    }
    return nil
}