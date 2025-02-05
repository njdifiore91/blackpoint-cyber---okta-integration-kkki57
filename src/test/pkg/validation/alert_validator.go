// Package validation provides comprehensive security-focused validation logic for alerts
// Version: 1.0.0
package validation

import (
    "fmt"
    "sync"
    "time"

    "github.com/blackpoint/pkg/gold"
    "../metrics"
    "../fixtures"
)

// AlertValidationModes defines supported validation modes
var AlertValidationModes = map[string]string{
    "strict":   "exact_match",
    "fuzzy":    "partial_match",
    "weighted": "field_weighted",
    "security": "security_focused",
}

// AlertFieldWeights defines importance weights for different alert fields
var AlertFieldWeights = map[string]float64{
    "severity":         1.0,
    "status":          0.8,
    "intelligence":    0.6,
    "security_context": 1.0,
    "compliance":      0.9,
    "audit_trail":     0.7,
}

// SecurityValidationThresholds defines minimum thresholds for security validation
var SecurityValidationThresholds = map[string]float64{
    "min_security_score":   0.8,
    "min_compliance_score": 0.9,
    "min_audit_score":      0.7,
}

// AlertValidator manages enhanced alert validation with security focus
type AlertValidator struct {
    validationMode     string
    fieldWeights      map[string]float64
    securityThresholds map[string]float64
    metrics           *metrics.AccuracyMetrics
    mu               sync.RWMutex
}

// NewAlertValidator creates a new AlertValidator instance with security configuration
func NewAlertValidator(mode string, weights map[string]float64, securityThresholds map[string]float64) (*AlertValidator, error) {
    if _, ok := AlertValidationModes[mode]; !ok {
        return nil, fmt.Errorf("invalid validation mode: %s", mode)
    }

    // Use provided weights or defaults
    if weights == nil {
        weights = AlertFieldWeights
    }

    // Use provided thresholds or defaults
    if securityThresholds == nil {
        securityThresholds = SecurityValidationThresholds
    }

    // Initialize accuracy metrics
    metricsInstance, err := metrics.NewAccuracyMetrics(mode, weights, nil)
    if err != nil {
        return nil, fmt.Errorf("failed to initialize accuracy metrics: %v", err)
    }

    return &AlertValidator{
        validationMode:      mode,
        fieldWeights:       weights,
        securityThresholds: securityThresholds,
        metrics:           metricsInstance,
    }, nil
}

// ValidateAlert validates a single alert with enhanced security context and compliance checks
func (av *AlertValidator) ValidateAlert(actualAlert, expectedAlert *gold.Alert) (map[string]interface{}, error) {
    av.mu.Lock()
    defer av.mu.Unlock()

    if actualAlert == nil || expectedAlert == nil {
        return nil, fmt.Errorf("nil alert provided")
    }

    // Validate basic alert fields
    if actualAlert.AlertID != expectedAlert.AlertID {
        return nil, fmt.Errorf("alert ID mismatch")
    }

    results := make(map[string]interface{})

    // Validate core fields
    results["status_match"] = actualAlert.Status == expectedAlert.Status
    results["severity_match"] = actualAlert.Severity == expectedAlert.Severity

    // Validate security context
    securityScore, err := av.ValidateSecurityContext(actualAlert)
    if err != nil {
        return nil, fmt.Errorf("security context validation failed: %v", err)
    }
    results["security_scores"] = securityScore

    // Calculate overall accuracy
    var accuracy float64
    switch av.validationMode {
    case "strict":
        accuracy = av.calculateStrictAccuracy(actualAlert, expectedAlert)
    case "weighted":
        accuracy = av.calculateWeightedAccuracy(actualAlert, expectedAlert)
    case "security":
        accuracy = av.calculateSecurityFocusedAccuracy(actualAlert, expectedAlert)
    default:
        accuracy = av.calculateFuzzyAccuracy(actualAlert, expectedAlert)
    }

    results["accuracy"] = accuracy
    results["passed"] = accuracy >= av.securityThresholds["min_security_score"]

    return results, nil
}

// ValidateAlertBatch validates a batch of alerts with comprehensive security validation
func (av *AlertValidator) ValidateAlertBatch(actualAlerts, expectedAlerts []*gold.Alert) (map[string]interface{}, error) {
    if len(actualAlerts) != len(expectedAlerts) {
        return nil, fmt.Errorf("alert batch size mismatch")
    }

    results := make(map[string]interface{})
    var totalAccuracy float64
    var securityScores []float64
    failedValidations := 0

    for i := range actualAlerts {
        alertResults, err := av.ValidateAlert(actualAlerts[i], expectedAlerts[i])
        if err != nil {
            failedValidations++
            continue
        }

        accuracy := alertResults["accuracy"].(float64)
        totalAccuracy += accuracy
        securityScores = append(securityScores, alertResults["security_scores"].(map[string]float64)["overall"])
    }

    batchSize := float64(len(actualAlerts))
    results["average_accuracy"] = totalAccuracy / batchSize
    results["security_score"] = calculateAverageScore(securityScores)
    results["failed_validations"] = failedValidations
    results["success_rate"] = (batchSize - float64(failedValidations)) / batchSize * 100

    // Generate comprehensive validation report
    report, err := av.GenerateValidationReport(results)
    if err != nil {
        return nil, fmt.Errorf("failed to generate validation report: %v", err)
    }
    results["validation_report"] = report

    return results, nil
}

// ValidateSecurityContext validates alert security context and compliance
func (av *AlertValidator) ValidateSecurityContext(alert *gold.Alert) (map[string]float64, error) {
    scores := make(map[string]float64)

    // Validate security metadata
    if alert.SecurityMetadata != nil {
        scores["metadata"] = validateSecurityMetadata(alert.SecurityMetadata)
    }

    // Validate compliance tags
    if len(alert.ComplianceTags) > 0 {
        scores["compliance"] = validateComplianceTags(alert.ComplianceTags)
    }

    // Validate audit trail
    if len(alert.AuditTrail) > 0 {
        scores["audit"] = validateAuditTrail(alert.AuditTrail)
    }

    // Calculate overall security score
    scores["overall"] = calculateWeightedSecurityScore(scores)

    return scores, nil
}

// GenerateValidationReport generates detailed validation report with security metrics
func (av *AlertValidator) GenerateValidationReport(results map[string]interface{}) (map[string]interface{}, error) {
    report := map[string]interface{}{
        "timestamp":        time.Now().UTC(),
        "validation_mode": av.validationMode,
        "metrics":         results,
        "thresholds":      av.securityThresholds,
        "validation_summary": map[string]interface{}{
            "accuracy_requirement_met": results["average_accuracy"].(float64) >= av.securityThresholds["min_security_score"],
            "security_requirement_met": results["security_score"].(float64) >= av.securityThresholds["min_security_score"],
        },
    }

    return report, nil
}

// Helper functions

func (av *AlertValidator) calculateStrictAccuracy(actual, expected *gold.Alert) float64 {
    matches := 0
    total := 6 // Number of critical fields to compare

    if actual.Status == expected.Status {
        matches++
    }
    if actual.Severity == expected.Severity {
        matches++
    }
    if validateMap(actual.IntelligenceData, expected.IntelligenceData) {
        matches++
    }
    if validateMap(actual.SecurityMetadata, expected.SecurityMetadata) {
        matches++
    }
    if validateStringSlice(actual.ComplianceTags, expected.ComplianceTags) {
        matches++
    }
    if validateAuditTrail(actual.AuditTrail) >= av.securityThresholds["min_audit_score"] {
        matches++
    }

    return float64(matches) / float64(total) * 100
}

func (av *AlertValidator) calculateWeightedAccuracy(actual, expected *gold.Alert) float64 {
    var weightedScore, totalWeight float64

    // Apply weights to each field
    for field, weight := range av.fieldWeights {
        switch field {
        case "severity":
            if actual.Severity == expected.Severity {
                weightedScore += weight
            }
        case "status":
            if actual.Status == expected.Status {
                weightedScore += weight
            }
        case "security_context":
            if scores, _ := av.ValidateSecurityContext(actual); scores["overall"] >= av.securityThresholds["min_security_score"] {
                weightedScore += weight
            }
        }
        totalWeight += weight
    }

    return (weightedScore / totalWeight) * 100
}

func (av *AlertValidator) calculateSecurityFocusedAccuracy(actual, expected *gold.Alert) float64 {
    securityScores, _ := av.ValidateSecurityContext(actual)
    baseAccuracy := av.calculateWeightedAccuracy(actual, expected)

    // Weight security scores more heavily
    return (baseAccuracy*0.4 + securityScores["overall"]*0.6)
}

func validateMap(actual, expected map[string]interface{}) bool {
    if len(actual) != len(expected) {
        return false
    }
    for k, v := range expected {
        if actualVal, ok := actual[k]; !ok || actualVal != v {
            return false
        }
    }
    return true
}

func validateStringSlice(actual, expected []string) bool {
    if len(actual) != len(expected) {
        return false
    }
    for i, v := range expected {
        if actual[i] != v {
            return false
        }
    }
    return true
}

func validateSecurityMetadata(metadata map[string]interface{}) float64 {
    if metadata == nil {
        return 0
    }
    requiredFields := []string{"classification", "data_sensitivity", "security_zone"}
    matches := 0
    for _, field := range requiredFields {
        if _, ok := metadata[field]; ok {
            matches++
        }
    }
    return float64(matches) / float64(len(requiredFields))
}

func validateComplianceTags(tags []string) float64 {
    if len(tags) == 0 {
        return 0
    }
    return 1.0
}

func validateAuditTrail(trail []gold.AuditEntry) float64 {
    if len(trail) == 0 {
        return 0
    }
    validEntries := 0
    for _, entry := range trail {
        if entry.Action != "" && !entry.Timestamp.IsZero() && entry.Actor != "" {
            validEntries++
        }
    }
    return float64(validEntries) / float64(len(trail))
}

func calculateWeightedSecurityScore(scores map[string]float64) float64 {
    weights := map[string]float64{
        "metadata":   0.4,
        "compliance": 0.3,
        "audit":     0.3,
    }

    var weightedScore, totalWeight float64
    for category, score := range scores {
        if weight, ok := weights[category]; ok {
            weightedScore += score * weight
            totalWeight += weight
        }
    }

    if totalWeight == 0 {
        return 0
    }
    return weightedScore / totalWeight
}

func calculateAverageScore(scores []float64) float64 {
    if len(scores) == 0 {
        return 0
    }
    var sum float64
    for _, score := range scores {
        sum += score
    }
    return sum / float64(len(scores))
}