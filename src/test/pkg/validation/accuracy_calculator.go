// Package validation provides accuracy calculation functionality for the BlackPoint Security Integration Framework
// Version: 1.0.0
package validation

import (
    "fmt"
    "math"
    "sync"
    "time"

    "../../pkg/common/utils"
    "../../pkg/metrics/accuracy_metrics"
    "./event_validator"
)

// Global constants for accuracy thresholds
var AccuracyThresholds = map[string]float64{
    "critical": 90.0,
    "high":     85.0,
    "medium":   82.0,
    "low":      80.0,
}

// ComparisonModes defines supported accuracy calculation methods
var ComparisonModes = map[string]string{
    "strict":   "exact_match",
    "fuzzy":    "partial_match",
    "weighted": "field_weighted",
    "security": "security_context_match",
}

// SecurityValidationConfig defines security validation requirements
var SecurityValidationConfig = map[string]interface{}{
    "encryption_required":    true,
    "field_level_validation": true,
    "compliance_check":       true,
}

// AccuracyCalculator manages accuracy calculation with security validation
type AccuracyCalculator struct {
    comparisonMode  string
    thresholds      map[string]float64
    metrics         *accuracy_metrics.AccuracyMetrics
    securityConfig  map[string]interface{}
    complianceRules map[string]interface{}
    mu             sync.RWMutex
}

// NewAccuracyCalculator creates a new AccuracyCalculator instance
func NewAccuracyCalculator(mode string, customThresholds map[string]float64, securityConfig map[string]interface{}, complianceRules map[string]interface{}) (*AccuracyCalculator, error) {
    // Validate comparison mode
    if _, ok := ComparisonModes[mode]; !ok {
        return nil, fmt.Errorf("invalid comparison mode: %s", mode)
    }

    // Initialize thresholds
    thresholds := AccuracyThresholds
    if customThresholds != nil {
        thresholds = customThresholds
    }

    // Initialize metrics
    metrics, err := accuracy_metrics.NewAccuracyMetrics(mode, nil, securityConfig)
    if err != nil {
        return nil, fmt.Errorf("failed to initialize accuracy metrics: %v", err)
    }

    return &AccuracyCalculator{
        comparisonMode:  mode,
        thresholds:      thresholds,
        metrics:         metrics,
        securityConfig:  securityConfig,
        complianceRules: complianceRules,
    }, nil
}

// Calculate performs accuracy calculation with security validation
func (ac *AccuracyCalculator) Calculate(actual interface{}, expected interface{}) (float64, map[string]interface{}, error) {
    ac.mu.Lock()
    defer ac.mu.Unlock()

    startTime := time.Now()

    // Validate input data
    if actual == nil || expected == nil {
        return 0, nil, fmt.Errorf("actual and expected data cannot be nil")
    }

    // Validate security context
    validator := event_validator.NewEventValidator(nil, &event_validator.SecurityContext{
        Classification:   "high",
        ComplianceReqs:  []string{"SOC2", "ISO27001"},
        EncryptionLevel: "AES256",
    })

    if err := validator.ValidateSecurityContext(actual); err != nil {
        return 0, nil, fmt.Errorf("security context validation failed: %v", err)
    }

    // Calculate accuracy based on comparison mode
    var accuracy float64
    var err error

    switch ac.comparisonMode {
    case "strict":
        accuracy, err = ac.calculateStrictAccuracy(actual, expected)
    case "fuzzy":
        accuracy, err = ac.calculateFuzzyAccuracy(actual, expected)
    case "weighted":
        accuracy, err = ac.calculateWeightedAccuracy(actual, expected)
    case "security":
        accuracy, err = ac.calculateSecurityAwareAccuracy(actual, expected)
    }

    if err != nil {
        return 0, nil, err
    }

    // Generate security validation results
    securityResults := map[string]interface{}{
        "validation_time":    time.Since(startTime).Seconds(),
        "security_score":     ac.calculateSecurityScore(actual),
        "compliance_status":  ac.validateCompliance(actual),
        "encryption_status":  ac.validateEncryption(actual),
        "validation_passed":  accuracy >= ac.thresholds["low"],
        "threshold_applied":  ac.thresholds["low"],
    }

    return accuracy, securityResults, nil
}

// GenerateReport generates comprehensive accuracy and security analysis report
func (ac *AccuracyCalculator) GenerateReport(results []interface{}, securityMetrics map[string]interface{}) (map[string]interface{}, error) {
    if len(results) == 0 {
        return nil, fmt.Errorf("no results to analyze")
    }

    // Calculate overall metrics
    overallAccuracy := 0.0
    securityScore := 0.0
    complianceRate := 0.0
    validationCount := len(results)

    for _, result := range results {
        if metrics, ok := result.(map[string]interface{}); ok {
            if acc, exists := metrics["accuracy"].(float64); exists {
                overallAccuracy += acc
            }
            if score, exists := metrics["security_score"].(float64); exists {
                securityScore += score
            }
            if rate, exists := metrics["compliance_rate"].(float64); exists {
                complianceRate += rate
            }
        }
    }

    // Generate detailed report
    report := map[string]interface{}{
        "summary": map[string]interface{}{
            "total_validations":     validationCount,
            "average_accuracy":      overallAccuracy / float64(validationCount),
            "average_security":      securityScore / float64(validationCount),
            "compliance_rate":       complianceRate / float64(validationCount),
            "validation_timestamp":  time.Now().UTC(),
            "comparison_mode":       ac.comparisonMode,
        },
        "thresholds": ac.thresholds,
        "security_metrics": securityMetrics,
        "validation_details": map[string]interface{}{
            "passed_validations": ac.countPassedValidations(results),
            "failed_validations": ac.countFailedValidations(results),
            "security_violations": ac.analyzeSecurityViolations(results),
        },
    }

    return report, nil
}

// Helper functions

func (ac *AccuracyCalculator) calculateStrictAccuracy(actual, expected interface{}) (float64, error) {
    matches := utils.ValidateTestData(nil, actual, map[string]interface{}{
        "expected": expected,
        "mode":    "strict",
    })
    return float64(matches.(int)) * 100, nil
}

func (ac *AccuracyCalculator) calculateFuzzyAccuracy(actual, expected interface{}) (float64, error) {
    metrics, err := ac.metrics.CalculateEventAccuracy(actual, expected)
    if err != nil {
        return 0, err
    }
    return metrics * 100, nil
}

func (ac *AccuracyCalculator) calculateWeightedAccuracy(actual, expected interface{}) (float64, error) {
    metrics, err := ac.metrics.CalculateBatchAccuracy([]interface{}{actual}, []interface{}{expected})
    if err != nil {
        return 0, err
    }
    return metrics["average_accuracy"] * 100, nil
}

func (ac *AccuracyCalculator) calculateSecurityAwareAccuracy(actual, expected interface{}) (float64, error) {
    baseAccuracy, err := ac.calculateWeightedAccuracy(actual, expected)
    if err != nil {
        return 0, err
    }

    securityScore := ac.calculateSecurityScore(actual)
    return math.Min(baseAccuracy, securityScore*100), nil
}

func (ac *AccuracyCalculator) calculateSecurityScore(data interface{}) float64 {
    validator := event_validator.NewEventValidator(nil, nil)
    if err := validator.ValidateEventProcessing(nil, data, nil); err != nil {
        return 0.0
    }
    return 1.0
}

func (ac *AccuracyCalculator) validateCompliance(data interface{}) bool {
    if ac.complianceRules == nil {
        return true
    }
    validator := event_validator.NewEventValidator(nil, nil)
    return validator.ValidateCompliance(data) == nil
}

func (ac *AccuracyCalculator) validateEncryption(data interface{}) bool {
    if !ac.securityConfig["encryption_required"].(bool) {
        return true
    }
    validator := event_validator.NewEventValidator(nil, nil)
    return validator.ValidateEncryption(data) == nil
}

func (ac *AccuracyCalculator) countPassedValidations(results []interface{}) int {
    passed := 0
    for _, result := range results {
        if metrics, ok := result.(map[string]interface{}); ok {
            if acc, exists := metrics["accuracy"].(float64); exists {
                if acc >= ac.thresholds["low"] {
                    passed++
                }
            }
        }
    }
    return passed
}

func (ac *AccuracyCalculator) countFailedValidations(results []interface{}) int {
    return len(results) - ac.countPassedValidations(results)
}

func (ac *AccuracyCalculator) analyzeSecurityViolations(results []interface{}) []string {
    var violations []string
    for _, result := range results {
        if metrics, ok := result.(map[string]interface{}); ok {
            if violations, exists := metrics["security_violations"].([]string); exists {
                return violations
            }
        }
    }
    return violations
}