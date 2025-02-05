// Package framework provides custom matchers for the BlackPoint Security Integration Framework testing suite.
// Version: 1.0.0
package framework

import (
    "fmt" // v1.21
    "reflect" // v1.21
    "regexp" // v1.21
    "testing" // v1.21
    
    "../../pkg/common" // Internal package for logging utilities
    "./assertions" // Internal package for assertions
)

// AccuracyConfig holds configuration for accuracy tracking
type AccuracyConfig struct {
    // Minimum required accuracy threshold (default: 0.80)
    MinAccuracy float64
    // Fields to track for accuracy metrics
    TrackedFields []string
    // Whether to fail test on accuracy below threshold
    FailOnAccuracyMiss bool
}

// accuracyMetrics tracks field-level matching accuracy
type accuracyMetrics struct {
    totalFields    int
    matchedFields  int
    fieldResults   map[string]bool
}

// newAccuracyMetrics initializes a new accuracyMetrics instance
func newAccuracyMetrics() *accuracyMetrics {
    return &accuracyMetrics{
        fieldResults: make(map[string]bool),
    }
}

// MatchEventFields performs enhanced matching of security event fields with accuracy tracking
func MatchEventFields(t *testing.T, expected, actual map[string]interface{}, message string, accuracyConfig *AccuracyConfig) bool {
    t.Helper()

    // Initialize accuracy tracking
    metrics := newAccuracyMetrics()
    
    // Set default accuracy threshold if not configured
    if accuracyConfig == nil {
        accuracyConfig = &AccuracyConfig{
            MinAccuracy: common.ValidationThresholds["accuracy"],
            FailOnAccuracyMiss: true,
        }
    }

    // Validate inputs
    if expected == nil || actual == nil {
        common.LogTestError(t, common.NewTestError("VALIDATION_ERROR", "nil maps provided for comparison"), nil)
        return false
    }

    // Track all fields for accuracy calculation
    for field := range expected {
        metrics.totalFields++
        expectedVal := expected[field]
        actualVal, exists := actual[field]

        if !exists {
            metrics.fieldResults[field] = false
            logFieldMismatch(t, field, expectedVal, nil, "field missing")
            continue
        }

        // Perform type-specific matching
        matched := false
        switch v := expectedVal.(type) {
        case string:
            matched = matchStringField(t, field, v, actualVal)
        case map[string]interface{}:
            matched = MatchEventFields(t, v, actualVal.(map[string]interface{}), fmt.Sprintf("%s.%s", message, field), accuracyConfig)
        default:
            matched = reflect.DeepEqual(expectedVal, actualVal)
        }

        metrics.fieldResults[field] = matched
        if matched {
            metrics.matchedFields++
        } else {
            logFieldMismatch(t, field, expectedVal, actualVal, "value mismatch")
        }
    }

    // Calculate accuracy
    accuracy := float64(metrics.matchedFields) / float64(metrics.totalFields)

    // Log accuracy metrics
    common.LogTestMetrics(t, map[string]interface{}{
        "accuracy": accuracy,
        "total_fields": metrics.totalFields,
        "matched_fields": metrics.matchedFields,
        "field_results": metrics.fieldResults,
    })

    // Check accuracy threshold
    if accuracy < accuracyConfig.MinAccuracy {
        err := common.NewTestError("DATA_ACCURACY_ERROR",
            fmt.Sprintf("accuracy %.2f%% below required threshold %.2f%%", accuracy*100, accuracyConfig.MinAccuracy*100))
        common.LogTestError(t, err, map[string]interface{}{
            "accuracy": accuracy,
            "threshold": accuracyConfig.MinAccuracy,
            "field_results": metrics.fieldResults,
        })
        return !accuracyConfig.FailOnAccuracyMiss
    }

    return true
}

// MatchRegex matches a string value against a regular expression pattern
func MatchRegex(t *testing.T, pattern string, actual string, message string) bool {
    t.Helper()

    re, err := regexp.Compile(pattern)
    if err != nil {
        common.LogTestError(t, common.NewTestError("VALIDATION_ERROR", 
            fmt.Sprintf("invalid regex pattern: %s", err)), nil)
        return false
    }

    matched := re.MatchString(actual)
    if !matched {
        common.LogTestError(t, common.NewTestError("VALIDATION_ERROR",
            fmt.Sprintf("%s\nExpected to match pattern: %s\nActual: %s", message, pattern, actual)), nil)
    }

    return matched
}

// MatchAny matches a value against any of the provided expected values
func MatchAny(t *testing.T, expected []interface{}, actual interface{}, message string) bool {
    t.Helper()

    if len(expected) == 0 {
        common.LogTestError(t, common.NewTestError("VALIDATION_ERROR", "empty expected values slice"), nil)
        return false
    }

    for _, exp := range expected {
        if reflect.DeepEqual(exp, actual) {
            return true
        }
    }

    common.LogTestError(t, common.NewTestError("VALIDATION_ERROR",
        fmt.Sprintf("%s\nValue did not match any expected values\nActual: %v\nExpected one of: %v",
            message, actual, expected)), nil)
    return false
}

// MatchPartialStruct matches a subset of struct fields against expected values
func MatchPartialStruct(t *testing.T, expected, actual interface{}, fields []string, message string) bool {
    t.Helper()

    expectedValue := reflect.ValueOf(expected)
    actualValue := reflect.ValueOf(actual)

    // Validate inputs are structs
    if expectedValue.Kind() != reflect.Struct || actualValue.Kind() != reflect.Struct {
        common.LogTestError(t, common.NewTestError("VALIDATION_ERROR", "inputs must be structs"), nil)
        return false
    }

    // Track matching results
    allMatched := true
    for _, field := range fields {
        expectedField := expectedValue.FieldByName(field)
        actualField := actualValue.FieldByName(field)

        if !expectedField.IsValid() || !actualField.IsValid() {
            common.LogTestError(t, common.NewTestError("VALIDATION_ERROR",
                fmt.Sprintf("field not found: %s", field)), nil)
            allMatched = false
            continue
        }

        if !reflect.DeepEqual(expectedField.Interface(), actualField.Interface()) {
            common.LogTestError(t, common.NewTestError("VALIDATION_ERROR",
                fmt.Sprintf("%s\nField %s mismatch\nExpected: %v\nActual: %v",
                    message, field, expectedField.Interface(), actualField.Interface())), nil)
            allMatched = false
        }
    }

    return allMatched
}

// matchStringField performs string-specific matching with support for patterns
func matchStringField(t *testing.T, field, expected, actual interface{}) bool {
    t.Helper()

    actualStr, ok := actual.(string)
    if !ok {
        return false
    }

    // Check if expected is a pattern (starts with "regex:")
    if expStr, ok := expected.(string); ok && len(expStr) > 6 && expStr[:6] == "regex:" {
        return MatchRegex(t, expStr[6:], actualStr, fmt.Sprintf("field %s", field))
    }

    return expected == actual
}

// logFieldMismatch logs detailed information about field matching failures
func logFieldMismatch(t *testing.T, field string, expected, actual interface{}, reason string) {
    common.LogTestError(t, common.NewTestError("VALIDATION_ERROR",
        fmt.Sprintf("Field %s: %s\nExpected: %v\nActual: %v",
            field, reason, expected, actual)), map[string]interface{}{
        "field": field,
        "expected": expected,
        "actual": actual,
        "reason": reason,
    })
}