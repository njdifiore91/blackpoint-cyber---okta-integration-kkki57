// Package framework provides comprehensive assertion utilities for the BlackPoint Security Integration Framework testing suite.
// Version: 1.0.0
package framework

import (
    "fmt" // v1.21
    "reflect" // v1.21
    "testing" // v1.21
    "time" // v1.21
    
    "../../pkg/common" // Internal package for logging utilities
)

// Default intervals for async assertions
var (
    defaultAssertInterval = 100 * time.Millisecond
    defaultAssertTimeout  = 10 * time.Second
)

// AssertEqual performs a deep equality comparison between expected and actual values
// with enhanced error reporting and monitoring integration.
func AssertEqual(t *testing.T, expected, actual interface{}, message string) bool {
    t.Helper()

    // Perform deep equality comparison
    equal := reflect.DeepEqual(expected, actual)

    // Generate detailed type information
    expectedType := reflect.TypeOf(expected)
    actualType := reflect.TypeOf(actual)

    // Prepare logging fields
    fields := map[string]interface{}{
        "expected_type":  expectedType.String(),
        "actual_type":    actualType.String(),
        "expected_value": fmt.Sprintf("%+v", expected),
        "actual_value":   fmt.Sprintf("%+v", actual),
        "assertion_type": "equality",
    }

    if equal {
        common.LogTestInfo(t, fmt.Sprintf("Assertion passed: %s", message), fields)
        common.LogTestMetrics(t, map[string]interface{}{
            "assertion_result": 1.0,
            "assertion_type":   "equality",
        })
        return true
    }

    // Enhanced error reporting for failure case
    fields["error_details"] = generateDiff(expected, actual)
    common.LogTestError(t, common.NewTestError("ASSERTION_ERROR", 
        fmt.Sprintf("%s\nExpected: %+v\nActual: %+v", message, expected, actual)), 
        fields)
    
    common.LogTestMetrics(t, map[string]interface{}{
        "assertion_result": 0.0,
        "assertion_type":   "equality",
    })
    
    return false
}

// AssertNotEqual asserts that two values are not equal with enhanced error reporting.
func AssertNotEqual(t *testing.T, expected, actual interface{}, message string) bool {
    t.Helper()

    // Perform deep equality comparison
    equal := reflect.DeepEqual(expected, actual)

    // Generate detailed type information
    expectedType := reflect.TypeOf(expected)
    actualType := reflect.TypeOf(actual)

    // Prepare logging fields
    fields := map[string]interface{}{
        "expected_type":  expectedType.String(),
        "actual_type":    actualType.String(),
        "expected_value": fmt.Sprintf("%+v", expected),
        "actual_value":   fmt.Sprintf("%+v", actual),
        "assertion_type": "inequality",
    }

    if !equal {
        common.LogTestInfo(t, fmt.Sprintf("Assertion passed: %s", message), fields)
        common.LogTestMetrics(t, map[string]interface{}{
            "assertion_result": 1.0,
            "assertion_type":   "inequality",
        })
        return true
    }

    common.LogTestError(t, common.NewTestError("ASSERTION_ERROR",
        fmt.Sprintf("%s\nExpected not equal to: %+v\nActual: %+v", message, expected, actual)),
        fields)
    
    common.LogTestMetrics(t, map[string]interface{}{
        "assertion_result": 0.0,
        "assertion_type":   "inequality",
    })
    
    return false
}

// AssertEventually asserts that a condition becomes true within a specified timeout period
// with progress tracking and monitoring integration.
func AssertEventually(t *testing.T, condition func() bool, timeout, interval time.Duration, message string) bool {
    t.Helper()

    if timeout == 0 {
        timeout = defaultAssertTimeout
    }
    if interval == 0 {
        interval = defaultAssertInterval
    }

    startTime := time.Now()
    attempts := 0
    
    fields := map[string]interface{}{
        "timeout":  timeout.String(),
        "interval": interval.String(),
        "assertion_type": "eventually",
    }

    ticker := time.NewTicker(interval)
    defer ticker.Stop()
    
    timer := time.NewTimer(timeout)
    defer timer.Stop()

    for {
        attempts++
        
        if condition() {
            elapsed := time.Since(startTime)
            fields["duration"] = elapsed.String()
            fields["attempts"] = attempts
            
            common.LogTestInfo(t, fmt.Sprintf("Assertion passed: %s", message), fields)
            common.LogTestMetrics(t, map[string]interface{}{
                "assertion_result": 1.0,
                "assertion_type":   "eventually",
                "assertion_duration_ms": elapsed.Milliseconds(),
                "assertion_attempts": attempts,
            })
            return true
        }

        select {
        case <-ticker.C:
            continue
        case <-timer.C:
            elapsed := time.Since(startTime)
            fields["duration"] = elapsed.String()
            fields["attempts"] = attempts
            
            common.LogTestError(t, common.NewTestError("ASSERTION_ERROR",
                fmt.Sprintf("%s\nTimed out after %v with %d attempts", message, timeout, attempts)),
                fields)
            
            common.LogTestMetrics(t, map[string]interface{}{
                "assertion_result": 0.0,
                "assertion_type":   "eventually",
                "assertion_duration_ms": elapsed.Milliseconds(),
                "assertion_attempts": attempts,
            })
            return false
        }
    }
}

// AssertNil asserts that a value is nil with enhanced type checking and error reporting.
func AssertNil(t *testing.T, value interface{}, message string) bool {
    t.Helper()

    // Handle nil interface case
    if value == nil {
        common.LogTestInfo(t, fmt.Sprintf("Assertion passed: %s", message), map[string]interface{}{
            "assertion_type": "nil",
        })
        common.LogTestMetrics(t, map[string]interface{}{
            "assertion_result": 1.0,
            "assertion_type":   "nil",
        })
        return true
    }

    // Handle nil value of concrete type
    v := reflect.ValueOf(value)
    if v.Kind() == reflect.Ptr && v.IsNil() {
        common.LogTestInfo(t, fmt.Sprintf("Assertion passed: %s", message), map[string]interface{}{
            "assertion_type": "nil",
            "value_type": v.Type().String(),
        })
        common.LogTestMetrics(t, map[string]interface{}{
            "assertion_result": 1.0,
            "assertion_type":   "nil",
        })
        return true
    }

    fields := map[string]interface{}{
        "actual_type":  reflect.TypeOf(value).String(),
        "actual_value": fmt.Sprintf("%+v", value),
        "assertion_type": "nil",
    }

    common.LogTestError(t, common.NewTestError("ASSERTION_ERROR",
        fmt.Sprintf("%s\nExpected: nil\nActual: %+v", message, value)),
        fields)
    
    common.LogTestMetrics(t, map[string]interface{}{
        "assertion_result": 0.0,
        "assertion_type":   "nil",
    })
    
    return false
}

// generateDiff creates a detailed difference report between expected and actual values
func generateDiff(expected, actual interface{}) string {
    if expected == nil || actual == nil {
        return fmt.Sprintf("expected: %v, actual: %v", expected, actual)
    }

    expectedValue := reflect.ValueOf(expected)
    actualValue := reflect.ValueOf(actual)

    if expectedValue.Type() != actualValue.Type() {
        return fmt.Sprintf("type mismatch: expected %v, got %v",
            expectedValue.Type(), actualValue.Type())
    }

    switch expectedValue.Kind() {
    case reflect.Struct:
        return generateStructDiff(expectedValue, actualValue)
    case reflect.Map:
        return generateMapDiff(expectedValue, actualValue)
    case reflect.Slice, reflect.Array:
        return generateSliceDiff(expectedValue, actualValue)
    default:
        return fmt.Sprintf("expected: %v, actual: %v", expected, actual)
    }
}

// generateStructDiff generates a detailed diff for struct values
func generateStructDiff(expected, actual reflect.Value) string {
    var diff string
    for i := 0; i < expected.NumField(); i++ {
        fieldName := expected.Type().Field(i).Name
        expectedField := expected.Field(i)
        actualField := actual.Field(i)
        
        if !reflect.DeepEqual(expectedField.Interface(), actualField.Interface()) {
            diff += fmt.Sprintf("\nField %s:\n\texpected: %+v\n\tactual: %+v",
                fieldName, expectedField.Interface(), actualField.Interface())
        }
    }
    return diff
}

// generateMapDiff generates a detailed diff for map values
func generateMapDiff(expected, actual reflect.Value) string {
    var diff string
    for _, key := range expected.MapKeys() {
        expectedVal := expected.MapIndex(key)
        actualVal := actual.MapIndex(key)
        
        if !actualVal.IsValid() {
            diff += fmt.Sprintf("\nMissing key %v in actual", key)
            continue
        }
        
        if !reflect.DeepEqual(expectedVal.Interface(), actualVal.Interface()) {
            diff += fmt.Sprintf("\nKey %v:\n\texpected: %+v\n\tactual: %+v",
                key, expectedVal.Interface(), actualVal.Interface())
        }
    }
    return diff
}

// generateSliceDiff generates a detailed diff for slice/array values
func generateSliceDiff(expected, actual reflect.Value) string {
    var diff string
    for i := 0; i < expected.Len(); i++ {
        if i >= actual.Len() {
            diff += fmt.Sprintf("\nMissing element at index %d", i)
            continue
        }
        
        expectedVal := expected.Index(i)
        actualVal := actual.Index(i)
        
        if !reflect.DeepEqual(expectedVal.Interface(), actualVal.Interface()) {
            diff += fmt.Sprintf("\nIndex %d:\n\texpected: %+v\n\tactual: %+v",
                i, expectedVal.Interface(), actualVal.Interface())
        }
    }
    return diff
}