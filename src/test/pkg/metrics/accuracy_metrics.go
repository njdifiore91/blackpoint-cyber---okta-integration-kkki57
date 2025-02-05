// Package metrics provides accuracy measurement and validation functionality for the BlackPoint Security Integration Framework
// Version: 1.0.0
package metrics

import (
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"

	"github.com/blackpoint/pkg/common/errors"
	"github.com/blackpoint/pkg/common/utils"
)

// Constants for accuracy validation
const (
	MinimumAccuracyThreshold = 80.0 // Minimum required accuracy percentage
	MinimumSuccessRate      = 95.0 // Minimum required success rate percentage
)

// AccuracyCalculationModes defines supported accuracy calculation methods
var AccuracyCalculationModes = map[string]string{
	"strict":         "exact_match",
	"fuzzy":          "partial_match",
	"weighted":       "field_weighted",
	"security_aware": "security_context_match",
}

// DefaultFieldWeights defines default weights for different field types
var DefaultFieldWeights = map[string]float64{
	"critical":         1.0,
	"high":            0.8,
	"medium":          0.6,
	"low":             0.4,
	"security_context": 1.0,
}

// Prometheus metrics
var (
	accuracyMetrics = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "blackpoint_accuracy_percentage",
			Help: "Accuracy percentage of event processing",
			Buckets: []float64{50, 60, 70, 80, 90, 95, 99, 100},
		},
		[]string{"calculation_mode", "event_type"},
	)

	successRateMetric = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "blackpoint_success_rate_percentage",
			Help: "Success rate percentage of event processing",
		},
	)

	validationErrorsCounter = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blackpoint_validation_errors_total",
			Help: "Total number of validation errors by type",
		},
		[]string{"error_type"},
	)
)

// AccuracyMetrics manages accuracy calculation and validation
type AccuracyMetrics struct {
	calculationMode string
	fieldWeights    map[string]float64
	threshold       float64
	securityContext map[string]interface{}
	metricsClient   *prometheus.Client
	mu             sync.RWMutex
}

// NewAccuracyMetrics creates a new AccuracyMetrics instance
func NewAccuracyMetrics(mode string, weights map[string]float64, securityContext map[string]interface{}) (*AccuracyMetrics, error) {
	if _, ok := AccuracyCalculationModes[mode]; !ok {
		return nil, errors.NewError("E3001", fmt.Sprintf("invalid calculation mode: %s", mode), nil)
	}

	metrics := &AccuracyMetrics{
		calculationMode: mode,
		threshold:      MinimumAccuracyThreshold,
		securityContext: securityContext,
	}

	// Use provided weights or defaults
	if weights != nil {
		metrics.fieldWeights = weights
	} else {
		metrics.fieldWeights = DefaultFieldWeights
	}

	// Register Prometheus metrics
	prometheus.MustRegister(accuracyMetrics, successRateMetric, validationErrorsCounter)

	return metrics, nil
}

// CalculateEventAccuracy calculates accuracy between actual and expected events
func (am *AccuracyMetrics) CalculateEventAccuracy(actualEvent, expectedEvent *BronzeEvent) (float64, error) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if actualEvent == nil || expectedEvent == nil {
		return 0, errors.NewError("E3001", "nil event provided", nil)
	}

	// Validate event IDs match
	if actualEvent.ID != expectedEvent.ID {
		return 0, errors.NewError("E3001", "event ID mismatch", nil)
	}

	// Unmarshal payloads
	var actualPayload, expectedPayload map[string]interface{}
	if err := json.Unmarshal(actualEvent.Payload, &actualPayload); err != nil {
		return 0, errors.WrapError(err, "failed to unmarshal actual payload", nil)
	}
	if err := json.Unmarshal(expectedEvent.Payload, &expectedPayload); err != nil {
		return 0, errors.WrapError(err, "failed to unmarshal expected payload", nil)
	}

	var accuracy float64
	switch am.calculationMode {
	case "strict":
		accuracy = am.calculateStrictAccuracy(actualPayload, expectedPayload)
	case "fuzzy":
		accuracy = am.calculateFuzzyAccuracy(actualPayload, expectedPayload)
	case "weighted":
		accuracy = am.calculateWeightedAccuracy(actualPayload, expectedPayload)
	case "security_aware":
		accuracy = am.calculateSecurityAwareAccuracy(actualPayload, expectedPayload)
	}

	// Record metrics
	accuracyMetrics.WithLabelValues(am.calculationMode, actualEvent.SourcePlatform).Observe(accuracy)

	return accuracy, nil
}

// CalculateBatchAccuracy calculates accuracy metrics for a batch of events
func (am *AccuracyMetrics) CalculateBatchAccuracy(actualEvents, expectedEvents []*BronzeEvent) (map[string]float64, error) {
	if len(actualEvents) != len(expectedEvents) {
		return nil, errors.NewError("E3001", "event batch size mismatch", nil)
	}

	metrics := make(map[string]float64)
	var totalAccuracy float64
	successCount := 0

	for i := range actualEvents {
		accuracy, err := am.CalculateEventAccuracy(actualEvents[i], expectedEvents[i])
		if err != nil {
			validationErrorsCounter.WithLabelValues("event_comparison").Inc()
			continue
		}

		totalAccuracy += accuracy
		if accuracy >= am.threshold {
			successCount++
		}
	}

	batchSize := float64(len(actualEvents))
	metrics["average_accuracy"] = totalAccuracy / batchSize
	metrics["success_rate"] = float64(successCount) / batchSize * 100

	// Record success rate metric
	successRateMetric.Set(metrics["success_rate"])

	return metrics, nil
}

// GenerateAccuracyReport generates a detailed accuracy analysis report
func (am *AccuracyMetrics) GenerateAccuracyReport(metrics map[string]float64) (map[string]interface{}, error) {
	report := map[string]interface{}{
		"timestamp":         time.Now().UTC(),
		"calculation_mode": am.calculationMode,
		"threshold":        am.threshold,
		"metrics":          metrics,
		"validation": map[string]interface{}{
			"accuracy_requirement_met": metrics["average_accuracy"] >= MinimumAccuracyThreshold,
			"success_rate_requirement_met": metrics["success_rate"] >= MinimumSuccessRate,
		},
	}

	if am.securityContext != nil {
		report["security_context"] = am.securityContext
	}

	return report, nil
}

// Helper functions for different accuracy calculation modes

func (am *AccuracyMetrics) calculateStrictAccuracy(actual, expected map[string]interface{}) float64 {
	matches := 0
	total := len(expected)

	for key, expectedVal := range expected {
		if actualVal, ok := actual[key]; ok {
			if assert.ObjectsAreEqual(actualVal, expectedVal) {
				matches++
			}
		}
	}

	return float64(matches) / float64(total) * 100
}

func (am *AccuracyMetrics) calculateFuzzyAccuracy(actual, expected map[string]interface{}) float64 {
	var totalScore float64
	total := len(expected)

	for key, expectedVal := range expected {
		if actualVal, ok := actual[key]; ok {
			similarity := calculateFieldSimilarity(actualVal, expectedVal)
			totalScore += similarity
		}
	}

	return totalScore / float64(total) * 100
}

func (am *AccuracyMetrics) calculateWeightedAccuracy(actual, expected map[string]interface{}) float64 {
	var weightedScore, totalWeight float64

	for key, expectedVal := range expected {
		weight := am.fieldWeights["low"] // Default weight
		if w, ok := am.fieldWeights[key]; ok {
			weight = w
		}

		if actualVal, ok := actual[key]; ok {
			similarity := calculateFieldSimilarity(actualVal, expectedVal)
			weightedScore += similarity * weight
		}
		totalWeight += weight
	}

	return weightedScore / totalWeight * 100
}

func (am *AccuracyMetrics) calculateSecurityAwareAccuracy(actual, expected map[string]interface{}) float64 {
	// Apply extra weight to security-critical fields
	securityScore := am.calculateWeightedAccuracy(actual, expected)
	
	// Validate security context if present
	if secContext, ok := actual["security_context"].(map[string]interface{}); ok {
		if expectedContext, ok := expected["security_context"].(map[string]interface{}); ok {
			contextScore := am.calculateStrictAccuracy(secContext, expectedContext)
			return (securityScore + contextScore) / 2
		}
	}

	return securityScore
}

func calculateFieldSimilarity(actual, expected interface{}) float64 {
	switch v := expected.(type) {
	case string:
		if actualStr, ok := actual.(string); ok {
			return calculateStringSimilarity(actualStr, v)
		}
	case float64:
		if actualNum, ok := actual.(float64); ok {
			return calculateNumericSimilarity(actualNum, v)
		}
	case bool:
		if actualBool, ok := actual.(bool); ok && actualBool == v {
			return 1.0
		}
	}
	return 0.0
}

func calculateStringSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	// Implement Levenshtein distance or similar algorithm for fuzzy matching
	return 0.5
}

func calculateNumericSimilarity(n1, n2 float64) float64 {
	if n1 == n2 {
		return 1.0
	}
	// Calculate similarity based on relative difference
	diff := math.Abs(n1 - n2)
	max := math.Max(math.Abs(n1), math.Abs(n2))
	if max == 0 {
		return 1.0
	}
	return 1.0 - (diff / max)
}

func init() {
	// Initialize Prometheus metrics
	prometheus.MustRegister(accuracyMetrics, successRateMetric, validationErrorsCounter)
}