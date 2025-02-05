// Package e2e provides end-to-end testing for the BlackPoint Security Integration Framework
package e2e

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/require"
    "github.com/prometheus/client_golang/prometheus"

    "../../internal/framework/test_suite"
    "../../pkg/validation/schema_validator"
    "../../../backend/pkg/integration/config"
    "../../pkg/common/logging"
    "../../pkg/fixtures"
)

var (
    // Prometheus metrics for deployment testing
    deploymentDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_integration_deployment_duration_seconds",
            Help: "Duration of integration deployment tests",
            Buckets: prometheus.ExponentialBuckets(1, 2, 10),
        },
        []string{"platform", "status"},
    )

    deploymentAccuracy = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackpoint_integration_deployment_accuracy",
            Help: "Accuracy of integration deployment",
        },
        []string{"platform", "tier"},
    )

    validationErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_integration_validation_errors_total",
            Help: "Number of validation errors during deployment",
        },
        []string{"platform", "error_type"},
    )
)

// TestIntegrationDeployment is the main test entry point for integration deployment validation
func TestIntegrationDeployment(t *testing.T) {
    // Initialize test suite with security context
    suite := test_suite.NewTestSuite(t, "integration_deployment", &test_suite.TestSuiteConfig{
        Timeout:          30 * time.Minute,
        SecurityEnabled:  true,
        MonitoringEnabled: true,
        RetryAttempts:    3,
        ValidationConfig: map[string]float64{
            "accuracy":     0.80, // Minimum 80% accuracy required
            "performance": 0.95,  // 95% success rate required
        },
    })

    // Initialize schema validator
    validator := schema_validator.NewSchemaValidator(t)

    // Test each platform type
    for _, platform := range []string{"aws", "azure", "okta"} {
        t.Run(platform, func(t *testing.T) {
            t.Parallel()
            if err := testPlatformDeployment(t, platform, validator, suite); err != nil {
                t.Errorf("Platform deployment failed for %s: %v", platform, err)
            }
        })
    }
}

// testPlatformDeployment tests deployment for a specific platform
func testPlatformDeployment(t *testing.T, platform string, validator *schema_validator.SchemaValidator, suite *test_suite.TestSuite) error {
    startTime := time.Now()
    timer := prometheus.NewTimer(deploymentDuration.WithLabelValues(platform, "running"))
    defer timer.ObserveDuration()

    // Load platform configuration
    cfg := &config.IntegrationConfig{
        PlatformType: platform,
        Name:        "e2e-test-" + platform,
        Environment: "testing",
        Auth: config.AuthenticationConfig{
            Type: "oauth2",
            Credentials: map[string]interface{}{
                "client_id":     "test-client",
                "client_secret": "test-secret",
                "token_url":     "https://test.auth.com/token",
            },
        },
        Collection: config.DataCollectionConfig{
            Mode:      "hybrid",
            BatchSize: 1000,
            Interval:  "5m",
        },
        Validation: config.ValidationConfig{
            SchemaValidation: true,
            StrictMode:      true,
            ErrorThreshold:  5,
        },
    }

    // Validate configuration
    if err := config.ValidateConfig(cfg); err != nil {
        validationErrors.WithLabelValues(platform, "config").Inc()
        return err
    }

    // Generate test events
    bronzeEvents, err := fixtures.GenerateBronzeEventBatch(1000, &fixtures.BatchOptions{
        Concurrent:     true,
        WorkerCount:    4,
        SecurityContext: &fixtures.SecurityContext{
            Level:      "high",
            Compliance: []string{"SOC2", "ISO27001"},
        },
    })
    if err != nil {
        validationErrors.WithLabelValues(platform, "event_generation").Inc()
        return err
    }

    // Validate data processing across tiers
    accuracyResults, err := validateDataProcessing(t, platform, bronzeEvents, validator)
    if err != nil {
        validationErrors.WithLabelValues(platform, "data_processing").Inc()
        return err
    }

    // Record accuracy metrics
    for tier, accuracy := range accuracyResults {
        deploymentAccuracy.WithLabelValues(platform, tier).Set(accuracy)
        if accuracy < 0.80 {
            validationErrors.WithLabelValues(platform, "accuracy").Inc()
            return fmt.Errorf("accuracy below threshold for tier %s: %.2f%%", tier, accuracy*100)
        }
    }

    // Log deployment metrics
    logging.LogTestMetrics(t, map[string]interface{}{
        "platform":          platform,
        "deployment_time":   time.Since(startTime).Seconds(),
        "events_processed":  len(bronzeEvents),
        "accuracy_results":  accuracyResults,
    })

    return nil
}

// validateDataProcessing validates data processing across all tiers
func validateDataProcessing(t *testing.T, platform string, bronzeEvents []*bronze.BronzeEvent, validator *schema_validator.SchemaValidator) (map[string]float64, error) {
    results := make(map[string]float64)
    
    // Validate Bronze tier
    bronzeAccuracy := 0.0
    for _, event := range bronzeEvents {
        if validator.ValidateEventSchema(event, "bronze") {
            bronzeAccuracy++
        }
    }
    results["bronze"] = bronzeAccuracy / float64(len(bronzeEvents))

    // Validate Silver tier transformation
    silverEvents := make([]*silver.SilverEvent, 0)
    silverAccuracy := 0.0
    for _, bronzeEvent := range bronzeEvents {
        silverEvent, err := silver.NewSilverEvent(bronzeEvent.ClientID, "security_event", nil, silver.SecurityContext{
            Classification: "confidential",
            Sensitivity:   "high",
            Compliance:    []string{"SOC2", "ISO27001"},
        })
        if err != nil {
            continue
        }
        if err := silverEvent.FromBronzeEvent(bronzeEvent, nil, silver.SecurityContext{}); err != nil {
            continue
        }
        if validator.ValidateEventSchema(silverEvent, "silver") {
            silverAccuracy++
        }
        silverEvents = append(silverEvents, silverEvent)
    }
    results["silver"] = silverAccuracy / float64(len(bronzeEvents))

    // Validate Gold tier transformation
    goldAccuracy := 0.0
    for _, silverEvent := range silverEvents {
        goldEvent := &gold.GoldEvent{
            AlertID:      utils.GenerateUUID(),
            ClientID:    silverEvent.ClientID,
            Severity:    "high",
            DetectionTime: time.Now().UTC(),
            SilverEventIDs: []string{silverEvent.EventID},
            SchemaVersion: "2.0",
            SecurityMetadata: gold.SecurityMetadata{
                Classification:   "confidential",
                ConfidenceScore: 0.95,
                ThreatLevel:     "high",
            },
        }
        if validator.ValidateEventSchema(goldEvent, "gold") {
            goldAccuracy++
        }
    }
    results["gold"] = goldAccuracy / float64(len(silverEvents))

    return results, nil
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(deploymentDuration)
    prometheus.MustRegister(deploymentAccuracy)
    prometheus.MustRegister(validationErrors)
}