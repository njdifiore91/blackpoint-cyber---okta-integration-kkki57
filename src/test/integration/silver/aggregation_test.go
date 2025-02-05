package silver_test

import (
    "context"
    "testing"
    "time"
    "sync"

    "github.com/stretchr/testify/assert"
    "golang.org/x/sync/errgroup"
    "github.com/prometheus/client_golang/prometheus"

    "github.com/blackpoint/test/internal/framework"
    "github.com/blackpoint/pkg/silver"
    "github.com/blackpoint/test/pkg/validation"
    "github.com/blackpoint/test/pkg/fixtures"
)

const (
    testTimeout       = 5 * time.Minute
    batchSize        = 1000
    maxLatency       = 5 * time.Second
    minThroughput    = 1000
    minAccuracy      = 0.8
    concurrentBatches = 10
    metricsInterval  = time.Second
)

// Prometheus metrics
var (
    aggregationLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_test_silver_aggregation_latency_seconds",
            Help: "Aggregation processing latency in seconds",
            Buckets: []float64{0.1, 0.5, 1, 2, 5},
        },
        []string{"test_case", "batch_size"},
    )

    aggregationThroughput = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackpoint_test_silver_aggregation_throughput",
            Help: "Events processed per second",
        },
        []string{"test_case"},
    )

    securityContextErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_test_silver_security_context_errors",
            Help: "Number of security context validation errors",
        },
        []string{"error_type"},
    )
)

func TestMain(m *testing.M) {
    // Initialize test suite with security context
    suite := framework.NewTestSuite(nil, "silver_aggregation", &framework.TestSuiteConfig{
        SecurityEnabled: true,
        MonitoringEnabled: true,
        ValidationConfig: map[string]float64{
            "accuracy": minAccuracy,
            "performance": 0.95,
        },
    })

    // Register metrics
    prometheus.MustRegister(aggregationLatency)
    prometheus.MustRegister(aggregationThroughput)
    prometheus.MustRegister(securityContextErrors)

    // Run tests
    code := m.Run()

    // Cleanup
    prometheus.Unregister(aggregationLatency)
    prometheus.Unregister(aggregationThroughput)
    prometheus.Unregister(securityContextErrors)

    suite.Cleanup()
    os.Exit(code)
}

func TestSingleEventAggregation(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    defer cancel()

    // Create test event with security context
    event, err := fixtures.GenerateValidBronzeEvent(&fixtures.GenerateOptions{
        SecurityLevel: "high",
        AuditLevel: "detailed",
    })
    assert.NoError(t, err)

    // Create security context for validation
    securityCtx := &validation.SecurityContext{
        Classification: "confidential",
        Sensitivity: "high",
        ComplianceReqs: []string{"SOC2", "ISO27001"},
        EncryptionLevel: "AES256",
        AuditLevel: "detailed",
    }

    // Process event
    startTime := time.Now()
    err = silver.ProcessEvent(ctx, event)
    processingTime := time.Since(startTime)

    // Record metrics
    aggregationLatency.WithLabelValues("single", "1").Observe(processingTime.Seconds())

    // Validate processing
    assert.NoError(t, err)
    assert.Less(t, processingTime, maxLatency)

    // Validate security context preservation
    err = validation.ValidateSecurityContext(t, event, securityCtx)
    assert.NoError(t, err)

    // Validate event accuracy
    accuracy, err := validation.ValidateEventAccuracy(t, event, securityCtx)
    assert.NoError(t, err)
    assert.GreaterOrEqual(t, accuracy, minAccuracy)
}

func TestBatchEventAggregation(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    defer cancel()

    // Generate batch of test events
    events, metrics, err := fixtures.GenerateBronzeEventBatch(batchSize, &fixtures.BatchOptions{
        SecurityContext: &fixtures.SecurityContext{
            Level: "high",
            Compliance: []string{"SOC2", "ISO27001"},
            AuditRequirements: map[string]string{
                "level": "detailed",
                "retention": "90d",
            },
        },
    })
    assert.NoError(t, err)

    // Process batch
    startTime := time.Now()
    errs := silver.ProcessBatch(ctx, events)
    processingTime := time.Since(startTime)

    // Record metrics
    aggregationLatency.WithLabelValues("batch", string(batchSize)).Observe(processingTime.Seconds())
    throughput := float64(len(events)) / processingTime.Seconds()
    aggregationThroughput.WithLabelValues("batch").Set(throughput)

    // Validate processing
    assert.Empty(t, errs)
    assert.Less(t, processingTime, maxLatency)
    assert.GreaterOrEqual(t, throughput, float64(minThroughput))

    // Validate batch accuracy
    accuracyMetrics, err := validation.ValidateEventBatchAccuracy(t, events, metrics)
    assert.NoError(t, err)
    assert.GreaterOrEqual(t, accuracyMetrics["average_accuracy"], minAccuracy)
}

func TestConcurrentAggregation(t *testing.T) {
    ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
    defer cancel()

    var wg sync.WaitGroup
    g, ctx := errgroup.WithContext(ctx)

    // Create security context for validation
    securityCtx := &validation.SecurityContext{
        Classification: "confidential",
        Sensitivity: "high",
        ComplianceReqs: []string{"SOC2", "ISO27001"},
        EncryptionLevel: "AES256",
        AuditLevel: "detailed",
    }

    // Process multiple batches concurrently
    startTime := time.Now()
    for i := 0; i < concurrentBatches; i++ {
        wg.Add(1)
        g.Go(func() error {
            defer wg.Done()

            // Generate batch
            events, _, err := fixtures.GenerateBronzeEventBatch(batchSize, &fixtures.BatchOptions{
                Concurrent: true,
                SecurityContext: securityCtx,
            })
            if err != nil {
                return err
            }

            // Process batch
            errs := silver.ProcessBatch(ctx, events)
            if len(errs) > 0 {
                return errs[0]
            }

            return nil
        })
    }

    // Wait for all batches to complete
    err := g.Wait()
    processingTime := time.Since(startTime)

    // Record metrics
    totalEvents := batchSize * concurrentBatches
    throughput := float64(totalEvents) / processingTime.Seconds()
    aggregationLatency.WithLabelValues("concurrent", string(totalEvents)).Observe(processingTime.Seconds())
    aggregationThroughput.WithLabelValues("concurrent").Set(throughput)

    // Validate processing
    assert.NoError(t, err)
    assert.Less(t, processingTime, maxLatency*time.Duration(concurrentBatches))
    assert.GreaterOrEqual(t, throughput, float64(minThroughput))

    // Validate system performance under load
    performanceMetrics := validation.ValidateSystemPerformance(t, totalEvents, processingTime)
    assert.GreaterOrEqual(t, performanceMetrics["success_rate"], 0.95)
}