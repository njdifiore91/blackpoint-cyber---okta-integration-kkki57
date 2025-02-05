// Package storage provides secure storage implementations for the BlackPoint Security Integration Framework
package storage

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/aws/aws-sdk-go-v2/service/s3"  // v1.21.0
    "github.com/chaossearch/chaossearch-go-sdk" // v1.0.0
    "github.com/prometheus/client_golang/prometheus" // v1.11.0
    "go.opentelemetry.io/otel/trace" // v1.0.0
    "go.opentelemetry.io/otel/attribute" // v1.0.0

    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/logging"
    "github.com/blackpoint/security" // v1.0.0
)

// Storage tier retention periods
const (
    BronzeRetentionDays = 30
    SilverRetentionDays = 90
    GoldRetentionDays   = 365
)

// Metrics
var (
    storageOperations = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "chaossearch_operations_total",
            Help: "Total number of ChaosSearch operations",
        },
        []string{"operation", "tier", "status"},
    )

    storageLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "chaossearch_operation_latency_seconds",
            Help:    "Latency of ChaosSearch operations",
            Buckets: prometheus.ExponentialBuckets(0.001, 2, 10),
        },
        []string{"operation", "tier"},
    )
)

func init() {
    prometheus.MustRegister(storageOperations)
    prometheus.MustRegister(storageLatency)
}

// ChaosSearchConfig contains configuration for the ChaosSearch client
type ChaosSearchConfig struct {
    Endpoint        string
    Region         string
    BucketName     string
    IndexPrefix    string
    ShardCount     int
    ReplicaCount   int
    SecurityConfig security.Config
}

// ChaosSearchClient provides secure access to ChaosSearch storage
type ChaosSearchClient struct {
    config         *ChaosSearchConfig
    apiClient      *chaossearch.Client
    s3Client       *s3.Client
    encryptor      *security.Encryptor
    validator      *security.ComplianceValidator
    tracer         trace.Tracer
    mu             sync.RWMutex
}

// NewChaosSearchClient creates a new secure ChaosSearch client
func NewChaosSearchClient(ctx context.Context, config *ChaosSearchConfig) (*ChaosSearchClient, error) {
    if err := validateConfig(config); err != nil {
        return nil, errors.WrapError(err, "invalid configuration", nil)
    }

    // Initialize API client with security context
    apiClient, err := chaossearch.NewClient(
        chaossearch.WithEndpoint(config.Endpoint),
        chaossearch.WithRegion(config.Region),
        chaossearch.WithSecurityConfig(config.SecurityConfig),
    )
    if err != nil {
        return nil, errors.WrapError(err, "failed to initialize ChaosSearch API client", nil)
    }

    // Initialize S3 client with encryption
    s3Client, err := security.NewSecureS3Client(ctx, config.Region)
    if err != nil {
        return nil, errors.WrapError(err, "failed to initialize S3 client", nil)
    }

    // Initialize security components
    encryptor, err := security.NewEncryptor(config.SecurityConfig)
    if err != nil {
        return nil, errors.WrapError(err, "failed to initialize encryptor", nil)
    }

    validator, err := security.NewComplianceValidator(config.SecurityConfig)
    if err != nil {
        return nil, errors.WrapError(err, "failed to initialize compliance validator", nil)
    }

    client := &ChaosSearchClient{
        config:    config,
        apiClient: apiClient,
        s3Client:  s3Client,
        encryptor: encryptor,
        validator: validator,
        tracer:    trace.GetTracerProvider().Tracer("chaossearch"),
    }

    return client, nil
}

// StoreEventSecure stores an event with encryption and compliance validation
func (c *ChaosSearchClient) StoreEventSecure(ctx context.Context, tier string, event interface{}) error {
    ctx, span := c.tracer.Start(ctx, "StoreEventSecure")
    defer span.End()

    timer := prometheus.NewTimer(storageLatency.WithLabelValues("store", tier))
    defer timer.ObserveDuration()

    // Validate compliance requirements
    if err := c.validator.ValidateEvent(ctx, event); err != nil {
        storageOperations.WithLabelValues("store", tier, "error").Inc()
        return errors.NewSecurityError("E3001", "compliance validation failed", map[string]interface{}{
            "tier": tier,
            "error": err.Error(),
        })
    }

    // Apply field-level encryption
    encryptedEvent, err := c.encryptor.EncryptFields(event)
    if err != nil {
        storageOperations.WithLabelValues("store", tier, "error").Inc()
        return errors.WrapError(err, "encryption failed", nil)
    }

    // Generate secure partition key
    partitionKey := generatePartitionKey(tier, time.Now())

    // Store with security context
    c.mu.Lock()
    defer c.mu.Unlock()

    err = c.apiClient.StoreEvent(ctx, &chaossearch.StoreEventInput{
        Bucket:        c.config.BucketName,
        IndexPrefix:   c.config.IndexPrefix,
        PartitionKey: partitionKey,
        Event:        encryptedEvent,
        Metadata: map[string]string{
            "tier":      tier,
            "encrypted": "true",
            "timestamp": time.Now().UTC().Format(time.RFC3339),
        },
    })

    if err != nil {
        storageOperations.WithLabelValues("store", tier, "error").Inc()
        return errors.WrapError(err, "failed to store event", nil)
    }

    storageOperations.WithLabelValues("store", tier, "success").Inc()
    logging.SecurityAudit("Event stored securely", map[string]interface{}{
        "tier":          tier,
        "partitionKey": partitionKey,
    })

    return nil
}

// QueryEventsSecure performs a secure query with compliance validation
func (c *ChaosSearchClient) QueryEventsSecure(ctx context.Context, tier string, query interface{}) (interface{}, error) {
    ctx, span := c.tracer.Start(ctx, "QueryEventsSecure")
    defer span.End()

    timer := prometheus.NewTimer(storageLatency.WithLabelValues("query", tier))
    defer timer.ObserveDuration()

    // Validate query compliance
    if err := c.validator.ValidateQuery(ctx, query); err != nil {
        storageOperations.WithLabelValues("query", tier, "error").Inc()
        return nil, errors.NewSecurityError("E3001", "query validation failed", nil)
    }

    c.mu.RLock()
    defer c.mu.RUnlock()

    results, err := c.apiClient.QueryEvents(ctx, &chaossearch.QueryEventsInput{
        Bucket:      c.config.BucketName,
        IndexPrefix: c.config.IndexPrefix,
        Query:      query,
    })

    if err != nil {
        storageOperations.WithLabelValues("query", tier, "error").Inc()
        return nil, errors.WrapError(err, "query failed", nil)
    }

    // Decrypt sensitive fields
    decryptedResults, err := c.encryptor.DecryptFields(results)
    if err != nil {
        storageOperations.WithLabelValues("query", tier, "error").Inc()
        return nil, errors.WrapError(err, "decryption failed", nil)
    }

    storageOperations.WithLabelValues("query", tier, "success").Inc()
    logging.SecurityAudit("Events queried securely", map[string]interface{}{
        "tier": tier,
    })

    return decryptedResults, nil
}

// validateConfig validates the ChaosSearch configuration
func validateConfig(config *ChaosSearchConfig) error {
    if config == nil {
        return errors.NewError("E2001", "configuration is required", nil)
    }
    if config.Endpoint == "" {
        return errors.NewError("E2001", "endpoint is required", nil)
    }
    if config.BucketName == "" {
        return errors.NewError("E2001", "bucket name is required", nil)
    }
    if config.ShardCount < 1 {
        return errors.NewError("E2001", "invalid shard count", nil)
    }
    if config.ReplicaCount < 1 {
        return errors.NewError("E2001", "invalid replica count", nil)
    }
    return nil
}

// generatePartitionKey generates a secure partition key for data storage
func generatePartitionKey(tier string, timestamp time.Time) string {
    return fmt.Sprintf("%s/%s/%d", tier, timestamp.Format("2006/01/02"), timestamp.Unix())
}