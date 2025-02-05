// Package integration provides core integration management functionality
package integration

import (
    "context"
    "sync"
    "time"

    "go.opentelemetry.io/otel" // v1.19.0
    "go.opentelemetry.io/otel/trace"
    "github.com/prometheus/client_golang/prometheus" // v1.17.0

    "../../pkg/common/errors"
    "../../pkg/common/logging"
    "../../pkg/integration/config"
    "../../pkg/integration/platform"
)

// Prometheus metrics
var (
    integrationDeployments = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_integration_deployments_total",
            Help: "Total number of integration deployments",
        },
        []string{"platform_type", "status"},
    )

    integrationLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "blackpoint_integration_operation_latency_seconds",
            Help:    "Latency of integration operations",
            Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
        },
        []string{"operation", "platform_type"},
    )

    activeIntegrations = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "blackpoint_active_integrations",
            Help: "Number of currently active integrations",
        },
        []string{"platform_type"},
    )
)

func init() {
    prometheus.MustRegister(integrationDeployments)
    prometheus.MustRegister(integrationLatency)
    prometheus.MustRegister(activeIntegrations)
}

// IntegrationManager provides thread-safe management of security platform integrations
type IntegrationManager struct {
    mutex              *sync.RWMutex
    activeIntegrations map[string]*Integration
    platformRegistry   *registry.Registry
    metricsCollector   *prometheus.Collector
    operationTimeout   time.Duration
    tracer            trace.Tracer
}

// Integration represents a deployed platform integration instance
type Integration struct {
    ID            string
    Config        *config.IntegrationConfig
    Platform      platform.Platform
    Status        *platform.PlatformStatus
    DeployedAt    time.Time
    LastUpdated   time.Time
}

var (
    managerInstance *IntegrationManager
    managerMutex    sync.Once
    defaultTimeout  = 30 * time.Second
)

// GetManager returns the singleton instance of IntegrationManager
func GetManager() *IntegrationManager {
    managerMutex.Do(func() {
        managerInstance = &IntegrationManager{
            mutex:              &sync.RWMutex{},
            activeIntegrations: make(map[string]*Integration),
            platformRegistry:   registry.GetRegistry(),
            operationTimeout:   defaultTimeout,
            tracer:            otel.Tracer("integration-manager"),
        }
        
        logging.Info("Integration manager initialized",
            "timeout", defaultTimeout,
        )
    })
    return managerInstance
}

// DeployIntegration deploys a new integration with enhanced validation and monitoring
func (m *IntegrationManager) DeployIntegration(ctx context.Context, cfg *config.IntegrationConfig) (string, error) {
    ctx, span := m.tracer.Start(ctx, "DeployIntegration")
    defer span.End()

    timer := prometheus.NewTimer(integrationLatency.WithLabelValues("deploy", cfg.PlatformType))
    defer timer.ObserveDuration()

    // Validate integration configuration
    if err := validator.ValidateIntegration(ctx, cfg); err != nil {
        integrationDeployments.WithLabelValues(cfg.PlatformType, "failed").Inc()
        return "", errors.WrapError(err, "integration validation failed", map[string]interface{}{
            "platform_type": cfg.PlatformType,
        })
    }

    // Get platform instance
    platform, err := m.platformRegistry.GetPlatform(cfg.PlatformType)
    if err != nil {
        integrationDeployments.WithLabelValues(cfg.PlatformType, "failed").Inc()
        return "", errors.WrapError(err, "failed to get platform instance", nil)
    }

    // Initialize platform
    if err := platform.Initialize(ctx, cfg); err != nil {
        integrationDeployments.WithLabelValues(cfg.PlatformType, "failed").Inc()
        return "", errors.WrapError(err, "platform initialization failed", nil)
    }

    // Create integration instance
    integration := &Integration{
        ID:          generateIntegrationID(cfg),
        Config:      cfg,
        Platform:    platform,
        DeployedAt:  time.Now().UTC(),
        LastUpdated: time.Now().UTC(),
    }

    // Initialize status
    status, err := platform.GetStatus(ctx)
    if err != nil {
        integrationDeployments.WithLabelValues(cfg.PlatformType, "failed").Inc()
        return "", errors.WrapError(err, "failed to get platform status", nil)
    }
    integration.Status = status

    // Store integration with thread safety
    m.mutex.Lock()
    m.activeIntegrations[integration.ID] = integration
    m.mutex.Unlock()

    // Start data collection
    if err := platform.StartCollection(ctx); err != nil {
        m.mutex.Lock()
        delete(m.activeIntegrations, integration.ID)
        m.mutex.Unlock()
        
        integrationDeployments.WithLabelValues(cfg.PlatformType, "failed").Inc()
        return "", errors.WrapError(err, "failed to start data collection", nil)
    }

    // Update metrics
    integrationDeployments.WithLabelValues(cfg.PlatformType, "success").Inc()
    activeIntegrations.WithLabelValues(cfg.PlatformType).Inc()

    logging.Info("Integration deployed successfully",
        "integration_id", integration.ID,
        "platform_type", cfg.PlatformType,
    )

    return integration.ID, nil
}

// StopIntegration safely stops and removes an integration
func (m *IntegrationManager) StopIntegration(ctx context.Context, integrationID string) error {
    ctx, span := m.tracer.Start(ctx, "StopIntegration")
    defer span.End()

    m.mutex.Lock()
    defer m.mutex.Unlock()

    integration, exists := m.activeIntegrations[integrationID]
    if !exists {
        return errors.NewError("E2001", "integration not found", map[string]interface{}{
            "integration_id": integrationID,
        })
    }

    timer := prometheus.NewTimer(integrationLatency.WithLabelValues("stop", integration.Config.PlatformType))
    defer timer.ObserveDuration()

    // Stop data collection
    if err := integration.Platform.StopCollection(ctx); err != nil {
        return errors.WrapError(err, "failed to stop data collection", nil)
    }

    // Update metrics
    activeIntegrations.WithLabelValues(integration.Config.PlatformType).Dec()

    // Remove from active integrations
    delete(m.activeIntegrations, integrationID)

    logging.Info("Integration stopped successfully",
        "integration_id", integrationID,
        "platform_type", integration.Config.PlatformType,
    )

    return nil
}

// GetIntegrationStatus retrieves current status of an integration
func (m *IntegrationManager) GetIntegrationStatus(ctx context.Context, integrationID string) (*platform.PlatformStatus, error) {
    ctx, span := m.tracer.Start(ctx, "GetIntegrationStatus")
    defer span.End()

    m.mutex.RLock()
    defer m.mutex.RUnlock()

    integration, exists := m.activeIntegrations[integrationID]
    if !exists {
        return nil, errors.NewError("E2001", "integration not found", map[string]interface{}{
            "integration_id": integrationID,
        })
    }

    timer := prometheus.NewTimer(integrationLatency.WithLabelValues("status", integration.Config.PlatformType))
    defer timer.ObserveDuration()

    status, err := integration.Platform.GetStatus(ctx)
    if err != nil {
        return nil, errors.WrapError(err, "failed to get platform status", nil)
    }

    integration.Status = status
    integration.LastUpdated = time.Now().UTC()

    return status, nil
}

// ListIntegrations returns a list of all active integrations
func (m *IntegrationManager) ListIntegrations(ctx context.Context) []*Integration {
    ctx, span := m.tracer.Start(ctx, "ListIntegrations")
    defer span.End()

    m.mutex.RLock()
    defer m.mutex.RUnlock()

    integrations := make([]*Integration, 0, len(m.activeIntegrations))
    for _, integration := range m.activeIntegrations {
        integrations = append(integrations, integration)
    }

    return integrations
}

// GetMetrics returns current integration metrics
func (m *IntegrationManager) GetMetrics(ctx context.Context) map[string]interface{} {
    ctx, span := m.tracer.Start(ctx, "GetMetrics")
    defer span.End()

    m.mutex.RLock()
    defer m.mutex.RUnlock()

    metrics := make(map[string]interface{})
    metrics["total_integrations"] = len(m.activeIntegrations)
    
    platformCounts := make(map[string]int)
    for _, integration := range m.activeIntegrations {
        platformCounts[integration.Config.PlatformType]++
    }
    metrics["platform_counts"] = platformCounts

    return metrics
}

// Helper function to generate unique integration ID
func generateIntegrationID(cfg *config.IntegrationConfig) string {
    return fmt.Sprintf("%s-%s-%d", cfg.PlatformType, cfg.Name, time.Now().UnixNano())
}