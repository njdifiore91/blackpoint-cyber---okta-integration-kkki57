// Package integration provides deployment functionality for security platform integrations
package integration

import (
    "context"
    "sync"
    "time"

    "github.com/pkg/errors"
    "github.com/sirupsen/logrus"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"

    "../../pkg/integration/types"
    "../integration/config"
    "../../pkg/api/client"
)

var (
    defaultDeployTimeout = 15 * time.Minute
    defaultMaxRetries = 5
    deploymentCheckInterval = 15 * time.Second
    maxConcurrentDeployments = 30
    healthCheckTimeout = 30 * time.Second
    deploymentMetricsInterval = 60 * time.Second

    // Prometheus metrics
    deploymentDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
        Name: "blackpoint_integration_deployment_duration_seconds",
        Help: "Duration of integration deployments",
        Buckets: []float64{30, 60, 120, 300, 600, 900},
    }, []string{"platform_type", "environment"})

    deploymentStatus = promauto.NewGaugeVec(prometheus.GaugeOpts{
        Name: "blackpoint_integration_deployment_status",
        Help: "Current status of integration deployments",
    }, []string{"platform_type", "environment", "status"})

    deploymentErrors = promauto.NewCounterVec(prometheus.CounterOpts{
        Name: "blackpoint_integration_deployment_errors_total",
        Help: "Total number of deployment errors",
    }, []string{"platform_type", "environment", "error_type"})
)

// Deployer manages the deployment of security platform integrations
type Deployer struct {
    apiClient       *client.APIClient
    timeout         time.Duration
    maxRetries      int
    logger          *logrus.Logger
    deploymentLock  sync.Mutex
    activeDeployments map[string]*types.DeploymentStatus
}

// NewDeployer creates a new deployer instance with the specified configuration
func NewDeployer(client *client.APIClient, timeout time.Duration, logger *logrus.Logger) (*Deployer, error) {
    if client == nil {
        return nil, errors.New("API client is required")
    }
    if timeout <= 0 {
        timeout = defaultDeployTimeout
    }
    if logger == nil {
        logger = logrus.New()
        logger.SetLevel(logrus.InfoLevel)
    }

    return &Deployer{
        apiClient:         client,
        timeout:          timeout,
        maxRetries:       defaultMaxRetries,
        logger:           logger,
        activeDeployments: make(map[string]*types.DeploymentStatus),
    }, nil
}

// Deploy performs a comprehensive deployment of an integration with validation and monitoring
func (d *Deployer) Deploy(ctx context.Context, integration *types.Integration, options *client.DeploymentOptions) error {
    startTime := time.Now()
    defer func() {
        deploymentDuration.WithLabelValues(
            integration.PlatformType,
            integration.Config.Environment,
        ).Observe(time.Since(startTime).Seconds())
    }()

    // Validate deployment prerequisites
    if err := d.ValidateDeployment(integration, options); err != nil {
        deploymentErrors.WithLabelValues(
            integration.PlatformType,
            integration.Config.Environment,
            "validation_error",
        ).Inc()
        return errors.Wrap(err, "deployment validation failed")
    }

    // Check concurrent deployment limits
    d.deploymentLock.Lock()
    if len(d.activeDeployments) >= maxConcurrentDeployments {
        d.deploymentLock.Unlock()
        return errors.New("maximum concurrent deployments reached")
    }
    
    // Create deployment context
    deployCtx, cancel := context.WithTimeout(ctx, d.timeout)
    defer cancel()

    // Initialize deployment status
    deploymentID := integration.ID
    status := &types.DeploymentStatus{
        ID:        deploymentID,
        StartTime: startTime,
        Status:    "in_progress",
    }
    d.activeDeployments[deploymentID] = status
    d.deploymentLock.Unlock()

    // Cleanup deployment status when done
    defer func() {
        d.deploymentLock.Lock()
        delete(d.activeDeployments, deploymentID)
        d.deploymentLock.Unlock()
    }()

    // Start deployment monitoring
    monitorCtx, monitorCancel := context.WithCancel(deployCtx)
    defer monitorCancel()
    
    go func() {
        if err := d.MonitorDeployment(monitorCtx, deploymentID); err != nil {
            d.logger.WithError(err).Error("Deployment monitoring failed")
        }
    }()

    // Execute deployment
    d.logger.WithFields(logrus.Fields{
        "integration_id":   integration.ID,
        "platform_type":    integration.PlatformType,
        "environment":      integration.Config.Environment,
    }).Info("Starting integration deployment")

    // Deploy integration resources
    err := d.executeDeployment(deployCtx, integration, options)
    if err != nil {
        status.Status = "failed"
        status.Error = err.Error()
        deploymentErrors.WithLabelValues(
            integration.PlatformType,
            integration.Config.Environment,
            "deployment_error",
        ).Inc()
        return errors.Wrap(err, "deployment execution failed")
    }

    // Update deployment status
    status.Status = "completed"
    status.CompletionTime = time.Now()
    
    deploymentStatus.WithLabelValues(
        integration.PlatformType,
        integration.Config.Environment,
        "completed",
    ).Inc()

    return nil
}

// ValidateDeployment performs comprehensive validation of deployment prerequisites
func (d *Deployer) ValidateDeployment(integration *types.Integration, options *client.DeploymentOptions) error {
    if integration == nil {
        return errors.New("integration configuration is required")
    }

    // Validate integration configuration
    if err := integration.Validate(); err != nil {
        return errors.Wrap(err, "invalid integration configuration")
    }

    // Validate deployment options
    if options == nil {
        return errors.New("deployment options are required")
    }

    // Load and validate integration configuration
    if err := config.ValidateConfigFile(options.ConfigPath); err != nil {
        return errors.Wrap(err, "invalid integration configuration file")
    }

    return nil
}

// MonitorDeployment monitors deployment progress and health
func (d *Deployer) MonitorDeployment(ctx context.Context, deploymentID string) error {
    ticker := time.NewTicker(deploymentCheckInterval)
    defer ticker.Stop()

    metricsTimer := time.NewTicker(deploymentMetricsInterval)
    defer metricsTimer.Stop()

    for {
        select {
        case <-ctx.Done():
            return ctx.Err()
        case <-ticker.C:
            status, err := d.checkDeploymentStatus(ctx, deploymentID)
            if err != nil {
                d.logger.WithError(err).Error("Failed to check deployment status")
                continue
            }

            d.deploymentLock.Lock()
            if deployment, exists := d.activeDeployments[deploymentID]; exists {
                deployment.Status = status
            }
            d.deploymentLock.Unlock()

        case <-metricsTimer.C:
            d.updateDeploymentMetrics(deploymentID)
        }
    }
}

// executeDeployment performs the actual deployment with retry logic
func (d *Deployer) executeDeployment(ctx context.Context, integration *types.Integration, options *client.DeploymentOptions) error {
    var lastErr error
    for attempt := 0; attempt <= d.maxRetries; attempt++ {
        if attempt > 0 {
            d.logger.WithField("attempt", attempt).Info("Retrying deployment")
            time.Sleep(time.Second * time.Duration(attempt))
        }

        err := d.apiClient.Post(ctx, "/api/v1/integrations/deploy", integration, nil)
        if err == nil {
            return nil
        }

        lastErr = err
        if !isRetryableError(err) {
            return errors.Wrap(err, "non-retryable deployment error")
        }
    }

    return errors.Wrap(lastErr, "deployment failed after retries")
}

// checkDeploymentStatus checks the current status of a deployment
func (d *Deployer) checkDeploymentStatus(ctx context.Context, deploymentID string) (string, error) {
    ctx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
    defer cancel()

    var status struct {
        Status string `json:"status"`
    }

    err := d.apiClient.Get(ctx, "/api/v1/integrations/status/"+deploymentID, &status)
    if err != nil {
        return "", errors.Wrap(err, "failed to get deployment status")
    }

    return status.Status, nil
}

// updateDeploymentMetrics updates Prometheus metrics for deployment monitoring
func (d *Deployer) updateDeploymentMetrics(deploymentID string) {
    d.deploymentLock.Lock()
    defer d.deploymentLock.Unlock()

    if deployment, exists := d.activeDeployments[deploymentID]; exists {
        deploymentStatus.WithLabelValues(
            deployment.PlatformType,
            deployment.Environment,
            deployment.Status,
        ).Inc()
    }
}

// isRetryableError determines if an error can be retried
func isRetryableError(err error) bool {
    if err == nil {
        return false
    }

    // Check for specific error types that can be retried
    if errors.Is(err, context.DeadlineExceeded) || 
       errors.Is(err, context.Canceled) {
        return true
    }

    // Check for network-related errors
    if strings.Contains(err.Error(), "connection refused") ||
       strings.Contains(err.Error(), "timeout") {
        return true
    }

    return false
}