// Package integrations provides HTTP handlers for managing security platform integrations
package integrations

import (
    "context"
    "net/http"
    "time"

    "github.com/gin-gonic/gin" // v1.9.0
    "github.com/go-playground/validator/v10" // v10.11.0
    "github.com/opentracing/opentracing-go" // v1.2.0
    "github.com/prometheus/client_golang/prometheus" // v1.12.0

    "../../internal/integration/manager"
    "../../pkg/integration/config"
    "../../pkg/common/errors"
)

// Prometheus metrics
var (
    requestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_integration_api_request_duration_seconds",
            Help: "Duration of integration API requests",
            Buckets: prometheus.ExponentialBuckets(0.01, 2, 10),
        },
        []string{"endpoint", "status"},
    )

    requestTotal = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_integration_api_requests_total",
            Help: "Total number of integration API requests",
        },
        []string{"endpoint", "status"},
    )
)

func init() {
    prometheus.MustRegister(requestDuration)
    prometheus.MustRegister(requestTotal)
}

// HandleDeployIntegration handles POST requests to deploy new platform integrations
func HandleDeployIntegration(c *gin.Context) {
    timer := prometheus.NewTimer(requestDuration.WithLabelValues("/deploy", "processing"))
    defer timer.ObserveDuration()

    // Start tracing span
    span, ctx := opentracing.StartSpanFromContext(c.Request.Context(), "HandleDeployIntegration")
    defer span.Finish()

    // Bind and validate request payload
    var integrationCfg config.IntegrationConfig
    if err := c.ShouldBindJSON(&integrationCfg); err != nil {
        requestTotal.WithLabelValues("/deploy", "error").Inc()
        c.JSON(http.StatusBadRequest, errors.NewError("E2001", "invalid request payload", map[string]interface{}{
            "error": err.Error(),
        }))
        return
    }

    // Validate integration configuration
    if err := integrationCfg.Validate(); err != nil {
        requestTotal.WithLabelValues("/deploy", "error").Inc()
        c.JSON(http.StatusBadRequest, err)
        return
    }

    // Get integration manager instance
    mgr := manager.GetManager()

    // Deploy integration with timeout
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    integrationID, err := mgr.DeployIntegration(ctx, &integrationCfg)
    if err != nil {
        requestTotal.WithLabelValues("/deploy", "error").Inc()
        c.JSON(http.StatusInternalServerError, err)
        return
    }

    requestTotal.WithLabelValues("/deploy", "success").Inc()
    c.JSON(http.StatusCreated, gin.H{
        "integration_id": integrationID,
        "status": "deployed",
        "timestamp": time.Now().UTC(),
    })
}

// HandleStopIntegration handles DELETE requests to stop and remove integrations
func HandleStopIntegration(c *gin.Context) {
    timer := prometheus.NewTimer(requestDuration.WithLabelValues("/stop", "processing"))
    defer timer.ObserveDuration()

    // Start tracing span
    span, ctx := opentracing.StartSpanFromContext(c.Request.Context(), "HandleStopIntegration")
    defer span.Finish()

    // Get integration ID from path
    integrationID := c.Param("integration_id")
    if integrationID == "" {
        requestTotal.WithLabelValues("/stop", "error").Inc()
        c.JSON(http.StatusBadRequest, errors.NewError("E2001", "missing integration_id", nil))
        return
    }

    // Get integration manager instance
    mgr := manager.GetManager()

    // Stop integration with timeout
    ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
    defer cancel()

    if err := mgr.StopIntegration(ctx, integrationID); err != nil {
        requestTotal.WithLabelValues("/stop", "error").Inc()
        c.JSON(http.StatusInternalServerError, err)
        return
    }

    requestTotal.WithLabelValues("/stop", "success").Inc()
    c.JSON(http.StatusOK, gin.H{
        "integration_id": integrationID,
        "status": "stopped",
        "timestamp": time.Now().UTC(),
    })
}

// HandleGetIntegrationStatus handles GET requests to retrieve integration status
func HandleGetIntegrationStatus(c *gin.Context) {
    timer := prometheus.NewTimer(requestDuration.WithLabelValues("/status", "processing"))
    defer timer.ObserveDuration()

    // Start tracing span
    span, ctx := opentracing.StartSpanFromContext(c.Request.Context(), "HandleGetIntegrationStatus")
    defer span.Finish()

    // Get integration ID from path
    integrationID := c.Param("integration_id")
    if integrationID == "" {
        requestTotal.WithLabelValues("/status", "error").Inc()
        c.JSON(http.StatusBadRequest, errors.NewError("E2001", "missing integration_id", nil))
        return
    }

    // Get integration manager instance
    mgr := manager.GetManager()

    // Get status with timeout
    ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
    defer cancel()

    status, err := mgr.GetIntegrationStatus(ctx, integrationID)
    if err != nil {
        requestTotal.WithLabelValues("/status", "error").Inc()
        c.JSON(http.StatusInternalServerError, err)
        return
    }

    requestTotal.WithLabelValues("/status", "success").Inc()
    c.JSON(http.StatusOK, status)
}

// HandleListIntegrations handles GET requests to list all active integrations
func HandleListIntegrations(c *gin.Context) {
    timer := prometheus.NewTimer(requestDuration.WithLabelValues("/list", "processing"))
    defer timer.ObserveDuration()

    // Start tracing span
    span, ctx := opentracing.StartSpanFromContext(c.Request.Context(), "HandleListIntegrations")
    defer span.Finish()

    // Parse pagination parameters
    page := c.DefaultQuery("page", "1")
    pageSize := c.DefaultQuery("page_size", "10")

    // Get integration manager instance
    mgr := manager.GetManager()

    // List integrations with timeout
    ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
    defer cancel()

    integrations := mgr.ListIntegrations(ctx)

    // Apply pagination (simplified implementation)
    // In production, this should be handled at the database level
    total := len(integrations)
    
    requestTotal.WithLabelValues("/list", "success").Inc()
    c.JSON(http.StatusOK, gin.H{
        "integrations": integrations,
        "total": total,
        "page": page,
        "page_size": pageSize,
        "timestamp": time.Now().UTC(),
    })
}