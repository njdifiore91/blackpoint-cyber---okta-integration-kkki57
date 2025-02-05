// Package integrations provides API routes and middleware configuration for platform integrations
package integrations

import (
    "net/http"
    "time"

    "github.com/gin-gonic/gin" // v1.9.0
    "github.com/gin-contrib/middleware" // v1.0.0
    "go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin" // v0.42.0
    "github.com/prometheus/client_golang/prometheus" // v1.17.0

    "./handlers"
)

// Prometheus metrics for route monitoring
var (
    routeLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_integration_route_latency_seconds",
            Help: "Latency of integration API routes",
            Buckets: prometheus.ExponentialBuckets(0.01, 2, 10),
        },
        []string{"route", "method", "status"},
    )

    routeRequests = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_integration_route_requests_total",
            Help: "Total number of integration API requests",
        },
        []string{"route", "method", "status"},
    )
)

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(routeLatency)
    prometheus.MustRegister(routeRequests)
}

// SetupIntegrationRoutes configures all integration API routes with enhanced security and monitoring
func SetupIntegrationRoutes(router *gin.Engine) {
    // Configure security headers middleware
    router.Use(middleware.SecureHeaders())

    // Configure CORS with secure defaults
    router.Use(middleware.CORSWithConfig(middleware.CORSConfig{
        AllowOrigins:     []string{"https://*.blackpoint.com"},
        AllowMethods:     []string{"GET", "POST", "DELETE"},
        AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
        ExposeHeaders:    []string{"Content-Length"},
        AllowCredentials: true,
        MaxAge:          12 * time.Hour,
    }))

    // Configure request size limits and timeouts
    router.Use(middleware.RequestSizeLimiter(10 * 1024 * 1024)) // 10MB limit
    router.Use(middleware.Timeout(30 * time.Second))

    // Configure OpenTelemetry tracing
    router.Use(otelgin.Middleware("blackpoint-integration-api"))

    // Create v1 API group with authentication middleware
    v1 := router.Group("/api/v1")
    v1.Use(middleware.OAuth2Auth())
    v1.Use(middleware.RateLimiter(1000, time.Minute)) // 1000 requests per minute

    // Integration management endpoints
    integrations := v1.Group("/integrations")
    {
        // Deploy new integration
        integrations.POST("", metricMiddleware("/integrations", "POST"),
            validateIntegrationConfig(),
            handlers.HandleDeployIntegration,
        )

        // Stop integration
        integrations.DELETE("/:integration_id", metricMiddleware("/integrations/:id", "DELETE"),
            validateIntegrationID(),
            handlers.HandleStopIntegration,
        )

        // Get integration status
        integrations.GET("/:integration_id", metricMiddleware("/integrations/:id", "GET"),
            validateIntegrationID(),
            handlers.HandleGetIntegrationStatus,
        )

        // List all integrations
        integrations.GET("", metricMiddleware("/integrations", "GET"),
            validatePaginationParams(),
            handlers.HandleListIntegrations,
        )
    }
}

// metricMiddleware records route-specific metrics
func metricMiddleware(route, method string) gin.HandlerFunc {
    return func(c *gin.Context) {
        start := time.Now()

        // Process request
        c.Next()

        // Record metrics
        status := c.Writer.Status()
        latency := time.Since(start).Seconds()

        routeLatency.WithLabelValues(route, method, http.StatusText(status)).Observe(latency)
        routeRequests.WithLabelValues(route, method, http.StatusText(status)).Inc()
    }
}

// validateIntegrationConfig validates the integration configuration payload
func validateIntegrationConfig() gin.HandlerFunc {
    return func(c *gin.Context) {
        var config struct {
            PlatformType string `json:"platform_type" binding:"required"`
            Name        string `json:"name" binding:"required,min=3,max=50"`
            Environment string `json:"environment" binding:"required,oneof=development staging production"`
        }

        if err := c.ShouldBindJSON(&config); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{
                "error": "invalid integration configuration",
                "details": err.Error(),
            })
            c.Abort()
            return
        }

        c.Next()
    }
}

// validateIntegrationID validates the integration ID parameter
func validateIntegrationID() gin.HandlerFunc {
    return func(c *gin.Context) {
        integrationID := c.Param("integration_id")
        if integrationID == "" {
            c.JSON(http.StatusBadRequest, gin.H{
                "error": "missing integration_id parameter",
            })
            c.Abort()
            return
        }

        c.Next()
    }
}

// validatePaginationParams validates pagination query parameters
func validatePaginationParams() gin.HandlerFunc {
    return func(c *gin.Context) {
        page := c.DefaultQuery("page", "1")
        pageSize := c.DefaultQuery("page_size", "10")

        // Additional validation could be added here if needed

        c.Set("page", page)
        c.Set("page_size", pageSize)
        c.Next()
    }
}