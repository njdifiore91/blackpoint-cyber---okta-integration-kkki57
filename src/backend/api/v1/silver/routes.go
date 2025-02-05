// Package silver provides API routes for the Silver tier of the BlackPoint Security Integration Framework
package silver

import (
    "time"

    "github.com/gin-gonic/gin"                  // v1.9.0
    "go.opentelemetry.io/otel"                  // v1.0.0
    "github.com/security/go-security"           // v1.2.0
    "golang.org/x/time/rate"                    // v0.5.0

    "github.com/blackpoint/api/v1/silver/handlers"
    "github.com/blackpoint/pkg/common/middleware"
)

// Constants for Silver tier API configuration
const (
    // Rate limiting configuration
    silverAPIRateLimit rate.Limit = 100  // requests per minute
    silverAPIBurst     int        = 50   // burst capacity
    
    // Request timeouts
    silverAPITimeout   = 30 * time.Second
    
    // Retry configuration
    silverAPIMaxRetries = 3
)

// Security headers for Silver tier
var silverAPISecurityHeaders = map[string]string{
    "X-Content-Type-Options":     "nosniff",
    "X-Frame-Options":           "DENY",
    "X-XSS-Protection":          "1; mode=block",
    "Content-Security-Policy":    "default-src 'self'",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Cache-Control":             "no-store, max-age=0",
}

// SetupSilverRoutes configures all Silver tier API routes with comprehensive security
func SetupSilverRoutes(router *gin.Engine, securityCtx *security.Context) error {
    // Initialize OpenTelemetry tracer
    tracer := otel.Tracer("silver-api")
    
    // Create Silver tier route group
    silverGroup := router.Group("/api/v1/silver")

    // Apply security headers middleware
    silverGroup.Use(func(c *gin.Context) {
        for key, value := range silverAPISecurityHeaders {
            c.Header(key, value)
        }
    })

    // Apply security and monitoring middleware stack
    silverGroup.Use(
        // Request tracing
        middleware.TracingMiddleware(tracer),

        // Authentication and authorization
        middleware.AuthMiddleware,

        // Rate limiting per client
        func(c *gin.Context) {
            middleware.RateLimitMiddleware(c, silverAPIRateLimit, silverAPIBurst)
        },

        // Request metrics collection
        middleware.MetricsMiddleware("silver_api"),

        // Security audit logging
        middleware.AuditMiddleware(securityCtx),

        // Enhanced logging with security context
        middleware.LoggingMiddleware,

        // Centralized error handling
        middleware.ErrorMiddleware,
    )

    // Configure routes with security context
    silverGroup.GET("/events", func(c *gin.Context) {
        // Add request timeout
        c.Request = c.Request.WithContext(
            middleware.TimeoutContext(c.Request.Context(), silverAPITimeout),
        )
        handlers.GetEventsHandler(c)
    })

    silverGroup.GET("/events/:id", func(c *gin.Context) {
        // Add request timeout
        c.Request = c.Request.WithContext(
            middleware.TimeoutContext(c.Request.Context(), silverAPITimeout),
        )
        handlers.GetEventByIDHandler(c)
    })

    // Health check endpoint with basic security
    silverGroup.GET("/health", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "status": "healthy",
            "tier":   "silver",
            "time":   time.Now().UTC(),
        })
    })

    // Metrics endpoint with security context
    silverGroup.GET("/metrics", middleware.AuthMiddleware, func(c *gin.Context) {
        // Implement secure metrics endpoint
        middleware.MetricsHandler(c, "silver_api")
    })

    return nil
}