// Package gold implements secure routing for Gold tier API endpoints
package gold

import (
    "time"

    "github.com/gin-gonic/gin" // v1.9.0
    "github.com/blackpoint/pkg/common/middleware"
)

const (
    // API configuration
    goldAPIPrefix   = "/api/v1/gold"
    goldRateLimit   = 50          // 50 requests per minute
    goldTimeout     = 30          // 30 seconds timeout
    goldCacheExpiry = 300         // 5 minutes cache expiry
    goldMaxRetries  = 3           // Maximum retries for circuit breaker
)

// SetupGoldRoutes configures and initializes all Gold tier API routes with comprehensive security features
func SetupGoldRoutes(router *gin.Engine) {
    // Create Gold tier API route group
    goldGroup := router.Group(goldAPIPrefix)

    // Apply security middleware stack
    goldGroup.Use(
        // Authentication and authorization
        middleware.AuthMiddleware,
        
        // Rate limiting - 50 requests per minute
        func(c *gin.Context) {
            middleware.RateLimitMiddleware(c, goldRateLimit, goldRateLimit*2)
        },

        // Security headers
        middleware.SecurityHeadersMiddleware,

        // Request validation
        middleware.RequestValidationMiddleware,

        // Response sanitization
        middleware.ResponseSanitizationMiddleware,

        // Compliance tracking
        middleware.ComplianceMiddleware,

        // Circuit breaker for fault tolerance
        func(c *gin.Context) {
            middleware.CircuitBreakerMiddleware(c, goldMaxRetries)
        },

        // Request timeout
        func(c *gin.Context) {
            middleware.TimeoutMiddleware(c, time.Duration(goldTimeout)*time.Second)
        },

        // Comprehensive logging
        middleware.LoggingMiddleware,

        // Error handling
        middleware.ErrorMiddleware,
    )

    // Alert Management Routes
    // GET /alerts - List security alerts with pagination and filtering
    goldGroup.GET("/alerts", ListAlertsHandler)

    // GET /alerts/:id - Get specific alert by ID with security validation
    goldGroup.GET("/alerts/:id", GetAlertHandler)

    // POST /alerts - Create new security alert with enhanced validation
    goldGroup.POST("/alerts", CreateAlertHandler)

    // PUT /alerts/:id/status - Update alert status with audit trail
    goldGroup.PUT("/alerts/:id/status", UpdateAlertStatusHandler)

    // Configure CORS for Gold tier
    goldGroup.Use(func(c *gin.Context) {
        c.Header("Access-Control-Allow-Origin", "*")
        c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, OPTIONS")
        c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Request-ID")
        c.Header("Access-Control-Max-Age", "86400")
        
        if c.Request.Method == "OPTIONS" {
            c.AbortWithStatus(204)
            return
        }
        
        c.Next()
    })

    // Configure security headers
    goldGroup.Use(func(c *gin.Context) {
        c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        c.Header("Content-Security-Policy", "default-src 'self'")
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("X-Frame-Options", "DENY")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        c.Header("Feature-Policy", "none")
    })

    // Configure response compression
    goldGroup.Use(func(c *gin.Context) {
        c.Header("Content-Encoding", "gzip")
        c.Next()
    })

    // Configure request correlation
    goldGroup.Use(func(c *gin.Context) {
        requestID := c.GetHeader("X-Request-ID")
        if requestID == "" {
            requestID = generateRequestID()
            c.Header("X-Request-ID", requestID)
        }
        c.Set("request_id", requestID)
        c.Next()
    })

    // Configure performance optimization
    goldGroup.Use(func(c *gin.Context) {
        c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
        c.Header("Pragma", "no-cache")
        c.Header("Expires", "0")
        c.Next()
    })
}

// generateRequestID generates a unique request identifier
func generateRequestID() string {
    return time.Now().UTC().Format("20060102150405") + "-" + 
           fmt.Sprintf("%016x", rand.Int63())
}