// Package bronze implements high-performance, secure event handling for the Bronze tier API
package bronze

import (
    "context"
    "net/http"
    "sync"
    "time"

    "github.com/gin-gonic/gin" // v1.9.0
    "github.com/prometheus/client_golang/prometheus" // v1.16.0
    "golang.org/x/sync/errgroup" // v0.5.0
    "golang.org/x/time/rate" // v0.3.0

    "github.com/blackpoint/pkg/bronze/event"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/logging"
)

var (
    // Prometheus metrics for request monitoring
    requestMetrics = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "bronze_api_requests_total",
            Help: "Total number of Bronze tier API requests",
        },
        []string{"endpoint", "status", "client_id"},
    )

    // Processing latency histogram
    processingLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "bronze_event_processing_seconds",
            Help: "Event processing latency in seconds",
            Buckets: []float64{0.1, 0.25, 0.5, 0.75, 1.0, 2.0},
        },
        []string{"endpoint", "client_id"},
    )

    // Constants
    maxBatchSize = 1000
    defaultRateLimit = 1000

    // Rate limiter cache
    rateLimiters = sync.Map{}
)

// getRateLimiter returns or creates a rate limiter for a client
func getRateLimiter(clientID string) *rate.Limiter {
    if limiter, exists := rateLimiters.Load(clientID); exists {
        return limiter.(*rate.Limiter)
    }

    limiter := rate.NewLimiter(rate.Limit(defaultRateLimit), defaultRateLimit)
    rateLimiters.Store(clientID, limiter)
    return limiter
}

// RegisterRoutes registers all Bronze tier API endpoints with security middleware
func RegisterRoutes(router *gin.Engine) {
    // Initialize metrics
    prometheus.MustRegister(requestMetrics, processingLatency)

    // Create Bronze API group with authentication middleware
    bronzeGroup := router.Group("/api/v1/bronze")
    bronzeGroup.Use(authMiddleware())
    
    // Register endpoints
    bronzeGroup.POST("/events", handleSingleEvent)
    bronzeGroup.POST("/events/batch", handleBatchEvents)
}

// handleSingleEvent processes a single security event with validation
func handleSingleEvent(c *gin.Context) {
    clientID := c.GetString("client_id")
    timer := prometheus.NewTimer(processingLatency.WithLabelValues("single", clientID))
    defer timer.ObserveDuration()

    // Apply rate limiting
    if !getRateLimiter(clientID).Allow() {
        requestMetrics.WithLabelValues("single", "rate_limited", clientID).Inc()
        c.JSON(http.StatusTooManyRequests, errors.NewError("E4002", "rate limit exceeded", nil))
        return
    }

    // Parse and validate event
    var bronzeEvent event.BronzeEvent
    if err := c.ShouldBindJSON(&bronzeEvent); err != nil {
        requestMetrics.WithLabelValues("single", "invalid_request", clientID).Inc()
        c.JSON(http.StatusBadRequest, errors.WrapError(err, "invalid event format", nil))
        return
    }

    // Validate event schema
    if err := event.ValidateEventSchema(&bronzeEvent); err != nil {
        requestMetrics.WithLabelValues("single", "validation_failed", clientID).Inc()
        c.JSON(http.StatusBadRequest, err)
        return
    }

    // Process event with timeout
    ctx, cancel := context.WithTimeout(c.Request.Context(), time.Second)
    defer cancel()

    if err := event.ProcessEvent(&bronzeEvent, ctx); err != nil {
        requestMetrics.WithLabelValues("single", "processing_failed", clientID).Inc()
        c.JSON(http.StatusInternalServerError, err)
        return
    }

    requestMetrics.WithLabelValues("single", "success", clientID).Inc()
    c.JSON(http.StatusCreated, gin.H{"status": "success", "event_id": bronzeEvent.ID})
}

// handleBatchEvents processes multiple events concurrently with validation
func handleBatchEvents(c *gin.Context) {
    clientID := c.GetString("client_id")
    timer := prometheus.NewTimer(processingLatency.WithLabelValues("batch", clientID))
    defer timer.ObserveDuration()

    // Parse batch request
    var events []event.BronzeEvent
    if err := c.ShouldBindJSON(&events); err != nil {
        requestMetrics.WithLabelValues("batch", "invalid_request", clientID).Inc()
        c.JSON(http.StatusBadRequest, errors.WrapError(err, "invalid batch format", nil))
        return
    }

    // Validate batch size
    if len(events) == 0 {
        requestMetrics.WithLabelValues("batch", "empty_batch", clientID).Inc()
        c.JSON(http.StatusBadRequest, errors.NewError("E3001", "empty batch", nil))
        return
    }
    if len(events) > maxBatchSize {
        requestMetrics.WithLabelValues("batch", "size_exceeded", clientID).Inc()
        c.JSON(http.StatusBadRequest, errors.NewError("E3001", "batch size exceeds limit", map[string]interface{}{
            "max_size": maxBatchSize,
            "provided": len(events),
        }))
        return
    }

    // Process events concurrently
    g, ctx := errgroup.WithContext(c.Request.Context())
    ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
    defer cancel()

    results := make([]error, len(events))
    for i := range events {
        i := i // https://golang.org/doc/faq#closures_and_goroutines
        g.Go(func() error {
            if err := event.ValidateEventSchema(&events[i]); err != nil {
                results[i] = err
                return nil
            }
            return event.ProcessEvent(&events[i], ctx)
        })
    }

    if err := g.Wait(); err != nil {
        requestMetrics.WithLabelValues("batch", "processing_failed", clientID).Inc()
        c.JSON(http.StatusInternalServerError, errors.WrapError(err, "batch processing failed", nil))
        return
    }

    // Collect results
    successCount := 0
    failureCount := 0
    failedEvents := make([]string, 0)

    for i, err := range results {
        if err != nil {
            failureCount++
            failedEvents = append(failedEvents, events[i].ID)
        } else {
            successCount++
        }
    }

    requestMetrics.WithLabelValues("batch", "success", clientID).Inc()
    c.JSON(http.StatusOK, gin.H{
        "status": "completed",
        "summary": map[string]interface{}{
            "total":     len(events),
            "success":   successCount,
            "failures":  failureCount,
            "failed_ids": failedEvents,
        },
    })
}

// authMiddleware validates client authentication and authorization
func authMiddleware() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract and validate client credentials
        clientID := c.GetHeader("X-Client-ID")
        if clientID == "" {
            c.AbortWithStatusJSON(http.StatusUnauthorized, errors.NewError("E1001", "missing client ID", nil))
            return
        }

        // Set client ID for request context
        c.Set("client_id", clientID)

        // Log security audit
        logging.SecurityAudit("API request authenticated", map[string]interface{}{
            "client_id": clientID,
            "endpoint":  c.FullPath(),
            "method":    c.Request.Method,
        })

        c.Next()
    }
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(requestMetrics, processingLatency)
}