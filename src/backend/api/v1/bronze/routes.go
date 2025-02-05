// Package bronze implements API routes for the Bronze tier of the BlackPoint Security Integration Framework
package bronze

import (
    "net/http"
    "time"

    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/logging"
    "github.com/blackpoint/pkg/common/middleware"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "golang.org/x/time/rate" // v0.5.0
)

// Global constants for route configuration
const (
    defaultRateLimit          rate.Limit = 1000 // requests per minute
    defaultBurst             int        = 50
    bronzeAPIPrefix          string     = "/api/v1/bronze"
    requestTimeout           = 5 * time.Second
    circuitBreakerThreshold = 100
)

// Prometheus metrics for route monitoring
var (
    routeLatency = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "bronze_route_latency_seconds",
            Help: "Latency of Bronze tier API routes",
            Buckets: []float64{0.1, 0.5, 1.0, 2.0, 5.0},
        },
        []string{"route", "method"},
    )

    routeErrors = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "bronze_route_errors_total",
            Help: "Total number of Bronze tier route errors",
        },
        []string{"route", "error_code"},
    )

    activeRequests = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "bronze_active_requests",
            Help: "Number of active requests by route",
        },
        []string{"route"},
    )
)

// NewBronzeRouter creates and configures a new router for Bronze tier API endpoints
func NewBronzeRouter(processor *event.EventProcessor, metrics *monitoring.MetricsCollector) http.Handler {
    // Create base router
    mux := http.NewServeMux()

    // Configure base middleware chain
    baseChain := setupMiddleware(metrics)

    // Register routes with security and monitoring
    mux.Handle(bronzeAPIPrefix+"/events", 
        baseChain.Then(handleSingleEvent(processor)))

    mux.Handle(bronzeAPIPrefix+"/events/batch", 
        baseChain.Then(handleBatchEvents(processor)))

    mux.Handle(bronzeAPIPrefix+"/events/status", 
        baseChain.Then(handleEventStatus(processor)))

    // Log router initialization
    logging.Info("Bronze tier router initialized",
        map[string]interface{}{
            "routes": []string{"/events", "/events/batch", "/events/status"},
            "rate_limit": defaultRateLimit,
            "timeout": requestTimeout,
        })

    return mux
}

// setupMiddleware configures the middleware chain with security and monitoring
func setupMiddleware(metrics *monitoring.MetricsCollector) middleware.Chain {
    return middleware.Chain{
        // Authentication and authorization
        middleware.AuthMiddleware(jwt.ValidateToken),
        
        // Security headers
        middleware.SecurityHeadersMiddleware(map[string]string{
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        }),

        // Rate limiting with client tiers
        middleware.RateLimitMiddleware(defaultRateLimit, defaultBurst),

        // Request timeout control
        middleware.TimeoutMiddleware(requestTimeout),

        // Circuit breaker protection
        middleware.CircuitBreakerMiddleware(circuitBreakerThreshold),

        // Request tracing
        middleware.TracingMiddleware(metrics.TraceProvider()),

        // Logging with security context
        middleware.LoggingMiddleware(),

        // Error handling
        middleware.ErrorMiddleware(),

        // Request validation
        middleware.ValidationMiddleware(validation.ValidateRequest),
    }
}

// handleSingleEvent handles individual event ingestion
func handleSingleEvent(processor *event.EventProcessor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        timer := prometheus.NewTimer(routeLatency.WithLabelValues("/events", r.Method))
        defer timer.ObserveDuration()

        activeRequests.WithLabelValues("/events").Inc()
        defer activeRequests.WithLabelValues("/events").Dec()

        if r.Method != http.MethodPost {
            routeErrors.WithLabelValues("/events", "method_not_allowed").Inc()
            errors.SendError(w, errors.NewError("E3001", "Method not allowed", nil))
            return
        }

        handlers.HandleSingleEvent(w, r)
    }
}

// handleBatchEvents handles batch event ingestion
func handleBatchEvents(processor *event.EventProcessor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        timer := prometheus.NewTimer(routeLatency.WithLabelValues("/events/batch", r.Method))
        defer timer.ObserveDuration()

        activeRequests.WithLabelValues("/events/batch").Inc()
        defer activeRequests.WithLabelValues("/events/batch").Dec()

        if r.Method != http.MethodPost {
            routeErrors.WithLabelValues("/events/batch", "method_not_allowed").Inc()
            errors.SendError(w, errors.NewError("E3001", "Method not allowed", nil))
            return
        }

        handlers.HandleBatchEvents(w, r)
    }
}

// handleEventStatus handles event status queries
func handleEventStatus(processor *event.EventProcessor) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        timer := prometheus.NewTimer(routeLatency.WithLabelValues("/events/status", r.Method))
        defer timer.ObserveDuration()

        activeRequests.WithLabelValues("/events/status").Inc()
        defer activeRequests.WithLabelValues("/events/status").Dec()

        if r.Method != http.MethodGet {
            routeErrors.WithLabelValues("/events/status", "method_not_allowed").Inc()
            errors.SendError(w, errors.NewError("E3001", "Method not allowed", nil))
            return
        }

        handlers.HandleEventStatus(w, r)
    }
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(routeLatency, routeErrors, activeRequests)
}