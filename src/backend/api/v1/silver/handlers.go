// Package silver provides HTTP handlers for the Silver tier API endpoints
package silver

import (
    "net/http"
    "time"
    "sync"

    "github.com/gin-gonic/gin"                         // v1.9.0
    "github.com/prometheus/client_golang/prometheus"    // v1.12.0
    "github.com/go-playground/validator/v10"           // v10.11.0

    "github.com/blackpoint/pkg/silver/event"
    "github.com/blackpoint/pkg/common/middleware"
    "github.com/blackpoint/pkg/common/errors"
)

// Constants for request handling
const (
    defaultPageSize = 100
    maxPageSize     = 1000
    defaultTimeRange = 24 * time.Hour
    maxTimeRange     = 90 * 24 * time.Hour
    slaThreshold    = 5 * time.Second
)

// Metrics collectors
var (
    requestLatency = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_silver_api_request_latency_seconds",
            Help: "Request latency in seconds for Silver tier API endpoints",
            Buckets: []float64{0.1, 0.5, 1, 2, 5},
        },
        []string{"endpoint", "status"},
    )

    requestErrors = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_silver_api_errors_total",
            Help: "Number of Silver tier API errors by type",
        },
        []string{"endpoint", "error_type"},
    )

    slaBreaches = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_silver_api_sla_breaches_total",
            Help: "Number of SLA breaches by endpoint",
        },
        []string{"endpoint"},
    )
)

// QueryParams represents validated query parameters
type QueryParams struct {
    StartTime      time.Time              `json:"start_time" validate:"required"`
    EndTime        time.Time              `json:"end_time" validate:"required,gtfield=StartTime"`
    Filters        map[string]interface{} `json:"filters"`
    Page          int                     `json:"page" validate:"min=1"`
    PageSize      int                     `json:"page_size" validate:"min=1,max=1000"`
    SecurityContext *SecurityContext       `json:"security_context"`
}

// SecurityContext represents request security metadata
type SecurityContext struct {
    ClientID     string   `json:"client_id"`
    Roles        []string `json:"roles"`
    Permissions  map[string]interface{} `json:"permissions"`
}

// GetEventsHandler handles GET requests for retrieving normalized security events
func GetEventsHandler(c *gin.Context) {
    timer := prometheus.NewTimer(requestLatency.WithLabelValues("get_events", "processing"))
    defer timer.ObserveDuration()

    // Start SLA tracking
    start := time.Now()
    defer func() {
        if time.Since(start) > slaThreshold {
            slaBreaches.WithLabelValues("get_events").Inc()
        }
    }()

    // Validate client authentication
    claims, exists := c.Get("claims")
    if !exists {
        requestErrors.WithLabelValues("get_events", "unauthorized").Inc()
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized", "code": "E1001"})
        return
    }

    // Parse and validate query parameters
    params, err := validateQueryParams(c)
    if err != nil {
        requestErrors.WithLabelValues("get_events", "invalid_params").Inc()
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error(), "code": "E3001"})
        return
    }

    // Validate client data access permissions
    if err := event.ValidateEventAccess(params.SecurityContext); err != nil {
        requestErrors.WithLabelValues("get_events", "access_denied").Inc()
        c.JSON(http.StatusForbidden, gin.H{"error": "Access denied", "code": "E1002"})
        return
    }

    // Query events with security context
    events, err := event.ProcessEvent(c.Request.Context(), &event.QueryOptions{
        StartTime: params.StartTime,
        EndTime:   params.EndTime,
        Filters:   params.Filters,
        Page:      params.Page,
        PageSize:  params.PageSize,
        Security:  params.SecurityContext,
    })

    if err != nil {
        requestErrors.WithLabelValues("get_events", "processing_error").Inc()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to process events", "code": "E4001"})
        return
    }

    // Return events with security headers
    c.Header("X-Content-Security-Policy", "default-src 'self'")
    c.Header("X-Request-ID", c.GetString("request_id"))
    c.JSON(http.StatusOK, events)
}

// GetEventByIDHandler handles GET requests for retrieving specific events
func GetEventByIDHandler(c *gin.Context) {
    timer := prometheus.NewTimer(requestLatency.WithLabelValues("get_event_by_id", "processing"))
    defer timer.ObserveDuration()

    // Extract and validate event ID
    eventID := c.Param("id")
    if eventID == "" {
        requestErrors.WithLabelValues("get_event_by_id", "invalid_id").Inc()
        c.JSON(http.StatusBadRequest, gin.H{"error": "Missing event ID", "code": "E3001"})
        return
    }

    // Verify client authorization
    claims, exists := c.Get("claims")
    if !exists {
        requestErrors.WithLabelValues("get_event_by_id", "unauthorized").Inc()
        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized", "code": "E1001"})
        return
    }

    // Create security context
    securityContext := &SecurityContext{
        ClientID: claims.(map[string]interface{})["client_id"].(string),
        Roles:    claims.(map[string]interface{})["roles"].([]string),
    }

    // Retrieve event with security context
    evt, err := event.ProcessEvent(c.Request.Context(), &event.QueryOptions{
        EventID:  eventID,
        Security: securityContext,
    })

    if err != nil {
        requestErrors.WithLabelValues("get_event_by_id", "processing_error").Inc()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve event", "code": "E4001"})
        return
    }

    if evt == nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Event not found", "code": "E3001"})
        return
    }

    // Return event with security headers
    c.Header("X-Content-Security-Policy", "default-src 'self'")
    c.Header("X-Request-ID", c.GetString("request_id"))
    c.JSON(http.StatusOK, evt)
}

// validateQueryParams validates and sanitizes query parameters
func validateQueryParams(c *gin.Context) (*QueryParams, error) {
    var params QueryParams

    // Parse time range
    startTime := c.Query("start_time")
    endTime := c.Query("end_time")
    if startTime == "" || endTime == "" {
        // Use default time range
        params.EndTime = time.Now().UTC()
        params.StartTime = params.EndTime.Add(-defaultTimeRange)
    } else {
        var err error
        params.StartTime, err = time.Parse(time.RFC3339, startTime)
        if err != nil {
            return nil, errors.NewError("E3001", "Invalid start time format", nil)
        }
        params.EndTime, err = time.Parse(time.RFC3339, endTime)
        if err != nil {
            return nil, errors.NewError("E3001", "Invalid end time format", nil)
        }
    }

    // Validate time range
    if params.EndTime.Sub(params.StartTime) > maxTimeRange {
        return nil, errors.NewError("E3001", "Time range exceeds maximum allowed", nil)
    }

    // Parse pagination
    page := c.DefaultQuery("page", "1")
    pageSize := c.DefaultQuery("page_size", "100")
    params.Page = atoi(page, 1)
    params.PageSize = atoi(pageSize, defaultPageSize)

    if params.PageSize > maxPageSize {
        params.PageSize = maxPageSize
    }

    // Parse and validate filters
    if filters := c.Query("filters"); filters != "" {
        if err := json.Unmarshal([]byte(filters), &params.Filters); err != nil {
            return nil, errors.NewError("E3001", "Invalid filter format", nil)
        }
    }

    // Create security context from claims
    claims, _ := c.Get("claims")
    params.SecurityContext = &SecurityContext{
        ClientID:    claims.(map[string]interface{})["client_id"].(string),
        Roles:       claims.(map[string]interface{})["roles"].([]string),
        Permissions: claims.(map[string]interface{})["permissions"].(map[string]interface{}),
    }

    return &params, nil
}

func init() {
    // Register metrics with Prometheus
    prometheus.MustRegister(
        requestLatency,
        requestErrors,
        slaBreaches,
    )
}