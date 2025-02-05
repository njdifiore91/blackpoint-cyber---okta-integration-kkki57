// Package silver provides validation logic for Silver tier API endpoints
package silver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/blackpoint/pkg/common/errors"
	"github.com/blackpoint/pkg/common/utils"
	"github.com/blackpoint/pkg/silver/schema"
	"github.com/prometheus/client_golang/prometheus"
)

// Constants for request validation
const (
	maxRequestSize int64 = 1 << 20 // 1MB
	maxTimeRange = 90 * 24 * time.Hour // 90 days
	maxPageSize = 1000
)

// Valid event types for Silver tier
var validEventTypes = []string{
	"security_alert",
	"user_activity",
	"system_log",
}

// Thread-safe request buffer pool
var requestPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

// Metrics collectors
var (
	validationErrors = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blackpoint_silver_validation_errors_total",
			Help: "Total number of validation errors by type",
		},
		[]string{"error_type"},
	)

	validationLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "blackpoint_silver_validation_latency_seconds",
			Help: "Validation latency in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"validation_type"},
	)
)

func init() {
	// Register metrics
	prometheus.MustRegister(validationErrors)
	prometheus.MustRegister(validationLatency)
}

// ValidateRequest validates incoming HTTP requests for Silver tier endpoints
func ValidateRequest(r *http.Request) error {
	timer := prometheus.NewTimer(validationLatency.WithLabelValues("request"))
	defer timer.ObserveDuration()

	// Validate HTTP method
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		validationErrors.WithLabelValues("invalid_method").Inc()
		return errors.NewError("E3001", "invalid HTTP method", map[string]interface{}{
			"method": r.Method,
		})
	}

	// Validate request size
	if r.ContentLength > maxRequestSize {
		validationErrors.WithLabelValues("size_exceeded").Inc()
		return errors.NewError("E3001", "request size exceeds limit", map[string]interface{}{
			"max_size": maxRequestSize,
			"size":     r.ContentLength,
		})
	}

	// Validate content type
	if ct := r.Header.Get("Content-Type"); ct != "application/json" {
		validationErrors.WithLabelValues("invalid_content_type").Inc()
		return errors.NewError("E3001", "invalid content type", map[string]interface{}{
			"content_type": ct,
		})
	}

	// Validate required headers
	requiredHeaders := []string{"X-Client-ID", "X-Request-ID", "Authorization"}
	for _, header := range requiredHeaders {
		if r.Header.Get(header) == "" {
			validationErrors.WithLabelValues("missing_header").Inc()
			return errors.NewError("E3001", "missing required header", map[string]interface{}{
				"header": header,
			})
		}
	}

	return nil
}

// ValidateEventData validates normalized event data with comprehensive security checks
func ValidateEventData(data []byte) (*schema.SilverEvent, error) {
	timer := prometheus.NewTimer(validationLatency.WithLabelValues("event_data"))
	defer timer.ObserveDuration()

	// Get buffer from pool
	buf := requestPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer requestPool.Put(buf)

	// Parse JSON with security checks
	var event schema.SilverEvent
	if err := json.Unmarshal(data, &event); err != nil {
		validationErrors.WithLabelValues("invalid_json").Inc()
		return nil, errors.WrapError(err, "invalid JSON format", nil)
	}

	// Validate required fields
	if event.EventID == "" || event.ClientID == "" || event.EventType == "" {
		validationErrors.WithLabelValues("missing_fields").Inc()
		return nil, errors.NewError("E3001", "missing required fields", nil)
	}

	// Validate event type
	validType := false
	for _, t := range validEventTypes {
		if event.EventType == t {
			validType = true
			break
		}
	}
	if !validType {
		validationErrors.WithLabelValues("invalid_event_type").Inc()
		return nil, errors.NewError("E3001", "invalid event type", map[string]interface{}{
			"type":    event.EventType,
			"allowed": validEventTypes,
		})
	}

	// Sanitize string fields
	event.EventType = utils.SanitizeString(event.EventType, utils.SanitizationOptions{
		MaxLength:  100,
		TrimSpace: true,
		StripHTML: true,
	})

	// Validate normalized data structure
	if err := schema.ValidateSchema(&event); err != nil {
		validationErrors.WithLabelValues("schema_validation").Inc()
		return nil, err
	}

	return &event, nil
}

// ValidateQueryParams validates query parameters for Silver tier endpoints
func ValidateQueryParams(params url.Values) error {
	timer := prometheus.NewTimer(validationLatency.WithLabelValues("query_params"))
	defer timer.ObserveDuration()

	// Validate timerange
	if tr := params.Get("timerange"); tr != "" {
		duration, err := time.ParseDuration(tr)
		if err != nil {
			validationErrors.WithLabelValues("invalid_timerange").Inc()
			return errors.NewError("E3001", "invalid timerange format", nil)
		}
		if duration > maxTimeRange {
			validationErrors.WithLabelValues("timerange_exceeded").Inc()
			return errors.NewError("E3001", "timerange exceeds maximum allowed", map[string]interface{}{
				"max_range": maxTimeRange,
				"requested": duration,
			})
		}
	}

	// Validate filter parameters
	if filter := params.Get("filter"); filter != "" {
		if err := utils.ValidateJSON(filter, utils.ValidationOptions{
			MaxDepth:   5,
			StrictMode: true,
		}); err != nil {
			validationErrors.WithLabelValues("invalid_filter").Inc()
			return errors.WrapError(err, "invalid filter format", nil)
		}
	}

	// Validate pagination
	if page := params.Get("page_size"); page != "" {
		size := 0
		if err := json.Unmarshal([]byte(page), &size); err != nil {
			validationErrors.WithLabelValues("invalid_page_size").Inc()
			return errors.NewError("E3001", "invalid page size format", nil)
		}
		if size > maxPageSize {
			validationErrors.WithLabelValues("page_size_exceeded").Inc()
			return errors.NewError("E3001", "page size exceeds maximum allowed", map[string]interface{}{
				"max_size": maxPageSize,
				"size":     size,
			})
		}
	}

	return nil
}