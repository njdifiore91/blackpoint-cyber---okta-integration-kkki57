// Package bronze implements HTTP handlers for the Bronze tier API endpoints
package bronze

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/blackpoint/pkg/common/errors"
	"github.com/blackpoint/pkg/common/logging"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	defaultTimeout  = 1 * time.Second
	defaultBatchSize = 1000
	maxWorkers     = 10
	rateLimit      = 1000
)

var (
	// Prometheus metrics
	eventProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "bronze_event_processing_duration_seconds",
			Help: "Duration of event processing in the Bronze tier",
			Buckets: []float64{0.1, 0.5, 1.0, 2.0, 5.0},
		},
		[]string{"status", "client_id"},
	)

	eventBatchSize = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "bronze_event_batch_size",
			Help: "Size of event batches processed",
			Buckets: []float64{10, 100, 500, 1000},
		},
		[]string{"client_id"},
	)

	eventProcessingErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bronze_event_processing_errors_total",
			Help: "Total number of event processing errors",
		},
		[]string{"error_code", "client_id"},
	)
)

// Event represents a security event in the Bronze tier
type Event struct {
	ID        string                 `json:"id"`
	ClientID  string                 `json:"client_id"`
	Timestamp time.Time             `json:"timestamp"`
	Source    string                 `json:"source"`
	Type      string                 `json:"type"`
	Data      map[string]interface{} `json:"data"`
}

// BatchRequest represents a batch of events
type BatchRequest struct {
	ClientID string   `json:"client_id"`
	Events   []Event  `json:"events"`
}

// BatchResponse represents the response for batch processing
type BatchResponse struct {
	Processed int      `json:"processed"`
	Failed    int      `json:"failed"`
	Errors    []string `json:"errors,omitempty"`
}

// BronzeHandler handles Bronze tier API requests with enhanced security and monitoring
type BronzeHandler struct {
	processor        EventProcessor
	timeout         time.Duration
	workerPool      *sync.Pool
	rateLimiter     *RateLimiter
	metricsCollector *prometheus.Collector
}

// EventProcessor defines the interface for event processing
type EventProcessor interface {
	ProcessEvent(ctx context.Context, event Event) error
	ProcessBatch(ctx context.Context, events []Event) (BatchResponse, error)
}

// NewBronzeHandler creates a new BronzeHandler with security and monitoring configuration
func NewBronzeHandler(processor EventProcessor, timeout time.Duration) *BronzeHandler {
	if timeout == 0 {
		timeout = defaultTimeout
	}

	handler := &BronzeHandler{
		processor: processor,
		timeout:  timeout,
		workerPool: &sync.Pool{
			New: func() interface{} {
				return make(chan Event, defaultBatchSize)
			},
		},
		rateLimiter: NewRateLimiter(rateLimit),
	}

	return handler
}

// HandleSingleEvent processes a single security event with validation and monitoring
func (h *BronzeHandler) HandleSingleEvent(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	clientID := r.Header.Get("X-Client-ID")

	// Validate request
	if r.Method != http.MethodPost {
		h.sendError(w, errors.NewError("E3001", "Method not allowed", nil))
		return
	}

	// Rate limiting check
	if !h.rateLimiter.Allow(clientID) {
		h.sendError(w, errors.NewError("E4002", "Rate limit exceeded", nil))
		return
	}

	// Parse event
	var event Event
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		h.sendError(w, errors.NewError("E3001", "Invalid event format", nil))
		return
	}

	// Validate event
	if err := h.validateEvent(event); err != nil {
		h.sendError(w, err)
		return
	}

	// Process event with timeout
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()

	if err := h.processor.ProcessEvent(ctx, event); err != nil {
		h.sendError(w, err)
		return
	}

	// Record metrics
	duration := time.Since(startTime).Seconds()
	eventProcessingDuration.WithLabelValues("success", clientID).Observe(duration)

	// Audit logging
	logging.Info("Event processed successfully",
		zap.String("client_id", clientID),
		zap.String("event_id", event.ID),
		zap.Duration("duration", time.Since(startTime)),
	)

	w.WriteHeader(http.StatusAccepted)
}

// HandleBatchEvents processes multiple events in parallel with enhanced monitoring
func (h *BronzeHandler) HandleBatchEvents(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	clientID := r.Header.Get("X-Client-ID")

	// Validate request
	if r.Method != http.MethodPost {
		h.sendError(w, errors.NewError("E3001", "Method not allowed", nil))
		return
	}

	// Parse batch request
	var batch BatchRequest
	if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
		h.sendError(w, errors.NewError("E3001", "Invalid batch format", nil))
		return
	}

	// Validate batch size
	if len(batch.Events) > defaultBatchSize {
		h.sendError(w, errors.NewError("E3001", "Batch size exceeds limit", nil))
		return
	}

	// Process batch with timeout
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout*2)
	defer cancel()

	response, err := h.processor.ProcessBatch(ctx, batch.Events)
	if err != nil {
		h.sendError(w, err)
		return
	}

	// Record metrics
	duration := time.Since(startTime).Seconds()
	eventProcessingDuration.WithLabelValues("batch", clientID).Observe(duration)
	eventBatchSize.WithLabelValues(clientID).Observe(float64(len(batch.Events)))

	// Audit logging
	logging.Info("Batch processed",
		zap.String("client_id", clientID),
		zap.Int("total_events", len(batch.Events)),
		zap.Int("processed", response.Processed),
		zap.Int("failed", response.Failed),
		zap.Duration("duration", time.Since(startTime)),
	)

	// Send response
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// validateEvent performs comprehensive event validation
func (h *BronzeHandler) validateEvent(event Event) error {
	if event.ClientID == "" {
		return errors.NewError("E3001", "Missing client ID", nil)
	}
	if event.Timestamp.IsZero() {
		return errors.NewError("E3001", "Missing timestamp", nil)
	}
	if event.Source == "" {
		return errors.NewError("E3001", "Missing source", nil)
	}
	if event.Type == "" {
		return errors.NewError("E3001", "Missing event type", nil)
	}
	return nil
}

// sendError sends an error response with proper status code and logging
func (h *BronzeHandler) sendError(w http.ResponseWriter, err error) {
	var bpErr *errors.BlackPointError
	if !errors.As(err, &bpErr) {
		bpErr = errors.NewError("E4001", "Internal server error", nil)
	}

	status := http.StatusInternalServerError
	switch bpErr.Code {
	case "E3001":
		status = http.StatusBadRequest
	case "E4002":
		status = http.StatusTooManyRequests
	}

	// Record error metrics
	eventProcessingErrors.WithLabelValues(bpErr.Code, "").Inc()

	// Error logging
	logging.Error("Event processing failed",
		err,
		zap.String("error_code", bpErr.Code),
		zap.Int("status_code", status),
	)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{
		"error": bpErr.Error(),
		"code":  bpErr.Code,
	})
}