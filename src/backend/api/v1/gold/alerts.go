// Package gold implements secure REST API endpoints for Gold tier alert management
package gold

import (
    "context"
    "encoding/json"
    "net/http"
    "time"

    "go.opentelemetry.io/otel" // v1.0.0
    "go.opentelemetry.io/otel/attribute"
    "go.opentelemetry.io/otel/trace"

    "github.com/blackpoint/pkg/gold"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/middleware"
    "github.com/blackpoint/internal/storage"
)

// Global constants for alert management
const (
    defaultPageSize = 100
    maxPageSize = 1000
    defaultAlertQueryTimeout = 30 * time.Second
    encryptionKeyRotationInterval = 30 * 24 * time.Hour
    auditLogRetentionPeriod = 365 * 24 * time.Hour
    complianceCheckInterval = 24 * time.Hour
)

// AlertsAPI handles secure alert management endpoints
type AlertsAPI struct {
    storageClient    *storage.ChaosSearchClient
    router           *http.ServeMux
    auditor          *SecurityAuditor
    complianceManager *ComplianceManager
    tracer           trace.Tracer
}

// SecurityAuditor handles security audit logging
type SecurityAuditor interface {
    LogAccess(ctx context.Context, alertID string, action string) error
    LogModification(ctx context.Context, alertID string, changes map[string]interface{}) error
}

// ComplianceManager handles compliance requirements
type ComplianceManager interface {
    ValidateAccess(ctx context.Context, alertID string) error
    TrackCompliance(ctx context.Context, alert *gold.Alert) error
}

// NewAlertsAPI creates a new AlertsAPI instance with security features
func NewAlertsAPI(storageClient *storage.ChaosSearchClient, auditor *SecurityAuditor, complianceManager *ComplianceManager) (*AlertsAPI, error) {
    if storageClient == nil {
        return nil, errors.NewError("E4001", "storage client is required", nil)
    }

    api := &AlertsAPI{
        storageClient:     storageClient,
        router:           http.NewServeMux(),
        auditor:          auditor,
        complianceManager: complianceManager,
        tracer:           otel.GetTracerProvider().Tracer("alerts-api"),
    }

    // Register routes with security middleware
    api.registerSecureRoutes()

    return api, nil
}

// registerSecureRoutes configures routes with security middleware
func (a *AlertsAPI) registerSecureRoutes() {
    // GET /api/v1/gold/alerts/{id}
    a.router.Handle("/api/v1/gold/alerts/", middleware.Chain(
        http.HandlerFunc(a.handleGetAlert),
        middleware.AuthMiddleware,
        middleware.LoggingMiddleware,
        middleware.ErrorMiddleware,
        middleware.RateLimitMiddleware(100, 1000), // 100 req/sec, burst 1000
    ))
}

// handleGetAlert handles secure alert retrieval
func (a *AlertsAPI) handleGetAlert(w http.ResponseWriter, r *http.Request) {
    ctx, span := a.tracer.Start(r.Context(), "handleGetAlert")
    defer span.End()

    // Extract alert ID with validation
    alertID := r.URL.Path[len("/api/v1/gold/alerts/"):]
    if !validateAlertID(alertID) {
        http.Error(w, "Invalid alert ID", http.StatusBadRequest)
        return
    }

    // Extract client ID from auth context
    claims, ok := ctx.Value("claims").(map[string]interface{})
    if !ok {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    clientID := claims["client_id"].(string)

    // Validate compliance requirements
    if err := a.complianceManager.ValidateAccess(ctx, alertID); err != nil {
        http.Error(w, "Access denied", http.StatusForbidden)
        return
    }

    // Create query context with timeout
    queryCtx, cancel := context.WithTimeout(ctx, defaultAlertQueryTimeout)
    defer cancel()

    // Query alert with security context
    query := map[string]interface{}{
        "alert_id":   alertID,
        "client_id": clientID,
    }
    
    result, err := a.storageClient.QueryEventsSecure(queryCtx, "gold", query)
    if err != nil {
        http.Error(w, "Internal server error", http.StatusInternalServerError)
        return
    }

    // Convert to Alert type
    alert, ok := result.(*gold.Alert)
    if !ok {
        http.Error(w, "Invalid alert data", http.StatusInternalServerError)
        return
    }

    // Log security audit
    if err := a.auditor.LogAccess(ctx, alertID, "read"); err != nil {
        // Log error but don't fail request
        span.RecordError(err)
    }

    // Track compliance
    if err := a.complianceManager.TrackCompliance(ctx, alert); err != nil {
        span.RecordError(err)
    }

    // Set security headers
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("X-Content-Security-Policy", "default-src 'self'")
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("X-Content-Type-Options", "nosniff")

    // Return alert data
    if err := json.NewEncoder(w).Encode(alert); err != nil {
        http.Error(w, "Error encoding response", http.StatusInternalServerError)
        return
    }
}

// validateAlertID performs security validation of alert IDs
func validateAlertID(id string) bool {
    if len(id) != 36 { // UUID length
        return false
    }
    // Add additional validation as needed
    return true
}

// ServeHTTP implements the http.Handler interface
func (a *AlertsAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    a.router.ServeHTTP(w, r)
}