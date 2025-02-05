// Package gold implements HTTP request handlers for the Gold tier API endpoints
package gold

import (
    "encoding/json"
    "net/http"
    "time"
    "strings"

    "github.com/gin-gonic/gin"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/gold"
    "github.com/blackpoint/pkg/common/utils"
)

const (
    // Cache settings
    alertCacheTTL = 5 * time.Minute
    listCacheTTL  = 1 * time.Minute

    // Pagination defaults
    defaultPageSize = 50
    maxPageSize     = 200

    // Request size limits
    maxRequestBodySize = 1 << 20 // 1MB
)

// GetAlertHandler handles GET requests for retrieving security alerts by ID
func GetAlertHandler(c *gin.Context) {
    // Extract and validate alert ID
    alertID := c.Param("alert_id")
    if !utils.ValidateSecurityPattern(alertID, "^[a-zA-Z0-9-]{36}$") {
        c.JSON(http.StatusBadRequest, errors.NewError("E3001", "invalid alert ID format", nil))
        return
    }

    // Extract security context from authenticated request
    securityCtx := &gold.SecurityMetadata{
        Classification:   c.GetString("classification"),
        ConfidenceScore: 1.0,
        ThreatLevel:     "high",
        DataSensitivity: c.GetString("data_sensitivity"),
        SecurityTags:    []string{"gold_tier", "alert_retrieval"},
    }

    // Check cache before database query
    cacheKey := "alert:" + alertID
    if cachedAlert, exists := c.Get(cacheKey); exists {
        c.Header("X-Cache", "HIT")
        c.JSON(http.StatusOK, cachedAlert)
        return
    }

    // Retrieve alert with security context
    alert, err := gold.GetAlert(alertID, securityCtx)
    if err != nil {
        if errors.IsErrorCode(err, "E3001", "") {
            c.JSON(http.StatusNotFound, err)
            return
        }
        c.JSON(http.StatusInternalServerError, err)
        return
    }

    // Set security headers
    c.Header("X-Content-Type-Options", "nosniff")
    c.Header("X-Frame-Options", "DENY")
    c.Header("X-XSS-Protection", "1; mode=block")
    c.Header("Cache-Control", "private, no-cache, no-store, must-revalidate")

    // Cache successful response
    c.Set(cacheKey, alert)
    c.Header("X-Cache", "MISS")
    c.JSON(http.StatusOK, alert)
}

// ListAlertsHandler handles GET requests for listing security alerts
func ListAlertsHandler(c *gin.Context) {
    // Parse and validate query parameters
    pageSize := utils.ParseIntParam(c.Query("page_size"), defaultPageSize)
    if pageSize > maxPageSize {
        pageSize = maxPageSize
    }

    cursor := c.Query("cursor")
    filters := parseAlertFilters(c)

    // Extract security context
    securityCtx := &gold.SecurityMetadata{
        Classification:   c.GetString("classification"),
        ConfidenceScore: 1.0,
        ThreatLevel:     "high",
        DataSensitivity: c.GetString("data_sensitivity"),
        SecurityTags:    []string{"gold_tier", "alert_listing"},
    }

    // Generate cache key based on parameters
    cacheKey := generateCacheKey("alerts", pageSize, cursor, filters)
    if cachedResult, exists := c.Get(cacheKey); exists {
        c.Header("X-Cache", "HIT")
        c.JSON(http.StatusOK, cachedResult)
        return
    }

    // Query alerts with security context and pagination
    alerts, nextCursor, err := gold.ListAlerts(pageSize, cursor, filters, securityCtx)
    if err != nil {
        c.JSON(http.StatusInternalServerError, err)
        return
    }

    response := map[string]interface{}{
        "alerts":       alerts,
        "next_cursor": nextCursor,
        "page_size":   pageSize,
    }

    // Set security and caching headers
    c.Header("X-Content-Type-Options", "nosniff")
    c.Header("Cache-Control", "private, no-cache, no-store, must-revalidate")
    
    // Cache successful response
    c.Set(cacheKey, response)
    c.Header("X-Cache", "MISS")
    c.JSON(http.StatusOK, response)
}

// CreateAlertHandler handles POST requests for creating new security alerts
func CreateAlertHandler(c *gin.Context) {
    // Validate request body size
    if c.Request.ContentLength > maxRequestBodySize {
        c.JSON(http.StatusRequestEntityTooLarge, errors.NewError("E3001", "request body too large", nil))
        return
    }

    var goldEvent gold.GoldEvent
    if err := c.ShouldBindJSON(&goldEvent); err != nil {
        c.JSON(http.StatusBadRequest, errors.WrapError(err, "invalid request body", nil))
        return
    }

    // Extract security context
    securityCtx := &gold.SecurityMetadata{
        Classification:   c.GetString("classification"),
        ConfidenceScore: 1.0,
        ThreatLevel:     "high",
        DataSensitivity: c.GetString("data_sensitivity"),
        SecurityTags:    []string{"gold_tier", "alert_creation"},
        EncryptionInfo:  map[string]string{"algorithm": "AES-256-GCM"},
    }

    // Validate event schema
    if err := goldEvent.ValidateWithSecurity(); err != nil {
        c.JSON(http.StatusBadRequest, err)
        return
    }

    // Create alert with security context
    alert, err := gold.CreateAlert(&goldEvent, securityCtx)
    if err != nil {
        c.JSON(http.StatusInternalServerError, err)
        return
    }

    // Set security headers
    c.Header("X-Content-Type-Options", "nosniff")
    c.Header("Cache-Control", "no-store")
    
    c.JSON(http.StatusCreated, alert)
}

// UpdateAlertStatusHandler handles PUT requests for updating alert status
func UpdateAlertStatusHandler(c *gin.Context) {
    // Extract and validate alert ID
    alertID := c.Param("alert_id")
    if !utils.ValidateSecurityPattern(alertID, "^[a-zA-Z0-9-]{36}$") {
        c.JSON(http.StatusBadRequest, errors.NewError("E3001", "invalid alert ID format", nil))
        return
    }

    // Parse request body
    var updateReq struct {
        Status string                 `json:"status"`
        Reason string                 `json:"reason"`
        Metadata map[string]interface{} `json:"metadata"`
    }

    if err := c.ShouldBindJSON(&updateReq); err != nil {
        c.JSON(http.StatusBadRequest, errors.WrapError(err, "invalid request body", nil))
        return
    }

    // Extract security context
    securityCtx := &gold.SecurityMetadata{
        Classification:   c.GetString("classification"),
        ConfidenceScore: 1.0,
        ThreatLevel:     "high",
        DataSensitivity: c.GetString("data_sensitivity"),
        SecurityTags:    []string{"gold_tier", "alert_update"},
    }

    // Update alert status with security context
    err := gold.UpdateAlertStatus(alertID, updateReq.Status, updateReq.Reason, securityCtx)
    if err != nil {
        if errors.IsErrorCode(err, "E3001", "") {
            c.JSON(http.StatusBadRequest, err)
            return
        }
        c.JSON(http.StatusInternalServerError, err)
        return
    }

    // Set security headers
    c.Header("X-Content-Type-Options", "nosniff")
    c.Header("Cache-Control", "no-store")
    
    c.Status(http.StatusNoContent)
}

// Helper functions

func parseAlertFilters(c *gin.Context) map[string]interface{} {
    filters := make(map[string]interface{})
    
    if severity := c.Query("severity"); severity != "" {
        filters["severity"] = severity
    }
    
    if status := c.Query("status"); status != "" {
        filters["status"] = status
    }
    
    if timeRange := c.Query("time_range"); timeRange != "" {
        filters["time_range"] = timeRange
    }

    return filters
}

func generateCacheKey(prefix string, pageSize int, cursor string, filters map[string]interface{}) string {
    parts := []string{prefix}
    parts = append(parts, string(pageSize))
    
    if cursor != "" {
        parts = append(parts, cursor)
    }
    
    for k, v := range filters {
        parts = append(parts, k+"="+strings.ToLower(v.(string)))
    }
    
    return strings.Join(parts, ":")
}