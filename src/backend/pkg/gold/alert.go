// Package gold implements alert management functionality for the Gold tier
package gold

import (
    "encoding/json"
    "time"
    "sync"
    "golang.org/x/time/rate" // v0.1.0

    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/utils"
)

// Alert status types
var alertStatusTypes = []string{
    "new",
    "acknowledged",
    "investigating",
    "resolved",
    "closed",
}

// Constants for alert management
const (
    maxAlertLifetime = 90 * 24 * time.Hour
    maxAlertsPerClient = 10000
)

// Sensitive fields requiring encryption
var sensitiveFields = []string{
    "ip_address",
    "username",
    "email",
    "hostname",
}

// Rate limiter for alert operations
var alertRateLimiter = rate.NewLimiter(100, 1000)

// StatusHistory tracks alert status changes with audit information
type StatusHistory struct {
    Status      string                 `json:"status"`
    Timestamp   time.Time             `json:"timestamp"`
    UpdatedBy   string                `json:"updated_by"`
    Reason      string                `json:"reason"`
    Metadata    map[string]interface{} `json:"metadata"`
}

// Alert represents a security alert with enhanced security features
type Alert struct {
    AlertID          string                 `json:"alert_id"`
    Status           string                 `json:"status"`
    CreatedAt        time.Time             `json:"created_at"`
    UpdatedAt        time.Time             `json:"updated_at"`
    Severity         string                 `json:"severity"`
    IntelligenceData map[string]interface{} `json:"intelligence_data"`
    History          []StatusHistory        `json:"history"`
    SecurityMetadata *SecurityMetadata      `json:"security_metadata"`
    ComplianceTags   map[string]string      `json:"compliance_tags"`
    EncryptedFields  []string              `json:"encrypted_fields"`
    mutex            sync.RWMutex          // Protects concurrent access
}

// CreateAlert creates a new security alert from a Gold event with enhanced security controls
func CreateAlert(event *GoldEvent, ctx *SecurityMetadata) (*Alert, error) {
    if event == nil || ctx == nil {
        return nil, errors.NewError("E3001", "invalid input parameters", nil)
    }

    // Rate limit check
    if !alertRateLimiter.Allow() {
        return nil, errors.NewError("E4002", "alert creation rate limit exceeded", nil)
    }

    // Generate secure alert ID
    alertID, err := utils.GenerateUUID()
    if err != nil {
        return nil, errors.WrapError(err, "failed to generate alert ID", nil)
    }

    // Encrypt sensitive fields
    encryptedFields := make([]string, 0)
    intelligenceData := make(map[string]interface{})
    for k, v := range event.IntelligenceData {
        if isSensitiveField(k) {
            encrypted, err := utils.EncryptField(v.(string))
            if err != nil {
                return nil, errors.WrapError(err, "failed to encrypt sensitive field", nil)
            }
            intelligenceData[k] = encrypted
            encryptedFields = append(encryptedFields, k)
        } else {
            intelligenceData[k] = v
        }
    }

    // Create new alert
    alert := &Alert{
        AlertID:          alertID,
        Status:           "new",
        CreatedAt:        time.Now().UTC(),
        UpdatedAt:        time.Now().UTC(),
        Severity:         event.Severity,
        IntelligenceData: intelligenceData,
        History: []StatusHistory{{
            Status:    "new",
            Timestamp: time.Now().UTC(),
            UpdatedBy: ctx.Classification,
            Reason:    "Alert created",
            Metadata:  map[string]interface{}{"source": "automatic"},
        }},
        SecurityMetadata: ctx,
        ComplianceTags:   generateComplianceTags(event),
        EncryptedFields:  encryptedFields,
    }

    // Validate created alert
    if err := alert.Validate(); err != nil {
        return nil, errors.WrapError(err, "alert validation failed", nil)
    }

    return alert, nil
}

// UpdateAlertStatus updates the status of an existing alert with audit trail
func UpdateAlertStatus(alertID string, newStatus string, updateReason string, ctx *SecurityMetadata) error {
    if alertID == "" || newStatus == "" || ctx == nil {
        return errors.NewError("E3001", "invalid input parameters", nil)
    }

    // Rate limit check
    if !alertRateLimiter.Allow() {
        return errors.NewError("E4002", "alert update rate limit exceeded", nil)
    }

    // Validate status
    validStatus := false
    for _, status := range alertStatusTypes {
        if status == newStatus {
            validStatus = true
            break
        }
    }
    if !validStatus {
        return errors.NewError("E3001", "invalid alert status", nil)
    }

    // Update alert status (implementation would retrieve and update alert in storage)
    statusUpdate := StatusHistory{
        Status:    newStatus,
        Timestamp: time.Now().UTC(),
        UpdatedBy: ctx.Classification,
        Reason:    updateReason,
        Metadata: map[string]interface{}{
            "security_level": ctx.DataSensitivity,
            "update_type":   "manual",
        },
    }

    // Audit logging would be implemented here

    return nil
}

// Validate validates alert data integrity and security patterns
func (a *Alert) Validate() error {
    a.mutex.RLock()
    defer a.mutex.RUnlock()

    // Validate required fields
    if a.AlertID == "" {
        return errors.NewError("E3001", "alert ID is required", nil)
    }

    if a.Status == "" {
        return errors.NewError("E3001", "alert status is required", nil)
    }

    if a.SecurityMetadata == nil {
        return errors.NewError("E3001", "security metadata is required", nil)
    }

    // Validate timestamps
    if a.CreatedAt.IsZero() || a.UpdatedAt.IsZero() {
        return errors.NewError("E3001", "invalid timestamps", nil)
    }

    // Validate status
    validStatus := false
    for _, status := range alertStatusTypes {
        if status == a.Status {
            validStatus = true
            break
        }
    }
    if !validStatus {
        return errors.NewError("E3001", "invalid alert status", nil)
    }

    // Validate severity
    validSeverity := false
    for _, severity := range severityLevels {
        if severity == a.Severity {
            validSeverity = true
            break
        }
    }
    if !validSeverity {
        return errors.NewError("E3001", "invalid severity level", nil)
    }

    // Validate intelligence data
    if a.IntelligenceData == nil {
        return errors.NewError("E3001", "intelligence data is required", nil)
    }

    // Validate encrypted fields
    for _, field := range a.EncryptedFields {
        if !isSensitiveField(field) {
            return errors.NewError("E3001", "invalid encrypted field", nil)
        }
    }

    return nil
}

// isSensitiveField checks if a field requires encryption
func isSensitiveField(field string) bool {
    for _, sensitive := range sensitiveFields {
        if sensitive == field {
            return true
        }
    }
    return false
}

// generateComplianceTags generates compliance tags based on event data
func generateComplianceTags(event *GoldEvent) map[string]string {
    tags := make(map[string]string)
    if event.ComplianceInfo.Standards != nil {
        for _, standard := range event.ComplianceInfo.Standards {
            tags[standard] = "applicable"
        }
    }
    tags["data_retention"] = event.ComplianceInfo.DataRetention
    tags["data_handling"] = event.ComplianceInfo.DataHandling
    return tags
}