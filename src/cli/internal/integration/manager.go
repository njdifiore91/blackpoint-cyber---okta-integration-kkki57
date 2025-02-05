// Package integration provides integration management functionality for the BlackPoint CLI
package integration

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/patrickmn/go-cache"

    "github.com/blackpoint/cli/pkg/api/client"
    "github.com/blackpoint/cli/pkg/common/errors"
    "github.com/blackpoint/cli/pkg/integration/types"
)

// IntegrationManager handles security platform integration lifecycle management
type IntegrationManager struct {
    apiClient     *client.APIClient
    timeout       time.Duration
    connectionPool sync.Pool
    responseCache *cache.Cache
    mu           sync.RWMutex
}

// NewIntegrationManager creates a new integration manager instance with security optimizations
func NewIntegrationManager(apiClient *client.APIClient, timeout time.Duration) (*IntegrationManager, error) {
    if apiClient == nil {
        return nil, errors.NewCLIError("E1001", "API client is required", nil)
    }

    if timeout <= 0 {
        timeout = 5 * time.Minute // Default timeout for integration operations
    }

    manager := &IntegrationManager{
        apiClient: apiClient,
        timeout:   timeout,
        connectionPool: sync.Pool{
            New: func() interface{} {
                return make(map[string]interface{})
            },
        },
        responseCache: cache.New(5*time.Minute, 10*time.Minute),
        mu:           sync.RWMutex{},
    }

    return manager, nil
}

// CreateIntegration creates a new security platform integration with comprehensive validation
func (m *IntegrationManager) CreateIntegration(ctx context.Context, integration *types.Integration) (*types.Integration, error) {
    if integration == nil {
        return nil, errors.NewCLIError("E1004", "Integration configuration is required", nil)
    }

    // Validate integration configuration
    if err := integration.Validate(); err != nil {
        return nil, errors.WrapError(err, "Invalid integration configuration")
    }

    // Create context with timeout
    ctx, cancel := context.WithTimeout(ctx, m.timeout)
    defer cancel()

    // Create integration via API
    var result types.Integration
    err := m.apiClient.Post(ctx, "/api/v1/integrations", integration, &result)
    if err != nil {
        return nil, errors.WrapError(err, "Failed to create integration")
    }

    return &result, nil
}

// UpdateIntegration updates an existing integration with validation
func (m *IntegrationManager) UpdateIntegration(ctx context.Context, integration *types.Integration) (*types.Integration, error) {
    if integration == nil || integration.ID == "" {
        return nil, errors.NewCLIError("E1004", "Integration ID is required", nil)
    }

    // Validate integration configuration
    if err := integration.Validate(); err != nil {
        return nil, errors.WrapError(err, "Invalid integration configuration")
    }

    ctx, cancel := context.WithTimeout(ctx, m.timeout)
    defer cancel()

    var result types.Integration
    err := m.apiClient.Put(ctx, fmt.Sprintf("/api/v1/integrations/%s", integration.ID), integration, &result)
    if err != nil {
        return nil, errors.WrapError(err, "Failed to update integration")
    }

    // Invalidate cache
    m.responseCache.Delete(fmt.Sprintf("integration_%s", integration.ID))

    return &result, nil
}

// DeleteIntegration removes an integration with proper cleanup
func (m *IntegrationManager) DeleteIntegration(ctx context.Context, integrationID string) error {
    if integrationID == "" {
        return errors.NewCLIError("E1004", "Integration ID is required", nil)
    }

    ctx, cancel := context.WithTimeout(ctx, m.timeout)
    defer cancel()

    err := m.apiClient.Delete(ctx, fmt.Sprintf("/api/v1/integrations/%s", integrationID))
    if err != nil {
        return errors.WrapError(err, "Failed to delete integration")
    }

    // Clean up cache and resources
    m.responseCache.Delete(fmt.Sprintf("integration_%s", integrationID))
    return nil
}

// GetIntegration retrieves integration details with caching
func (m *IntegrationManager) GetIntegration(ctx context.Context, integrationID string) (*types.Integration, error) {
    if integrationID == "" {
        return nil, errors.NewCLIError("E1004", "Integration ID is required", nil)
    }

    // Check cache first
    cacheKey := fmt.Sprintf("integration_%s", integrationID)
    if cached, found := m.responseCache.Get(cacheKey); found {
        if integration, ok := cached.(*types.Integration); ok {
            return integration, nil
        }
    }

    ctx, cancel := context.WithTimeout(ctx, m.timeout)
    defer cancel()

    var result types.Integration
    err := m.apiClient.Get(ctx, fmt.Sprintf("/api/v1/integrations/%s", integrationID), &result)
    if err != nil {
        return nil, errors.WrapError(err, "Failed to retrieve integration")
    }

    // Cache the result
    m.responseCache.Set(cacheKey, &result, cache.DefaultExpiration)

    return &result, nil
}

// ListIntegrations retrieves all integrations with filtering support
func (m *IntegrationManager) ListIntegrations(ctx context.Context) ([]types.Integration, error) {
    ctx, cancel := context.WithTimeout(ctx, m.timeout)
    defer cancel()

    var result []types.Integration
    err := m.apiClient.Get(ctx, "/api/v1/integrations", &result)
    if err != nil {
        return nil, errors.WrapError(err, "Failed to list integrations")
    }

    return result, nil
}

// ValidateIntegration performs comprehensive validation of integration configuration
func (m *IntegrationManager) ValidateIntegration(ctx context.Context, integration *types.Integration) (*types.ValidationResult, error) {
    if integration == nil {
        return nil, errors.NewCLIError("E1004", "Integration configuration is required", nil)
    }

    // Perform local validation first
    if err := integration.Validate(); err != nil {
        return &types.ValidationResult{
            Valid:   false,
            Errors: []string{err.Error()},
        }, nil
    }

    ctx, cancel := context.WithTimeout(ctx, m.timeout)
    defer cancel()

    var result types.ValidationResult
    err := m.apiClient.Post(ctx, "/api/v1/integrations/validate", integration, &result)
    if err != nil {
        return nil, errors.WrapError(err, "Failed to validate integration")
    }

    return &result, nil
}