// Package integration provides platform-specific integration management functionality
package integration

import (
    "context"
    "fmt"
    "sync"
    "time"

    "github.com/patrickmn/go-cache"

    "../../pkg/integration/types"
    "../../pkg/integration/validation"
    "../../pkg/api/client"
    "../../pkg/common/errors"
)

// supportedPlatforms defines the list of supported security platforms
var supportedPlatforms = []string{
    "aws", "azure", "gcp", "okta", "auth0", "crowdstrike",
    "sentinelone", "carbonblack", "microsoft365", "zscaler",
}

const (
    // defaultTimeout defines the default timeout for platform operations
    defaultTimeout = 30 * time.Second

    // maxRetries defines maximum retry attempts for platform operations
    maxRetries = 3

    // configCacheTTL defines the TTL for cached platform configurations
    configCacheTTL = 5 * time.Minute
)

// PlatformManager handles platform-specific integration operations with enhanced security
type PlatformManager struct {
    client      *client.APIClient
    ctx         context.Context
    configCache *cache.Cache
    mu          sync.RWMutex
}

// NewPlatformManager creates a new platform manager instance with configuration caching
func NewPlatformManager(client *client.APIClient, ctx context.Context) (*PlatformManager, error) {
    if client == nil {
        return nil, errors.NewCLIError("E1001", "API client is required", nil)
    }

    return &PlatformManager{
        client:      client,
        ctx:        ctx,
        configCache: cache.New(configCacheTTL, 10*time.Minute),
    }, nil
}

// GetPlatformTypes retrieves list of supported platform types with validation
func (pm *PlatformManager) GetPlatformTypes() ([]string, error) {
    pm.mu.RLock()
    defer pm.mu.RUnlock()

    // Check cache first
    if cached, found := pm.configCache.Get("platform_types"); found {
        if types, ok := cached.([]string); ok {
            return types, nil
        }
    }

    // Make API request with retry logic
    var platforms []string
    endpoint := fmt.Sprintf("/api/v1/platforms/types")
    
    err := pm.client.Get(pm.ctx, endpoint, &platforms)
    if err != nil {
        return nil, errors.WrapError(err, "failed to retrieve platform types")
    }

    // Validate retrieved platforms against supported list
    validPlatforms := make([]string, 0)
    for _, platform := range platforms {
        for _, supported := range supportedPlatforms {
            if platform == supported {
                validPlatforms = append(validPlatforms, platform)
                break
            }
        }
    }

    // Cache valid platforms
    pm.configCache.Set("platform_types", validPlatforms, cache.DefaultExpiration)

    return validPlatforms, nil
}

// ValidatePlatform validates platform configuration with enhanced security checks
func (pm *PlatformManager) ValidatePlatform(integration *types.Integration) error {
    if integration == nil {
        return errors.NewCLIError("E1004", "Integration configuration is required", nil)
    }

    // Validate platform type
    validPlatform := false
    for _, platform := range supportedPlatforms {
        if integration.PlatformType == platform {
            validPlatform = true
            break
        }
    }
    if !validPlatform {
        return errors.NewCLIError("E1004", "Unsupported platform type", nil)
    }

    // Validate integration configuration
    if err := integration.Validate(); err != nil {
        return errors.WrapError(err, "invalid integration configuration")
    }

    // Validate platform-specific configuration
    endpoint := fmt.Sprintf("/api/v1/platforms/%s/validate", integration.PlatformType)
    
    var validationResult struct {
        Valid   bool   `json:"valid"`
        Message string `json:"message,omitempty"`
    }

    err := pm.client.Post(pm.ctx, endpoint, integration.Config, &validationResult)
    if err != nil {
        return errors.WrapError(err, "platform validation failed")
    }

    if !validationResult.Valid {
        return errors.NewCLIError("E1004", fmt.Sprintf("Platform validation failed: %s", validationResult.Message), nil)
    }

    return nil
}

// GetPlatformConfig retrieves platform-specific configuration template with caching
func (pm *PlatformManager) GetPlatformConfig(platformType string) (*types.IntegrationConfig, error) {
    pm.mu.RLock()
    defer pm.mu.RUnlock()

    // Check cache first
    cacheKey := fmt.Sprintf("platform_config_%s", platformType)
    if cached, found := pm.configCache.Get(cacheKey); found {
        if config, ok := cached.(*types.IntegrationConfig); ok {
            return config, nil
        }
    }

    // Validate platform type
    validPlatform := false
    for _, platform := range supportedPlatforms {
        if platformType == platform {
            validPlatform = true
            break
        }
    }
    if !validPlatform {
        return nil, errors.NewCLIError("E1004", "Unsupported platform type", nil)
    }

    // Make API request with retry logic
    endpoint := fmt.Sprintf("/api/v1/platforms/%s/config", platformType)
    
    var config types.IntegrationConfig
    err := pm.client.Get(pm.ctx, endpoint, &config)
    if err != nil {
        return nil, errors.WrapError(err, "failed to retrieve platform configuration")
    }

    // Validate retrieved configuration
    if err := config.Validate(); err != nil {
        return nil, errors.WrapError(err, "invalid platform configuration template")
    }

    // Cache valid configuration
    pm.configCache.Set(cacheKey, &config, cache.DefaultExpiration)

    return &config, nil
}