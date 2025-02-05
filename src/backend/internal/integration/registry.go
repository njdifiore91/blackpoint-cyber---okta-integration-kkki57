// Package integration provides a thread-safe registry for managing security platform integrations
package integration

import (
    "fmt"
    "sync"
    "time"
    "golang.org/x/time/rate" // v0.1.0

    "../../pkg/common/errors"
    "../../pkg/common/logging"
    "../../pkg/integration/platform"
)

const (
    // defaultTimeout for registry operations
    defaultTimeout = 30 * time.Second
    
    // maxConcurrentOperations limits concurrent registry operations
    maxConcurrentOperations = 100
    
    // platformCacheTTL defines how long platform instances are cached
    platformCacheTTL = 1 * time.Hour
)

// PlatformFactory defines the function type for creating new platform instances
type PlatformFactory func() (platform.Platform, error)

// Registry provides thread-safe management of platform implementations
type Registry struct {
    mutex           *sync.RWMutex
    factories       map[string]PlatformFactory
    platformCache   *sync.Map
    operationTimeout time.Duration
    rateLimiter     *rate.Limiter
}

var (
    // registryInstance holds the singleton registry instance
    registryInstance *Registry
    
    // registryMutex ensures thread-safe singleton initialization
    registryMutex sync.Once
)

// GetRegistry returns the singleton registry instance
func GetRegistry() *Registry {
    registryMutex.Do(func() {
        registryInstance = &Registry{
            mutex:           &sync.RWMutex{},
            factories:       make(map[string]PlatformFactory),
            platformCache:   &sync.Map{},
            operationTimeout: defaultTimeout,
            rateLimiter:     rate.NewLimiter(rate.Limit(maxConcurrentOperations), maxConcurrentOperations),
        }
        
        logging.Info("Platform registry initialized",
            "timeout", defaultTimeout,
            "max_operations", maxConcurrentOperations,
        )
    })
    return registryInstance
}

// RegisterPlatform registers a new platform factory with validation
func (r *Registry) RegisterPlatform(platformType string, factory PlatformFactory) error {
    // Validate inputs
    if platformType == "" || factory == nil {
        return errors.NewError("E2001", "invalid platform registration parameters", map[string]interface{}{
            "platform_type": platformType,
        })
    }

    // Apply rate limiting
    if err := r.rateLimiter.Wait(context.Background()); err != nil {
        return errors.NewError("E4002", "registry operation rate limit exceeded", nil)
    }

    // Acquire write lock with timeout
    lockChan := make(chan bool, 1)
    go func() {
        r.mutex.Lock()
        lockChan <- true
    }()

    select {
    case <-lockChan:
        defer r.mutex.Unlock()
    case <-time.After(r.operationTimeout):
        return errors.NewError("E4001", "registry lock acquisition timeout", nil)
    }

    // Check if platform type already registered
    if _, exists := r.factories[platformType]; exists {
        return errors.NewError("E2001", "platform type already registered", map[string]interface{}{
            "platform_type": platformType,
        })
    }

    // Validate factory by creating test instance
    testPlatform, err := factory()
    if err != nil {
        return errors.WrapError(err, "factory validation failed", map[string]interface{}{
            "platform_type": platformType,
        })
    }
    if testPlatform == nil {
        return errors.NewError("E2001", "factory produced nil platform", nil)
    }

    // Register factory
    r.factories[platformType] = factory
    
    logging.Info("Platform type registered successfully",
        "platform_type", platformType,
    )

    return nil
}

// GetPlatform creates or retrieves a cached platform instance
func (r *Registry) GetPlatform(platformType string) (platform.Platform, error) {
    // Check cache first
    if cached, ok := r.platformCache.Load(platformType); ok {
        entry := cached.(*platformCacheEntry)
        if !entry.isExpired() {
            return entry.platform, nil
        }
        r.platformCache.Delete(platformType)
    }

    // Apply rate limiting
    if err := r.rateLimiter.Wait(context.Background()); err != nil {
        return nil, errors.NewError("E4002", "registry operation rate limit exceeded", nil)
    }

    // Acquire read lock with timeout
    lockChan := make(chan bool, 1)
    go func() {
        r.mutex.RLock()
        lockChan <- true
    }()

    select {
    case <-lockChan:
        defer r.mutex.RUnlock()
    case <-time.After(r.operationTimeout):
        return nil, errors.NewError("E4001", "registry lock acquisition timeout", nil)
    }

    // Get factory
    factory, exists := r.factories[platformType]
    if !exists {
        return nil, errors.NewError("E2001", "platform type not registered", map[string]interface{}{
            "platform_type": platformType,
        })
    }

    // Create new platform instance
    platform, err := factory()
    if err != nil {
        return nil, errors.WrapError(err, "failed to create platform instance", map[string]interface{}{
            "platform_type": platformType,
        })
    }

    // Cache the new instance
    r.platformCache.Store(platformType, &platformCacheEntry{
        platform:   platform,
        expiresAt: time.Now().Add(platformCacheTTL),
    })

    logging.Info("Platform instance created",
        "platform_type", platformType,
    )

    return platform, nil
}

// ListPlatforms returns a list of registered platform types
func (r *Registry) ListPlatforms() []string {
    // Apply rate limiting
    if err := r.rateLimiter.Wait(context.Background()); err != nil {
        logging.Error("Rate limit exceeded during platform listing", err)
        return []string{}
    }

    // Acquire read lock with timeout
    lockChan := make(chan bool, 1)
    go func() {
        r.mutex.RLock()
        lockChan <- true
    }()

    select {
    case <-lockChan:
        defer r.mutex.RUnlock()
    case <-time.After(r.operationTimeout):
        logging.Error("Lock acquisition timeout during platform listing", 
            errors.NewError("E4001", "registry lock acquisition timeout", nil))
        return []string{}
    }

    platforms := make([]string, 0, len(r.factories))
    for platformType := range r.factories {
        platforms = append(platforms, platformType)
    }

    return platforms
}

// platformCacheEntry represents a cached platform instance with expiration
type platformCacheEntry struct {
    platform   platform.Platform
    expiresAt  time.Time
}

// isExpired checks if the cache entry has expired
func (e *platformCacheEntry) isExpired() bool {
    return time.Now().After(e.expiresAt)
}