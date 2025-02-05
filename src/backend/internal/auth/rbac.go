// Package auth provides RBAC functionality for the BlackPoint Security Integration Framework
package auth

import (
    "sync"
    "time"

    "github.com/casbin/casbin/v2"           // v2.71.1
    "github.com/hashicorp/golang-lru"       // v0.5.4
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/logging"
    "./jwt"
)

// RBACManager handles RBAC operations with thread-safety and caching
type RBACManager struct {
    enforcer        *casbin.Enforcer
    mutex           sync.RWMutex
    roleHierarchy   map[string][]string
    permissionCache *lru.Cache
}

// Predefined roles and their hierarchy
const (
    RoleAdmin              = "admin"
    RoleIntegrationDev    = "integration_developer"
    RoleSecurityAnalyst   = "security_analyst"
    RoleReadOnly          = "read_only"
)

// Resource tiers
const (
    TierBronze = "bronze"
    TierSilver = "silver"
    TierGold   = "gold"
)

// Actions
const (
    ActionRead   = "read"
    ActionWrite  = "write"
    ActionDelete = "delete"
    ActionAdmin  = "admin"
)

// Global instance
var (
    rbacManager *RBACManager
    once        sync.Once
)

// InitRBAC initializes the RBAC system with role hierarchy, permissions, and caching
func InitRBAC(modelPath string, policyPath string, cacheSize int) error {
    var initErr error
    once.Do(func() {
        manager := &RBACManager{}
        if err := manager.initialize(modelPath, policyPath, cacheSize); err != nil {
            initErr = errors.NewError("E1002", "Failed to initialize RBAC", map[string]interface{}{
                "error": err.Error(),
            })
            return
        }
        rbacManager = manager
    })
    return initErr
}

// initialize sets up the RBAC manager with configuration
func (rm *RBACManager) initialize(modelPath string, policyPath string, cacheSize int) error {
    // Initialize Casbin enforcer
    enforcer, err := casbin.NewEnforcer(modelPath, policyPath)
    if err != nil {
        return err
    }
    rm.enforcer = enforcer

    // Initialize permission cache
    cache, err := lru.New(cacheSize)
    if err != nil {
        return err
    }
    rm.permissionCache = cache

    // Set up role hierarchy
    rm.roleHierarchy = map[string][]string{
        RoleAdmin:           {TierBronze, TierSilver, TierGold},
        RoleIntegrationDev: {TierBronze},
        RoleSecurityAnalyst: {TierBronze, TierSilver, TierGold},
        RoleReadOnly:       {TierBronze, TierSilver},
    }

    // Load role policies
    if err := rm.loadPolicies(); err != nil {
        return err
    }

    logging.Info("RBAC system initialized successfully",
        map[string]interface{}{
            "cache_size": cacheSize,
            "roles":      len(rm.roleHierarchy),
        })

    return nil
}

// loadPolicies configures the role-permission mappings
func (rm *RBACManager) loadPolicies() error {
    // Admin policies
    rm.enforcer.AddPolicy(RoleAdmin, TierBronze, ActionAdmin)
    rm.enforcer.AddPolicy(RoleAdmin, TierSilver, ActionAdmin)
    rm.enforcer.AddPolicy(RoleAdmin, TierGold, ActionAdmin)

    // Integration Developer policies
    rm.enforcer.AddPolicy(RoleIntegrationDev, TierBronze, ActionWrite)
    rm.enforcer.AddPolicy(RoleIntegrationDev, TierBronze, ActionRead)

    // Security Analyst policies
    rm.enforcer.AddPolicy(RoleSecurityAnalyst, TierBronze, ActionRead)
    rm.enforcer.AddPolicy(RoleSecurityAnalyst, TierSilver, ActionRead)
    rm.enforcer.AddPolicy(RoleSecurityAnalyst, TierGold, ActionRead)

    // Read Only policies
    rm.enforcer.AddPolicy(RoleReadOnly, TierBronze, ActionRead)
    rm.enforcer.AddPolicy(RoleReadOnly, TierSilver, ActionRead)

    return rm.enforcer.SavePolicy()
}

// CheckAccess verifies if a user has permission to access a resource
func CheckAccess(token string, resource string, action string) (bool, error) {
    if rbacManager == nil {
        return false, errors.NewError("E1002", "RBAC system not initialized", nil)
    }

    // Validate token and extract claims
    claims, err := jwt.ValidateToken(token)
    if err != nil {
        return false, errors.NewError("E1002", "Invalid token", map[string]interface{}{
            "error": err.Error(),
        })
    }

    role, ok := claims["role"].(string)
    if !ok {
        return false, errors.NewError("E1002", "Role not found in token", nil)
    }

    return rbacManager.CheckPermission(role, resource, action)
}

// CheckPermission checks if a role has permission for an action on a resource
func (rm *RBACManager) CheckPermission(role string, resource string, action string) (bool, error) {
    rm.mutex.RLock()
    defer rm.mutex.RUnlock()

    // Check cache first
    cacheKey := role + ":" + resource + ":" + action
    if cached, ok := rm.permissionCache.Get(cacheKey); ok {
        return cached.(bool), nil
    }

    // Validate role
    if err := rm.validateRole(role); err != nil {
        return false, err
    }

    // Check permission
    allowed, err := rm.enforcer.Enforce(role, resource, action)
    if err != nil {
        return false, errors.NewError("E1002", "Failed to check permission", map[string]interface{}{
            "role":     role,
            "resource": resource,
            "action":   action,
            "error":    err.Error(),
        })
    }

    // Cache the result
    rm.permissionCache.Add(cacheKey, allowed)

    // Log access attempt
    logging.Info("RBAC access check",
        map[string]interface{}{
            "role":     role,
            "resource": resource,
            "action":   action,
            "allowed":  allowed,
            "time":     time.Now().UTC(),
        })

    return allowed, nil
}

// validateRole checks if a role exists and is valid
func (rm *RBACManager) validateRole(role string) error {
    if _, exists := rm.roleHierarchy[role]; !exists {
        return errors.NewError("E1002", "Invalid role", map[string]interface{}{
            "role": role,
        })
    }
    return nil
}