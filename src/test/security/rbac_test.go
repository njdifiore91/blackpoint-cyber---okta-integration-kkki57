// Package security provides comprehensive RBAC testing for the BlackPoint Security Integration Framework
package security

import (
    "context"
    "testing"
    "time"

    "github.com/stretchr/testify/assert"
    "github.com/prometheus/client_golang/prometheus"

    "../../internal/framework/test_suite"
    "../../../backend/internal/auth/rbac"
)

// Test constants
const (
    testTimeout = 5 * time.Minute
    modelPath   = "../../configs/rbac_model.conf"
    policyPath  = "../../configs/rbac_policy.csv"
)

// Test roles and resources
var (
    testRoles = []string{
        rbac.RoleAdmin,
        rbac.RoleIntegrationDev,
        rbac.RoleSecurityAnalyst,
        rbac.RoleReadOnly,
    }

    testResources = []string{
        rbac.TierBronze,
        rbac.TierSilver,
        rbac.TierGold,
    }

    testActions = []string{
        rbac.ActionRead,
        rbac.ActionWrite,
        rbac.ActionDelete,
        rbac.ActionAdmin,
    }
)

// Prometheus metrics
var (
    rbacTestDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name: "blackpoint_rbac_test_duration_seconds",
            Help: "Duration of RBAC test execution",
            Buckets: prometheus.ExponentialBuckets(0.1, 2, 10),
        },
        []string{"test_name", "role"},
    )

    rbacPermissionChecks = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "blackpoint_rbac_permission_checks_total",
            Help: "Total number of RBAC permission checks",
        },
        []string{"role", "resource", "action", "result"},
    )
)

// TestRBACPermissions tests RBAC permissions for different roles and resources
func TestRBACPermissions(t *testing.T) {
    // Initialize test suite
    suite := test_suite.NewTestSuite(t, "RBACPermissions", &test_suite.TestConfig{
        Timeout: testTimeout,
        SecurityEnabled: true,
        ValidationConfig: map[string]float64{
            "accuracy": 100.0, // RBAC tests must be 100% accurate
        },
    })

    // Initialize RBAC system
    err := rbac.InitRBAC(modelPath, policyPath, 1000)
    assert.NoError(t, err, "Failed to initialize RBAC system")

    // Test Admin role permissions
    t.Run("AdminPermissions", func(t *testing.T) {
        timer := prometheus.NewTimer(rbacTestDuration.WithLabelValues("admin_permissions", rbac.RoleAdmin))
        defer timer.ObserveDuration()

        for _, resource := range testResources {
            for _, action := range testActions {
                allowed, err := rbac.CheckAccess("admin_token", resource, action)
                assert.NoError(t, err)
                assert.True(t, allowed, "Admin should have all permissions")
                
                rbacPermissionChecks.WithLabelValues(
                    rbac.RoleAdmin,
                    resource,
                    action,
                    "allowed",
                ).Inc()
            }
        }
    })

    // Test Integration Developer permissions
    t.Run("IntegrationDevPermissions", func(t *testing.T) {
        timer := prometheus.NewTimer(rbacTestDuration.WithLabelValues("integration_dev_permissions", rbac.RoleIntegrationDev))
        defer timer.ObserveDuration()

        // Should have read/write access to Bronze tier only
        allowed, err := rbac.CheckAccess("integration_dev_token", rbac.TierBronze, rbac.ActionRead)
        assert.NoError(t, err)
        assert.True(t, allowed)

        allowed, err = rbac.CheckAccess("integration_dev_token", rbac.TierBronze, rbac.ActionWrite)
        assert.NoError(t, err)
        assert.True(t, allowed)

        // Should not have access to Silver/Gold tiers
        allowed, err = rbac.CheckAccess("integration_dev_token", rbac.TierSilver, rbac.ActionRead)
        assert.NoError(t, err)
        assert.False(t, allowed)

        rbacPermissionChecks.WithLabelValues(
            rbac.RoleIntegrationDev,
            rbac.TierBronze,
            rbac.ActionWrite,
            "allowed",
        ).Inc()
    })

    // Test Security Analyst permissions
    t.Run("SecurityAnalystPermissions", func(t *testing.T) {
        timer := prometheus.NewTimer(rbacTestDuration.WithLabelValues("security_analyst_permissions", rbac.RoleSecurityAnalyst))
        defer timer.ObserveDuration()

        // Should have read access to all tiers
        for _, resource := range testResources {
            allowed, err := rbac.CheckAccess("security_analyst_token", resource, rbac.ActionRead)
            assert.NoError(t, err)
            assert.True(t, allowed)

            // Should not have write access
            allowed, err = rbac.CheckAccess("security_analyst_token", resource, rbac.ActionWrite)
            assert.NoError(t, err)
            assert.False(t, allowed)

            rbacPermissionChecks.WithLabelValues(
                rbac.RoleSecurityAnalyst,
                resource,
                rbac.ActionRead,
                "allowed",
            ).Inc()
        }
    })

    // Test Read Only permissions
    t.Run("ReadOnlyPermissions", func(t *testing.T) {
        timer := prometheus.NewTimer(rbacTestDuration.WithLabelValues("read_only_permissions", rbac.RoleReadOnly))
        defer timer.ObserveDuration()

        // Should have read access to Bronze and Silver tiers only
        allowed, err := rbac.CheckAccess("read_only_token", rbac.TierBronze, rbac.ActionRead)
        assert.NoError(t, err)
        assert.True(t, allowed)

        allowed, err = rbac.CheckAccess("read_only_token", rbac.TierSilver, rbac.ActionRead)
        assert.NoError(t, err)
        assert.True(t, allowed)

        // Should not have access to Gold tier
        allowed, err = rbac.CheckAccess("read_only_token", rbac.TierGold, rbac.ActionRead)
        assert.NoError(t, err)
        assert.False(t, allowed)

        rbacPermissionChecks.WithLabelValues(
            rbac.RoleReadOnly,
            rbac.TierBronze,
            rbac.ActionRead,
            "allowed",
        ).Inc()
    })
}

// TestRoleHierarchy tests role hierarchy and permission inheritance
func TestRoleHierarchy(t *testing.T) {
    suite := test_suite.NewTestSuite(t, "RoleHierarchy", &test_suite.TestConfig{
        Timeout: testTimeout,
        SecurityEnabled: true,
    })

    // Initialize RBAC system
    err := rbac.InitRBAC(modelPath, policyPath, 1000)
    assert.NoError(t, err, "Failed to initialize RBAC system")

    t.Run("AdminInheritance", func(t *testing.T) {
        timer := prometheus.NewTimer(rbacTestDuration.WithLabelValues("admin_inheritance", rbac.RoleAdmin))
        defer timer.ObserveDuration()

        // Admin should inherit all permissions
        for _, resource := range testResources {
            for _, action := range testActions {
                allowed, err := rbac.CheckAccess("admin_token", resource, action)
                assert.NoError(t, err)
                assert.True(t, allowed, "Admin should inherit all permissions")
            }
        }
    })

    t.Run("SecurityAnalystInheritance", func(t *testing.T) {
        timer := prometheus.NewTimer(rbacTestDuration.WithLabelValues("security_analyst_inheritance", rbac.RoleSecurityAnalyst))
        defer timer.ObserveDuration()

        // Security Analyst should inherit read permissions across all tiers
        for _, resource := range testResources {
            allowed, err := rbac.CheckAccess("security_analyst_token", resource, rbac.ActionRead)
            assert.NoError(t, err)
            assert.True(t, allowed, "Security Analyst should inherit read permissions")
        }
    })

    t.Run("InvalidPermissions", func(t *testing.T) {
        // Test invalid role
        _, err := rbac.CheckAccess("invalid_token", rbac.TierBronze, rbac.ActionRead)
        assert.Error(t, err, "Should fail with invalid role")

        // Test invalid resource
        _, err = rbac.CheckAccess("admin_token", "invalid_resource", rbac.ActionRead)
        assert.Error(t, err, "Should fail with invalid resource")

        rbacPermissionChecks.WithLabelValues(
            "invalid_role",
            rbac.TierBronze,
            rbac.ActionRead,
            "denied",
        ).Inc()
    })
}

func init() {
    // Register Prometheus metrics
    prometheus.MustRegister(rbacTestDuration, rbacPermissionChecks)
}