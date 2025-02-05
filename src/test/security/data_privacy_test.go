package security_test

import (
    "context"
    "encoding/json"
    "testing"
    "time"

    "github.com/stretchr/testify/require"
    "../../backend/internal/encryption/field"
)

// privacyTestSuite provides helper methods for privacy testing
type privacyTestSuite struct {
    t         *testing.T
    encryptor *field.FieldEncryptor
    ctx       context.Context
}

// newPrivacyTestSuite creates a new privacy test suite instance
func newPrivacyTestSuite(t *testing.T) *privacyTestSuite {
    ctx := context.Background()
    encryptor, err := field.NewFieldEncryptor(nil, []string{
        "pii", "personal", "sensitive", "confidential",
    })
    require.NoError(t, err, "Failed to create field encryptor")

    return &privacyTestSuite{
        t:         t,
        encryptor: encryptor,
        ctx:       ctx,
    }
}

// setupTestData creates test data with privacy-sensitive fields
func (s *privacyTestSuite) setupTestData(tier, clientID string) map[string]interface{} {
    return map[string]interface{}{
        "event_id":    "test-event-123",
        "client_id":   clientID,
        "tier":        tier,
        "timestamp":   time.Now().UTC(),
        "email":       "test@example.com",
        "ssn":         "123-45-6789",
        "credit_card": "4111-1111-1111-1111",
        "address": map[string]interface{}{
            "street":  "123 Test St",
            "city":    "Test City",
            "country": "Test Country",
        },
        "metadata": map[string]interface{}{
            "source":      "test",
            "sensitivity": "high",
        },
    }
}

// TestFieldLevelEncryption tests field-level encryption functionality
func TestFieldLevelEncryption(t *testing.T) {
    suite := newPrivacyTestSuite(t)
    ctx := suite.ctx

    // Test case 1: Basic field encryption
    t.Run("Basic Field Encryption", func(t *testing.T) {
        data := suite.setupTestData("bronze", "test-client-1")
        
        // Encrypt sensitive fields
        encrypted, err := suite.encryptor.EncryptFields(ctx, data)
        require.NoError(t, err, "Field encryption failed")
        require.NotEqual(t, data["email"], encrypted["email"], "Email should be encrypted")
        require.NotEqual(t, data["ssn"], encrypted["ssn"], "SSN should be encrypted")
        require.NotEqual(t, data["credit_card"], encrypted["credit_card"], "Credit card should be encrypted")
        
        // Verify non-sensitive fields remain unchanged
        require.Equal(t, data["event_id"], encrypted["event_id"], "Non-sensitive field should not be encrypted")
    })

    // Test case 2: Encryption pattern validation
    t.Run("Pattern Validation", func(t *testing.T) {
        data := map[string]interface{}{
            "password":        "secret123",
            "api_key":        "key123",
            "access_token":   "token123",
            "client_secret":  "secret456",
            "public_field":   "public123",
        }

        encrypted, err := suite.encryptor.EncryptFields(ctx, data)
        require.NoError(t, err, "Pattern validation encryption failed")

        for field, value := range encrypted {
            if field != "public_field" {
                require.NotEqual(t, data[field], value, "Sensitive field should be encrypted: %s", field)
            } else {
                require.Equal(t, data[field], value, "Non-sensitive field should not be encrypted: %s", field)
            }
        }
    })

    // Test case 3: Encryption/Decryption roundtrip
    t.Run("Encryption Roundtrip", func(t *testing.T) {
        originalData := suite.setupTestData("silver", "test-client-2")
        
        // Encrypt
        encrypted, err := suite.encryptor.EncryptFields(ctx, originalData)
        require.NoError(t, err, "Encryption failed")

        // Decrypt
        decrypted, err := suite.encryptor.DecryptFields(ctx, encrypted)
        require.NoError(t, err, "Decryption failed")

        // Verify roundtrip
        require.Equal(t, originalData["email"], decrypted["email"], "Email should match after roundtrip")
        require.Equal(t, originalData["ssn"], decrypted["ssn"], "SSN should match after roundtrip")
    })
}

// TestDataPrivacyAcrossTiers tests privacy controls across data tiers
func TestDataPrivacyAcrossTiers(t *testing.T) {
    suite := newPrivacyTestSuite(t)
    ctx := suite.ctx

    // Test case 1: Bronze tier privacy controls
    t.Run("Bronze Tier Privacy", func(t *testing.T) {
        data := suite.setupTestData("bronze", "test-client-3")
        encrypted, err := suite.encryptor.EncryptFields(ctx, data)
        require.NoError(t, err, "Bronze tier encryption failed")

        // Verify all PII fields are encrypted
        piiFields := []string{"email", "ssn", "credit_card"}
        for _, field := range piiFields {
            require.NotEqual(t, data[field], encrypted[field], "PII field should be encrypted in Bronze tier: %s", field)
        }
    })

    // Test case 2: Silver tier privacy inheritance
    t.Run("Silver Tier Privacy", func(t *testing.T) {
        data := suite.setupTestData("silver", "test-client-4")
        data["derived_data"] = "computed_value"
        
        encrypted, err := suite.encryptor.EncryptFields(ctx, data)
        require.NoError(t, err, "Silver tier encryption failed")

        // Verify inherited encryption and additional fields
        require.NotEqual(t, data["email"], encrypted["email"], "Inherited PII should be encrypted")
        require.NotEqual(t, data["derived_data"], encrypted["derived_data"], "Derived sensitive data should be encrypted")
    })

    // Test case 3: Cross-tier data access
    t.Run("Cross-tier Privacy", func(t *testing.T) {
        bronzeData := suite.setupTestData("bronze", "test-client-5")
        silverData := map[string]interface{}{
            "bronze_ref": bronzeData["event_id"],
            "email":     bronzeData["email"],
            "metadata":  map[string]interface{}{"derived": true},
        }

        // Verify privacy controls are maintained across tiers
        encryptedSilver, err := suite.encryptor.EncryptFields(ctx, silverData)
        require.NoError(t, err, "Cross-tier encryption failed")
        require.NotEqual(t, silverData["email"], encryptedSilver["email"], "PII should remain encrypted across tiers")
    })
}

// TestDataIsolation tests client data isolation with encryption
func TestDataIsolation(t *testing.T) {
    suite := newPrivacyTestSuite(t)
    ctx := suite.ctx

    // Test case 1: Client-specific encryption
    t.Run("Client Isolation", func(t *testing.T) {
        client1Data := suite.setupTestData("bronze", "client-1")
        client2Data := suite.setupTestData("bronze", "client-2")

        // Encrypt data for both clients
        encrypted1, err := suite.encryptor.EncryptFields(ctx, client1Data)
        require.NoError(t, err, "Client 1 encryption failed")
        encrypted2, err := suite.encryptor.EncryptFields(ctx, client2Data)
        require.NoError(t, err, "Client 2 encryption failed")

        // Verify different encryption results for same fields
        require.NotEqual(t, encrypted1["email"], encrypted2["email"], "Encryption should be client-specific")
    })

    // Test case 2: Cross-client access control
    t.Run("Cross-client Access", func(t *testing.T) {
        data := suite.setupTestData("silver", "client-3")
        encrypted, err := suite.encryptor.EncryptFields(ctx, data)
        require.NoError(t, err, "Encryption failed")

        // Attempt cross-client decryption (should fail)
        encrypted["client_id"] = "client-4"
        _, err = suite.encryptor.DecryptFields(ctx, encrypted)
        require.Error(t, err, "Cross-client decryption should fail")
    })
}

// TestPrivacyCompliance tests privacy compliance requirements
func TestPrivacyCompliance(t *testing.T) {
    suite := newPrivacyTestSuite(t)
    ctx := suite.ctx

    // Test case 1: GDPR compliance
    t.Run("GDPR Requirements", func(t *testing.T) {
        data := suite.setupTestData("bronze", "eu-client-1")
        data["gdpr_consent"] = true
        data["data_retention"] = "90days"

        encrypted, err := suite.encryptor.EncryptFields(ctx, data)
        require.NoError(t, err, "GDPR encryption failed")

        // Verify all PII fields are encrypted
        piiFields := []string{"email", "ssn", "credit_card", "address"}
        for _, field := range piiFields {
            require.NotEqual(t, data[field], encrypted[field], "PII field should be encrypted for GDPR: %s", field)
        }
    })

    // Test case 2: Data retention
    t.Run("Data Retention", func(t *testing.T) {
        data := suite.setupTestData("silver", "test-client-6")
        data["retention_period"] = "30days"
        data["created_at"] = time.Now().Add(-31 * 24 * time.Hour)

        // Verify data past retention period is handled appropriately
        encrypted, err := suite.encryptor.EncryptFields(ctx, data)
        require.NoError(t, err, "Retention encryption failed")
        require.NotNil(t, encrypted["retention_period"], "Retention metadata should be preserved")
    })

    // Test case 3: Audit logging
    t.Run("Privacy Audit", func(t *testing.T) {
        data := suite.setupTestData("gold", "audit-client-1")
        data["audit_required"] = true

        // Perform operations that should be logged
        encrypted, err := suite.encryptor.EncryptFields(ctx, data)
        require.NoError(t, err, "Audit encryption failed")
        
        decrypted, err := suite.encryptor.DecryptFields(ctx, encrypted)
        require.NoError(t, err, "Audit decryption failed")
        require.NotNil(t, decrypted["audit_required"], "Audit metadata should be preserved")
    })
}