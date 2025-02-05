// Package encryption provides field-level encryption for sensitive data using AWS KMS
package encryption

import (
    "context"
    "encoding/base64"
    "encoding/json"
    "regexp"
    "strings"
    "sync"
    "time"

    "github.com/patrickmn/go-cache" // v2.1.0
    "../../pkg/common/errors"
)

const (
    encryptedFieldPrefix = "ENC:"
    encryptionTimeout   = 30 * time.Second
    maxFieldSize        = 1024 * 1024 // 1MB max field size
    patternCacheTTL     = 10 * time.Minute
    patternCleanupInterval = 30 * time.Minute
)

// Pre-compiled patterns for sensitive data detection
var (
    sensitiveFieldPatterns = []string{
        "password", "secret", "key", "token", "credential",
        "ssn", "email", "phone", "account", "card",
    }

    emailPattern    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
    ssnPattern      = regexp.MustCompile(`^\d{3}-?\d{2}-?\d{4}$`)
    phonePattern    = regexp.MustCompile(`^\+?1?\d{9,15}$`)
    cardPattern     = regexp.MustCompile(`^\d{4}-?\d{4}-?\d{4}-?\d{4}$`)
)

// FieldEncryptor manages field-level encryption with enhanced security and performance
type FieldEncryptor struct {
    kms           *KMSManager
    patternCache  *cache.Cache
    bufferPool    *sync.Pool
    sensitiveFields []string
}

// NewFieldEncryptor creates a new field encryptor instance with enhanced initialization
func NewFieldEncryptor(kms *KMSManager, additionalSensitiveFields []string) (*FieldEncryptor, error) {
    if kms == nil {
        return nil, errors.NewError("E4001", "KMS manager cannot be nil", nil)
    }

    // Combine built-in and additional sensitive field patterns
    allPatterns := make([]string, len(sensitiveFieldPatterns))
    copy(allPatterns, sensitiveFieldPatterns)
    allPatterns = append(allPatterns, additionalSensitiveFields...)

    return &FieldEncryptor{
        kms:            kms,
        patternCache:   cache.New(patternCacheTTL, patternCleanupInterval),
        bufferPool:     &sync.Pool{
            New: func() interface{} {
                return make([]byte, 0, maxFieldSize)
            },
        },
        sensitiveFields: allPatterns,
    }, nil
}

// isFieldSensitive checks if a field requires encryption based on patterns and caching
func (fe *FieldEncryptor) isFieldSensitive(fieldName string) (bool, error) {
    // Check cache first
    if isSensitive, found := fe.patternCache.Get(fieldName); found {
        return isSensitive.(bool), nil
    }

    fieldLower := strings.ToLower(fieldName)

    // Check against sensitive field patterns
    for _, pattern := range fe.sensitiveFields {
        if strings.Contains(fieldLower, pattern) {
            fe.patternCache.Set(fieldName, true, cache.DefaultExpiration)
            return true, nil
        }
    }

    // Store negative result in cache
    fe.patternCache.Set(fieldName, false, cache.DefaultExpiration)
    return false, nil
}

// encryptField encrypts a single field value with enhanced validation
func (fe *FieldEncryptor) encryptField(ctx context.Context, value interface{}) (string, error) {
    // Validate value size
    jsonBytes, err := json.Marshal(value)
    if err != nil {
        return "", errors.NewError("E3001", "Failed to marshal field value", nil)
    }

    if len(jsonBytes) > maxFieldSize {
        return "", errors.NewError("E3001", "Field value exceeds maximum size", map[string]interface{}{
            "maxSize": maxFieldSize,
            "actualSize": len(jsonBytes),
        })
    }

    // Get buffer from pool
    buf := fe.bufferPool.Get().([]byte)
    defer fe.bufferPool.Put(buf)

    // Encrypt the value
    ctx, cancel := context.WithTimeout(ctx, encryptionTimeout)
    defer cancel()

    encrypted, err := fe.kms.EncryptData(ctx, jsonBytes, "")
    if err != nil {
        return "", errors.WrapError(err, "Failed to encrypt field value", nil)
    }

    // Encode the encrypted value
    encoded := base64.URLEncoding.EncodeToString(encrypted)
    return encryptedFieldPrefix + encoded, nil
}

// EncryptFields encrypts sensitive fields in the data map with concurrent processing
func (fe *FieldEncryptor) EncryptFields(ctx context.Context, data map[string]interface{}) (map[string]interface{}, error) {
    if data == nil {
        return nil, nil
    }

    // Create result map
    result := make(map[string]interface{}, len(data))
    var encryptErr error
    var mu sync.Mutex
    var wg sync.WaitGroup

    // Process fields concurrently
    for key, value := range data {
        wg.Add(1)
        go func(k string, v interface{}) {
            defer wg.Done()

            sensitive, err := fe.isFieldSensitive(k)
            if err != nil {
                mu.Lock()
                encryptErr = err
                mu.Unlock()
                return
            }

            if sensitive {
                encrypted, err := fe.encryptField(ctx, v)
                if err != nil {
                    mu.Lock()
                    encryptErr = err
                    mu.Unlock()
                    return
                }
                mu.Lock()
                result[k] = encrypted
                mu.Unlock()
            } else {
                mu.Lock()
                result[k] = v
                mu.Unlock()
            }
        }(key, value)
    }

    wg.Wait()

    if encryptErr != nil {
        return nil, encryptErr
    }

    return result, nil
}

// DecryptFields decrypts previously encrypted fields in the data map
func (fe *FieldEncryptor) DecryptFields(ctx context.Context, data map[string]interface{}) (map[string]interface{}, error) {
    if data == nil {
        return nil, nil
    }

    result := make(map[string]interface{}, len(data))
    var decryptErr error
    var mu sync.Mutex
    var wg sync.WaitGroup

    for key, value := range data {
        wg.Add(1)
        go func(k string, v interface{}) {
            defer wg.Done()

            strVal, ok := v.(string)
            if !ok || !strings.HasPrefix(strVal, encryptedFieldPrefix) {
                mu.Lock()
                result[k] = v
                mu.Unlock()
                return
            }

            // Extract and decode encrypted value
            encoded := strings.TrimPrefix(strVal, encryptedFieldPrefix)
            encrypted, err := base64.URLEncoding.DecodeString(encoded)
            if err != nil {
                mu.Lock()
                decryptErr = errors.NewError("E3001", "Failed to decode encrypted value", nil)
                mu.Unlock()
                return
            }

            // Decrypt the value
            decrypted, err := fe.kms.DecryptData(ctx, encrypted)
            if err != nil {
                mu.Lock()
                decryptErr = err
                mu.Unlock()
                return
            }

            // Unmarshal the decrypted value
            var fieldValue interface{}
            if err := json.Unmarshal(decrypted, &fieldValue); err != nil {
                mu.Lock()
                decryptErr = errors.NewError("E3001", "Failed to unmarshal decrypted value", nil)
                mu.Unlock()
                return
            }

            mu.Lock()
            result[k] = fieldValue
            mu.Unlock()
        }(key, value)
    }

    wg.Wait()

    if decryptErr != nil {
        return nil, decryptErr
    }

    return result, nil
}