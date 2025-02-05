// Package encryption provides AWS KMS integration for secure key management and data encryption
package encryption

import (
    "context"
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    "encoding/binary"
    "fmt"
    "sync"
    "time"

    "github.com/aws/aws-sdk-go-v2/service/kms" // v1.20.0
    "github.com/aws/aws-sdk-go-v2/service/kms/types"
    "github.com/patrickmn/go-cache" // v2.1.0
    "../../pkg/common/errors"
)

const (
    defaultKeyRotationDays    = 180
    defaultKeySpec           = "SYMMETRIC_DEFAULT"
    defaultKeyUsage         = "ENCRYPT_DECRYPT"
    maxDataSize            = int64(4 * 1024 * 1024) // 4MB max data size
    defaultOperationTimeout = 30 * time.Second
    keyCacheDuration       = 1 * time.Hour
    keyCleanupInterval     = 10 * time.Minute
)

// KMSManager handles AWS KMS operations with enhanced security controls
type KMSManager struct {
    kmsClient    *kms.Client
    defaultKeyID string
    operationLock sync.Mutex
    keyCache     *cache.Cache
}

// NewKMSManager creates a new KMS manager instance with security auditing
func NewKMSManager(client *kms.Client, defaultKeyID string) (*KMSManager, error) {
    if client == nil {
        return nil, errors.NewError("E4001", "KMS client cannot be nil", nil)
    }
    
    if defaultKeyID == "" {
        return nil, errors.NewError("E4001", "Default KMS key ID cannot be empty", nil)
    }

    return &KMSManager{
        kmsClient:    client,
        defaultKeyID: defaultKeyID,
        keyCache:     cache.New(keyCacheDuration, keyCleanupInterval),
    }, nil
}

// CreateKey creates a new KMS key with rotation policy and tags
func (km *KMSManager) CreateKey(ctx context.Context, description string, tags map[string]string) (string, error) {
    ctx, cancel := context.WithTimeout(ctx, defaultOperationTimeout)
    defer cancel()

    // Convert tags to KMS format
    kmsTags := make([]types.Tag, 0, len(tags))
    for k, v := range tags {
        kmsTags = append(kmsTags, types.Tag{
            TagKey:   &k,
            TagValue: &v,
        })
    }

    input := &kms.CreateKeyInput{
        Description: &description,
        KeySpec:    &defaultKeySpec,
        KeyUsage:   &defaultKeyUsage,
        Tags:       kmsTags,
    }

    result, err := km.kmsClient.CreateKey(ctx, input)
    if err != nil {
        return "", errors.NewError("E4001", "Failed to create KMS key", map[string]interface{}{
            "description": description,
        })
    }

    // Enable automatic key rotation
    rotateInput := &kms.EnableKeyRotationInput{
        KeyId: result.KeyMetadata.KeyId,
    }
    
    _, err = km.kmsClient.EnableKeyRotation(ctx, rotateInput)
    if err != nil {
        return "", errors.NewError("E4001", "Failed to enable key rotation", map[string]interface{}{
            "keyId": *result.KeyMetadata.KeyId,
        })
    }

    return *result.KeyMetadata.KeyId, nil
}

// EncryptData encrypts data using KMS-generated data key with size validation
func (km *KMSManager) EncryptData(ctx context.Context, data []byte, keyID string) ([]byte, error) {
    if len(data) == 0 {
        return nil, errors.NewError("E3001", "Data to encrypt cannot be empty", nil)
    }

    if int64(len(data)) > maxDataSize {
        return nil, errors.NewError("E3001", "Data size exceeds maximum allowed size", map[string]interface{}{
            "maxSize": maxDataSize,
            "dataSize": len(data),
        })
    }

    if keyID == "" {
        keyID = km.defaultKeyID
    }

    // Generate data key
    key, encryptedKey, err := km.generateDataKey(ctx, keyID, 32) // AES-256
    if err != nil {
        return nil, err
    }
    defer func() {
        // Secure zeroing of the plaintext key
        for i := range key {
            key[i] = 0
        }
    }()

    // Create AES cipher
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, errors.NewError("E4001", "Failed to create cipher", nil)
    }

    // Generate nonce for GCM
    nonce := make([]byte, 12)
    if _, err := rand.Read(nonce); err != nil {
        return nil, errors.NewError("E4001", "Failed to generate nonce", nil)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, errors.NewError("E4001", "Failed to create GCM", nil)
    }

    // Encrypt the data
    ciphertext := gcm.Seal(nil, nonce, data, nil)

    // Combine encrypted key, nonce, and ciphertext
    result := make([]byte, 8+len(encryptedKey)+len(nonce)+len(ciphertext))
    binary.BigEndian.PutUint32(result[0:4], uint32(len(encryptedKey)))
    binary.BigEndian.PutUint32(result[4:8], uint32(len(nonce)))
    copy(result[8:8+len(encryptedKey)], encryptedKey)
    copy(result[8+len(encryptedKey):8+len(encryptedKey)+len(nonce)], nonce)
    copy(result[8+len(encryptedKey)+len(nonce):], ciphertext)

    return result, nil
}

// generateDataKey generates a new data key using AWS KMS
func (km *KMSManager) generateDataKey(ctx context.Context, keyID string, keySize int) ([]byte, []byte, error) {
    ctx, cancel := context.WithTimeout(ctx, defaultOperationTimeout)
    defer cancel()

    input := &kms.GenerateDataKeyInput{
        KeyId:   &keyID,
        NumberOfBytes: &keySize,
    }

    result, err := km.kmsClient.GenerateDataKey(ctx, input)
    if err != nil {
        return nil, nil, errors.NewError("E4001", "Failed to generate data key", map[string]interface{}{
            "keyId": keyID,
        })
    }

    return result.Plaintext, result.CiphertextBlob, nil
}

// DecryptData decrypts data that was encrypted using EncryptData
func (km *KMSManager) DecryptData(ctx context.Context, encryptedData []byte) ([]byte, error) {
    if len(encryptedData) < 8 {
        return nil, errors.NewError("E3001", "Invalid encrypted data format", nil)
    }

    // Extract lengths
    encKeyLen := binary.BigEndian.Uint32(encryptedData[0:4])
    nonceLen := binary.BigEndian.Uint32(encryptedData[4:8])
    
    if len(encryptedData) < int(8+encKeyLen+nonceLen) {
        return nil, errors.NewError("E3001", "Invalid encrypted data length", nil)
    }

    // Extract components
    encryptedKey := encryptedData[8:8+encKeyLen]
    nonce := encryptedData[8+encKeyLen:8+encKeyLen+nonceLen]
    ciphertext := encryptedData[8+encKeyLen+nonceLen:]

    // Decrypt the data key
    ctx, cancel := context.WithTimeout(ctx, defaultOperationTimeout)
    defer cancel()

    input := &kms.DecryptInput{
        CiphertextBlob: encryptedKey,
    }

    result, err := km.kmsClient.Decrypt(ctx, input)
    if err != nil {
        return nil, errors.NewError("E4001", "Failed to decrypt data key", nil)
    }

    key := result.Plaintext
    defer func() {
        // Secure zeroing of the plaintext key
        for i := range key {
            key[i] = 0
        }
    }()

    // Create AES cipher
    block, err := aes.NewCipher(key)
    if err != nil {
        return nil, errors.NewError("E4001", "Failed to create cipher", nil)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, errors.NewError("E4001", "Failed to create GCM", nil)
    }

    // Decrypt the data
    plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
    if err != nil {
        return nil, errors.NewError("E3001", "Failed to decrypt data", nil)
    }

    return plaintext, nil
}