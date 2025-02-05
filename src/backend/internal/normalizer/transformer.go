// Package normalizer provides secure event transformation capabilities
package normalizer

import (
    "encoding/json"
    "sync"
    "time"

    "github.com/blackpoint/pkg/bronze/schema"
    "github.com/blackpoint/pkg/silver/schema"
    "github.com/blackpoint/pkg/common/errors"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/trace"
    "go.opentelemetry.io/otel/attribute"
    "crypto/aes"
    "crypto/cipher"
)

// Global constants for transformation configuration
const (
    transformationTimeout = 2 * time.Second
    maxFieldLength       = 4096
    maxConcurrentTransforms = 100
)

// Sensitive field patterns that require encryption
var sensitiveFieldPatterns = []string{
    "password",
    "key",
    "token",
    "secret",
}

// TransformFunc represents a field transformation function
type TransformFunc func(interface{}) (interface{}, error)

// Transformer handles secure event transformation with monitoring
type Transformer struct {
    timeout          time.Duration
    transformers     map[string]TransformFunc
    transformLimiter chan struct{}
    tracer          trace.Tracer
    mu              sync.RWMutex
}

// NewTransformer creates a new event transformer with security controls
func NewTransformer(timeout time.Duration) *Transformer {
    if timeout == 0 {
        timeout = transformationTimeout
    }

    return &Transformer{
        timeout:          timeout,
        transformers:     make(map[string]TransformFunc),
        transformLimiter: make(chan struct{}, maxConcurrentTransforms),
        tracer:          otel.Tracer("normalizer.transformer"),
    }
}

// TransformEvent securely transforms a Bronze event into a Silver event
func (t *Transformer) TransformEvent(bronzeEvent *schema.BronzeEvent, mappedFields map[string]interface{}, secCtx *schema.SecurityContext) (*schema.SilverEvent, error) {
    ctx, span := t.tracer.Start(context.Background(), "transform_event")
    defer span.End()

    // Validate inputs
    if bronzeEvent == nil {
        return nil, errors.NewError("E3001", "nil bronze event", nil)
    }
    if mappedFields == nil {
        return nil, errors.NewError("E3001", "nil mapped fields", nil)
    }

    // Apply concurrency limiting
    select {
    case t.transformLimiter <- struct{}{}:
        defer func() { <-t.transformLimiter }()
    default:
        return nil, errors.NewError("E4002", "transformation capacity exceeded", nil)
    }

    // Create transformation context with timeout
    ctx, cancel := context.WithTimeout(ctx, t.timeout)
    defer cancel()

    // Create security context if not provided
    if secCtx == nil {
        secCtx = &schema.SecurityContext{
            Classification: "INTERNAL",
            Sensitivity:   "MEDIUM",
            Compliance:    []string{"DEFAULT"},
            Encryption:    make(map[string]string),
            AccessControl: make(map[string]string),
        }
    }

    // Transform and validate fields
    normalizedData, err := t.transformFields(ctx, mappedFields)
    if err != nil {
        span.SetAttributes(attribute.String("error", err.Error()))
        return nil, err
    }

    // Create Silver event
    silverEvent, err := schema.NewSilverEvent(
        bronzeEvent.ClientID,
        determineEventType(normalizedData),
        normalizedData,
        *secCtx,
    )
    if err != nil {
        span.SetAttributes(attribute.String("error", err.Error()))
        return nil, err
    }

    // Set Bronze event linkage
    if err := silverEvent.FromBronzeEvent(bronzeEvent, normalizedData, *secCtx); err != nil {
        return nil, err
    }

    // Validate transformed event
    if err := silverEvent.Validate(); err != nil {
        span.SetAttributes(attribute.String("error", err.Error()))
        return nil, err
    }

    span.SetAttributes(
        attribute.String("event_id", silverEvent.EventID),
        attribute.String("client_id", silverEvent.ClientID),
        attribute.String("event_type", silverEvent.EventType),
    )

    return silverEvent, nil
}

// RegisterTransformer registers a custom field transformer
func (t *Transformer) RegisterTransformer(fieldName string, transformer TransformFunc) {
    t.mu.Lock()
    defer t.mu.Unlock()
    t.transformers[fieldName] = transformer
}

// transformFields applies registered transformers and security controls
func (t *Transformer) transformFields(ctx context.Context, fields map[string]interface{}) (map[string]interface{}, error) {
    normalized := make(map[string]interface{})

    t.mu.RLock()
    defer t.mu.RUnlock()

    for key, value := range fields {
        // Check context cancellation
        select {
        case <-ctx.Done():
            return nil, errors.NewError("E4001", "transformation timeout", nil)
        default:
        }

        // Apply field transformation
        transformed := value
        if transformer, exists := t.transformers[key]; exists {
            var err error
            transformed, err = transformer(value)
            if err != nil {
                return nil, errors.WrapError(err, "field transformation failed", map[string]interface{}{
                    "field": key,
                })
            }
        }

        // Validate field length
        if str, ok := transformed.(string); ok {
            if len(str) > maxFieldLength {
                return nil, errors.NewError("E3001", "field length exceeds maximum", map[string]interface{}{
                    "field": key,
                    "max_length": maxFieldLength,
                })
            }
        }

        // Handle sensitive fields
        if isSensitiveField(key) {
            encrypted, err := encryptSensitiveValue(transformed)
            if err != nil {
                return nil, err
            }
            transformed = encrypted
        }

        normalized[key] = transformed
    }

    return normalized, nil
}

// isSensitiveField checks if a field requires encryption
func isSensitiveField(fieldName string) bool {
    for _, pattern := range sensitiveFieldPatterns {
        if strings.Contains(strings.ToLower(fieldName), pattern) {
            return true
        }
    }
    return false
}

// encryptSensitiveValue encrypts sensitive field values
func encryptSensitiveValue(value interface{}) ([]byte, error) {
    data, err := json.Marshal(value)
    if err != nil {
        return nil, errors.WrapError(err, "failed to marshal sensitive value", nil)
    }

    // Implementation would use proper key management service
    // This is a placeholder for the encryption logic
    block, err := aes.NewCipher([]byte("placeholder-key-replace-in-production"))
    if err != nil {
        return nil, errors.WrapError(err, "failed to create cipher", nil)
    }

    gcm, err := cipher.NewGCM(block)
    if err != nil {
        return nil, errors.WrapError(err, "failed to create GCM", nil)
    }

    nonce := make([]byte, gcm.NonceSize())
    if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
        return nil, errors.WrapError(err, "failed to generate nonce", nil)
    }

    return gcm.Seal(nonce, nonce, data, nil), nil
}

// determineEventType infers the event type from normalized data
func determineEventType(data map[string]interface{}) string {
    if eventType, ok := data["event_type"].(string); ok {
        return eventType
    }
    return "UNKNOWN"
}