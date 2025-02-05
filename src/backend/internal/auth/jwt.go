// Package auth provides JWT-based authentication for the BlackPoint Security Integration Framework
package auth

import (
    "crypto/rsa"
    "crypto/x509"
    "encoding/pem"
    "fmt"
    "io/ioutil"
    "os"
    "sync"
    "time"

    "github.com/golang-jwt/jwt/v5" // v5.0.0
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/pkg/common/logging"
)

// Global variables for JWT management
var (
    jwtSigningKey    *rsa.PrivateKey
    jwtPublicKey     *rsa.PublicKey
    tokenExpiration  time.Duration
    tokenBlacklist   sync.Map
)

// JWTConfig defines the configuration for JWT operations
type JWTConfig struct {
    PrivateKeyPath      string
    PublicKeyPath       string
    TokenExpiration     time.Duration
    KeyRotationInterval time.Duration
}

// JWTManager handles JWT operations with enhanced security
type JWTManager struct {
    signingKey         *rsa.PrivateKey
    publicKey          *rsa.PublicKey
    tokenExpiration    time.Duration
    tokenBlacklist     *sync.Map
    keyRotationTicker  *time.Ticker
}

// CustomClaims extends standard JWT claims with BlackPoint-specific fields
type CustomClaims struct {
    jwt.RegisteredClaims
    ClientID    string            `json:"client_id"`
    Permissions []string          `json:"permissions"`
    Metadata    map[string]string `json:"metadata,omitempty"`
}

// InitJWTManager initializes the JWT manager with security configuration
func InitJWTManager(config JWTConfig) error {
    if config.TokenExpiration == 0 {
        config.TokenExpiration = time.Hour // Default 1-hour expiration
    }

    // Load and validate private key
    privateKeyBytes, err := ioutil.ReadFile(config.PrivateKeyPath)
    if err != nil {
        return errors.NewError("E1001", "Failed to read private key", map[string]interface{}{
            "path": config.PrivateKeyPath,
        })
    }

    privateKeyBlock, _ := pem.Decode(privateKeyBytes)
    if privateKeyBlock == nil {
        return errors.NewError("E1001", "Failed to decode private key PEM", nil)
    }

    privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
    if err != nil {
        return errors.NewError("E1001", "Invalid private key format", nil)
    }

    // Load and validate public key
    publicKeyBytes, err := ioutil.ReadFile(config.PublicKeyPath)
    if err != nil {
        return errors.NewError("E1001", "Failed to read public key", map[string]interface{}{
            "path": config.PublicKeyPath,
        })
    }

    publicKeyBlock, _ := pem.Decode(publicKeyBytes)
    if publicKeyBlock == nil {
        return errors.NewError("E1001", "Failed to decode public key PEM", nil)
    }

    publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
    if err != nil {
        return errors.NewError("E1001", "Invalid public key format", nil)
    }

    rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
    if !ok {
        return errors.NewError("E1001", "Public key is not RSA format", nil)
    }

    // Set global variables
    jwtSigningKey = privateKey
    jwtPublicKey = rsaPublicKey
    tokenExpiration = config.TokenExpiration

    logging.Info("JWT manager initialized successfully",
        zap.Duration("token_expiration", config.TokenExpiration),
        zap.Duration("key_rotation_interval", config.KeyRotationInterval))

    return nil
}

// GenerateToken creates a new JWT token with enhanced security claims
func GenerateToken(claims map[string]interface{}) (string, error) {
    if claims == nil {
        return "", errors.NewError("E1001", "Claims cannot be nil", nil)
    }

    now := time.Now().UTC()
    standardClaims := jwt.RegisteredClaims{
        ExpiresAt: jwt.NewNumericDate(now.Add(tokenExpiration)),
        IssuedAt:  jwt.NewNumericDate(now),
        NotBefore: jwt.NewNumericDate(now),
        Issuer:    "blackpoint-security",
        Subject:   claims["client_id"].(string),
        ID:        generateTokenID(),
    }

    customClaims := CustomClaims{
        RegisteredClaims: standardClaims,
        ClientID:        claims["client_id"].(string),
        Permissions:     claims["permissions"].([]string),
        Metadata:        claims["metadata"].(map[string]string),
    }

    token := jwt.NewWithClaims(jwt.SigningMethodRS256, customClaims)
    signedToken, err := token.SignedString(jwtSigningKey)
    if err != nil {
        return "", errors.NewError("E1001", "Failed to sign token", nil)
    }

    logging.Info("JWT token generated",
        zap.String("client_id", customClaims.ClientID),
        zap.Time("expiry", standardClaims.ExpiresAt.Time))

    return signedToken, nil
}

// ValidateToken validates a JWT token with comprehensive security checks
func ValidateToken(tokenString string) (jwt.MapClaims, error) {
    // Check token blacklist
    if _, blacklisted := tokenBlacklist.Load(tokenString); blacklisted {
        return nil, errors.NewError("E1001", "Token has been blacklisted", nil)
    }

    token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
        if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
            return nil, errors.NewError("E1001", "Invalid signing method", nil)
        }
        return jwtPublicKey, nil
    })

    if err != nil {
        return nil, errors.NewError("E1001", "Failed to parse token", map[string]interface{}{
            "error": err.Error(),
        })
    }

    if !token.Valid {
        return nil, errors.NewError("E1001", "Invalid token", nil)
    }

    claims, ok := token.Claims.(jwt.MapClaims)
    if !ok {
        return nil, errors.NewError("E1001", "Invalid claims format", nil)
    }

    // Validate issuer
    if claims["iss"].(string) != "blackpoint-security" {
        return nil, errors.NewError("E1001", "Invalid token issuer", nil)
    }

    logging.Info("JWT token validated",
        zap.String("client_id", claims["client_id"].(string)),
        zap.String("token_id", claims["jti"].(string)))

    return claims, nil
}

// RefreshToken refreshes a JWT token while preserving claims
func RefreshToken(oldToken string) (string, error) {
    claims, err := ValidateToken(oldToken)
    if err != nil {
        return "", err
    }

    // Blacklist old token
    tokenBlacklist.Store(oldToken, time.Now().UTC())

    // Generate new token with same claims but updated expiration
    newClaims := make(map[string]interface{})
    for k, v := range claims {
        newClaims[k] = v
    }

    return GenerateToken(newClaims)
}

// generateTokenID generates a unique token identifier
func generateTokenID() string {
    return fmt.Sprintf("%d-%s", time.Now().UnixNano(), generateRandomString(16))
}

// generateRandomString generates a cryptographically secure random string
func generateRandomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    for i := range b {
        b[i] = charset[secureRand.Intn(len(charset))]
    }
    return string(b)
}