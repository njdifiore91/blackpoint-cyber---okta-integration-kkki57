// Package auth provides secure token management for the BlackPoint CLI
package auth

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "fmt"
    "time"

    "github.com/golang-jwt/jwt/v5"
    
    "github.com/blackpoint/cli/pkg/common/errors"
    "github.com/blackpoint/cli/pkg/config/types"
)

// Constants for token management
const (
    accessTokenDuration  = time.Hour      // 1 hour lifetime for access tokens
    refreshTokenDuration = time.Hour * 24 // 24 hour lifetime for refresh tokens
    tokenIDLength       = 32             // Length of secure random token IDs
    maxTokenRetries     = 3              // Maximum number of token refresh attempts
)

// tokenSigningMethod specifies the JWT signing algorithm
var tokenSigningMethod = jwt.SigningMethodHS256

// TokenClaims extends standard JWT claims with BlackPoint-specific fields
type TokenClaims struct {
    jwt.RegisteredClaims
    ClientID    string `json:"client_id"`
    TokenType   string `json:"token_type"`
    Permissions []string `json:"permissions,omitempty"`
}

// generateSecureTokenID creates a cryptographically secure random token ID
func generateSecureTokenID() (string, error) {
    bytes := make([]byte, tokenIDLength)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate secure token ID: %w", err)
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateToken creates a new JWT access token and refresh token pair
func GenerateToken(config *types.AuthConfig) (string, string, error) {
    if config == nil {
        return "", "", errors.NewCLIError("E1001", "auth config cannot be nil", nil)
    }

    // Generate secure token IDs
    accessID, err := generateSecureTokenID()
    if err != nil {
        return "", "", errors.WrapError(err, "failed to generate access token ID")
    }

    refreshID, err := generateSecureTokenID()
    if err != nil {
        return "", "", errors.WrapError(err, "failed to generate refresh token ID")
    }

    now := time.Now()

    // Create access token claims
    accessClaims := TokenClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            ID:        accessID,
            IssuedAt:  jwt.NewNumericDate(now),
            ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenDuration)),
            NotBefore: jwt.NewNumericDate(now),
            Issuer:    "blackpoint-cli",
            Subject:   config.APIKey,
        },
        TokenType: "access",
    }

    // Create refresh token claims
    refreshClaims := TokenClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            ID:        refreshID,
            IssuedAt:  jwt.NewNumericDate(now),
            ExpiresAt: jwt.NewNumericDate(now.Add(refreshTokenDuration)),
            NotBefore: jwt.NewNumericDate(now),
            Issuer:    "blackpoint-cli",
            Subject:   config.APIKey,
        },
        TokenType: "refresh",
    }

    // Sign access token
    accessToken := jwt.NewWithClaims(tokenSigningMethod, accessClaims)
    signedAccessToken, err := accessToken.SignedString([]byte(config.APIKey))
    if err != nil {
        return "", "", errors.WrapError(err, "failed to sign access token")
    }

    // Sign refresh token
    refreshToken := jwt.NewWithClaims(tokenSigningMethod, refreshClaims)
    signedRefreshToken, err := refreshToken.SignedString([]byte(config.APIKey))
    if err != nil {
        return "", "", errors.WrapError(err, "failed to sign refresh token")
    }

    return signedAccessToken, signedRefreshToken, nil
}

// ValidateToken performs comprehensive validation of a JWT token
func ValidateToken(tokenString string, config *types.AuthConfig) (*jwt.Token, error) {
    if config == nil {
        return nil, errors.NewCLIError("E1001", "auth config cannot be nil", nil)
    }

    // Parse and validate token
    token, err := jwt.ParseWithClaims(tokenString, &TokenClaims{}, func(token *jwt.Token) (interface{}, error) {
        // Validate signing method
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, errors.NewCLIError("E1002", fmt.Sprintf("unexpected signing method: %v", token.Header["alg"]), nil)
        }
        return []byte(config.APIKey), nil
    })

    if err != nil {
        return nil, errors.WrapError(err, "token validation failed")
    }

    // Verify claims
    claims, ok := token.Claims.(*TokenClaims)
    if !ok {
        return nil, errors.NewCLIError("E1003", "invalid token claims", nil)
    }

    // Validate issuer
    if claims.Issuer != "blackpoint-cli" {
        return nil, errors.NewCLIError("E1003", "invalid token issuer", nil)
    }

    // Check expiration
    if claims.ExpiresAt.Before(time.Now()) {
        return nil, errors.NewCLIError("E1004", "token has expired", nil)
    }

    return token, nil
}

// RefreshToken generates a new access token using a valid refresh token
func RefreshToken(refreshToken string, config *types.AuthConfig) (string, error) {
    if config == nil {
        return "", errors.NewCLIError("E1001", "auth config cannot be nil", nil)
    }

    // Validate refresh token
    token, err := ValidateToken(refreshToken, config)
    if err != nil {
        return "", errors.WrapError(err, "refresh token validation failed")
    }

    claims, ok := token.Claims.(*TokenClaims)
    if !ok {
        return "", errors.NewCLIError("E1003", "invalid refresh token claims", nil)
    }

    // Verify token type
    if claims.TokenType != "refresh" {
        return "", errors.NewCLIError("E1003", "invalid token type for refresh", nil)
    }

    // Generate new access token
    accessID, err := generateSecureTokenID()
    if err != nil {
        return "", errors.WrapError(err, "failed to generate new access token ID")
    }

    now := time.Now()
    accessClaims := TokenClaims{
        RegisteredClaims: jwt.RegisteredClaims{
            ID:        accessID,
            IssuedAt:  jwt.NewNumericDate(now),
            ExpiresAt: jwt.NewNumericDate(now.Add(accessTokenDuration)),
            NotBefore: jwt.NewNumericDate(now),
            Issuer:    "blackpoint-cli",
            Subject:   claims.Subject,
        },
        TokenType:    "access",
        Permissions:  claims.Permissions,
    }

    // Sign new access token
    newToken := jwt.NewWithClaims(tokenSigningMethod, accessClaims)
    signedToken, err := newToken.SignedString([]byte(config.APIKey))
    if err != nil {
        return "", errors.WrapError(err, "failed to sign new access token")
    }

    return signedToken, nil
}

// IsTokenExpired checks if a token has expired
func IsTokenExpired(token *jwt.Token) (bool, error) {
    if token == nil {
        return false, errors.NewCLIError("E1001", "token cannot be nil", nil)
    }

    claims, ok := token.Claims.(*TokenClaims)
    if !ok {
        return false, errors.NewCLIError("E1003", "invalid token claims", nil)
    }

    if claims.ExpiresAt == nil {
        return false, errors.NewCLIError("E1003", "token missing expiry claim", nil)
    }

    return claims.ExpiresAt.Before(time.Now()), nil
}