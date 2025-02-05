// Package auth provides OAuth 2.0 authentication for the BlackPoint Security Integration Framework
package auth

import (
    "context"
    "crypto/rand"
    "encoding/base64"
    "sync"
    "time"

    "golang.org/x/oauth2"                    // v0.12.0
    "github.com/coreos/go-oidc/v3/oidc"      // v3.6.0
    "github.com/go-redis/redis/v8"           // v8.11.5
    
    "./jwt"
    "../../pkg/common/errors"
    "../../pkg/common/logging"
)

// SecurityConfig defines enhanced security settings for OAuth
type SecurityConfig struct {
    TokenLifetime        time.Duration
    PKCERequired        bool
    TokenBlacklistTTL   time.Duration
    RateLimitPerMinute  int
    MaxFailedAttempts   int
    FailedAttemptsTTL   time.Duration
}

// OAuthManager handles OAuth operations with enhanced security
type OAuthManager struct {
    config          *oauth2.Config
    provider        *oidc.Provider
    verifier        *oidc.IDTokenVerifier
    tokenBlacklist  *redis.Client
    securityLogger  logging.SecurityLogger
    securityConfig  SecurityConfig
    rateLimiter    *sync.Map
    mu             sync.RWMutex
}

// OAuthConfig contains configuration for OAuth initialization
type OAuthConfig struct {
    ClientID        string
    ClientSecret    string
    RedirectURL     string
    ProviderURL     string
    SecurityOptions SecurityConfig
}

// InitOAuthManager initializes the OAuth manager with security configuration
func InitOAuthManager(config OAuthConfig) (*OAuthManager, error) {
    ctx := context.Background()

    // Initialize OIDC provider
    provider, err := oidc.NewProvider(ctx, config.ProviderURL)
    if err != nil {
        return nil, errors.NewError("E1001", "Failed to initialize OIDC provider", map[string]interface{}{
            "provider_url": config.ProviderURL,
        })
    }

    // Configure OAuth2 settings
    oauth2Config := &oauth2.Config{
        ClientID:     config.ClientID,
        ClientSecret: config.ClientSecret,
        RedirectURL:  config.RedirectURL,
        Endpoint:     provider.Endpoint(),
        Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
    }

    // Initialize token blacklist with Redis
    rdb := redis.NewClient(&redis.Options{
        Addr:     "localhost:6379", // Configure from environment
        Password: "",               // Configure from environment
        DB:       0,
    })

    // Create OAuth manager instance
    manager := &OAuthManager{
        config:         oauth2Config,
        provider:       provider,
        verifier:      provider.Verifier(&oidc.Config{ClientID: config.ClientID}),
        tokenBlacklist: rdb,
        securityConfig: config.SecurityOptions,
        rateLimiter:   &sync.Map{},
    }

    logging.Info("OAuth manager initialized",
        zap.String("client_id", config.ClientID),
        zap.String("provider", config.ProviderURL))

    return manager, nil
}

// GenerateAuthURL generates an OAuth authorization URL with PKCE
func (m *OAuthManager) GenerateAuthURL(ctx context.Context, state string) (string, string, error) {
    // Check rate limiting
    if !m.checkRateLimit(ctx) {
        return "", "", errors.NewError("E1001", "Rate limit exceeded", nil)
    }

    // Generate PKCE challenge
    codeVerifier := generateCodeVerifier()
    codeChallenge := generateCodeChallenge(codeVerifier)

    // Store PKCE verifier temporarily
    err := m.tokenBlacklist.Set(ctx, "pkce:"+state, codeVerifier, 10*time.Minute).Err()
    if err != nil {
        return "", "", errors.NewError("E1001", "Failed to store PKCE verifier", nil)
    }

    // Generate authorization URL with PKCE
    opts := []oauth2.AuthCodeOption{
        oauth2.AccessTypeOffline,
        oauth2.SetAuthURLParam("code_challenge", codeChallenge),
        oauth2.SetAuthURLParam("code_challenge_method", "S256"),
    }

    authURL := m.config.AuthCodeURL(state, opts...)
    return authURL, codeVerifier, nil
}

// ExchangeAuthCode exchanges authorization code for tokens with enhanced security
func (m *OAuthManager) ExchangeAuthCode(ctx context.Context, code, state string) (*oauth2.Token, *oidc.IDToken, error) {
    // Verify PKCE code verifier
    codeVerifier, err := m.tokenBlacklist.Get(ctx, "pkce:"+state).Result()
    if err != nil {
        return nil, nil, errors.NewError("E1001", "Invalid or expired PKCE verifier", nil)
    }
    m.tokenBlacklist.Del(ctx, "pkce:"+state)

    // Exchange code for token with PKCE
    oauth2Token, err := m.config.Exchange(ctx, code,
        oauth2.SetAuthURLParam("code_verifier", codeVerifier))
    if err != nil {
        return nil, nil, errors.NewError("E1001", "Failed to exchange authorization code", nil)
    }

    // Verify ID token
    rawIDToken, ok := oauth2Token.Extra("id_token").(string)
    if !ok {
        return nil, nil, errors.NewError("E1001", "No ID token in OAuth response", nil)
    }

    idToken, err := m.verifier.Verify(ctx, rawIDToken)
    if err != nil {
        return nil, nil, errors.NewError("E1001", "Failed to verify ID token", nil)
    }

    // Generate BlackPoint JWT
    claims := map[string]interface{}{
        "client_id": oauth2Token.Extra("sub"),
        "email":     idToken.Claims["email"],
        "name":      idToken.Claims["name"],
    }
    
    bpToken, err := jwt.GenerateToken(claims)
    if err != nil {
        return nil, nil, err
    }

    oauth2Token.AccessToken = bpToken

    logging.Info("OAuth token exchange completed",
        zap.String("client_id", claims["client_id"].(string)),
        zap.Time("expiry", oauth2Token.Expiry))

    return oauth2Token, idToken, nil
}

// RevokeToken revokes and blacklists an active token
func (m *OAuthManager) RevokeToken(ctx context.Context, token string) error {
    // Validate token before revocation
    claims, err := jwt.ValidateToken(token)
    if err != nil {
        return err
    }

    // Add to blacklist with TTL
    err = m.tokenBlacklist.Set(ctx, "blacklist:"+token, time.Now().UTC().String(),
        m.securityConfig.TokenBlacklistTTL).Err()
    if err != nil {
        return errors.NewError("E1001", "Failed to blacklist token", nil)
    }

    logging.Info("Token revoked",
        zap.String("client_id", claims["client_id"].(string)),
        zap.String("token_id", claims["jti"].(string)))

    return nil
}

// Helper functions

func (m *OAuthManager) checkRateLimit(ctx context.Context) bool {
    clientIP := ctx.Value("client_ip").(string)
    key := "ratelimit:" + clientIP

    count, _ := m.tokenBlacklist.Incr(ctx, key).Result()
    if count == 1 {
        m.tokenBlacklist.Expire(ctx, key, time.Minute)
    }

    return count <= int64(m.securityConfig.RateLimitPerMinute)
}

func generateCodeVerifier() string {
    b := make([]byte, 32)
    rand.Read(b)
    return base64.RawURLEncoding.EncodeToString(b)
}

func generateCodeChallenge(verifier string) string {
    // Implementation of PKCE S256 challenge generation
    h := sha256.New()
    h.Write([]byte(verifier))
    return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}