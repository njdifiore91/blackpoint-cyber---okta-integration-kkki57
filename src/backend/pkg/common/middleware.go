// Package common provides shared middleware components for the BlackPoint Security Integration Framework
package common

import (
    "net/http"
    "time"
    "sync"
    "context"
    "fmt"

    "golang.org/x/time/rate" // v0.5.0
    "./errors"
    "./logging"
    "../../internal/auth/jwt"
)

// Global constants for middleware configuration
const (
    defaultRateLimit rate.Limit = 1000
    defaultBurst     int        = 50
    securityAuditEnabled bool   = true
    requestTimeout   time.Duration = 30 * time.Second
)

// Global rate limiter store
var (
    rateLimiters sync.Map // map[string]*rate.Limiter
)

// responseWriter wraps http.ResponseWriter with additional monitoring capabilities
type responseWriter struct {
    http.ResponseWriter
    status        int
    size         int64
    startTime    time.Time
    requestID    string
    securityContext map[string]interface{}
}

func (w *responseWriter) WriteHeader(status int) {
    w.status = status
    // Add security headers
    w.Header().Set("X-Content-Type-Options", "nosniff")
    w.Header().Set("X-Frame-Options", "DENY")
    w.Header().Set("X-XSS-Protection", "1; mode=block")
    w.Header().Set("X-Request-ID", w.requestID)
    w.ResponseWriter.WriteHeader(status)
}

func (w *responseWriter) Write(data []byte) (int, error) {
    if w.status == 0 {
        w.status = http.StatusOK
    }
    size, err := w.ResponseWriter.Write(data)
    w.size += int64(size)
    return size, err
}

// AuthMiddleware provides JWT authentication with enhanced security monitoring
func AuthMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        token := r.Header.Get("Authorization")
        if token == "" {
            logging.Error("Missing authentication token", nil)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Remove "Bearer " prefix if present
        if len(token) > 7 && token[:7] == "Bearer " {
            token = token[7:]
        }

        // Validate token
        claims, err := jwt.ValidateToken(token)
        if err != nil {
            logging.Error("Invalid authentication token", err)
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Add claims to request context
        ctx := context.WithValue(r.Context(), "claims", claims)
        r = r.WithContext(ctx)

        if securityAuditEnabled {
            logging.SecurityAudit("Authentication successful", map[string]interface{}{
                "client_id": claims["client_id"],
                "request_path": r.URL.Path,
            })
        }

        next.ServeHTTP(w, r)
    })
}

// LoggingMiddleware provides request/response logging with security monitoring
func LoggingMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        requestID := fmt.Sprintf("%d-%s", time.Now().UnixNano(), r.RemoteAddr)
        startTime := time.Now()

        // Create custom response writer
        rw := &responseWriter{
            ResponseWriter: w,
            startTime:    startTime,
            requestID:    requestID,
            securityContext: make(map[string]interface{}),
        }

        // Log request
        logging.Info("Request started",
            map[string]interface{}{
                "request_id": requestID,
                "method":    r.Method,
                "path":      r.URL.Path,
                "remote_ip": r.RemoteAddr,
            })

        // Process request
        next.ServeHTTP(rw, r)

        // Calculate duration
        duration := time.Since(startTime)

        // Log response
        logging.Info("Request completed",
            map[string]interface{}{
                "request_id": requestID,
                "status":    rw.status,
                "size":      rw.size,
                "duration":  duration,
            })
    })
}

// ErrorMiddleware provides centralized error handling with security context
func ErrorMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        defer func() {
            if err := recover(); err != nil {
                // Create error with security context
                bpErr := errors.NewError("E4001", "Internal server error",
                    map[string]interface{}{
                        "panic": err,
                        "path":  r.URL.Path,
                    })

                logging.Error("Panic recovered", bpErr)

                // Return standardized error response
                w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusInternalServerError)
                w.Write([]byte(`{"error":"Internal server error","code":"E4001"}`))
            }
        }()

        next.ServeHTTP(w, r)
    })
}

// RateLimitMiddleware provides dynamic rate limiting by client tier
func RateLimitMiddleware(next http.Handler, limit rate.Limit, burst int) http.Handler {
    if limit == 0 {
        limit = defaultRateLimit
    }
    if burst == 0 {
        burst = defaultBurst
    }

    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Get client ID from context
        claims, ok := r.Context().Value("claims").(jwt.Claims)
        if !ok {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }
        clientID := claims.ClientID

        // Get or create rate limiter for client
        limiterI, _ := rateLimiters.LoadOrStore(clientID, rate.NewLimiter(limit, burst))
        limiter := limiterI.(*rate.Limiter)

        if !limiter.Allow() {
            logging.Error("Rate limit exceeded",
                errors.NewError("E4002", "Too many requests",
                    map[string]interface{}{
                        "client_id": clientID,
                        "limit":     limit,
                    }))
            http.Error(w, "Too many requests", http.StatusTooManyRequests)
            return
        }

        // Add rate limit headers
        w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%d", burst))
        w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%d", limiter.Tokens()))

        next.ServeHTTP(w, r)
    })
}