// Package encryption provides secure TLS configuration and certificate management
package encryption

import (
    "context"
    "crypto/tls"
    "crypto/x509"
    "crypto/x509/pkix"
    "sync"
    "time"

    "github.com/prometheus/client_golang/prometheus" // v1.16.0
    "../../pkg/common/errors"
    "../../pkg/common/logging"
)

// Global constants for TLS configuration
const (
    DefaultTLSVersion = tls.VersionTLS13
    DefaultCertRotationPeriod = 90 * 24 * time.Hour
    DefaultCertificateWarningPeriod = 15 * 24 * time.Hour
    MaxValidationRetries = 3
)

// DefaultCipherSuites defines secure cipher suites for TLS 1.3
var DefaultCipherSuites = []uint16{
    tls.TLS_AES_128_GCM_SHA256,
    tls.TLS_AES_256_GCM_SHA384,
}

// TLS monitoring metrics
var (
    certExpiryGauge = prometheus.NewGauge(prometheus.GaugeOpts{
        Name: "blackpoint_tls_cert_expiry_days",
        Help: "Days until certificate expiration",
    })
    certRotationCounter = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackpoint_tls_cert_rotations_total",
        Help: "Total number of certificate rotations",
    })
    certValidationErrors = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "blackpoint_tls_cert_validation_errors_total",
        Help: "Total number of certificate validation errors",
    })
)

// TLSOptions configures TLS settings
type TLSOptions struct {
    CertPath        string
    KeyPath         string
    MinVersion      uint16
    CipherSuites    []uint16
    RotationPeriod  time.Duration
    ClientAuth      tls.ClientAuthType
    ClientCAs       *x509.CertPool
}

// CertificateInfo contains certificate metadata
type CertificateInfo struct {
    Subject     pkix.Name
    Issuer      pkix.Name
    NotBefore   time.Time
    NotAfter    time.Time
    DNSNames    []string
    SerialNumber string
}

// TLSManager handles certificate lifecycle
type TLSManager struct {
    config         *tls.Config
    rotationPeriod time.Duration
    certPath       string
    keyPath        string
    ctx            context.Context
    certMutex      sync.RWMutex
}

// NewTLSConfig creates a secure TLS configuration
func NewTLSConfig(options TLSOptions) (*tls.Config, error) {
    if options.MinVersion == 0 {
        options.MinVersion = DefaultTLSVersion
    }
    if len(options.CipherSuites) == 0 {
        options.CipherSuites = DefaultCipherSuites
    }

    cert, err := LoadCertificate(options.CertPath, options.KeyPath)
    if err != nil {
        return nil, errors.NewError("E4001", "failed to load TLS certificate", map[string]interface{}{
            "cert_path": options.CertPath,
            "error": err.Error(),
        })
    }

    config := &tls.Config{
        Certificates: []tls.Certificate{cert},
        MinVersion:  options.MinVersion,
        CipherSuites: options.CipherSuites,
        ClientAuth:  options.ClientAuth,
        ClientCAs:   options.ClientCAs,
        PreferServerCipherSuites: true,
        SessionTicketsDisabled:   false,
        Renegotiation:           tls.RenegotiateNever,
    }

    return config, nil
}

// LoadCertificate loads and validates a TLS certificate
func LoadCertificate(certPath, keyPath string) (tls.Certificate, error) {
    cert, err := tls.LoadX509KeyPair(certPath, keyPath)
    if err != nil {
        return tls.Certificate{}, errors.NewError("E4001", "failed to load certificate pair", map[string]interface{}{
            "cert_path": certPath,
            "error": err.Error(),
        })
    }

    x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
    if err != nil {
        return tls.Certificate{}, errors.NewError("E4001", "failed to parse X.509 certificate", nil)
    }

    if err := ValidateCertificate(x509Cert); err != nil {
        return tls.Certificate{}, err
    }

    return cert, nil
}

// ValidateCertificate performs comprehensive certificate validation
func ValidateCertificate(cert *x509.Certificate) error {
    now := time.Now()

    // Check expiration
    if now.After(cert.NotAfter) {
        certValidationErrors.Inc()
        return errors.NewError("E4001", "certificate has expired", map[string]interface{}{
            "not_after": cert.NotAfter,
        })
    }

    if now.Before(cert.NotBefore) {
        certValidationErrors.Inc()
        return errors.NewError("E4001", "certificate not yet valid", map[string]interface{}{
            "not_before": cert.NotBefore,
        })
    }

    // Update expiry metric
    daysUntilExpiry := cert.NotAfter.Sub(now).Hours() / 24
    certExpiryGauge.Set(daysUntilExpiry)

    return nil
}

// NewTLSManager creates a new TLS manager instance
func NewTLSManager(options TLSOptions) (*TLSManager, error) {
    config, err := NewTLSConfig(options)
    if err != nil {
        return nil, err
    }

    if options.RotationPeriod == 0 {
        options.RotationPeriod = DefaultCertRotationPeriod
    }

    manager := &TLSManager{
        config:         config,
        rotationPeriod: options.RotationPeriod,
        certPath:       options.CertPath,
        keyPath:        options.KeyPath,
        ctx:            context.Background(),
    }

    // Start certificate monitoring
    go manager.MonitorCertificate()

    return manager, nil
}

// RotateCertificate performs certificate rotation
func (tm *TLSManager) RotateCertificate() error {
    tm.certMutex.Lock()
    defer tm.certMutex.Unlock()

    cert, err := LoadCertificate(tm.certPath, tm.keyPath)
    if err != nil {
        return errors.NewError("E4001", "failed to load new certificate", nil)
    }

    tm.config.Certificates = []tls.Certificate{cert}
    certRotationCounter.Inc()

    logging.Info("TLS certificate rotated successfully", nil)
    return nil
}

// GetCertificateInfo returns current certificate information
func (tm *TLSManager) GetCertificateInfo() (*CertificateInfo, error) {
    tm.certMutex.RLock()
    defer tm.certMutex.RUnlock()

    if len(tm.config.Certificates) == 0 {
        return nil, errors.NewError("E4001", "no certificate configured", nil)
    }

    cert, err := x509.ParseCertificate(tm.config.Certificates[0].Certificate[0])
    if err != nil {
        return nil, errors.NewError("E4001", "failed to parse certificate", nil)
    }

    return &CertificateInfo{
        Subject:      cert.Subject,
        Issuer:       cert.Issuer,
        NotBefore:    cert.NotBefore,
        NotAfter:     cert.NotAfter,
        DNSNames:     cert.DNSNames,
        SerialNumber: cert.SerialNumber.String(),
    }, nil
}

// MonitorCertificate continuously monitors certificate health
func (tm *TLSManager) MonitorCertificate() error {
    ticker := time.NewTicker(24 * time.Hour)
    defer ticker.Stop()

    for {
        select {
        case <-tm.ctx.Done():
            return nil
        case <-ticker.C:
            info, err := tm.GetCertificateInfo()
            if err != nil {
                logging.Error("Failed to get certificate info", err, nil)
                continue
            }

            // Check if rotation is needed
            if time.Until(info.NotAfter) < DefaultCertificateWarningPeriod {
                if err := tm.RotateCertificate(); err != nil {
                    logging.Error("Failed to rotate certificate", err, nil)
                }
            }
        }
    }
}

func init() {
    // Register metrics
    prometheus.MustRegister(certExpiryGauge)
    prometheus.MustRegister(certRotationCounter)
    prometheus.MustRegister(certValidationErrors)
}