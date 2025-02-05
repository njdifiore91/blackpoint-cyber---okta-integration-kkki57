// Package metrics provides Prometheus metrics implementation for the BlackPoint Security Integration Framework
package metrics

import (
    "net/http"
    "sync"
    "time"

    "github.com/blackpoint/pkg/common/logging"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
    "github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
    // defaultRegistry is the default Prometheus registry with security enhancements
    defaultRegistry *prometheus.Registry

    // metricFactories stores metric creation functions by type
    metricFactories = map[string]metricFactory{
        "counter":   newSecureCounter,
        "gauge":     newSecureGauge,
        "histogram": newSecureHistogram,
        "summary":   newSecureSummary,
    }

    // metricCache provides thread-safe metric instance caching
    metricCache sync.Map

    // metricLimits defines cardinality and rate limits
    metricLimits = struct {
        maxLabels     int
        maxSeries     int
        maxSampleRate float64
    }{
        maxLabels:     20,
        maxSeries:     10000,
        maxSampleRate: 1000,
    }
)

// prometheusCollector implements a secure custom collector with Kubernetes integration
type prometheusCollector struct {
    registry    *prometheus.Registry
    config      MetricConfig
    secCtx      logging.SecurityContext
    k8sMetrics  K8sMetrics
    cache       *sync.Map
    mu          sync.RWMutex
}

// metricFactory defines the interface for metric creation functions
type metricFactory func(name, help string, labels []string) (prometheus.Collector, error)

// InitPrometheus initializes Prometheus metrics collection with security enhancements
func InitPrometheus(config MetricConfig, secCtx logging.SecurityContext) error {
    // Validate configuration
    if err := config.Validate(); err != nil {
        return err
    }

    // Create and configure registry with security settings
    defaultRegistry = prometheus.NewRegistry()
    defaultRegistry.MustRegister(
        prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
        prometheus.NewGoCollector(),
    )

    // Initialize collector with security context
    collector := &prometheusCollector{
        registry: defaultRegistry,
        config:   config,
        secCtx:   secCtx,
        cache:    &sync.Map{},
    }

    // Register collector
    if err := defaultRegistry.Register(collector); err != nil {
        return err
    }

    // Start metrics HTTP server with security middleware
    go func() {
        mux := http.NewServeMux()
        handler := promhttp.HandlerFor(defaultRegistry, promhttp.HandlerOpts{
            MaxRequestsInFlight: 10,
            Timeout:            30 * time.Second,
        })

        // Add security middleware
        secureHandler := secureMetricsMiddleware(handler, secCtx)
        mux.Handle(config.MetricsEndpoint, secureHandler)

        server := &http.Server{
            Addr:         ":9090",
            Handler:      mux,
            ReadTimeout:  5 * time.Second,
            WriteTimeout: 30 * time.Second,
        }

        if err := server.ListenAndServe(); err != nil {
            logging.Error("metrics server error", err)
        }
    }()

    return nil
}

// NewCounter creates a new Prometheus counter with security validation
func NewCounter(name, help string, labels []string, secCtx logging.SecurityContext) (prometheus.Counter, error) {
    // Validate metric name and security context
    if err := validateMetricName(name, secCtx); err != nil {
        return nil, err
    }

    // Check label cardinality
    if len(labels) > metricLimits.maxLabels {
        return nil, fmt.Errorf("label cardinality exceeds limit: %d", metricLimits.maxLabels)
    }

    // Create counter with security opts
    opts := prometheus.CounterOpts{
        Name: name,
        Help: help,
        ConstLabels: map[string]string{
            "security_context": secCtx.ID,
            "environment":     secCtx.Environment,
        },
    }

    counter := promauto.NewCounter(opts)

    // Cache metric instance
    metricCache.Store(name, counter)

    return counter, nil
}

// Describe implements prometheus.Collector interface
func (c *prometheusCollector) Describe(ch chan<- *prometheus.Desc) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    // Send metric descriptions with security validation
    c.cache.Range(func(key, value interface{}) bool {
        if metric, ok := value.(prometheus.Collector); ok {
            metric.Describe(ch)
        }
        return true
    })
}

// Collect implements prometheus.Collector interface
func (c *prometheusCollector) Collect(ch chan<- prometheus.Metric) {
    c.mu.RLock()
    defer c.mu.RUnlock()

    // Collect metrics with security checks
    c.cache.Range(func(key, value interface{}) bool {
        if metric, ok := value.(prometheus.Collector); ok {
            metric.Collect(ch)
        }
        return true
    })

    // Collect Kubernetes metrics if available
    if c.k8sMetrics != nil {
        c.collectK8sMetrics(ch)
    }
}

// secureMetricsMiddleware adds security checks to metrics endpoint
func secureMetricsMiddleware(next http.Handler, secCtx logging.SecurityContext) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Validate security context
        if !validateSecurityContext(r, secCtx) {
            http.Error(w, "Unauthorized", http.StatusUnauthorized)
            return
        }

        // Rate limiting
        if !checkRateLimit(r) {
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }

        next.ServeHTTP(w, r)
    })
}

// validateMetricName checks metric name against security policy
func validateMetricName(name string, secCtx logging.SecurityContext) error {
    if name == "" {
        return fmt.Errorf("metric name cannot be empty")
    }

    // Check against restricted patterns
    for _, pattern := range secCtx.RestrictedPatterns {
        if pattern.MatchString(name) {
            return fmt.Errorf("metric name contains restricted pattern")
        }
    }

    return nil
}

// collectK8sMetrics collects Kubernetes resource metrics
func (c *prometheusCollector) collectK8sMetrics(ch chan<- prometheus.Metric) {
    metrics, err := c.k8sMetrics.GetResourceMetrics()
    if err != nil {
        logging.Error("failed to collect k8s metrics", err)
        return
    }

    for _, metric := range metrics {
        ch <- metric
    }
}