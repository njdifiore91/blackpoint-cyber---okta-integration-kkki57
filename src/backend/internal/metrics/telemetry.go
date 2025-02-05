// Package metrics provides telemetry and monitoring functionality for the BlackPoint Security Integration Framework
package metrics

import (
    "sync"
    "time"

    "github.com/blackpoint/pkg/common/logging"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/prometheus/client_golang/prometheus" // v1.14.0
    "go.opentelemetry.io/otel"                      // v1.11.0
    "go.opentelemetry.io/otel/trace"
    "k8s.io/client-go/kubernetes"                   // v0.26.0
    "k8s.io/client-go/rest"
    "k8s.io/metrics/pkg/client/clientset/versioned"
)

var (
    // defaultMetricConfig holds the global metric configuration
    defaultMetricConfig *MetricConfig

    // metricTypes defines supported metric types
    metricTypes = map[string]string{
        "counter":   "counter",
        "gauge":     "gauge",
        "histogram": "histogram",
        "summary":   "summary",
    }

    // defaultKubernetesLabels defines standard K8s labels
    defaultKubernetesLabels = map[string]string{
        "namespace":     "",
        "pod":          "",
        "container":    "",
        "node":         "",
        "cluster":      "",
    }

    // mutex for thread-safe operations
    metricMutex sync.RWMutex
)

// MetricConfig defines the configuration for telemetry and metrics
type MetricConfig struct {
    Namespace          string
    Subsystem         string
    Environment       string
    DefaultLabels     map[string]string
    KubernetesLabels  map[string]string
    MetricsEndpoint   string
    CollectionInterval int
    CardinalityLimit  int

    // Internal fields
    k8sClient         *kubernetes.Clientset
    metricsClient     *versioned.Clientset
    tracer            trace.Tracer
}

// NewMetricConfig creates a new MetricConfig with default values
func NewMetricConfig() *MetricConfig {
    return &MetricConfig{
        Namespace:          "blackpoint",
        Environment:       "development",
        DefaultLabels:     make(map[string]string),
        KubernetesLabels:  make(map[string]string),
        MetricsEndpoint:   "/metrics",
        CollectionInterval: 15,
        CardinalityLimit:  10000,
    }
}

// Validate validates the metric configuration
func (c *MetricConfig) Validate() error {
    if c.Namespace == "" {
        return errors.NewError("E4001", "metric namespace must be specified", nil)
    }

    if c.CollectionInterval < 5 {
        return errors.NewError("E4001", "collection interval must be at least 5 seconds", nil)
    }

    if c.CardinalityLimit < 1000 {
        return errors.NewError("E4001", "cardinality limit must be at least 1000", nil)
    }

    return c.ValidateKubernetesLabels()
}

// ValidateKubernetesLabels validates Kubernetes label configuration
func (c *MetricConfig) ValidateKubernetesLabels() error {
    for key := range c.KubernetesLabels {
        if _, exists := defaultKubernetesLabels[key]; !exists {
            return errors.NewError("E4001", "invalid kubernetes label: "+key, nil)
        }
    }
    return nil
}

// InitTelemetry initializes the telemetry system
func InitTelemetry(config *MetricConfig) error {
    metricMutex.Lock()
    defer metricMutex.Unlock()

    if err := config.Validate(); err != nil {
        return err
    }

    // Initialize OpenTelemetry
    tp := trace.NewTracerProvider()
    otel.SetTracerProvider(tp)
    config.tracer = tp.Tracer("blackpoint-telemetry")

    // Initialize Kubernetes clients
    k8sConfig, err := rest.InClusterConfig()
    if err != nil {
        logging.Error("failed to get kubernetes config", err)
    } else {
        config.k8sClient, err = kubernetes.NewForConfig(k8sConfig)
        if err != nil {
            logging.Error("failed to create kubernetes client", err)
        }

        config.metricsClient, err = versioned.NewForConfig(k8sConfig)
        if err != nil {
            logging.Error("failed to create metrics client", err)
        }
    }

    // Set up default labels
    config.DefaultLabels["environment"] = config.Environment
    config.DefaultLabels["namespace"] = config.Namespace
    if config.Subsystem != "" {
        config.DefaultLabels["subsystem"] = config.Subsystem
    }

    defaultMetricConfig = config

    // Start Kubernetes metrics collection
    if config.k8sClient != nil {
        go collectKubernetesMetrics(config)
    }

    logging.Info("telemetry system initialized", 
        logging.Field("namespace", config.Namespace),
        logging.Field("endpoint", config.MetricsEndpoint))

    return nil
}

// NewMetric creates a new metric with the specified configuration
func NewMetric(name string, metricType string, help string, labels []string) (interface{}, error) {
    metricMutex.RLock()
    defer metricMutex.RUnlock()

    if defaultMetricConfig == nil {
        return nil, errors.NewError("E4001", "telemetry system not initialized", nil)
    }

    if _, exists := metricTypes[metricType]; !exists {
        return nil, errors.NewError("E4001", "invalid metric type: "+metricType, nil)
    }

    // Combine default and custom labels
    allLabels := make([]string, 0)
    for k := range defaultMetricConfig.DefaultLabels {
        allLabels = append(allLabels, k)
    }
    for k := range defaultMetricConfig.KubernetesLabels {
        allLabels = append(allLabels, k)
    }
    allLabels = append(allLabels, labels...)

    // Check cardinality limit
    if len(allLabels) > defaultMetricConfig.CardinalityLimit {
        return nil, errors.NewError("E4001", "metric cardinality limit exceeded", nil)
    }

    opts := prometheus.Opts{
        Namespace: defaultMetricConfig.Namespace,
        Subsystem: defaultMetricConfig.Subsystem,
        Name:     name,
        Help:     help,
    }

    var metric interface{}
    var err error

    switch metricType {
    case "counter":
        metric = prometheus.NewCounterVec(
            prometheus.CounterOpts(opts),
            allLabels,
        )
    case "gauge":
        metric = prometheus.NewGaugeVec(
            prometheus.GaugeOpts(opts),
            allLabels,
        )
    case "histogram":
        metric = prometheus.NewHistogramVec(
            prometheus.HistogramOpts(opts),
            allLabels,
        )
    case "summary":
        metric = prometheus.NewSummaryVec(
            prometheus.SummaryOpts(opts),
            allLabels,
        )
    }

    if err = prometheus.Register(metric.(prometheus.Collector)); err != nil {
        return nil, errors.WrapError(err, "failed to register metric", nil)
    }

    return metric, nil
}

// collectKubernetesMetrics collects Kubernetes resource metrics
func collectKubernetesMetrics(config *MetricConfig) {
    ticker := time.NewTicker(time.Duration(config.CollectionInterval) * time.Second)
    defer ticker.Stop()

    for range ticker.C {
        ctx := context.Background()
        span := config.tracer.Start(ctx, "collect_kubernetes_metrics")
        defer span.End()

        if config.metricsClient == nil {
            continue
        }

        // Collect pod metrics
        podMetrics, err := config.metricsClient.MetricsV1beta1().PodMetricses("").List(ctx, metav1.ListOptions{})
        if err != nil {
            logging.Error("failed to collect pod metrics", err)
            continue
        }

        // Process and store metrics
        for _, pod := range podMetrics.Items {
            labels := prometheus.Labels{
                "namespace": pod.Namespace,
                "pod":      pod.Name,
            }

            for _, container := range pod.Containers {
                labels["container"] = container.Name
                
                // CPU usage
                cpuGauge, _ := NewMetric("container_cpu_usage", "gauge", "Container CPU usage in cores", nil)
                cpuGauge.(*prometheus.GaugeVec).With(labels).Set(float64(container.Usage.Cpu().MilliValue()) / 1000)

                // Memory usage
                memGauge, _ := NewMetric("container_memory_usage", "gauge", "Container memory usage in bytes", nil)
                memGauge.(*prometheus.GaugeVec).With(labels).Set(float64(container.Usage.Memory().Value()))
            }
        }
    }
}