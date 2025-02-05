// Package main provides the entry point for the Silver tier normalizer service
package main

import (
    "context"
    "os"
    "os/signal"
    "syscall"
    "time"

    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "go.opentelemetry.io/otel"
    "go.opentelemetry.io/otel/attribute"
    "net/http"

    "../../internal/normalizer/processor"
    "../../internal/streaming/consumer"
    "../../internal/config/loader"
    "../../pkg/common/logging"
)

const (
    defaultConfigPath = "/etc/blackpoint/normalizer.yaml"
    shutdownTimeout  = 30 * time.Second
    metricsPort     = ":9090"
    healthCheckPort = ":8080"
)

// Metrics collectors
var (
    eventsProcessed = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "normalizer_events_processed_total",
        Help: "Total number of events processed by the normalizer",
    })
    processingLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
        Name: "normalizer_processing_latency_seconds",
        Help: "Event processing latency in seconds",
        Buckets: []float64{0.1, 0.5, 1, 2, 5},
    })
    processingErrors = prometheus.NewCounter(prometheus.CounterOpts{
        Name: "normalizer_processing_errors_total",
        Help: "Total number of processing errors",
    })
)

// Config represents the normalizer service configuration
type Config struct {
    KafkaBrokers      string        `yaml:"kafka_brokers"`
    ConsumerGroup     string        `yaml:"consumer_group"`
    InputTopics       []string      `yaml:"input_topics"`
    ProcessingTimeout time.Duration `yaml:"processing_timeout"`
    BatchSize         int           `yaml:"batch_size"`
    Security          SecurityConfig `yaml:"security"`
    Monitoring        MonitoringConfig `yaml:"monitoring"`
    HealthCheck       HealthCheckConfig `yaml:"healthcheck"`
}

// SecurityConfig represents security-related configuration
type SecurityConfig struct {
    TLSEnabled    bool   `yaml:"tls_enabled"`
    SASLUsername  string `yaml:"sasl_username"`
    SASLPassword  string `yaml:"sasl_password"`
    SASLMechanism string `yaml:"sasl_mechanism"`
}

// MonitoringConfig represents monitoring-related configuration
type MonitoringConfig struct {
    MetricsEnabled bool    `yaml:"metrics_enabled"`
    TracingEnabled bool    `yaml:"tracing_enabled"`
    SamplingRate   float64 `yaml:"sampling_rate"`
}

// HealthCheckConfig represents health check configuration
type HealthCheckConfig struct {
    Enabled bool `yaml:"enabled"`
    Port    int  `yaml:"port"`
}

func main() {
    // Initialize logging with security context
    logger := logging.NewLogger()
    defer logger.Sync()

    // Load service configuration
    config, err := loadServiceConfig()
    if err != nil {
        logger.Error("Failed to load configuration", err)
        os.Exit(1)
    }

    // Initialize OpenTelemetry tracing
    if config.Monitoring.TracingEnabled {
        tp := initTracing(config)
        defer tp.Shutdown(context.Background())
    }

    // Register Prometheus metrics
    prometheus.MustRegister(eventsProcessed, processingLatency, processingErrors)

    // Start metrics server if enabled
    if config.Monitoring.MetricsEnabled {
        go func() {
            http.Handle("/metrics", promhttp.Handler())
            if err := http.ListenAndServe(metricsPort, nil); err != nil {
                logger.Error("Metrics server failed", err)
            }
        }()
    }

    // Start health check server if enabled
    if config.HealthCheck.Enabled {
        go startHealthCheckServer(config.HealthCheck.Port)
    }

    // Create and configure Kafka consumer
    kafkaConsumer, err := consumer.NewConsumer(createKafkaConfig(config), config.InputTopics, consumer.ConsumerOptions{
        BatchSize: config.BatchSize,
        EnableMetrics: config.Monitoring.MetricsEnabled,
    })
    if err != nil {
        logger.Error("Failed to create Kafka consumer", err)
        os.Exit(1)
    }

    // Initialize event processor
    eventProcessor, err := processor.NewProcessor(nil, nil, config.ProcessingTimeout)
    if err != nil {
        logger.Error("Failed to create event processor", err)
        os.Exit(1)
    }

    // Set up signal handling for graceful shutdown
    ctx, cancel, signalChan := setupSignalHandler()
    defer cancel()

    // Start event processing
    if err := kafkaConsumer.Start(); err != nil {
        logger.Error("Failed to start consumer", err)
        os.Exit(1)
    }

    logger.Info("Normalizer service started successfully",
        "kafka_brokers", config.KafkaBrokers,
        "consumer_group", config.ConsumerGroup,
        "input_topics", config.InputTopics,
    )

    // Wait for shutdown signal
    <-signalChan

    // Perform graceful shutdown
    if err := shutdown(ctx, kafkaConsumer, eventProcessor); err != nil {
        logger.Error("Error during shutdown", err)
        os.Exit(1)
    }

    logger.Info("Normalizer service shutdown complete")
}

func loadServiceConfig() (*Config, error) {
    configPath := os.Getenv("NORMALIZER_CONFIG_PATH")
    if configPath == "" {
        configPath = defaultConfigPath
    }

    var config Config
    if err := loader.LoadConfig(configPath, &config); err != nil {
        return nil, err
    }

    return &config, nil
}

func setupSignalHandler() (context.Context, context.CancelFunc, chan os.Signal) {
    ctx, cancel := context.WithCancel(context.Background())
    signalChan := make(chan os.Signal, 1)
    signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)

    return ctx, cancel, signalChan
}

func shutdown(ctx context.Context, consumer *consumer.Consumer, processor *processor.Processor) error {
    // Create shutdown context with timeout
    shutdownCtx, cancel := context.WithTimeout(ctx, shutdownTimeout)
    defer cancel()

    // Stop consumer first to prevent new messages
    if err := consumer.Stop(); err != nil {
        return err
    }

    // Wait for processing to complete or timeout
    select {
    case <-shutdownCtx.Done():
        return shutdownCtx.Err()
    default:
        return nil
    }
}

func startHealthCheckServer(port int) {
    http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("healthy"))
    })
    
    if err := http.ListenAndServe(fmt.Sprintf(":%d", port), nil); err != nil {
        logging.Error("Health check server failed", err)
    }
}

func createKafkaConfig(config *Config) *kafka.ConfigMap {
    kafkaConfig := &kafka.ConfigMap{
        "bootstrap.servers": config.KafkaBrokers,
        "group.id":         config.ConsumerGroup,
        "auto.offset.reset": "earliest",
    }

    if config.Security.TLSEnabled {
        kafkaConfig.SetKey("security.protocol", "SASL_SSL")
        kafkaConfig.SetKey("sasl.mechanisms", config.Security.SASLMechanism)
        kafkaConfig.SetKey("sasl.username", config.Security.SASLUsername)
        kafkaConfig.SetKey("sasl.password", config.Security.SASLPassword)
    }

    return kafkaConfig
}