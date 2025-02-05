// Package main provides the entry point for the BlackPoint Security Integration Framework's collector service
package main

import (
    "context"
    "flag"
    "fmt"
    "os"
    "os/signal"
    "sync"
    "syscall"
    "time"

    "github.com/blackpoint/pkg/common/logging"
    "github.com/blackpoint/pkg/common/errors"
    "github.com/blackpoint/internal/collector"
    "github.com/blackpoint/internal/collector/validation"
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promhttp"
    "net/http"
)

// Version information
var (
    version = "1.0.0"
    buildTime string
)

// Command line flags
var (
    configPath = flag.String("config", "", "Path to configuration file")
    logLevel = flag.String("log-level", "info", "Logging level (debug, info, warn, error)")
    metricsAddr = flag.String("metrics-addr", ":9090", "The address to expose metrics on")
)

// Metrics collectors
var (
    collectorMetrics = struct {
        startupTime    prometheus.Gauge
        eventCount     *prometheus.CounterVec
        processingTime *prometheus.HistogramVec
        errorCount     *prometheus.CounterVec
    }{
        startupTime: prometheus.NewGauge(prometheus.GaugeOpts{
            Name: "blackpoint_collector_startup_timestamp",
            Help: "Timestamp when the collector service started",
        }),
        eventCount: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "blackpoint_collector_events_total",
                Help: "Total number of events processed by collector",
            },
            []string{"status"},
        ),
        processingTime: prometheus.NewHistogramVec(
            prometheus.HistogramOpts{
                Name: "blackpoint_collector_processing_seconds",
                Help: "Time spent processing events",
                Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
            },
            []string{"operation"},
        ),
        errorCount: prometheus.NewCounterVec(
            prometheus.CounterOpts{
                Name: "blackpoint_collector_errors_total",
                Help: "Total number of collector errors",
            },
            []string{"type"},
        ),
    }
)

func main() {
    // Parse command line flags
    flag.Parse()

    // Initialize logging system
    logConfig := logging.NewLogConfig()
    logConfig.Level = *logLevel
    logConfig.EnableSecurityAudit = true
    if err := logging.InitLogger(logConfig); err != nil {
        fmt.Printf("Failed to initialize logger: %v\n", err)
        os.Exit(1)
    }

    // Log startup
    logging.Info("Starting BlackPoint Security collector service",
        logging.Field("version", version),
        logging.Field("build_time", buildTime),
    )

    // Register metrics
    prometheus.MustRegister(
        collectorMetrics.startupTime,
        collectorMetrics.eventCount,
        collectorMetrics.processingTime,
        collectorMetrics.errorCount,
    )
    collectorMetrics.startupTime.SetToCurrentTime()

    // Set up metrics endpoint
    go func() {
        http.Handle("/metrics", promhttp.Handler())
        if err := http.ListenAndServe(*metricsAddr, nil); err != nil {
            logging.Error("Metrics server failed",
                err,
                logging.Field("address", *metricsAddr),
            )
        }
    }()

    // Set up signal handling for graceful shutdown
    ctx, cancel := setupSignalHandler()
    defer cancel()

    // Load and validate configuration
    config, err := loadConfig(*configPath)
    if err != nil {
        logging.Error("Failed to load configuration", err)
        os.Exit(1)
    }

    // Initialize security context
    securityCtx, err := initSecurityContext(config)
    if err != nil {
        logging.Error("Failed to initialize security context", err)
        os.Exit(1)
    }

    // Initialize collector
    collector, err := initCollector(ctx, config, securityCtx)
    if err != nil {
        logging.Error("Failed to initialize collector", err)
        os.Exit(1)
    }

    // Start collector
    if err := collector.Start(); err != nil {
        logging.Error("Failed to start collector", err)
        os.Exit(1)
    }

    // Start performance monitoring
    monitorCtx, monitorCancel := context.WithCancel(ctx)
    go monitorPerformance(monitorCtx, collector)

    // Wait for shutdown signal
    <-ctx.Done()
    logging.Info("Shutdown signal received, starting graceful shutdown")

    // Cancel performance monitoring
    monitorCancel()

    // Perform graceful shutdown
    shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer shutdownCancel()

    var wg sync.WaitGroup
    wg.Add(1)
    go func() {
        defer wg.Done()
        if err := collector.Stop(); err != nil {
            logging.Error("Error during collector shutdown", err)
        }
    }()

    // Wait for shutdown to complete or timeout
    shutdownComplete := make(chan struct{})
    go func() {
        wg.Wait()
        close(shutdownComplete)
    }()

    select {
    case <-shutdownComplete:
        logging.Info("Graceful shutdown completed")
    case <-shutdownCtx.Done():
        logging.Error("Shutdown timed out", errors.NewError("E4001", "shutdown timeout exceeded", nil))
    }

    // Log shutdown completion with audit
    logging.SecurityAudit("Collector service shutdown completed", map[string]interface{}{
        "version":     version,
        "uptime":     time.Since(time.Unix(int64(collectorMetrics.startupTime.Get()), 0)),
        "shutdown_at": time.Now().UTC(),
    })
}

// setupSignalHandler creates a context that is canceled on SIGTERM or SIGINT
func setupSignalHandler() (context.Context, context.CancelFunc) {
    ctx, cancel := context.WithCancel(context.Background())
    sigCh := make(chan os.Signal, 2)
    signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

    go func() {
        sig := <-sigCh
        logging.Info("Received shutdown signal",
            logging.Field("signal", sig.String()),
        )
        cancel()
    }()

    return ctx, cancel
}

// initCollector initializes the collector service with security context and monitoring
func initCollector(ctx context.Context, config *collector.CollectorConfig, secCtx *validation.SecurityContext) (*collector.RealtimeCollector, error) {
    // Validate collector configuration
    if err := config.Validate(); err != nil {
        return nil, errors.WrapError(err, "invalid collector configuration", nil)
    }

    // Initialize collector with monitoring
    timer := prometheus.NewTimer(collectorMetrics.processingTime.WithLabelValues("init"))
    defer timer.ObserveDuration()

    collector, err := collector.NewRealtimeCollector(config, secCtx)
    if err != nil {
        collectorMetrics.errorCount.WithLabelValues("initialization").Inc()
        return nil, err
    }

    return collector, nil
}

// monitorPerformance monitors collector performance metrics
func monitorPerformance(ctx context.Context, collector *collector.RealtimeCollector) {
    ticker := time.NewTicker(15 * time.Second)
    defer ticker.Stop()

    for {
        select {
        case <-ctx.Done():
            return
        case <-ticker.C:
            metrics, err := collector.GetMetrics()
            if err != nil {
                logging.Error("Failed to collect performance metrics", err)
                continue
            }

            // Update Prometheus metrics
            collectorMetrics.eventCount.WithLabelValues("processed").Add(float64(metrics.ProcessedEvents))
            collectorMetrics.processingTime.WithLabelValues("avg").Observe(metrics.AverageProcessingTime.Seconds())

            // Log performance data
            logging.Info("Collector performance metrics",
                logging.Field("processed_events", metrics.ProcessedEvents),
                logging.Field("avg_processing_time", metrics.AverageProcessingTime),
                logging.Field("error_rate", metrics.ErrorRate),
            )
        }
    }
}