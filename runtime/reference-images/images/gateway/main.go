// Package main is the entrypoint for arhiax-gateway.
//
// The gateway is the Policy Enforcement Point (PEP) of the ARHIAX runtime.
// For every agent action it:
//  1. Builds an OPA input document from the request.
//  2. Queries OPA at data.arhiax.main for {allow, reasons, obligations}.
//  3. Writes an evidence record to the evidence store (append-only).
//  4. Enforces obligations (rate_limit, audit_log) when allow=true.
//  5. Returns the decision to the caller.
//
// Config is read exclusively from environment variables (12-factor).
// The full contract is documented in the Helm chart context transfer.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arhiax/arhiax/gateway/internal/evidence"
	"github.com/arhiax/arhiax/gateway/internal/opa"
	"github.com/arhiax/arhiax/gateway/internal/server"
)

// Build-time variables injected via -ldflags -X.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// Config holds all runtime configuration, read from environment variables.
// Every field maps 1:1 to an ARHIAX_* env var declared in the Helm chart's
// gateway Deployment template. Keep this struct in sync with values.yaml.
type Config struct {
	// Observability
	LogLevel  string // ARHIAX_LOG_LEVEL  (debug|info|warn|error)
	LogFormat string // ARHIAX_LOG_FORMAT (json|text)

	// Network
	HTTPPort    int // ARHIAX_HTTP_PORT
	MetricsPort int // ARHIAX_METRICS_PORT

	// Downstream services (auto-resolved by chart to in-cluster DNS)
	OPAURL           string // ARHIAX_OPA_URL
	EvidenceStoreURL string // ARHIAX_EVIDENCE_STORE_URL

	// Authn / authz
	JWTAudiences []string // ARHIAX_JWT_AUDIENCES (comma-separated)

	// Limits
	MaxRequestBodyBytes int64 // ARHIAX_MAX_REQUEST_BODY_BYTES
	RateLimitRPS        int   // ARHIAX_RATE_LIMIT_RPS

	// Downward API (injected by chart via fieldRef)
	PodNamespace string // POD_NAMESPACE
	PodName      string // POD_NAME
}

// loadConfig reads configuration from the environment, applying defaults
// that match the Helm chart's values.yaml defaults. This dual-sourcing is
// intentional: the binary must be runnable standalone (without Helm) for
// local development and integration tests.
func loadConfig() Config {
	return Config{
		LogLevel:            getEnv("ARHIAX_LOG_LEVEL", "info"),
		LogFormat:           getEnv("ARHIAX_LOG_FORMAT", "json"),
		HTTPPort:            getEnvInt("ARHIAX_HTTP_PORT", 8080),
		MetricsPort:         getEnvInt("ARHIAX_METRICS_PORT", 9090),
		OPAURL:              getEnv("ARHIAX_OPA_URL", "http://localhost:8181"),
		EvidenceStoreURL:    getEnv("ARHIAX_EVIDENCE_STORE_URL", "http://localhost:8090"),
		JWTAudiences:        splitCSV(getEnv("ARHIAX_JWT_AUDIENCES", "arhiax")),
		MaxRequestBodyBytes: int64(getEnvInt("ARHIAX_MAX_REQUEST_BODY_BYTES", 1048576)), // 1 MiB
		RateLimitRPS:        getEnvInt("ARHIAX_RATE_LIMIT_RPS", 100),
		PodNamespace:        getEnv("POD_NAMESPACE", "default"),
		PodName:             getEnv("POD_NAME", "arhiax-gateway-local"),
	}
}

func getEnv(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func getEnvInt(key string, def int) int {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// buildLogger constructs a slog.Logger per config. JSON is the production
// default (structured logs → Loki/ELK). Text is easier for local dev.
func buildLogger(cfg Config) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.LogLevel) {
	case "debug":
		level = slog.LevelDebug
	case "warn", "warning":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.ToLower(cfg.LogFormat) == "text" {
		handler = slog.NewTextHandler(os.Stdout, opts)
	} else {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	}

	// Bake identity fields into every log line. Operators can grep by pod.
	return slog.New(handler).With(
		slog.String("component", "arhiax-gateway"),
		slog.String("version", version),
	)
}

func main() {
	cfg := loadConfig()
	logger := buildLogger(cfg)

	logger.Info("arhiax-gateway starting",
		slog.String("commit", commit),
		slog.String("build_date", buildDate),
		slog.Int("http_port", cfg.HTTPPort),
		slog.Int("metrics_port", cfg.MetricsPort),
		slog.String("opa_url", cfg.OPAURL),
		slog.String("evidence_store_url", cfg.EvidenceStoreURL),
		slog.String("pod_namespace", cfg.PodNamespace),
		slog.String("pod_name", cfg.PodName),
	)

	// Wire downstream clients. Both use stdlib net/http with explicit
	// timeouts — no third-party HTTP client libraries, keeps the attack
	// surface and dependency graph minimal (single binary, zero CVEs
	// from transitive deps).
	opaClient := opa.NewClient(cfg.OPAURL, 5*time.Second, logger)
	evClient := evidence.NewClient(cfg.EvidenceStoreURL, 5*time.Second, logger)

	// Build the HTTP server (data plane on :8080).
	srv := server.New(server.Options{
		Logger:              logger,
		OPA:                 opaClient,
		Evidence:            evClient,
		PodNamespace:        cfg.PodNamespace,
		PodName:             cfg.PodName,
		Version:             version,
		MaxRequestBodyBytes: cfg.MaxRequestBodyBytes,
	})

	dataSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           srv.DataPlaneHandler(),
		ReadHeaderTimeout: 5 * time.Second,  // mitigates Slowloris
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Metrics server (control plane on :9090) runs on a separate listener
	// so NetworkPolicies in the chart can lock /metrics down to Prometheus
	// without exposing it on the data plane port.
	metricsSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.MetricsPort),
		Handler:           srv.MetricsHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	// Run both listeners concurrently. Errors are buffered so neither
	// goroutine blocks the other on shutdown.
	errCh := make(chan error, 2)
	go func() {
		logger.Info("data plane listening", slog.String("addr", dataSrv.Addr))
		if err := dataSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("data plane: %w", err)
		}
	}()
	go func() {
		logger.Info("metrics plane listening", slog.String("addr", metricsSrv.Addr))
		if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("metrics plane: %w", err)
		}
	}()

	// Graceful shutdown on SIGTERM (k8s rolling updates) or SIGINT (Ctrl-C).
	// 30s matches the default terminationGracePeriodSeconds we should set in
	// the chart; if the chart uses a different value, tune this accordingly.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	select {
	case sig := <-sigCh:
		logger.Info("shutdown signal received", slog.String("signal", sig.String()))
	case err := <-errCh:
		logger.Error("listener failed", slog.String("error", err.Error()))
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shut down data plane first (stops accepting new requests) then
	// metrics plane. Prometheus scrapes are cheap and we want them
	// available until the very end for post-mortem debugging.
	if err := dataSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("data plane shutdown error", slog.String("error", err.Error()))
	}
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("metrics plane shutdown error", slog.String("error", err.Error()))
	}

	logger.Info("arhiax-gateway stopped")
}
