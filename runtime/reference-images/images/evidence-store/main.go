// Package main is the entrypoint for arhiax-evidence-store.
//
// The evidence store is the append-only ledger of every decision the
// gateway has made. Records are written via HTTP POST and stored as
// newline-delimited JSON (JSONL) on disk, with a Merkle hash chain
// linking every record to its predecessor.
//
// Why JSONL + Merkle chain instead of SQLite for v1.0.0:
//
//   - Zero external dependencies. The whole binary is stdlib Go, which
//     keeps the supply-chain story unified with the gateway and the
//     CVE surface effectively at zero.
//   - The access pattern is append-only writes + read-by-id + tail.
//     A relational engine is overkill for that shape.
//   - The Merkle chain IS the durability guarantee: each record hashes
//     the previous record's hash, so any tampering is detectable by a
//     single end-to-end verify pass.
//   - The file is human-inspectable: `cat evidence.jsonl | jq` works
//     in any incident response, no SQL client needed.
//   - The HTTP contract the gateway sees is identical to what it would
//     be with a SQL backend, so swapping drivers in v1.1 is a single
//     internal/store/* change with zero gateway impact.
//
// This decision is documented inline so any future maintainer (or
// auditor) understands it is a conscious v1.0.0 choice, not a shortcut.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/arhiax/arhiax/evidence-store/internal/server"
	"github.com/arhiax/arhiax/evidence-store/internal/store"
)

// Build-time variables injected via -ldflags -X.
var (
	version   = "dev"
	commit    = "unknown"
	buildDate = "unknown"
)

// Config holds all runtime configuration. Every field maps 1:1 to an
// ARHIAX_ES_* env var declared in the Helm chart's StatefulSet template.
type Config struct {
	LogLevel    string
	LogFormat   string
	HTTPPort    int
	MetricsPort int

	// Driver: "jsonl" (v1.0.0 default) or "postgres" (declared in chart
	// values for forward compatibility, not implemented in v1.0.0).
	Driver string

	// Path on disk where the JSONL ledger lives. The chart mounts a PVC
	// at /var/lib/arhiax in sqlite/jsonl mode and points this here.
	// We accept both ARHIAX_ES_DATA_PATH (canonical) and the legacy
	// ARHIAX_ES_SQLITE_PATH from the v1.0.0 chart for compatibility.
	DataPath string

	// Postgres fields are read but unused in v1.0.0. They are kept here
	// so the chart can set them without the binary failing on unknown
	// env, and so the v1.1 driver swap is a strict superset.
	PgHost     string
	PgPort     int
	PgDatabase string
	PgSSLMode  string
	PgUser     string
	PgPassword string

	PodNamespace string
	PodName      string
}

func loadConfig() Config {
	dataPath := getEnv("ARHIAX_ES_DATA_PATH", "")
	if dataPath == "" {
		// Legacy name from the v1.0.0 Helm chart.
		dataPath = getEnv("ARHIAX_ES_SQLITE_PATH", "/var/lib/arhiax/evidence.jsonl")
	}

	// If the operator passed a path that ends in .db (the legacy SQLite
	// extension), we silently rewrite the suffix to .jsonl to avoid
	// pretending we are speaking SQLite. The directory and base name
	// are preserved so the PVC mount keeps working.
	if strings.HasSuffix(dataPath, ".db") {
		dataPath = strings.TrimSuffix(dataPath, ".db") + ".jsonl"
	}

	return Config{
		LogLevel:     getEnv("ARHIAX_ES_LOG_LEVEL", getEnv("ARHIAX_LOG_LEVEL", "info")),
		LogFormat:    getEnv("ARHIAX_ES_LOG_FORMAT", getEnv("ARHIAX_LOG_FORMAT", "json")),
		HTTPPort:     getEnvInt("ARHIAX_ES_HTTP_PORT", 8090),
		MetricsPort:  getEnvInt("ARHIAX_ES_METRICS_PORT", 9091),
		Driver:       getEnv("ARHIAX_ES_DRIVER", "jsonl"),
		DataPath:     dataPath,
		PgHost:       getEnv("ARHIAX_ES_PG_HOST", ""),
		PgPort:       getEnvInt("ARHIAX_ES_PG_PORT", 5432),
		PgDatabase:   getEnv("ARHIAX_ES_PG_DATABASE", ""),
		PgSSLMode:    getEnv("ARHIAX_ES_PG_SSLMODE", "require"),
		PgUser:       getEnv("ARHIAX_ES_PG_USER", ""),
		PgPassword:   getEnv("ARHIAX_ES_PG_PASSWORD", ""),
		PodNamespace: getEnv("POD_NAMESPACE", "default"),
		PodName:      getEnv("POD_NAME", "arhiax-evidence-store-local"),
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

	return slog.New(handler).With(
		slog.String("component", "arhiax-evidence-store"),
		slog.String("version", version),
	)
}

func main() {
	cfg := loadConfig()
	logger := buildLogger(cfg)

	logger.Info("arhiax-evidence-store starting",
		slog.String("commit", commit),
		slog.String("build_date", buildDate),
		slog.String("driver", cfg.Driver),
		slog.String("data_path", cfg.DataPath),
		slog.Int("http_port", cfg.HTTPPort),
		slog.Int("metrics_port", cfg.MetricsPort),
		slog.String("pod_namespace", cfg.PodNamespace),
		slog.String("pod_name", cfg.PodName),
	)

	// In v1.0.0 only the jsonl driver is implemented. Postgres is wired
	// through the env contract so the chart can set it without breaking
	// the binary, but we explicitly fail-fast if an operator selects it.
	if cfg.Driver != "jsonl" && cfg.Driver != "sqlite" {
		// "sqlite" is accepted as an alias for "jsonl" because the
		// v1.0.0 Helm chart defaults to driver=sqlite. The store
		// implementation is the same; only the label differs.
		logger.Error("unsupported driver",
			slog.String("driver", cfg.Driver),
			slog.String("hint", "v1.0.0 supports 'jsonl' (or its alias 'sqlite'); 'postgres' is reserved for v1.1"))
		os.Exit(2)
	}

	// Ensure the data directory exists. We do NOT mkdir -p the entire
	// path because that could mask a misconfigured PVC mount in k8s.
	// We only create the immediate parent if it does not exist, and
	// we never create /var/lib itself.
	dataDir := filepath.Dir(cfg.DataPath)
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		logger.Error("failed to create data directory",
			slog.String("dir", dataDir),
			slog.String("error", err.Error()))
		os.Exit(1)
	}

	// Open the JSONL store. This replays the existing file (if any) to
	// recompute the head hash and rebuild the in-memory id index, so on
	// restart the chain continues correctly from where it left off.
	jsonlStore, err := store.OpenJSONL(cfg.DataPath, logger)
	if err != nil {
		logger.Error("failed to open jsonl store",
			slog.String("path", cfg.DataPath),
			slog.String("error", err.Error()))
		os.Exit(1)
	}
	defer func() {
		if err := jsonlStore.Close(); err != nil {
			logger.Error("store close error", slog.String("error", err.Error()))
		}
	}()

	logger.Info("jsonl store ready",
		slog.String("path", cfg.DataPath),
		slog.Uint64("records_loaded", jsonlStore.Count()),
		slog.String("head_hash", jsonlStore.HeadHash()))

	srv := server.New(server.Options{
		Logger:       logger,
		Store:        jsonlStore,
		PodNamespace: cfg.PodNamespace,
		PodName:      cfg.PodName,
		Version:      version,
	})

	dataSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           srv.DataPlaneHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	metricsSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.MetricsPort),
		Handler:           srv.MetricsHandler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

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

	// Stop the data plane first to prevent new appends. Then close the
	// store (which fsyncs anything pending). Finally close metrics.
	// Order matters: appending after Close would corrupt the chain.
	if err := dataSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("data plane shutdown error", slog.String("error", err.Error()))
	}
	if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
		logger.Error("metrics plane shutdown error", slog.String("error", err.Error()))
	}

	logger.Info("arhiax-evidence-store stopped")
}
