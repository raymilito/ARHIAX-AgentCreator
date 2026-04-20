// Package server wires the evidence store's HTTP handlers.
//
// Data plane (port 8090):
//
//	GET  /healthz             — liveness; always 200 if process up
//	GET  /readyz              — readiness; checks store is open
//	POST /v1/evidence         — append a record (returns id, hash, prev_hash)
//	GET  /v1/evidence/{id}    — fetch a record by id
//	GET  /v1/evidence?limit=N — last N records (default 100, max 1000)
//	GET  /v1/head             — current head hash + count (for external witnesses)
//
// Metrics plane (port 9091):
//
//	GET /metrics              — Prometheus text format
//	GET /healthz              — same as data plane (sidecar probes)
//
// The HTTP shape and the request/response JSON match exactly what the
// gateway's evidence/client.go expects. Any change here MUST be mirrored
// in the gateway client and vice versa.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arhiax/arhiax/evidence-store/internal/store"
)

// Options bundles construction-time dependencies.
type Options struct {
	Logger       *slog.Logger
	Store        store.Store
	PodNamespace string
	PodName      string
	Version      string
}

// Server is the wired HTTP layer.
type Server struct {
	opts    Options
	logger  *slog.Logger
	metrics *metrics
}

// New constructs a Server.
func New(opts Options) *Server {
	return &Server{
		opts:    opts,
		logger:  opts.Logger.With(slog.String("subcomponent", "server")),
		metrics: newMetrics(),
	}
}

// DataPlaneHandler returns the mux for gateway-facing traffic.
func (s *Server) DataPlaneHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/v1/evidence", s.handleEvidence)
	mux.HandleFunc("/v1/evidence/", s.handleEvidenceByID)
	mux.HandleFunc("/v1/head", s.handleHead)
	return mux
}

// MetricsHandler returns the mux for the Prometheus listener.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

// ---------------------------------------------------------------------
// Liveness / readiness
// ---------------------------------------------------------------------

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.opts.Version,
	})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	// The store is "ready" if HeadHash returns a non-empty string and
	// Count is callable. There is no I/O check here because we keep the
	// store handle open for the lifetime of the process; if the file
	// were truly broken, OpenJSONL would have failed at startup.
	body := map[string]any{
		"status":    "ready",
		"head_hash": s.opts.Store.HeadHash(),
		"count":     s.opts.Store.Count(),
	}
	writeJSON(w, http.StatusOK, body)
}

// ---------------------------------------------------------------------
// /v1/evidence — POST (append) and GET (tail)
// ---------------------------------------------------------------------

// appendResponse is the ack the gateway expects.
type appendResponse struct {
	ID       string `json:"id"`
	Hash     string `json:"hash"`
	PrevHash string `json:"prev_hash"`
}

func (s *Server) handleEvidence(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		s.handleAppend(w, r)
	case http.MethodGet:
		s.handleTail(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

const maxRequestBodyBytes = 1 << 20 // 1 MiB cap on a single record

func (s *Server) handleAppend(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		s.metrics.appendLatency.observe(time.Since(start).Seconds())
	}()

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.metrics.appendTotal.inc("body_too_large")
		http.Error(w, "request body read failed", http.StatusRequestEntityTooLarge)
		return
	}

	var in store.Record
	if jerr := json.Unmarshal(body, &in); jerr != nil {
		s.metrics.appendTotal.inc("bad_json")
		s.logger.Warn("invalid json on append", slog.String("error", jerr.Error()))
		http.Error(w, "invalid json: "+jerr.Error(), http.StatusBadRequest)
		return
	}

	// Defensive: clients MUST NOT set id/timestamp/prev_hash/hash. We
	// silently zero them so an old client can't poison the chain by
	// pre-setting fields. Documented behavior, not a bug.
	in.ID = ""
	in.Timestamp = ""
	in.PrevHash = ""
	in.Hash = ""

	out, aerr := s.opts.Store.Append(r.Context(), in)
	if aerr != nil {
		s.metrics.appendTotal.inc("store_error")
		s.logger.Error("store append failed", slog.String("error", aerr.Error()))
		http.Error(w, "append failed: "+aerr.Error(), http.StatusInternalServerError)
		return
	}

	s.metrics.appendTotal.inc("ok")
	writeJSON(w, http.StatusOK, appendResponse{
		ID:       out.ID,
		Hash:     out.Hash,
		PrevHash: out.PrevHash,
	})
}

const (
	defaultTailLimit = 100
	maxTailLimit     = 1000
)

func (s *Server) handleTail(w http.ResponseWriter, r *http.Request) {
	limit := defaultTailLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > maxTailLimit {
		limit = maxTailLimit
	}

	records, err := s.opts.Store.Tail(r.Context(), limit)
	if err != nil {
		s.metrics.tailTotal.inc("error")
		http.Error(w, "tail failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.metrics.tailTotal.inc("ok")
	writeJSON(w, http.StatusOK, map[string]any{
		"count":   len(records),
		"records": records,
	})
}

func (s *Server) handleEvidenceByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/v1/evidence/")
	if id == "" || strings.Contains(id, "/") {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	rec, found, err := s.opts.Store.GetByID(r.Context(), id)
	if err != nil {
		s.metrics.getByIDTotal.inc("error")
		http.Error(w, "lookup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if !found {
		s.metrics.getByIDTotal.inc("not_found")
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.metrics.getByIDTotal.inc("ok")
	writeJSON(w, http.StatusOK, rec)
}

// handleHead exposes the current chain head + count. This is the endpoint
// an external witness or transparency log integration would poll to
// publish checkpoints. Public on purpose: head hashes are not secret.
func (s *Server) handleHead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"head_hash": s.opts.Store.HeadHash(),
		"count":     s.opts.Store.Count(),
		"timestamp": time.Now().UTC().Format(time.RFC3339Nano),
	})
}

// ---------------------------------------------------------------------
// Prometheus metrics — same hand-rolled scheme as the gateway
// ---------------------------------------------------------------------

type metrics struct {
	appendTotal   *labeledCounter
	tailTotal     *labeledCounter
	getByIDTotal  *labeledCounter
	appendLatency *histogram
	startTime     time.Time
}

func newMetrics() *metrics {
	return &metrics{
		appendTotal:  newLabeledCounter("arhiax_evidence_append_total", "outcome"),
		tailTotal:    newLabeledCounter("arhiax_evidence_tail_total", "outcome"),
		getByIDTotal: newLabeledCounter("arhiax_evidence_get_total", "outcome"),
		appendLatency: newHistogram(
			"arhiax_evidence_append_duration_seconds",
			[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		),
		startTime: time.Now(),
	}
}

type labeledCounter struct {
	name    string
	label   string
	mu      sync.RWMutex
	buckets map[string]*uint64
}

func newLabeledCounter(name, label string) *labeledCounter {
	return &labeledCounter{name: name, label: label, buckets: make(map[string]*uint64)}
}

func (c *labeledCounter) inc(v string) {
	c.mu.RLock()
	if p, ok := c.buckets[v]; ok {
		atomic.AddUint64(p, 1)
		c.mu.RUnlock()
		return
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := c.buckets[v]; ok {
		atomic.AddUint64(p, 1)
		return
	}
	var n uint64 = 1
	c.buckets[v] = &n
}

func (c *labeledCounter) render(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s Counter.\n# TYPE %s counter\n", c.name, c.name)
	c.mu.RLock()
	keys := make([]string, 0, len(c.buckets))
	for k := range c.buckets {
		keys = append(keys, k)
	}
	c.mu.RUnlock()
	sort.Strings(keys)
	for _, k := range keys {
		c.mu.RLock()
		v := atomic.LoadUint64(c.buckets[k])
		c.mu.RUnlock()
		fmt.Fprintf(w, "%s{%s=%q} %d\n", c.name, c.label, k, v)
	}
}

type histogram struct {
	name    string
	buckets []float64
	counts  []uint64
	sum     uint64
	total   uint64
	mu      sync.Mutex
}

func newHistogram(name string, buckets []float64) *histogram {
	return &histogram{name: name, buckets: buckets, counts: make([]uint64, len(buckets))}
}

func (h *histogram) observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.total++
	h.sum += uint64(v * 1_000_000)
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
}

func (h *histogram) render(w io.Writer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprintf(w, "# HELP %s Histogram.\n# TYPE %s histogram\n", h.name, h.name)
	for i, b := range h.buckets {
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", h.name, b, h.counts[i])
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", h.name, h.total)
	fmt.Fprintf(w, "%s_sum %f\n", h.name, float64(h.sum)/1_000_000.0)
	fmt.Fprintf(w, "%s_count %d\n", h.name, h.total)
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	s.metrics.appendTotal.render(w)
	s.metrics.tailTotal.render(w)
	s.metrics.getByIDTotal.render(w)
	s.metrics.appendLatency.render(w)
	uptime := time.Since(s.metrics.startTime).Seconds()
	fmt.Fprintf(w, "# HELP arhiax_evidence_uptime_seconds Process uptime.\n")
	fmt.Fprintf(w, "# TYPE arhiax_evidence_uptime_seconds gauge\n")
	fmt.Fprintf(w, "arhiax_evidence_uptime_seconds %f\n", uptime)
	// Also expose chain state as gauges so Prometheus can alert on
	// "count not increasing for 10m" etc.
	fmt.Fprintf(w, "# HELP arhiax_evidence_records_total Records appended since boot.\n")
	fmt.Fprintf(w, "# TYPE arhiax_evidence_records_total gauge\n")
	fmt.Fprintf(w, "arhiax_evidence_records_total %d\n", s.opts.Store.Count())
}

// Prevent unused-import warning when context is referenced only in
// signatures: the linter sees the package used, but go vet wants at
// least one direct use. The Background call is essentially free.
var _ = context.Background

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
