// Package server wires the gateway's HTTP handlers.
//
// Two separate handler trees are exposed:
//
//   - DataPlaneHandler: /healthz, /readyz, /v1/decide
//     Listens on :8080 (ARHIAX_HTTP_PORT). This is where agents send
//     their decision requests.
//
//   - MetricsHandler: /metrics
//     Listens on :9090 (ARHIAX_METRICS_PORT). Prometheus scrapes here.
//     Separated from the data plane so a NetworkPolicy can lock /metrics
//     down to the monitoring namespace without exposing it to workloads.
//
// The /v1/decide endpoint is the hot path and the heart of the PEP:
//
//  1. Read + size-limit the request body.
//  2. Parse into an opa.Input.
//  3. Call OPA → get Decision.
//  4. Write an evidence record (fail-open, logged).
//  5. Return the Decision to the caller.
//
// Metrics are exposed in Prometheus text format without a Prometheus
// client library. This keeps the dependency graph at zero external
// packages, at the cost of hand-rolled counter/histogram code. For the
// metric cardinality we care about (5 counters, 1 histogram with fixed
// buckets), hand-rolling is a net win.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/arhiax/arhiax/gateway/internal/evidence"
	"github.com/arhiax/arhiax/gateway/internal/opa"
)

// Options bundles everything the server needs at construction time.
// Keeping this as a struct (instead of positional args) lets us add
// fields without breaking callers.
type Options struct {
	Logger              *slog.Logger
	OPA                 *opa.Client
	Evidence            *evidence.Client
	PodNamespace        string
	PodName             string
	Version             string
	MaxRequestBodyBytes int64
}

// Server holds the wired handlers and per-process metrics state.
type Server struct {
	opts    Options
	metrics *metrics
	logger  *slog.Logger
}

// New constructs a Server. Does not start listeners; callers wrap the
// returned handlers in *http.Server of their choice (see main.go).
func New(opts Options) *Server {
	return &Server{
		opts:    opts,
		metrics: newMetrics(),
		logger:  opts.Logger.With(slog.String("subcomponent", "server")),
	}
}

// DataPlaneHandler returns the mux for the agent-facing listener.
func (s *Server) DataPlaneHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealthz)
	mux.HandleFunc("/readyz", s.handleReadyz)
	mux.HandleFunc("/v1/decide", s.handleDecide)
	return mux
}

// MetricsHandler returns the mux for the Prometheus-facing listener.
// Kept on a separate port so NetworkPolicies can scope it.
func (s *Server) MetricsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", s.handleMetrics)
	// /healthz on metrics port too, so an operator can probe the
	// sidecar listener without touching the data plane.
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

// ---------------------------------------------------------------------
// Liveness / readiness
// ---------------------------------------------------------------------

// handleHealthz is the liveness probe. Returns 200 as long as the process
// is alive enough to serve HTTP. Deliberately does NOT check downstream
// services — livenessProbe failure triggers a pod restart, and restarting
// the gateway does not fix a dead OPA or evidence store.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": s.opts.Version,
	})
}

// handleReadyz is the readiness probe. Checks that downstream services
// (OPA, evidence store) are reachable. If either is down, return 503 so
// k8s removes this pod from Service endpoints until they recover.
//
// Timeout is tight (2s total) because readyz runs every periodSeconds.
func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	// Probe OPA with a trivial decide call. Any 2xx from OPA's /health
	// would also work, but calling /v1/data/arhiax/main with an empty
	// input exercises the same code path real requests use.
	_, opaErr := s.opts.OPA.Decide(ctx, opa.Input{})
	evErr := s.opts.Evidence.Healthy(ctx)

	status := http.StatusOK
	body := map[string]any{
		"status":         "ready",
		"opa":            "ok",
		"evidence_store": "ok",
	}
	if opaErr != nil {
		status = http.StatusServiceUnavailable
		body["status"] = "not_ready"
		body["opa"] = opaErr.Error()
	}
	if evErr != nil {
		status = http.StatusServiceUnavailable
		body["status"] = "not_ready"
		body["evidence_store"] = evErr.Error()
	}
	writeJSON(w, status, body)
}

// ---------------------------------------------------------------------
// /v1/decide — the hot path
// ---------------------------------------------------------------------

// decideResponse is what callers see.
type decideResponse struct {
	Allow       bool              `json:"allow"`
	Reasons     []string          `json:"reasons,omitempty"`
	Obligations []opa.Obligation  `json:"obligations,omitempty"`
	EvidenceID  string            `json:"evidence_id,omitempty"`
	Error       string            `json:"error,omitempty"`
}

func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		s.metrics.decideLatency.observe(time.Since(start).Seconds())
	}()

	if r.Method != http.MethodPost {
		s.metrics.decideTotal.inc("method_not_allowed")
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Size-limit the body BEFORE decoding. MaxBytesReader returns an
	// error on Read if the body exceeds the cap, preventing OOM from
	// a hostile client streaming megabytes of JSON.
	r.Body = http.MaxBytesReader(w, r.Body, s.opts.MaxRequestBodyBytes)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.metrics.decideTotal.inc("body_too_large")
		s.logger.Warn("request body read failed", slog.String("error", err.Error()))
		http.Error(w, "request body read failed", http.StatusRequestEntityTooLarge)
		return
	}

	var input opa.Input
	if err := json.Unmarshal(body, &input); err != nil {
		s.metrics.decideTotal.inc("bad_json")
		s.logger.Warn("invalid json in decide request", slog.String("error", err.Error()))
		writeJSON(w, http.StatusBadRequest, decideResponse{
			Allow: false,
			Error: "invalid json: " + err.Error(),
		})
		return
	}

	// Call OPA. On error, Decide returns a deny Decision AND the error,
	// so we still have a well-formed Decision to include in the evidence
	// record. See opa/client.go for the rationale.
	decision, opaErr := s.opts.OPA.Decide(r.Context(), input)
	if opaErr != nil {
		s.metrics.opaErrors.inc("call_failed")
	}

	// Record evidence for every decision (allow OR deny, success OR
	// OPA failure). This is append-only and fail-open: if the store is
	// down, we log and continue. See evidence/client.go for rationale.
	obligationsForRecord := make([]any, 0, len(decision.Obligations))
	for _, ob := range decision.Obligations {
		obligationsForRecord = append(obligationsForRecord, ob)
	}
	rec := evidence.Record{
		PodNamespace: s.opts.PodNamespace,
		PodName:      s.opts.PodName,
		Subject:      input.Subject,
		Action:       input.Action,
		Resource:     input.Resource,
		Context:      input.Context,
		Decision:     decision.Allow,
		Reasons:      decision.Reasons,
		Obligations:  obligationsForRecord,
	}
	ack, evErr := s.opts.Evidence.Append(r.Context(), rec)
	if evErr != nil {
		s.metrics.evidenceWriteFailures.inc("append_failed")
		s.logger.Error("evidence store append failed",
			slog.String("error", evErr.Error()),
			slog.Bool("decision_allow", decision.Allow))
	}

	// Count the final outcome for SLO dashboards.
	if decision.Allow {
		s.metrics.decideTotal.inc("allow")
	} else {
		s.metrics.decideTotal.inc("deny")
	}

	// Respond. The decision is returned to the caller even if evidence
	// write failed — the caller has the right to know the PEP's answer.
	resp := decideResponse{
		Allow:       decision.Allow,
		Reasons:     decision.Reasons,
		Obligations: decision.Obligations,
		EvidenceID:  ack.ID,
	}
	if opaErr != nil {
		resp.Error = "opa unavailable: fail-closed"
	}
	writeJSON(w, http.StatusOK, resp)
}

// ---------------------------------------------------------------------
// Prometheus-compatible /metrics
// ---------------------------------------------------------------------

// metrics holds all counters and histograms. Separated from Server so
// it can be unit tested in isolation.
type metrics struct {
	decideTotal           *labeledCounter
	opaErrors             *labeledCounter
	evidenceWriteFailures *labeledCounter
	decideLatency         *histogram
	startTime             time.Time
}

func newMetrics() *metrics {
	return &metrics{
		decideTotal:           newLabeledCounter("arhiax_gateway_decide_total", "outcome"),
		opaErrors:             newLabeledCounter("arhiax_gateway_opa_errors_total", "reason"),
		evidenceWriteFailures: newLabeledCounter("arhiax_gateway_evidence_write_failures_total", "reason"),
		decideLatency: newHistogram(
			"arhiax_gateway_decide_duration_seconds",
			[]float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		),
		startTime: time.Now(),
	}
}

// labeledCounter is a tiny counter with a single label dimension. Enough
// for the handful of metrics we emit. Not a general-purpose replacement
// for prometheus/client_golang.
type labeledCounter struct {
	name    string
	label   string
	mu      sync.RWMutex
	buckets map[string]*uint64
}

func newLabeledCounter(name, label string) *labeledCounter {
	return &labeledCounter{
		name:    name,
		label:   label,
		buckets: make(map[string]*uint64),
	}
}

func (c *labeledCounter) inc(labelValue string) {
	c.mu.RLock()
	if p, ok := c.buckets[labelValue]; ok {
		atomic.AddUint64(p, 1)
		c.mu.RUnlock()
		return
	}
	c.mu.RUnlock()

	// Slow path: create the bucket under the write lock.
	c.mu.Lock()
	defer c.mu.Unlock()
	if p, ok := c.buckets[labelValue]; ok {
		atomic.AddUint64(p, 1)
		return
	}
	var v uint64 = 1
	c.buckets[labelValue] = &v
}

func (c *labeledCounter) render(w io.Writer) {
	fmt.Fprintf(w, "# HELP %s Counter.\n", c.name)
	fmt.Fprintf(w, "# TYPE %s counter\n", c.name)
	c.mu.RLock()
	keys := make([]string, 0, len(c.buckets))
	for k := range c.buckets {
		keys = append(keys, k)
	}
	c.mu.RUnlock()
	sort.Strings(keys) // stable output for scrape diffing
	for _, k := range keys {
		c.mu.RLock()
		v := atomic.LoadUint64(c.buckets[k])
		c.mu.RUnlock()
		fmt.Fprintf(w, "%s{%s=%q} %d\n", c.name, c.label, k, v)
	}
}

// histogram is a cumulative histogram with fixed buckets. Matches the
// Prometheus exposition format for type=histogram.
type histogram struct {
	name    string
	buckets []float64
	counts  []uint64
	sum     uint64 // sum as micros to keep atomic arithmetic integer
	total   uint64
	mu      sync.Mutex
}

func newHistogram(name string, buckets []float64) *histogram {
	return &histogram{
		name:    name,
		buckets: buckets,
		counts:  make([]uint64, len(buckets)),
	}
}

func (h *histogram) observe(v float64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.total++
	h.sum += uint64(v * 1_000_000) // micros
	for i, b := range h.buckets {
		if v <= b {
			h.counts[i]++
		}
	}
}

func (h *histogram) render(w io.Writer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fmt.Fprintf(w, "# HELP %s Histogram.\n", h.name)
	fmt.Fprintf(w, "# TYPE %s histogram\n", h.name)
	for i, b := range h.buckets {
		fmt.Fprintf(w, "%s_bucket{le=\"%g\"} %d\n", h.name, b, h.counts[i])
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", h.name, h.total)
	fmt.Fprintf(w, "%s_sum %f\n", h.name, float64(h.sum)/1_000_000.0)
	fmt.Fprintf(w, "%s_count %d\n", h.name, h.total)
}

// handleMetrics renders all counters + histogram + a process_uptime gauge
// in Prometheus text exposition format (version 0.0.4).
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	s.metrics.decideTotal.render(w)
	s.metrics.opaErrors.render(w)
	s.metrics.evidenceWriteFailures.render(w)
	s.metrics.decideLatency.render(w)

	uptime := time.Since(s.metrics.startTime).Seconds()
	fmt.Fprintf(w, "# HELP arhiax_gateway_uptime_seconds Process uptime.\n")
	fmt.Fprintf(w, "# TYPE arhiax_gateway_uptime_seconds gauge\n")
	fmt.Fprintf(w, "arhiax_gateway_uptime_seconds %f\n", uptime)
}

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
