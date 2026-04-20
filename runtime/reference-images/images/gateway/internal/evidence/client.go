// Package evidence implements a minimal HTTP client for the ARHIAX
// evidence store.
//
// The client appends records via:
//
//	POST <evidence_store_url>/v1/evidence
//	Body: <Record>
//	Response: {"id": "...", "hash": "...", "prev_hash": "..."}
//
// Every gateway decision (allow OR deny) writes exactly one evidence
// record. The record shape MUST match the schema the evidence-store binary
// enforces on append; any change here requires a matching change in
// evidence-store/internal/store/sqlite.go.
//
// Fail-open vs fail-closed on write failure: the gateway logs the failure
// loudly but does NOT fail the caller's request on evidence write errors.
// Rationale: the decision has already been made by OPA and returned to
// the caller; failing the request because we couldn't record it would
// punish the caller for an operator problem. The error is counted in the
// metrics (evidence_write_failures_total) so SREs can page on it.
//
// This is the ONE place in the gateway where we deliberately choose
// availability over durability, and it is documented here so an auditor
// reading the code understands it is a conscious trade-off, not an
// oversight.
package evidence

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Record is the shape the gateway sends to the evidence store. Most fields
// are passed through as `any` / `map[string]any` because the gateway does
// not need to interpret their structure — it only forwards what it saw
// on the wire plus the OPA decision.
//
// The store is responsible for assigning ID, Timestamp, PrevHash, and Hash;
// the gateway MUST NOT set these. If set, the store ignores them.
type Record struct {
	// Identity of the pod that made the decision (downward API).
	PodNamespace string `json:"pod_namespace"`
	PodName      string `json:"pod_name"`

	// The OPA input that was evaluated.
	Subject  any `json:"subject"`
	Action   any `json:"action"`
	Resource any `json:"resource"`
	Context  any `json:"context"`

	// The OPA output that was enforced.
	Decision    bool     `json:"decision"`
	Reasons     []string `json:"reasons,omitempty"`
	Obligations []any    `json:"obligations,omitempty"`
}

// AppendResponse is the evidence store's acknowledgment of a successful
// append. The gateway does not use ID/Hash/PrevHash for anything except
// optional debug logging, but they are part of the contract because
// external auditors may want to correlate gateway logs to store records
// by hash.
type AppendResponse struct {
	ID       string `json:"id"`
	Hash     string `json:"hash"`
	PrevHash string `json:"prev_hash"`
}

// Client is a stateless HTTP client for the evidence store. Safe for
// concurrent use.
type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient returns a Client that talks to the evidence store at baseURL.
// The timeout should be generous enough to tolerate SQLite write locks
// under load (the store serializes writers) but tight enough that a dead
// store does not stall the gateway. 5s is the default; tune via chart.
func NewClient(baseURL string, timeout time.Duration, logger *slog.Logger) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: logger.With(slog.String("subcomponent", "evidence_client")),
	}
}

// Append writes a single record to the evidence store. Returns the store's
// ack (ID + hashes) on success, or an error on any failure.
//
// Callers should log but not propagate the error to end users — see the
// package doc comment on fail-open semantics.
func (c *Client) Append(ctx context.Context, rec Record) (AppendResponse, error) {
	body, err := json.Marshal(rec)
	if err != nil {
		return AppendResponse{}, fmt.Errorf("marshal record: %w", err)
	}

	url := c.baseURL + "/v1/evidence"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return AppendResponse{}, fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("evidence store request failed",
			slog.String("url", url),
			slog.String("error", err.Error()))
		return AppendResponse{}, fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		c.logger.Error("evidence store non-2xx response",
			slog.Int("status", resp.StatusCode),
			slog.String("body", string(errBody)))
		return AppendResponse{}, fmt.Errorf("evidence store status %d", resp.StatusCode)
	}

	var ack AppendResponse
	if err := json.NewDecoder(resp.Body).Decode(&ack); err != nil {
		c.logger.Error("evidence store response decode failed",
			slog.String("error", err.Error()))
		return AppendResponse{}, fmt.Errorf("decode response: %w", err)
	}

	return ack, nil
}

// Healthy performs a best-effort liveness probe against the evidence store.
// Used by the gateway's own /readyz to short-circuit traffic if the store
// is unreachable at startup. Not called on the hot path.
func (c *Client) Healthy(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/healthz", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("evidence store unhealthy: status %d", resp.StatusCode)
	}
	return nil
}
