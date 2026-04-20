// Package opa implements a minimal HTTP client for Open Policy Agent.
//
// The client speaks the OPA Data API:
//
//	POST <opa_url>/v1/data/arhiax/main
//	Body:     {"input": <input document>}
//	Response: {"result": {"allow": bool, "reasons": [...], "obligations": [...]}}
//
// The request/response shape is the contract documented in section 3 of
// the Helm chart context transfer. Any change here requires a matching
// change in files/policies/main.rego in the chart.
//
// No third-party dependencies — stdlib net/http + encoding/json only.
package opa

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

// Subject identifies who is requesting the action.
type Subject struct {
	ID     string   `json:"id"`
	Roles  []string `json:"roles,omitempty"`
	JWTAud string   `json:"jwt_aud,omitempty"`
}

// Action describes what the subject is trying to do.
type Action struct {
	Verb string `json:"verb"`
	Tool string `json:"tool,omitempty"`
}

// Resource is the target of the action.
type Resource struct {
	Type string `json:"type"`
	URI  string `json:"uri,omitempty"`
}

// Context carries request-scoped metadata for decision logging and
// tenancy-aware policies.
type Context struct {
	Tenant  string `json:"tenant,omitempty"`
	Env     string `json:"env,omitempty"`
	TraceID string `json:"trace_id,omitempty"`
}

// Input is the full document sent to OPA. Matches the schema declared in
// the header comment of files/policies/main.rego.
type Input struct {
	Subject  Subject  `json:"subject"`
	Action   Action   `json:"action"`
	Resource Resource `json:"resource"`
	Context  Context  `json:"context"`
}

// Obligation is a side-effect the gateway MUST enforce when allow=true.
// The shape is intentionally permissive (map[string]any) because new
// obligation types can be added in Rego without a gateway redeploy.
// Known types: "rate_limit", "audit_log", "redact_fields", "tool_timeout".
type Obligation map[string]any

// Decision is the OPA response envelope as the gateway consumes it.
// Reasons are human-readable strings for audit logs and UI display.
type Decision struct {
	Allow       bool         `json:"allow"`
	Reasons     []string     `json:"reasons,omitempty"`
	Obligations []Obligation `json:"obligations,omitempty"`
}

// Client is a stateless HTTP client for OPA. Safe for concurrent use.
type Client struct {
	baseURL    string
	httpClient *http.Client
	logger     *slog.Logger
}

// NewClient returns a Client that talks to OPA at baseURL. The timeout
// bounds the full request (connect + write + read + body close) and
// should be tight: in-cluster OPA decisions are normally sub-10ms, so
// a 5s timeout is already 500x the p99.
func NewClient(baseURL string, timeout time.Duration, logger *slog.Logger) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
			// No custom Transport: the stdlib default pools connections
			// per-host with MaxIdleConnsPerHost=2, which is fine for the
			// single-upstream case. If the gateway ever fans out to
			// multiple OPA replicas behind a headless service, revisit.
		},
		logger: logger.With(slog.String("subcomponent", "opa_client")),
	}
}

// opaDataResponse is the outer envelope OPA wraps every /v1/data/* response
// in. We unmarshal into this, then into Decision, to tolerate OPA's standard
// response shape without coupling the gateway to it further than necessary.
type opaDataResponse struct {
	Result Decision `json:"result"`
}

// Decide sends the input to OPA and returns the decision. On any error
// (network, non-200 status, malformed JSON) the method returns a Decision
// with Allow=false and a reason describing the failure, plus the error.
//
// IMPORTANT: the caller MUST treat errors as deny. Returning a partial
// Decision on error is a convenience so the caller can write an evidence
// record with the failure reason without constructing one manually.
//
// This is the fail-closed semantics that any auditor of an AI governance
// runtime will expect: if the PEP cannot reach the PDP, the answer is no.
func (c *Client) Decide(ctx context.Context, input Input) (Decision, error) {
	body, err := json.Marshal(map[string]Input{"input": input})
	if err != nil {
		// Marshaling the gateway's own input struct should never fail.
		// If it does, something is very wrong; fail closed.
		return denyDecision("opa_client: marshal input failed"), fmt.Errorf("marshal input: %w", err)
	}

	url := c.baseURL + "/v1/data/arhiax/main"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return denyDecision("opa_client: build request failed"), fmt.Errorf("new request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		c.logger.Error("opa request failed",
			slog.String("url", url),
			slog.String("error", err.Error()))
		return denyDecision("opa_client: request failed"), fmt.Errorf("do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read up to 512 bytes of the error body for diagnostics without
		// blowing up logs if OPA returns a huge HTML error page.
		errBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		c.logger.Error("opa non-200 response",
			slog.Int("status", resp.StatusCode),
			slog.String("body", string(errBody)))
		return denyDecision(fmt.Sprintf("opa_client: status %d", resp.StatusCode)),
			fmt.Errorf("opa status %d", resp.StatusCode)
	}

	var env opaDataResponse
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		c.logger.Error("opa response decode failed", slog.String("error", err.Error()))
		return denyDecision("opa_client: decode response failed"), fmt.Errorf("decode response: %w", err)
	}

	return env.Result, nil
}

// denyDecision returns a deny Decision with the given reason. Used to keep
// error paths uniform and avoid typos in failure strings.
func denyDecision(reason string) Decision {
	return Decision{
		Allow:   false,
		Reasons: []string{reason},
	}
}
