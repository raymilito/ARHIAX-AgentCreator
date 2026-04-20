# ARHIAX Runtime — Container Images v1.0.0

This repository contains the Dockerfiles and source code for the three
container images that compose the ARHIAX Community Edition runtime data
plane:

- **`arhiax-gateway`** — Policy Enforcement Point (PEP). Receives agent
  decision requests, queries OPA, enforces obligations, writes evidence.
- **`arhiax-evidence-store`** — Append-only Merkle-chained decision log.
  Persists every decision the gateway makes, in tamper-evident form.
- **`arhiax-correlator`** — Optional cross-domain anomaly detector.
  Polls the evidence store and (in v1.1+) computes D-TCG+ correlation
  scores. v1.0.0 ships as a functional stub.

These images are referenced by the
[`arhiax-runtime` Helm chart](https://github.com/arhiax/arhiax) and
together implement the v1.0.0 contract documented in that chart's
context transfer.

---

## Design principles

These were locked at the start of the v1.0.0 build session and apply
to every component:

1. **Zero external dependencies on the data plane.** The Go binaries
   use only the Go standard library. The Python correlator uses only
   the CPython standard library. The supply-chain CVE surface is, by
   construction, the surface of the language runtime itself.
2. **Multi-stage builds to distroless runtime.** Final images contain
   the binary, CA certs, and nothing else. No shell, no package
   manager, no extra tools that an attacker could pivot through.
3. **Fail-closed by default.** If the gateway cannot reach OPA, the
   decision is deny. If the gateway cannot reach the evidence store,
   the decision is logged loudly but is still returned to the caller —
   that one trade-off is documented inline in the gateway source.
4. **Hand-rolled Prometheus metrics in text exposition format.** No
   prometheus client library, again for zero deps.
5. **Structured JSON logs in a single shape across all three
   components.** A Loki/Vector parser ingests the runtime with no
   per-component rules.
6. **Image UIDs match the chart's `securityContext.runAsUser`.** No
   PSA conflicts, no chown surprises on PVC mounts.

---

## Image contract

| Component         | Image                                                                  | UID    | Data port | Metrics port |
| ----------------- | ---------------------------------------------------------------------- | ------ | --------- | ------------ |
| Gateway           | `ghcr.io/arhiax/arhiax-gateway:1.0.0`                                  | 10001  | 8080      | 9090         |
| Evidence store    | `ghcr.io/arhiax/arhiax-evidence-store:1.0.0`                           | 10003  | 8090      | 9091         |
| Correlator        | `ghcr.io/arhiax/arhiax-correlator:1.0.0`                               | 10004  | 8100      | 9100         |

(OPA is unchanged from upstream `openpolicyagent/opa:0.68.0-rootless`
and is not built here.)

### Endpoints exposed

**Gateway** (data plane on port 8080):

- `GET /healthz` — liveness; always 200 if process up.
- `GET /readyz` — readiness; checks OPA and evidence store reachability.
- `POST /v1/decide` — submit a decision request. Body shape documented
  in `gateway/internal/opa/client.go`. Returns `{allow, reasons,
  obligations, evidence_id, error?}`.

**Gateway** (metrics plane on port 9090):

- `GET /metrics` — Prometheus text exposition. Counters: `decide_total`,
  `opa_errors_total`, `evidence_write_failures_total`. Histogram:
  `decide_duration_seconds`. Gauge: `uptime_seconds`.

**Evidence store** (data plane on port 8090):

- `GET /healthz`, `GET /readyz` — standard probes.
- `POST /v1/evidence` — append a record. Returns `{id, hash, prev_hash}`.
- `GET /v1/evidence?limit=N` — last N records (default 100, max 1000).
- `GET /v1/evidence/{id}` — fetch one record by id (O(1) seek).
- `GET /v1/head` — current head hash + count + timestamp. Used by
  external witnesses or transparency-log integrations.

**Evidence store** (metrics plane on port 9091):

- `GET /metrics` — counters: `append_total`, `tail_total`, `get_total`.
  Histogram: `append_duration_seconds`. Gauges: `uptime_seconds`,
  `records_total`.

**Correlator** (data plane on port 8100):

- `GET /healthz`, `GET /readyz` — standard probes. `readyz` returns
  503 until the poller has completed at least one tick.
- `GET /v1/state` — debug snapshot of poller state. Useful in dev.

**Correlator** (metrics plane on port 9100):

- `GET /metrics` — counters: `poll_ticks_total`, `poll_errors_total`.
  Gauges: `last_evidence_count`, `last_records_seen`,
  `seconds_since_last_tick`, `uptime_seconds`, `anomaly_threshold`.

### Environment variables

Each binary reads its configuration exclusively from environment
variables. The defaults match the Helm chart's `values.yaml` so the
binaries are runnable standalone for local development. The full
contract is in section 2 of the `arhiax-runtime` Helm chart context
transfer; here are the highlights.

**Gateway**:

- `ARHIAX_HTTP_PORT` (8080), `ARHIAX_METRICS_PORT` (9090)
- `ARHIAX_OPA_URL`, `ARHIAX_EVIDENCE_STORE_URL` (in-cluster DNS)
- `ARHIAX_LOG_LEVEL` (info), `ARHIAX_LOG_FORMAT` (json)
- `ARHIAX_MAX_REQUEST_BODY_BYTES` (1048576), `ARHIAX_RATE_LIMIT_RPS` (100)
- `ARHIAX_JWT_AUDIENCES` (csv)
- `POD_NAMESPACE`, `POD_NAME` (downward API)

**Evidence store**:

- `ARHIAX_ES_HTTP_PORT` (8090), `ARHIAX_ES_METRICS_PORT` (9091)
- `ARHIAX_ES_DRIVER` (jsonl) — `sqlite` is accepted as a chart-compat alias
- `ARHIAX_ES_DATA_PATH` (/var/lib/arhiax/evidence.jsonl) —
  also accepts the legacy `ARHIAX_ES_SQLITE_PATH` from the v1.0.0 chart
- `ARHIAX_ES_PG_*` — read but unused in v1.0.0; reserved for v1.1

**Correlator**:

- `ARHIAX_CORRELATOR_HTTP_PORT` (8100), `ARHIAX_CORRELATOR_METRICS_PORT` (9100)
- `ARHIAX_CORRELATOR_POLL_INTERVAL_SECONDS` (30)
- `ARHIAX_CORRELATOR_WINDOW_SECONDS` (300)
- `ARHIAX_CORRELATOR_ANOMALY_THRESHOLD` (0.75) — informational in v1.0.0
- `ARHIAX_CORRELATOR_EVIDENCE_STORE_URL`, `ARHIAX_CORRELATOR_OPA_URL`

---

## Quick start

### Build everything locally

```bash
make build
```

This produces three Docker images tagged at the repo's `VERSION`
(default 1.0.0). Use `make sizes` to confirm the images are within
the expected ranges (gateway ~6 MB, evidence store ~6 MB, correlator
~50 MB).

### Run a native smoke test (no Docker)

```bash
make smoke
```

This builds the Go binaries, starts gateway and evidence store on
local ports (18080/18090), submits one decision, prints the resulting
evidence head hash, and shuts everything down. Runs in under 5
seconds and is a quick sanity check during development.

### Build a single image

```bash
make build-gateway
make build-evidence-store
make build-correlator
```

### Pull the released images

Once the CI workflow has published a tag:

```bash
docker pull ghcr.io/arhiax/arhiax-gateway:1.0.0
docker pull ghcr.io/arhiax/arhiax-evidence-store:1.0.0
docker pull ghcr.io/arhiax/arhiax-correlator:1.0.0
```

### Verify a published image's signature

All published images are signed with cosign keyless via GitHub
Actions OIDC. Anyone can verify the signature without any pre-shared
key:

```bash
cosign verify ghcr.io/arhiax/arhiax-gateway:1.0.0 \
  --certificate-identity-regexp 'https://github.com/arhiax/arhiax/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

A successful verification proves the image was built by the GitHub
Actions workflow in this repo, on a commit signed by GitHub's OIDC
issuer, with an entry in the public Sigstore Rekor transparency log.

---

## Tamper-evidence model

The evidence store implements an append-only Merkle hash chain. Every
record's hash is `SHA-256(prev_hash || canonical_json(payload))`,
where `canonical_json` is a deterministic serialization with sorted
keys at every nesting level. The first record uses 32 zero bytes as
its `prev_hash` (the genesis).

**What this detects:**

- Modification of any record's content (the record's stored hash no
  longer matches the recomputed one).
- Deletion of any non-tail record (the next record's `prev_hash` no
  longer matches the new predecessor).
- Reordering of any records (same root cause as deletion).

**What this does NOT detect** (these are documented limitations, not
oversights):

- Truncation of the tail of the file. An attacker who removes the
  last N records leaves a self-consistent shorter chain. Defending
  against this requires an external witness (a checkpoint published
  to a third-party log). Roadmap for v1.1+.
- Total file replacement. Same root cause.
- The gateway choosing not to send a record in the first place.
  The store cannot record what it never received.

A future `arhiax-evidence verify` CLI will run `merkle.VerifyChain`
against any JSONL file dump to prove or disprove integrity. The
function is already exposed in `evidence-store/internal/merkle/`.

---

## CI workflow

`.github/workflows/build-images.yaml` runs on:

- **Tag push** (`v*.*.*`): builds, pushes to ghcr.io, signs with
  cosign keyless, attests build provenance, and tags `latest`.
- **Pull request**: builds only, no push, no signing. Validates the
  Dockerfiles do not regress.
- **Manual dispatch**: same as tag push, with a user-supplied version.

The workflow uses a matrix over the three images so all three build
in parallel. On tag push it produces:

- The image at `ghcr.io/<owner>/arhiax-<component>:<version>`.
- The image at `ghcr.io/<owner>/arhiax-<component>:latest`.
- A SLSA build provenance attestation (BuildKit `provenance: mode=max`).
- An SPDX SBOM attached to the manifest as a referrer.
- A cosign keyless signature recorded in Rekor.
- A GitHub-native build provenance attestation via
  `actions/attest-build-provenance`.

That is five independent integrity artifacts per image, all produced
in one workflow run, with no key management required from the
maintainer.

---

## Repository layout

```
arhiax-images-1.0.0/
├── README.md
├── Makefile
├── .github/workflows/
│   └── build-images.yaml
├── gateway/
│   ├── Dockerfile
│   ├── go.mod
│   ├── main.go
│   └── internal/
│       ├── opa/client.go         # OPA HTTP client; fail-closed semantics
│       ├── evidence/client.go    # Evidence store HTTP client; fail-open
│       └── server/server.go      # HTTP handlers, middleware, metrics
├── evidence-store/
│   ├── Dockerfile
│   ├── go.mod
│   ├── main.go
│   └── internal/
│       ├── merkle/chain.go       # SHA-256 chain + canonical JSON + verify
│       ├── store/jsonl.go        # Append-only JSONL store with replay
│       └── server/server.go      # HTTP handlers, metrics
└── correlator/
    ├── Dockerfile
    ├── requirements.txt          # Empty in v1.0.0; documents v1.1+ stack
    ├── main.py                   # Entrypoint, config, signal handling
    └── arhiax_correlator/
        ├── __init__.py
        ├── poller.py             # Background loop reading evidence store
        └── server.py             # HTTP listeners and handlers
```

---

## Versioning and roadmap

v1.0.0 is the initial public release of the runtime data plane. The
HTTP contracts and the chart's image references are now frozen for
the v1.x line. Internal implementation details (storage driver,
correlator algorithm) may change between minor versions without
breaking the contract.

**Known v1.1+ work:**

- Real D-TCG+ math in the correlator (numpy/scipy/pandas, with the
  Python build base pinned to 3.11 to match the distroless runtime).
- Postgres driver for the evidence store (the env contract and chart
  values are already wired; only the `internal/store/` package needs
  the new implementation).
- External witness integration (signed checkpoints + Rekor-style
  transparency log) to close the truncation gap in the tamper model.
- Per-record HMAC signing as an additional integrity layer (must use
  HMAC-SHA256, not raw SHA-256, to avoid length-extension issues).
- A `arhiax-evidence verify` CLI built on the existing
  `merkle.VerifyChain` function for offline audit.

---

## License

Apache License 2.0. See `LICENSE` (to be added at first publication).

## Vendor

Sinergia Consulting Group S.A.S., Barranquilla, Colombia.
