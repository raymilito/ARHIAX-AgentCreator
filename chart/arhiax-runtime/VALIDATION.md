# ARHIAX Runtime Helm Chart — Validation Status

**Chart**: `arhiax-runtime`
**Version**: `1.0.0`
**AppVersion**: `1.0.0`
**Generated**: 2026-04-08

---

## What has been validated

This chart was built and structurally validated in a sandbox environment
**without access to a Helm binary** (GitHub release assets and the Go module
proxy were unreachable from the build network, and Helm is not available in
Ubuntu universe). A purpose-built Python validator (`scripts/validate_chart.py`)
was run instead. It covers the following checks:

| # | Check | Status |
|---|---|---|
| 1 | YAML parseability of `Chart.yaml` and `values.yaml` (parent + subchart) | PASS |
| 2 | Balance of `{{ }}` delimiters and `if`/`with`/`range`/`define` vs `end` blocks | PASS (19/19 files) |
| 3 | Named template references vs definitions, per-chart namespace | PASS (parent: 82 refs / 27 defs; correlator: 13 refs / 7 defs) |
| 4 | `.Values.<path>` references against the actual `values.yaml` schema | PASS (parent: 219 refs; correlator: 39 refs) |
| 5 | Symbolic render: substitute `{{...}}` with placeholders and parse as YAML | PASS (19/19 files, 24 total K8s documents) |

Run the validator locally with:

```bash
python3 scripts/validate_chart.py
```

## What has NOT been validated and MUST be validated before publishing

The structural validator does NOT cover semantic checks that only a real Helm
binary can perform. Before publishing to a Helm repository, OCI registry, or
Artifact Hub, you MUST run at least the following commands locally:

### 1. `helm lint --strict`

```bash
helm lint --strict .
```

This catches:
- Sprig function misuse (e.g., `int` applied to a non-numeric string).
- `toYaml` on nil values.
- Missing `icon` field warnings.
- Chart metadata issues.

### 2. `helm template` with default and override values

```bash
# Default values
helm template arhiax ./arhiax-runtime > /tmp/default.yaml

# With the optional correlator subchart enabled
helm template arhiax ./arhiax-runtime \
  --set correlator.enabled=true > /tmp/with-correlator.yaml

# With Postgres evidence store driver
helm template arhiax ./arhiax-runtime \
  --set evidenceStore.driver=postgres \
  --set evidenceStore.postgres.host=pg.example.com \
  --set evidenceStore.postgres.existingSecret=pg-creds > /tmp/with-postgres.yaml

# With external bundle server mode
helm template arhiax ./arhiax-runtime \
  --set opa.bundleSource.mode=server \
  --set opa.bundleServer.enabled=true \
  --set opa.bundleServer.url=https://bundles.example.com > /tmp/with-bundle-server.yaml
```

Each of these should render without errors. This is where merged subchart
values, Sprig semantics, and the real Go template engine get exercised.

### 3. Kubernetes OpenAPI schema validation

```bash
# kubeconform is lighter and faster than kubeval
helm template arhiax ./arhiax-runtime | \
  kubeconform -strict -summary -kubernetes-version 1.29.0
```

This catches:
- Field names that do not exist on the target API version (e.g., `autoscaling/v2` HPA).
- Wrong types on known fields.
- Deprecated or removed APIs.

### 4. Dependency build

```bash
helm dependency build .
```

This actually materializes the correlator subchart dependency into `charts/`
(it is already physically present in this source tree, so this is mostly a
no-op, but it also updates `Chart.lock`).

### 5. Dry-run install against a real cluster

```bash
helm install arhiax ./arhiax-runtime \
  --namespace arhiax-system \
  --create-namespace \
  --dry-run=server
```

`--dry-run=server` (not `=client`) sends the manifests to the real API server
and catches admission controller rejections (e.g., PSA `restricted` profile
violations, NetworkPolicy syntax errors from the CNI).

### 6. Repackage with `helm package`

```bash
helm package . --version 1.0.0 --app-version 1.0.0
```

The current tarball in this source tree (`arhiax-runtime-1.0.0.tgz`) was
produced with `tar czf`, not `helm package`. Functionally equivalent (Helm
charts are just gzipped tarballs), but `helm package` additionally:
- Generates a `provenance` digest when you pass `--sign`.
- Writes the package filename using the exact `<name>-<version>.tgz`
  convention Helm expects.
- Updates the local `index.yaml` if you pass `-d <repo-dir>`.

The tarball produced here is installable directly with:

```bash
helm install arhiax arhiax-runtime-1.0.0.tgz
```

but you should repackage it with `helm package` before publishing to a public
repository to get the provenance metadata.

## Known risks and limitations of the structural validator

- **Sprig functions not exercised**: any `int`, `toYaml`, `printf`, `nindent`,
  `sha256sum`, `default`, etc. is treated as opaque text.
- **Subchart value merging not simulated**: the parent's override path
  `.Values.correlator.*` is not merged with the correlator subchart's own
  `values.yaml`. The real Helm engine does this merge at render time.
- **Conditional rendering not exercised**: the `enabled` flags of each
  component are not toggled to verify that all permutations render cleanly.
- **Helm built-ins beyond `.Values` / `.Release` / `.Chart` / `.Template`**
  are not modeled (e.g., `.Capabilities`, `.Files`). The one `.Files.Glob`
  usage in `opa-bundles-configmap.yaml` is handled via the symbolic render
  placeholder, not actually evaluated.

## Fixes applied during validation

Two real bugs were caught and fixed by the structural validator before
tarballing:

1. **`templates/gateway-hpa.yaml`**: the outer `{{- if and .Values.gateway.enabled .Values.gateway.autoscaling.enabled -}}` was missing its closing `{{- end }}`. Would have caused `helm install` to fail with "unexpected EOF in template". Fixed.

2. **`charts/correlator/values.yaml`**: `nameOverride` and `fullnameOverride` were referenced by the subchart's `_helpers.tpl` but not declared in the values schema. Technically Helm's `default` function tolerates nil, but declaring them makes the public contract explicit. Fixed.

One cosmetic change for linter compatibility:

3. **`templates/evidence-store-pvc.yaml`**: the opening `{{- if and ... -}}` guard was collapsed from a 4-line multiline expression to a single line. Functionally identical under Helm, but avoids confusing line-by-line linters.

---

## Summary

- Chart is **structurally sound** and ready for local `helm lint` + `helm template` validation.
- All four checks in `scripts/validate_chart.py` pass with zero errors and zero warnings.
- Two real bugs were caught and fixed pre-package.
- The tarball is installable but you should repackage with `helm package` before publishing.
