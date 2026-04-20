"""
arhiax-correlator — entrypoint.

The correlator is the OPTIONAL D-TCG+ cross-domain anomaly detection
service in the ARHIAX runtime. In v1.0.0 it ships as a FUNCTIONAL STUB:

  - It binds two HTTP listeners (data plane :8100, metrics plane :9100).
  - It serves /healthz, /readyz, /metrics correctly.
  - It runs a poll loop that reads recent records from the evidence
    store on a fixed interval, but does NOT yet compute any anomaly
    score. The loop's only side effect is incrementing a Prometheus
    counter so operators can verify it is alive.

This stub is enough to satisfy the chart's `correlator.enabled=true`
quick-start path and to give a deployable target for the v1.1+ work
where the actual D-TCG+ math (Granger causality across modalities,
behavioural baseline drift, cross-tenant anomaly aggregation) lands.

Why ship a stub at all instead of leaving the image absent:

  1. The Helm chart references three images. If one is missing the
     ImagePullBackOff would block any test of the correlator subchart
     plumbing — even though the plumbing itself (subchart enable, DNS,
     NetworkPolicy, ServiceMonitor) is what most users want to verify
     before they care about the math.

  2. The stub's poll loop exercises the real evidence-store HTTP API
     end-to-end, which catches contract drift between the two services
     in CI before it reaches production.

  3. Replacing a stub with a real implementation in v1.1 is one Python
     module swap and zero infrastructure changes.

This design rationale is in the file header so a future maintainer or
auditor reading this code understands the v1.0.0 scope on first contact.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import sys
import threading
import time
from typing import Any

from arhiax_correlator.server import build_data_plane, build_metrics_plane
from arhiax_correlator.poller import Poller


# Build-time variables. The Dockerfile passes them via ENV at COPY time
# but we resolve them lazily here so a `python main.py` outside Docker
# also works.
VERSION = os.environ.get("ARHIAX_CORRELATOR_VERSION", "1.0.0")
COMMIT = os.environ.get("ARHIAX_CORRELATOR_COMMIT", "unknown")
BUILD_DATE = os.environ.get("ARHIAX_CORRELATOR_BUILD_DATE", "unknown")


def _getenv_int(key: str, default: int) -> int:
    """Read an int from env with a fallback. Tolerates empty string."""
    raw = os.environ.get(key, "")
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _getenv_float(key: str, default: float) -> float:
    raw = os.environ.get(key, "")
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        return default


class Config:
    """Holds all runtime configuration. Mirrors the env vars declared in
    the chart's correlator subchart values.yaml. Keep field names in sync."""

    def __init__(self) -> None:
        self.log_level: str = os.environ.get(
            "ARHIAX_CORRELATOR_LOG_LEVEL",
            os.environ.get("ARHIAX_LOG_LEVEL", "info"),
        )
        self.log_format: str = os.environ.get(
            "ARHIAX_CORRELATOR_LOG_FORMAT",
            os.environ.get("ARHIAX_LOG_FORMAT", "json"),
        )
        self.http_port: int = _getenv_int("ARHIAX_CORRELATOR_HTTP_PORT", 8100)
        self.metrics_port: int = _getenv_int("ARHIAX_CORRELATOR_METRICS_PORT", 9100)
        self.poll_interval_s: int = _getenv_int(
            "ARHIAX_CORRELATOR_POLL_INTERVAL_SECONDS", 30
        )
        self.window_seconds: int = _getenv_int(
            "ARHIAX_CORRELATOR_WINDOW_SECONDS", 300
        )
        self.anomaly_threshold: float = _getenv_float(
            "ARHIAX_CORRELATOR_ANOMALY_THRESHOLD", 0.75
        )
        self.evidence_store_url: str = os.environ.get(
            "ARHIAX_CORRELATOR_EVIDENCE_STORE_URL",
            "http://localhost:8090",
        )
        self.opa_url: str = os.environ.get(
            "ARHIAX_CORRELATOR_OPA_URL",
            "http://localhost:8181",
        )
        self.pod_namespace: str = os.environ.get("POD_NAMESPACE", "default")
        self.pod_name: str = os.environ.get(
            "POD_NAME", "arhiax-correlator-local"
        )


class _JsonFormatter(logging.Formatter):
    """Minimal structured JSON log formatter. Stdlib only.

    The output shape matches what the Go binaries emit via slog so a
    single Loki/Vector parser can ingest all three components without
    component-specific rules."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "time": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)
            )
            + f".{int((record.created % 1) * 1_000_000):06d}Z",
            "level": record.levelname.upper(),
            "msg": record.getMessage(),
            "component": "arhiax-correlator",
            "version": VERSION,
        }
        # Pull any extra= fields the caller attached.
        for k, v in record.__dict__.items():
            if k in (
                "name", "msg", "args", "levelname", "levelno", "pathname",
                "filename", "module", "exc_info", "exc_text", "stack_info",
                "lineno", "funcName", "created", "msecs", "relativeCreated",
                "thread", "threadName", "processName", "process",
                "taskName",
            ):
                continue
            payload[k] = v
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def _build_logger(cfg: Config) -> logging.Logger:
    level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warn": logging.WARNING,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }
    level = level_map.get(cfg.log_level.lower(), logging.INFO)

    handler = logging.StreamHandler(sys.stdout)
    if cfg.log_format.lower() == "text":
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        )
    else:
        handler.setFormatter(_JsonFormatter())

    logger = logging.getLogger("arhiax_correlator")
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False
    return logger


def main() -> int:
    cfg = Config()
    logger = _build_logger(cfg)

    logger.info(
        "arhiax-correlator starting",
        extra={
            "commit": COMMIT,
            "build_date": BUILD_DATE,
            "http_port": cfg.http_port,
            "metrics_port": cfg.metrics_port,
            "poll_interval_seconds": cfg.poll_interval_s,
            "window_seconds": cfg.window_seconds,
            "anomaly_threshold": cfg.anomaly_threshold,
            "evidence_store_url": cfg.evidence_store_url,
            "opa_url": cfg.opa_url,
            "pod_namespace": cfg.pod_namespace,
            "pod_name": cfg.pod_name,
        },
    )

    # Build the poller. It runs in its own thread; the main thread holds
    # the HTTP listeners and the signal handler.
    poller = Poller(
        evidence_store_url=cfg.evidence_store_url,
        poll_interval_s=cfg.poll_interval_s,
        window_seconds=cfg.window_seconds,
        anomaly_threshold=cfg.anomaly_threshold,
        logger=logger,
    )

    # Build both HTTP listeners. Each returns a (httpd, thread) pair.
    data_httpd, data_thread = build_data_plane(
        port=cfg.http_port,
        poller=poller,
        version=VERSION,
        logger=logger,
    )
    metrics_httpd, metrics_thread = build_metrics_plane(
        port=cfg.metrics_port,
        poller=poller,
        version=VERSION,
        logger=logger,
    )

    # Start the poller AFTER both servers are listening so that anyone
    # scraping /metrics or /readyz at the moment of boot sees a coherent
    # state, not a half-constructed one.
    poller.start()

    # Signal handling. We use a threading.Event so the main thread can
    # block on it without polling, and the handler is async-safe (sets
    # only an event flag).
    stop_event = threading.Event()

    def _on_signal(signum: int, _frame: Any) -> None:
        signame = signal.Signals(signum).name
        logger.info("shutdown signal received", extra={"signal": signame})
        stop_event.set()

    signal.signal(signal.SIGTERM, _on_signal)
    signal.signal(signal.SIGINT, _on_signal)

    # Block until shutdown is requested.
    stop_event.wait()

    # Shut down in reverse order of startup: poller first (so we stop
    # making outbound calls), then data plane, then metrics plane.
    logger.info("stopping poller")
    poller.stop()

    logger.info("stopping data plane")
    data_httpd.shutdown()
    data_thread.join(timeout=10)

    logger.info("stopping metrics plane")
    metrics_httpd.shutdown()
    metrics_thread.join(timeout=10)

    logger.info("arhiax-correlator stopped")
    return 0


if __name__ == "__main__":
    sys.exit(main())
