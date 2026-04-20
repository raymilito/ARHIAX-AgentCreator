"""
arhiax_correlator.server — HTTP listeners.

Two listeners, mirroring the gateway and evidence-store layout:

  Data plane (default :8100):
    GET /healthz   — liveness; always 200 if process up
    GET /readyz    — readiness; 200 once the poller has ticked at least once
    GET /v1/state  — debug view of the poller's snapshot

  Metrics plane (default :9100):
    GET /metrics   — Prometheus text format
    GET /healthz   — same as data plane

Built on stdlib http.server. The two listeners run in their own threads
(ThreadingHTTPServer) so that a slow scrape on /metrics never blocks
a /healthz probe and vice versa.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Tuple

from arhiax_correlator.poller import Poller


# ---------------------------------------------------------------------
# Shared handler base — both listeners share the same plumbing
# ---------------------------------------------------------------------


class _BaseHandler(BaseHTTPRequestHandler):
    """Quiet, JSON-aware request handler. Concrete classes set the routes."""

    # Filled in per-instance class via attribute injection in build_*().
    poller: Poller
    version: str
    arhiax_logger: logging.Logger

    # Suppress the default per-request stderr access log; we already
    # emit a structured log line via arhiax_logger when we want to.
    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        return

    # ----- helpers -----

    def _write_json(self, status: int, body: Any) -> None:
        payload = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _write_text(self, status: int, body: str, content_type: str) -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _not_found(self) -> None:
        self._write_json(404, {"error": "not found", "path": self.path})

    def _method_not_allowed(self, allow: str) -> None:
        self.send_response(405)
        self.send_header("Allow", allow)
        self.send_header("Content-Type", "application/json")
        body = json.dumps({"error": "method not allowed"}).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ----- shared routes -----

    def _route_healthz(self) -> None:
        self._write_json(200, {"status": "ok", "version": self.version})


# ---------------------------------------------------------------------
# Data plane handler
# ---------------------------------------------------------------------


class DataPlaneHandler(_BaseHandler):
    def do_GET(self) -> None:  # noqa: N802 — http.server requires this name
        if self.path == "/healthz":
            self._route_healthz()
            return
        if self.path == "/readyz":
            self._route_readyz()
            return
        if self.path == "/v1/state":
            self._route_state()
            return
        self._not_found()

    def _route_readyz(self) -> None:
        if self.poller.is_ready():
            snap = self.poller.snapshot()
            self._write_json(
                200,
                {
                    "status": "ready",
                    "ticks": snap["ticks"],
                    "errors": snap["errors"],
                    "last_head_hash": snap["last_head_hash"],
                    "last_count": snap["last_count"],
                },
            )
        else:
            self._write_json(
                503,
                {"status": "not_ready", "reason": "poller has not ticked yet"},
            )

    def _route_state(self) -> None:
        # /v1/state is a debug endpoint that returns everything the
        # poller knows. Useful for troubleshooting in dev; not used by
        # any production component. The chart's NetworkPolicy can leave
        # /v1/* open since the data plane is meant to be inspectable.
        self._write_json(200, self.poller.snapshot())


# ---------------------------------------------------------------------
# Metrics plane handler
# ---------------------------------------------------------------------


class MetricsPlaneHandler(_BaseHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/healthz":
            self._route_healthz()
            return
        if self.path == "/metrics":
            self._route_metrics()
            return
        self._not_found()

    def _route_metrics(self) -> None:
        snap = self.poller.snapshot()
        now = time.time()
        uptime = now - snap["started_unix"] if snap["started_unix"] > 0 else 0.0
        seconds_since_tick = (
            now - snap["last_tick_unix"] if snap["last_tick_unix"] > 0 else -1.0
        )

        # Hand-rolled Prometheus exposition format. Same approach as
        # the Go binaries — keeps zero-deps narrative intact.
        lines: list[str] = []

        def counter(name: str, value: int, help_text: str) -> None:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {value}")

        def gauge(name: str, value: float, help_text: str) -> None:
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")

        counter(
            "arhiax_correlator_poll_ticks_total",
            snap["ticks"],
            "Total successful poll iterations since process start.",
        )
        counter(
            "arhiax_correlator_poll_errors_total",
            snap["errors"],
            "Total failed poll iterations since process start.",
        )
        gauge(
            "arhiax_correlator_last_evidence_count",
            float(snap["last_count"]),
            "Number of records the evidence store reported on the last successful tick.",
        )
        gauge(
            "arhiax_correlator_last_records_seen",
            float(snap["last_records_seen"]),
            "Number of records returned by the last tail() call.",
        )
        gauge(
            "arhiax_correlator_seconds_since_last_tick",
            seconds_since_tick,
            "Seconds since the most recent poll iteration (-1 if none yet).",
        )
        gauge(
            "arhiax_correlator_uptime_seconds",
            uptime,
            "Process uptime in seconds.",
        )
        gauge(
            "arhiax_correlator_anomaly_threshold",
            snap["anomaly_threshold"],
            "Configured anomaly score threshold (informational; v1.0.0 stub does not score).",
        )

        body = "\n".join(lines) + "\n"
        self._write_text(200, body, "text/plain; version=0.0.4; charset=utf-8")


# ---------------------------------------------------------------------
# Builders — invoked from main.py
# ---------------------------------------------------------------------


def _make_handler_class(
    base: type[_BaseHandler],
    poller: Poller,
    version: str,
    logger: logging.Logger,
) -> type[_BaseHandler]:
    """Return a subclass of `base` with the per-instance state baked in
    as class attributes. http.server's BaseHTTPRequestHandler API does
    not let us pass constructor args, so attribute injection on a
    dynamically-created subclass is the standard workaround."""
    name = f"{base.__name__}_Bound"
    return type(
        name,
        (base,),
        {
            "poller": poller,
            "version": version,
            "arhiax_logger": logger,
        },
    )


def _start_in_thread(httpd: ThreadingHTTPServer, name: str) -> threading.Thread:
    t = threading.Thread(target=httpd.serve_forever, name=name, daemon=True)
    t.start()
    return t


def build_data_plane(
    port: int,
    poller: Poller,
    version: str,
    logger: logging.Logger,
) -> Tuple[ThreadingHTTPServer, threading.Thread]:
    handler_cls = _make_handler_class(DataPlaneHandler, poller, version, logger)
    httpd = ThreadingHTTPServer(("0.0.0.0", port), handler_cls)  # noqa: S104
    thread = _start_in_thread(httpd, "arhiax-correlator-data")
    logger.info("data plane listening", extra={"addr": f":{port}"})
    return httpd, thread


def build_metrics_plane(
    port: int,
    poller: Poller,
    version: str,
    logger: logging.Logger,
) -> Tuple[ThreadingHTTPServer, threading.Thread]:
    handler_cls = _make_handler_class(MetricsPlaneHandler, poller, version, logger)
    httpd = ThreadingHTTPServer(("0.0.0.0", port), handler_cls)  # noqa: S104
    thread = _start_in_thread(httpd, "arhiax-correlator-metrics")
    logger.info("metrics plane listening", extra={"addr": f":{port}"})
    return httpd, thread
