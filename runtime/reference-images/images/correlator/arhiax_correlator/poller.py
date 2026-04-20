"""
arhiax_correlator.poller — background loop that reads recent evidence
records on a fixed interval.

In v1.0.0 this is a STUB: the poll fetches the last N records from the
evidence store via /v1/evidence?limit=, increments a counter, and stores
the latest head hash in memory. No anomaly detection runs.

In v1.1+ this becomes the entry point for the D-TCG+ pipeline:

  fetch window  →  feature extraction (per modality)
                →  cross-modal Granger / behavioural baseline drift
                →  anomaly score
                →  if score > threshold: emit signal back to OPA via
                   bundle override or to a sidecar enforcement queue

The current shape — a thread that wakes on an interval, reads the
store, mutates simple counters under a lock — is the right shape for
the future implementation too. Only the body of `_tick` changes.

The poller never throws into the main thread. All exceptions are caught,
logged, counted in `errors`, and the loop continues. A correlator that
crashes on a single bad record would be operationally worse than one
that skips it and pages an SRE on a sustained error rate.
"""

from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from typing import Any


class Poller:
    """Periodic evidence store reader. Thread-safe; one instance per process."""

    def __init__(
        self,
        evidence_store_url: str,
        poll_interval_s: int,
        window_seconds: int,
        anomaly_threshold: float,
        logger: logging.Logger,
        http_timeout_s: float = 5.0,
    ) -> None:
        self._url = evidence_store_url.rstrip("/")
        self._interval = max(1, poll_interval_s)
        self._window = window_seconds
        self._threshold = anomaly_threshold
        self._logger = logger
        self._http_timeout = http_timeout_s

        # State protected by _lock. Read access from the HTTP /metrics
        # handler MUST acquire it.
        self._lock = threading.Lock()
        self._ticks: int = 0
        self._errors: int = 0
        self._last_head_hash: str = ""
        self._last_count: int = 0
        self._last_records_seen: int = 0
        self._last_tick_unix: float = 0.0
        self._started_unix: float = 0.0

        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Spawn the background thread. Idempotent: calling twice is a no-op."""
        if self._thread is not None:
            return
        self._started_unix = time.time()
        self._thread = threading.Thread(
            target=self._run,
            name="arhiax-correlator-poller",
            daemon=True,
        )
        self._thread.start()
        self._logger.info(
            "poller started",
            extra={
                "interval_s": self._interval,
                "window_s": self._window,
                "evidence_store_url": self._url,
            },
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the loop to exit and wait up to `timeout` seconds."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                self._logger.warning("poller thread did not stop in time")
            self._thread = None

    # ------------------------------------------------------------------
    # Loop body
    # ------------------------------------------------------------------

    def _run(self) -> None:
        """Main loop. Sleeps in small slices so SIGTERM is responsive."""
        # First tick happens immediately so the metrics show life as
        # soon as the pod is ready, instead of after `interval` seconds.
        self._tick()
        while not self._stop_event.is_set():
            # Sleep in 0.5s slices so we can react to stop within ~500ms
            # even when interval is 30s. The k8s grace period is finite.
            slept = 0.0
            while slept < self._interval and not self._stop_event.is_set():
                time.sleep(0.5)
                slept += 0.5
            if self._stop_event.is_set():
                break
            self._tick()

    def _tick(self) -> None:
        """One iteration of the poll loop. Never raises."""
        try:
            head = self._fetch_head()
            tail = self._fetch_tail(limit=100)
            with self._lock:
                self._ticks += 1
                self._last_head_hash = head.get("head_hash", "") or ""
                self._last_count = int(head.get("count", 0) or 0)
                self._last_records_seen = len(tail.get("records", []) or [])
                self._last_tick_unix = time.time()
            self._logger.debug(
                "poll tick",
                extra={
                    "head_hash": self._last_head_hash[:16] + "..."
                    if self._last_head_hash
                    else "",
                    "count": self._last_count,
                    "records_seen": self._last_records_seen,
                },
            )
        except Exception as e:  # noqa: BLE001 — see module doc
            with self._lock:
                self._errors += 1
                self._last_tick_unix = time.time()
            # Log at WARNING (not ERROR) because a transient evidence-
            # store outage is operationally normal during rolling
            # updates of the StatefulSet. Sustained errors will trip
            # the alert on rate(arhiax_correlator_poll_errors_total).
            self._logger.warning(
                "poll tick failed",
                extra={"error": str(e), "error_type": type(e).__name__},
            )

    # ------------------------------------------------------------------
    # HTTP helpers
    # ------------------------------------------------------------------

    def _fetch_head(self) -> dict[str, Any]:
        return self._get_json(self._url + "/v1/head")

    def _fetch_tail(self, limit: int) -> dict[str, Any]:
        return self._get_json(f"{self._url}/v1/evidence?limit={limit}")

    def _get_json(self, url: str) -> dict[str, Any]:
        """Stdlib HTTP GET → parsed JSON. Tight timeout."""
        req = urllib.request.Request(
            url,
            method="GET",
            headers={"Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self._http_timeout) as resp:
                if resp.status != 200:
                    raise RuntimeError(f"GET {url} returned status {resp.status}")
                body = resp.read()
        except urllib.error.URLError as e:
            raise RuntimeError(f"GET {url} failed: {e.reason}") from e
        try:
            data = json.loads(body)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"GET {url} returned non-JSON body") from e
        if not isinstance(data, dict):
            raise RuntimeError(f"GET {url} returned non-object body")
        return data

    # ------------------------------------------------------------------
    # Read-only views for the HTTP server
    # ------------------------------------------------------------------

    def snapshot(self) -> dict[str, Any]:
        """Return a copy of the current state. Safe to call from any thread.

        Used by /readyz and /metrics handlers."""
        with self._lock:
            return {
                "ticks": self._ticks,
                "errors": self._errors,
                "last_head_hash": self._last_head_hash,
                "last_count": self._last_count,
                "last_records_seen": self._last_records_seen,
                "last_tick_unix": self._last_tick_unix,
                "started_unix": self._started_unix,
                "interval_s": self._interval,
                "window_s": self._window,
                "anomaly_threshold": self._threshold,
            }

    def is_ready(self) -> bool:
        """The correlator is ready when at least one tick has completed,
        whether successfully or not. A pod that has never reached the
        evidence store should NOT be marked ready, because that means
        it cannot fulfill its purpose."""
        with self._lock:
            return self._ticks > 0 or self._errors > 0
