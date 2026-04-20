"""
ARHIAX v11.4 — Client Mode Selector
====================================

Single entry point for the ATK service to obtain its 6 external clients
based on ARHIAX_MODE:

    ARHIAX_MODE=development  (default) → InMemory* clients (fast, deterministic, no network)
    ARHIAX_MODE=production              → Hardened* clients (httpx + tenacity + breaker + prom)
    ARHIAX_MODE=shadow                  → Hardened* clients but all decisions are MONITORING-only

The ATK service factory should call `build_clients()` once at startup and
inject the resulting dict into the ATKService constructor. Business logic in
the ATK remains identical across modes — only the client implementations change.

Usage in arhiax_atk_service.py:

    from client_mode import build_clients, attest_clients
    clients = build_clients()
    atk = ATKService(
        aim=clients["aim"],
        opa=clients["opa"],
        aut=clients["aut"],
        bbr=clients["bbr"],
        ega=clients["ega"],
        hic=clients["hic"],
    )
    # ATK-C07 startup attestation
    await atk.record_startup_attestation(await attest_clients(clients))
"""

from __future__ import annotations

import logging
import os
from enum import Enum
from typing import Any, Dict

logger = logging.getLogger("arhiax.clients")


class ARHIAXMode(Enum):
    DEVELOPMENT = "development"
    PRODUCTION = "production"
    SHADOW = "shadow"


def get_mode() -> ARHIAXMode:
    raw = os.environ.get("ARHIAX_MODE", "development").lower().strip()
    try:
        return ARHIAXMode(raw)
    except ValueError:
        logger.warning(f"unknown ARHIAX_MODE={raw!r}, defaulting to development")
        return ARHIAXMode.DEVELOPMENT


def build_clients() -> Dict[str, Any]:
    """Build the 6 external clients for the ATK service.

    Returns a dict keyed by: aim, opa, aut, bbr, ega, hic

    Mode selection:
        development → InMemory* from arhiax_atk_service
        production  → Hardened* from hardened_clients
        shadow      → Hardened* but callers must flag decisions as monitoring-only
    """
    mode = get_mode()
    logger.info(f"building ATK clients in mode={mode.value}")

    if mode == ARHIAXMode.DEVELOPMENT:
        # Lazy import to avoid circular dependency and keep prod dependency graph clean
        from arhiax_atk_service import (
            InMemoryAIM,
            InMemoryOPA,
            InMemoryAUT,
            InMemoryBBR,
            InMemoryEGA,
            InMemoryHIC,
        )
        return {
            "aim": InMemoryAIM(),
            "opa": InMemoryOPA(),
            "aut": InMemoryAUT(),
            "bbr": InMemoryBBR(),
            "ega": InMemoryEGA(),
            "hic": InMemoryHIC(),
        }

    # Production and shadow both use hardened clients
    from hardened_clients import build_all_hardened_clients
    clients = build_all_hardened_clients()

    if mode == ARHIAXMode.SHADOW:
        logger.warning(
            "ARHIAX_MODE=shadow: decisions will be recorded but NOT enforced. "
            "The ATK service MUST set envelope.shadowMode=True on all outcomes."
        )

    return clients


async def attest_clients(clients: Dict[str, Any]) -> Dict[str, Any]:
    """Return ATK-C07 startup attestation for the configured clients.

    For in-memory clients, returns a trivial attestation document.
    For hardened clients, delegates to hardened_clients.attest_all_clients.
    """
    mode = get_mode()
    if mode == ARHIAXMode.DEVELOPMENT:
        return {
            "attestationType": "ATK-C07",
            "version": "11.4",
            "mode": "development",
            "clients": {
                name: {"type": client.__class__.__name__, "in_memory": True}
                for name, client in clients.items()
            },
        }

    from hardened_clients import attest_all_clients
    att = await attest_all_clients(clients)
    att["mode"] = mode.value
    return att


async def close_clients(clients: Dict[str, Any]) -> None:
    """Graceful shutdown. Safe to call for in-memory clients (no-op)."""
    mode = get_mode()
    if mode == ARHIAXMode.DEVELOPMENT:
        return
    from hardened_clients import close_all_clients
    await close_all_clients(clients)
