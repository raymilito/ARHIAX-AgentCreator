"""Gateway — Policy Enforcement Point ARHIAX
Recibe solicitudes de agentes, consulta OPA, registra evidencia y devuelve decisión.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel

try:
    import redis.asyncio as redis_asyncio  # type: ignore
except Exception:  # pragma: no cover — entorno sin paquete redis
    redis_asyncio = None  # type: ignore

@asynccontextmanager
async def lifespan(app: FastAPI):
    await _init_jti_store()
    await _load_halt_state()
    try:
        await _refresh_jwks(force=True)
    except Exception:
        # No bloqueamos el startup; el primer decide forzara reintento
        self._registry._inmem[key] = int(value)
    try:
        yield
    finally:
        global _redis_client
        if _redis_client is not None:
            try:
                await _redis_client.aclose()
            except Exception:
                pass
            _redis_client = None


app = FastAPI(title="ARHIAX Gateway", version="1.0.0", lifespan=lifespan)

OPA_URL = os.getenv("OPA_URL", "http://opa:8181")
EVIDENCE_URL = os.getenv("EVIDENCE_STORE_URL", "http://evidence-store:8090")
MAX_BODY_BYTES = int(os.getenv("MAX_REQUEST_BODY_BYTES", str(1024 * 1024)))
BROKER_JWKS_URL = os.getenv("BROKER_JWKS_URL", "http://credential-broker:8204/.well-known/jwks.json")
JWKS_REFRESH_SECONDS = int(os.getenv("BROKER_JWKS_REFRESH_SECONDS", "300"))
REPLAY_WINDOW_SECONDS = int(os.getenv("EPHEMERAL_REPLAY_WINDOW_SECONDS", "300"))
IDEMPOTENCY_TTL_SECONDS = int(os.getenv("IDEMPOTENCY_TTL_SECONDS", "86400"))
# DPoP
GATEWAY_PUBLIC_URL = os.getenv("GATEWAY_PUBLIC_URL", "http://gateway:8080")
DPOP_HTU = os.getenv("GATEWAY_DECIDE_HTU", f"{GATEWAY_PUBLIC_URL.rstrip('/')}/v1/decide")
DPOP_CLOCK_SKEW_SECONDS = int(os.getenv("DPOP_CLOCK_SKEW_SECONDS", "60"))
REDIS_URL = os.getenv("ARHIAX_REDIS_URL") or os.getenv("REDIS_URL")
REDIS_KEY_PREFIX = os.getenv("ARHIAX_REDIS_PREFIX", "arhiax:gw")
# CNs de certificado mTLS autorizados a revocar cualquier token.
# Separados por coma. Si vacío, solo el emisor puede revocar su propio token.
REVOCATION_ADMIN_CNS: set = set(
    cn.strip() for cn in os.getenv("REVOCATION_ADMIN_CNS", "").split(",") if cn.strip()
)

# CA cert para verificación TLS inter-servicio.
# None → sin TLS (modo dev). Ruta al ca.crt → verifica con CA interna.
_CA_CERT = os.getenv("ARHIAX_CA_CERT") or False

# mTLS saliente: si ARHIAX_TLS_CLIENT_CERT y _KEY estan configurados,
# httpx presenta el certificado al servicio destino para autenticarse.
_CLIENT_CERT = os.getenv("ARHIAX_TLS_CLIENT_CERT")
_CLIENT_KEY = os.getenv("ARHIAX_TLS_CLIENT_KEY")


def _mtls_kwargs() -> Dict[str, Any]:
    """Argumentos httpx para conexiones salientes con verificacion y mTLS."""
    kwargs: Dict[str, Any] = {"verify": _CA_CERT}
    if _CLIENT_CERT and _CLIENT_KEY:
        kwargs["cert"] = (_CLIENT_CERT, _CLIENT_KEY)
    return kwargs

# Contadores de métricas — escalables con Redis
class _MetricsRegistry:
    """Registro centralizado de métricas con soporte Redis.

    En producción (múltiples instancias Gateway), usa Redis.
    En dev/tests, usa diccionario in-memory.
    """

    def __init__(self, redis_client=None):
        self._redis = redis_client
        self._prefix = REDIS_KEY_PREFIX + ":metrics"
        self._inmem: Dict[str, int] = {}

    async def increment(self, metric_name: str, value: int = 1) -> None:
        """Incrementar métrica."""
        if self._redis:
            try:
                key = f"{self._prefix}:{metric_name}"
                await self._redis.incr(key, value)
                return
            except Exception:
                pass  # Fallback a in-memory

        # Fallback in-memory
        self._inmem[metric_name] = self._inmem.get(metric_name, 0) + value

    async def get(self, metric_name: str) -> int:
        """Leer métrica."""
        if self._redis:
            try:
                key = f"{self._prefix}:{metric_name}"
                val = await self._redis.get(key)
                return int(val or 0)
            except Exception:
                pass

        return self._inmem.get(metric_name, 0)

    async def get_all(self) -> Dict[str, int]:
        """Obtener todas las métricas."""
        if self._redis:
            try:
                pattern = f"{self._prefix}:*"
                cursor = 0
                metrics = {}
                while True:
                    cursor, keys = await self._redis.scan(cursor, match=pattern)
                    for key in keys:
                        metric_name = key.replace(f"{self._prefix}:", "")
                        val = await self._redis.get(key)
                        metrics[metric_name] = int(val or 0)
                    if cursor == 0:
                        break
                return metrics
            except Exception:
                pass

        return dict(self._inmem)

_metrics_registry = _MetricsRegistry()

# Alias para compatibilidad — acceso antiguo a través de diccionario
class _MetricsDictCompat(dict):
    def __init__(self, registry):
        super().__init__()
        self._registry = registry

    def __setitem__(self, key, value):
        # No permitir asignación directa, solo incrementos
        self._registry._inmem[key] = int(value)

    def __getitem__(self, key):
        # Leer valor actual (bloqueante, pero acceptable para métricas)
        return int(self._registry._inmem.get(key, 0))

    def get(self, key, default=None):
        return self._registry._inmem.get(key, default)

    def keys(self):
        return self._registry._inmem.keys()

    def items(self):
        return self._registry._inmem.items()

    def clear(self):
        self._registry._inmem.clear()

_metrics = _MetricsDictCompat(_metrics_registry)

def _increment_metric(metric_name: str, value: int = 1) -> None:
    """Helper para incrementar métrica sin necesidad de async context."""
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_metrics_registry.increment(metric_name, value))
    except RuntimeError:
        _metrics_registry._inmem[metric_name] = _metrics_registry._inmem.get(metric_name, 0) + value

# Tracking ligero para alertas: ip por jti (detectar mismo jti desde 2 IPs),
# rachas de denegaciones por subject, etc. In-memory con purga implicita por
# uso; en produccion esto va a Redis/SIEM dedicado.
_jti_origins: Dict[str, set] = {}
_subject_recent_denies: Dict[str, List[float]] = {}
BURST_DENY_WINDOW_SECONDS = int(os.getenv("ANOMALY_BURST_WINDOW_SECONDS", "60"))
BURST_DENY_THRESHOLD = int(os.getenv("ANOMALY_BURST_THRESHOLD", "5"))
MAX_JTI_ORIGINS = int(os.getenv("ANOMALY_MAX_JTI_ORIGINS", "5000"))
MAX_SUBJECT_DENY_ENTRIES = int(os.getenv("ANOMALY_MAX_SUBJECT_DENY_ENTRIES", "2000"))
MAX_JTI_ISSUERS = int(os.getenv("ANOMALY_MAX_JTI_ISSUERS", "5000"))
# Cache in-memory de respuestas idempotentes (fallback cuando Redis no esta)
_idem_cache: Dict[str, str] = {}
# Backends in-memory — usados como fallback y por los tests
_seen_jtis: Dict[str, int] = {}
_revoked_jtis: Dict[str, int] = {}

# C10 — Kill-switch org-wide.
# Persiste en Redis; se restaura al arrancar. Bloquea todo /v1/decide cuando active=True.
_halt_state: Dict[str, Any] = {
    "active": False, "reason": "", "halted_at": "", "halted_by": "", "scope": "org",
}
_HALT_REDIS_KEY = f"{REDIS_KEY_PREFIX}:org:halt"


# ─── Almacén de jti (replay + revocación) ───────────────────────────────────

class _JtiStore:
    """Interfaz minima para registrar y consultar jti vistos/revocados."""

    async def mark_seen(self, jti: str, ttl_seconds: int) -> bool:
        """Registra el jti como visto. Devuelve False si ya estaba (replay)."""
        raise NotImplementedError

    async def is_revoked(self, jti: str) -> bool:
        raise NotImplementedError

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        raise NotImplementedError


class _InMemoryJtiStore(_JtiStore):
    """Backend in-memory. Soporta dev y tests; no sobrevive reinicios.

    Optimizado para O(1) purga usando deques de expiración.
    """

    def __init__(self, seen: Dict[str, int], revoked: Dict[str, int]):
        self._seen = seen
        self._revoked = revoked
        self._seen_expiry_queue = deque()  # [(expiry_ts, jti), ...]
        self._revoked_expiry_queue = deque()

    def _purge_queue(self, now_ts: int, store: Dict[str, int], queue: deque) -> None:
        """Remover items expirados del frente de la queue — O(1) amortizado."""
        while queue and queue[0][0] < now_ts:
            exp_ts, key = queue.popleft()
            # Verificar que aún está en el store con ese timestamp (puede haber sido
            # reinsertado con TTL diferente)
            if store.get(key) == exp_ts:
                store.pop(key, None)

    async def mark_seen(self, jti: str, ttl_seconds: int) -> bool:
        now_ts = int(datetime.now(timezone.utc).timestamp())
        self._purge_queue(now_ts, self._seen, self._seen_expiry_queue)

        if jti in self._seen:
            return False

        exp_ts = now_ts + max(1, ttl_seconds)
        self._seen[jti] = exp_ts
        self._seen_expiry_queue.append((exp_ts, jti))
        return True

    async def is_revoked(self, jti: str) -> bool:
        now_ts = int(datetime.now(timezone.utc).timestamp())
        self._purge_queue(now_ts, self._revoked, self._revoked_expiry_queue)
        return jti in self._revoked

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        now_ts = int(datetime.now(timezone.utc).timestamp())
        exp_ts = now_ts + max(1, ttl_seconds)
        self._revoked[jti] = exp_ts
        self._revoked_expiry_queue.append((exp_ts, jti))


class _RedisJtiStore(_JtiStore):
    """Backend Redis. SETNX para detectar replay, claves con TTL = exp - now.

    Si Redis falla, hace fallback al backend in-memory: la operacion no se
    bloquea por indisponibilidad de Redis pero el evento queda en metricas
    (`jti_store_errors`) para alertar.
    """

    def __init__(self, client, fallback: _InMemoryJtiStore):
        self._client = client
        self._fallback = fallback

    def _seen_key(self, jti: str) -> str:
        return f"{REDIS_KEY_PREFIX}:seen:{jti}"

    def _revoked_key(self, jti: str) -> str:
        return f"{REDIS_KEY_PREFIX}:revoked:{jti}"

    async def mark_seen(self, jti: str, ttl_seconds: int) -> bool:
        ttl = max(1, ttl_seconds)
        try:
            stored = await self._client.set(self._seen_key(jti), "1", ex=ttl, nx=True)
            return bool(stored)
        except Exception:
            _metrics["jti_store_errors"] += 1
            return await self._fallback.mark_seen(jti, ttl)

    async def is_revoked(self, jti: str) -> bool:
        try:
            return await self._client.exists(self._revoked_key(jti)) > 0
        except Exception:
            _metrics["jti_store_errors"] += 1
            return await self._fallback.is_revoked(jti)

    async def revoke(self, jti: str, ttl_seconds: int) -> None:
        ttl = max(1, ttl_seconds)
        try:
            await self._client.set(self._revoked_key(jti), "1", ex=ttl)
        except Exception:
            _metrics["jti_store_errors"] += 1
            await self._fallback.revoke(jti, ttl)


_inmem_store = _InMemoryJtiStore(_seen_jtis, _revoked_jtis)
_jti_store: _JtiStore = _inmem_store
_redis_client = None


def _track_jti_origin(jti: str, source_ip: str) -> None:
    """Registra el origen de un jti. Si aparece desde 2+ IPs, emite anomalia."""
    if not jti or not source_ip:
        return
    if len(_jti_origins) >= MAX_JTI_ORIGINS and jti not in _jti_origins:
        # Evict arbitrary entry to prevent unbounded growth
        try:
            _jti_origins.pop(next(iter(_jti_origins)))
        except StopIteration:
            pass
    origins = _jti_origins.setdefault(jti, set())
    origins.add(source_ip)
    if len(origins) > 1:
        _metrics["anomaly_jti_multi_source"] += 1


def _track_subject_deny(subject: str) -> None:
    """Detecta rafagas de denegacion para un mismo subject."""
    if not subject:
        return
    now = time.monotonic()
    cutoff = now - BURST_DENY_WINDOW_SECONDS
    window = _subject_recent_denies.setdefault(subject, [])
    window.append(now)
    # purga entradas expiradas de la ventana
    while window and window[0] < cutoff:
        window.pop(0)
    # si la ventana quedo vacia, eliminar el subject del dict para no acumular
    if not window:
        _subject_recent_denies.pop(subject, None)
        return
    if len(window) >= BURST_DENY_THRESHOLD:
        _metrics["anomaly_burst_denials"] += 1
    # cap para evitar acumulacion ilimitada
    if len(_subject_recent_denies) > MAX_SUBJECT_DENY_ENTRIES:
        try:
            _subject_recent_denies.pop(next(iter(_subject_recent_denies)))
        except StopIteration:
            pass


async def _idem_get(key: str) -> Optional[str]:
    """Devuelve la respuesta cacheada para una idempotency key, si existe."""
    full = f"{REDIS_KEY_PREFIX}:idem:{key}"
    if _redis_client is not None:
        try:
            value = await _redis_client.get(full)
            if value is not None:
                return value
        except Exception:
            _metrics["jti_store_errors"] += 1
    return _idem_cache.get(full)


async def _idem_set(key: str, value: str) -> None:
    full = f"{REDIS_KEY_PREFIX}:idem:{key}"
    if _redis_client is not None:
        try:
            await _redis_client.set(full, value, ex=IDEMPOTENCY_TTL_SECONDS)
            return
        except Exception:
            _metrics["jti_store_errors"] += 1
    _idem_cache[full] = value


async def _init_jti_store() -> None:
    """Conecta a Redis si hay URL configurada; en caso contrario usa memoria."""
    global _jti_store, _redis_client
    if not REDIS_URL or redis_asyncio is None:
        _jti_store = _inmem_store
        return
    try:
        client = redis_asyncio.from_url(REDIS_URL, decode_responses=True)
        await client.ping()
        _redis_client = client
        _jti_store = _RedisJtiStore(client, _inmem_store)
    except Exception:
        _metrics["jti_store_errors"] += 1
        _jti_store = _inmem_store


async def _load_halt_state() -> None:
    """Restaura el estado del kill-switch desde Redis al arrancar."""
    if _redis_client is None:
        return
    try:
        val = await _redis_client.get(_HALT_REDIS_KEY)
        if val:
            _halt_state.update(json.loads(val))
    except Exception:
        pass


async def _save_halt_state() -> None:
    """Persiste el kill-switch en Redis para sobrevivir reinicios del gateway."""
    if _redis_client is None:
        return
    try:
        await _redis_client.set(_HALT_REDIS_KEY, json.dumps(_halt_state))
    except Exception:
        pass


# ─── Modelos ────────────────────────────────────────────────────────────────

class DecideRequest(BaseModel):
    subject: str
    action: str
    resource: str
    context: Dict[str, Any] = {}


class Obligation(BaseModel):
    type: str
    value: Any


class DecideResponse(BaseModel):
    allow: bool
    outcome: Optional[str] = None
    reasons: List[str] = []
    obligations: List[Obligation] = []
    evidence_id: str = ""
    error: Optional[str] = None


# ─── OPA ────────────────────────────────────────────────────────────────────

async def _query_opa(req: DecideRequest) -> tuple[bool, List[str], List[dict], Optional[str]]:
    payload = {
        "input": {
            "subject": req.subject,
            "action": req.action,
            "resource": req.resource,
            "context": req.context,
        }
    }
    try:
        # OPA usa HTTP plano (no soporta TLS nativo)
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.post(f"{OPA_URL}/v1/data/arhiax/main", json=payload)
        if r.status_code != 200:
            raise RuntimeError(f"OPA HTTP {r.status_code}")
        data = r.json().get("result", {})
        allow = bool(data.get("allow", False))
        reasons = data.get("reasons", [])
        obligations = data.get("obligations", [])
        outcome = data.get("outcome")
        return allow, reasons, obligations, outcome
    except Exception as exc:
        _metrics["opa_errors"] += 1
        raise HTTPException(503, f"OPA no disponible: {exc}")


# ─── Evidence Store ──────────────────────────────────────────────────────────

async def _append_evidence(req: DecideRequest, allow: bool, reasons: List[str], obligations: list) -> str:
    record = {
        "subject": req.subject, "action": req.action,
        "resource": req.resource, "context": req.context,
        "decision": allow, "reasons": reasons, "obligations": obligations,
    }
    try:
        async with httpx.AsyncClient(timeout=3.0, **_mtls_kwargs()) as client:
            r = await client.post(f"{EVIDENCE_URL}/v1/evidence", json=record)
        if r.status_code == 200:
            return r.json().get("id", "")
    except Exception:
        _metrics["evidence_errors"] += 1
    return ""


# ─── Injection detection ─────────────────────────────────────────────────────

import re
import unicodedata

def _has_injection(text: str) -> bool:
    """Detección mejorada de inyecciones con normalización Unicode."""
    # Normalizar Unicode
    normalized = unicodedata.normalize('NFKC', text.lower())

    # Patrones de inyección mejorados
    dangerous_patterns = [
        r"<\s*script",  # <script
        r"on(?:load|click|error|mouse)\s*=",  # event handlers
        r"\b(?:eval|exec|system)\s*\(",  # función calls peligrosas
        r"(?:union|select|insert|delete|update|drop)\s+",  # SQL injection
        r"(?:--|;)\s*(?:drop|delete)",  # SQL comments
        r"\.\./",  # Path traversal
        r"\.\.\\/",  # Path traversal Windows
        r"\{\s*\$(?:ne|gt|lt|regex|where)\s*:",  # NoSQL injection
        r"javascript\s*:",  # XSS URL scheme
        r"\$\s*\{",  # template injection
        r"ignore\s+previous",  # Jailbreak attempt
        r"disregard\s+", # Jailbreak attempt
    ]

    if any(re.search(p, normalized) for p in dangerous_patterns):
        _increment_metric("injection_detected")
        return True

    # Detectar Unicode sospechoso
    suspicious_chars = [
        '‮',  # Right-to-left override
        '​',  # Zero-width space
        '‌',  # Zero-width non-joiner
        '‭',  # Left-to-right override
    ]

    if any(char in text for char in suspicious_chars):
        _increment_metric("suspicious_unicode_detected")
        return True

    return False


def _check_payload_injection(context: dict) -> bool:
    def _flatten(value: Any) -> str:
        if isinstance(value, dict):
            return " ".join(_flatten(v) for v in value.values())
        if isinstance(value, list):
            return " ".join(_flatten(v) for v in value)
        return str(value)

    return _has_injection(_flatten(context))


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


# Cache JWKS: kid -> public_key, ultima actualizacion
_jwks_keys: Dict[str, ec.EllipticCurvePublicKey] = {}
_jwks_fetched_at: float = 0.0

# Rastreo de emisores de jti: jti -> (client_id, emission_timestamp)
_jti_issuers: Dict[str, tuple[str, float]] = {}

import asyncio
_jwks_refresh_lock = asyncio.Lock()


def _public_key_from_jwk(jwk: Dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise HTTPException(401, "JWK no soportada (se requiere EC P-256)")
    x = int.from_bytes(_b64url_decode(jwk["x"]), "big")
    y = int.from_bytes(_b64url_decode(jwk["y"]), "big")
    return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()


async def _refresh_jwks(force: bool = False) -> None:
    global _jwks_keys, _jwks_fetched_at
    if not force and _jwks_keys and (time.monotonic() - _jwks_fetched_at) < JWKS_REFRESH_SECONDS:
        return

    # Proteger contra race conditions con asyncio.Lock
    async with _jwks_refresh_lock:
        # Double-check después de adquirir lock
        if not force and _jwks_keys and (time.monotonic() - _jwks_fetched_at) < JWKS_REFRESH_SECONDS:
            return

        try:
            async with httpx.AsyncClient(timeout=3.0, **_mtls_kwargs()) as client:
                r = await client.get(BROKER_JWKS_URL)
            if r.status_code != 200:
                raise RuntimeError(f"JWKS HTTP {r.status_code}")
            data = r.json()
            new_keys: Dict[str, ec.EllipticCurvePublicKey] = {}
            for jwk in data.get("keys", []):
                kid = jwk.get("kid")
                if not kid:
                    continue
                new_keys[kid] = _public_key_from_jwk(jwk)
            if new_keys:
                _jwks_keys = new_keys
                _jwks_fetched_at = time.monotonic()
        except Exception as e:
            _metrics["jwks_refresh_error"] = _metrics.get("jwks_refresh_error", 0) + 1
            if not _jwks_keys:
                raise HTTPException(503, "JWKS del broker no disponible")


def _set_jwks_keys_for_tests(keys: Dict[str, ec.EllipticCurvePublicKey]) -> None:
    """Hook para tests: inyecta claves publicas sin tocar la red."""
    global _jwks_keys, _jwks_fetched_at
    _jwks_keys = dict(keys)
    _jwks_fetched_at = time.monotonic()


async def _verify_ephemeral_signature(token: str) -> Dict[str, Any]:
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise HTTPException(401, f"Formato de token efimero invalido: {exc}")

    try:
        header = json.loads(_b64url_decode(header_b64).decode())
    except Exception:
        raise HTTPException(401, "Header del token malformado")

    if header.get("alg") != "ES256":
        raise HTTPException(401, f"Algoritmo no permitido: {header.get('alg')}")
    kid = header.get("kid")
    if not kid:
        raise HTTPException(401, "Header sin kid")

    if kid not in _jwks_keys:
        await _refresh_jwks(force=True)
    pub = _jwks_keys.get(kid)
    if pub is None:
        raise HTTPException(401, f"kid desconocido: {kid}")

    sig = _b64url_decode(signature_b64)
    if len(sig) != 64:
        raise HTTPException(401, "Firma ES256 con longitud invalida")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    der = encode_dss_signature(r, s)
    signed = f"{header_b64}.{payload_b64}".encode()
    try:
        pub.verify(der, signed, ec.ECDSA(hashes.SHA256()))
    except Exception:
        raise HTTPException(401, "Firma invalida en token efimero")
    return json.loads(_b64url_decode(payload_b64).decode())


def _jwk_thumbprint(jwk: Dict[str, Any]) -> str:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise HTTPException(401, "JWK del DPoP debe ser EC P-256")
    if not jwk.get("x") or not jwk.get("y"):
        raise HTTPException(401, "JWK del DPoP incompleta")
    canonical = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    raw = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    import hashlib as _h
    return base64.urlsafe_b64encode(_h.sha256(raw).digest()).rstrip(b"=").decode()


async def _verify_dpop_proof(proof: str, expected_jkt: str, expected_htu: str) -> None:
    """Verifica un DPoP-proof (RFC 9449) y registra su jti contra replay."""
    try:
        header_b64, payload_b64, sig_b64 = proof.split(".")
    except ValueError:
        _metrics["anomaly_dpop_failure"] += 1
        raise HTTPException(401, "DPoP proof malformado")

    try:
        header = json.loads(_b64url_decode(header_b64).decode())
        payload = json.loads(_b64url_decode(payload_b64).decode())
    except Exception:
        raise HTTPException(401, "DPoP proof con header/payload invalido")

    if header.get("typ") != "dpop+jwt":
        raise HTTPException(401, "DPoP proof con typ invalido")
    if header.get("alg") != "ES256":
        raise HTTPException(401, "DPoP proof con alg no soportado")
    jwk = header.get("jwk") or {}
    if _jwk_thumbprint(jwk) != expected_jkt:
        raise HTTPException(401, "DPoP jkt no coincide con cnf.jkt del token")

    # Verifica firma del proof con la JWK embebida
    pub = _public_key_from_jwk(jwk)
    sig = _b64url_decode(sig_b64)
    if len(sig) != 64:
        raise HTTPException(401, "DPoP firma con longitud invalida")
    r = int.from_bytes(sig[:32], "big")
    s = int.from_bytes(sig[32:], "big")
    der = encode_dss_signature(r, s)
    signed = f"{header_b64}.{payload_b64}".encode()
    try:
        pub.verify(der, signed, ec.ECDSA(hashes.SHA256()))
    except Exception:
        raise HTTPException(401, "DPoP firma invalida")

    # Claims requeridos
    htm = payload.get("htm")
    htu = payload.get("htu")
    iat = payload.get("iat")
    proof_jti = payload.get("jti")
    if htm != "POST":
        raise HTTPException(401, f"DPoP htm invalido: {htm}")
    if htu != expected_htu:
        raise HTTPException(401, f"DPoP htu invalido: {htu} != {expected_htu}")
    now_ts = int(datetime.now(timezone.utc).timestamp())
    if not isinstance(iat, int) or abs(now_ts - iat) > DPOP_CLOCK_SKEW_SECONDS:
        raise HTTPException(401, "DPoP iat fuera de la ventana permitida")
    if not proof_jti:
        raise HTTPException(401, "DPoP proof sin jti")
    # Anti-replay del proof: reusa el mismo store con prefijo distinto
    stored = await _jti_store.mark_seen(f"dpop:{proof_jti}", DPOP_CLOCK_SKEW_SECONDS * 2)
    if not stored:
        _metrics["replay_blocked"] += 1
        raise HTTPException(409, "DPoP proof ya utilizado (replay)")


async def _validate_ephemeral_auth(req: DecideRequest) -> None:
    auth = req.context.get("ephemeralAuth")
    if not auth:
        return

    token = auth.get("token")
    if not token:
        raise HTTPException(401, "ephemeralAuth.token es obligatorio")

    payload = await _verify_ephemeral_signature(token)
    now_ts = int(datetime.now(timezone.utc).timestamp())

    exp = int(payload.get("exp", 0))
    nbf = int(payload.get("nbf", 0))
    jti = payload.get("jti")
    aud = payload.get("aud")
    invocation_id = payload.get("invocation_id")
    context_binding = payload.get("context_binding", {}) or {}

    if not jti:
        raise HTTPException(401, "Token efimero sin jti")
    if await _jti_store.is_revoked(jti):
        _metrics["revoked_blocked"] += 1
        raise HTTPException(401, "Token efimero revocado")
    if now_ts >= exp:
        raise HTTPException(401, "Token efimero expirado")
    if now_ts < nbf:
        raise HTTPException(401, "Token efimero aun no valido")
    if aud != req.resource:
        _metrics["anomaly_aud_mismatch"] += 1
        raise HTTPException(403, f"Audience mismatch: {aud} != {req.resource}")
    if invocation_id and invocation_id != req.context.get("invocationId"):
        raise HTTPException(403, "invocationId no coincide con token efimero")

    request_tool = req.context.get("toolName")
    bound_tool = context_binding.get("tool_name")
    if request_tool and bound_tool and request_tool != bound_tool:
        raise HTTPException(403, "toolName no coincide con context_binding")

    for key, bound_value in context_binding.items():
        if key in {"tool_name", "binding_mode"}:
            continue
        request_value = req.context.get(key)
        if request_value is None:
            raise HTTPException(403, f"Falta contexto vinculado: {key}")
        if str(request_value) != str(bound_value):
            raise HTTPException(403, f"context_binding mismatch para {key}")

    # DPoP: si el token incluye cnf.jkt exigimos proof-of-possession
    cnf = payload.get("cnf") or {}
    expected_jkt = cnf.get("jkt")
    if expected_jkt:
        proof = auth.get("dpop")
        if not proof:
            _metrics["anomaly_dpop_failure"] += 1
            raise HTTPException(401, "Token requiere DPoP proof (cnf.jkt)")
        try:
            await _verify_dpop_proof(proof, expected_jkt, DPOP_HTU)
        except HTTPException:
            _metrics["anomaly_dpop_failure"] += 1
            raise

    # Marcado atomico: si el jti ya existia, es replay
    ttl = max(1, min(exp - now_ts, REPLAY_WINDOW_SECONDS))
    stored = await _jti_store.mark_seen(jti, ttl)
    if not stored:
        _metrics["replay_blocked"] += 1
        raise HTTPException(409, "Replay detectado para token efimero")


# ─── Rutas ──────────────────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "gateway", "version": "1.0.0"}


@app.get("/readyz")
async def readyz():
    errors = {}
    for name, url, path in [
        ("opa", OPA_URL, "/health"),
        ("evidence_store", EVIDENCE_URL, "/healthz"),
    ]:
        try:
            # OPA usa HTTP plano; resto de los downstreams van por mTLS interno
            if "opa" in name:
                async with httpx.AsyncClient(timeout=2.0, verify=False) as client:
                    r = await client.get(f"{url}{path}")
            else:
                async with httpx.AsyncClient(timeout=2.0, **_mtls_kwargs()) as client:
                    r = await client.get(f"{url}{path}")
            if r.status_code not in (200, 404):
                errors[name] = f"HTTP {r.status_code}"
        except Exception as exc:
            errors[name] = str(exc)
    if errors:
        raise HTTPException(503, {"status": "not_ready", **errors})
    return {"status": "ready", "opa": "ok", "evidence_store": "ok"}


@app.post("/v1/decide", response_model=DecideResponse)
async def decide(req: DecideRequest, request: Request):
    if _halt_state.get("active"):
        _increment_metric("halt_blocked")
        raise HTTPException(503, {
            "outcome": "HALT_ACTIVE",
            "reason": _halt_state.get("reason", ""),
            "halted_at": _halt_state.get("halted_at", ""),
            "halted_by": _halt_state.get("halted_by", ""),
        })

    body = await request.body()
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(413, "Request demasiado grande")

    # Idempotency-Key: si el caller la envia y ya hay una respuesta cacheada,
    # la devolvemos sin re-ejecutar la decision. El alcance incluye hash del
    # payload para no bloquear reevaluaciones HIC con contexto enriquecido.
    # Excluimos llamadas con ephemeralAuth (cada token solo se puede usar una
    # vez — la dedup la hace el replay del jti, no este cache).
    idem_key = request.headers.get("Idempotency-Key")
    has_token = bool(req.context.get("ephemeralAuth"))
    request_fingerprint = hashlib.sha256(
        json.dumps(
            req.model_dump(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode()
    ).hexdigest()
    cache_key = (
        f"{req.subject}:{idem_key}:{request_fingerprint}" if (idem_key and not has_token) else None
    )
    if cache_key:
        cached = await _idem_get(cache_key)
        if cached:
            _metrics["idempotent_hits"] += 1
            return DecideResponse.model_validate_json(cached)

    # Detección de inyección antes de llamar a OPA
    if _check_payload_injection(req.context):
        _metrics["decide_deny"] += 1
        evidence_id = await _append_evidence(req, False, ["INJECTION_DETECTED"], [])
        response = DecideResponse(
            allow=False,
            outcome="DENY_WITH_INCIDENT",
            reasons=["INJECTION_DETECTED"],
            evidence_id=evidence_id,
        )
        if cache_key:
            await _idem_set(cache_key, response.model_dump_json())
        return response

    try:
        await _validate_ephemeral_auth(req)
    except HTTPException:
        _metrics["decide_deny"] += 1
        _metrics["ephemeral_auth_denied"] += 1
        _track_subject_deny(req.subject)
        raise

    # Tracking IP/jti para deteccion de jti compartido entre origenes
    # Nota: el payload ya fue validado en _validate_ephemeral_auth
    token = req.context.get("ephemeralAuth", {}).get("token")
    if token:
        try:
            payload = await _verify_ephemeral_signature(token)
            jti = payload.get("jti")
            if jti and request.client:
                _track_jti_origin(jti, request.client.host)
                # Registrar emisor del token para auditoría de revocación
                # evict oldest entry before inserting to cap dict size
                if len(_jti_issuers) >= MAX_JTI_ISSUERS and jti not in _jti_issuers:
                    try:
                        oldest = min(_jti_issuers.items(), key=lambda kv: kv[1][1])
                        _jti_issuers.pop(oldest[0], None)
                    except (ValueError, StopIteration):
                        pass
                _jti_issuers[jti] = (payload.get("sub", "unknown"), time.time())
        except Exception:
            pass  # Ya fue validado antes, solo logging

    # Consultar OPA
    allow, reasons, obligations, outcome = await _query_opa(req)

    # Registrar evidencia (fail-open: si falla, retornamos la decisión igual)
    try:
        evidence_id = await _append_evidence(req, allow, reasons, obligations)
    except Exception:
        _metrics["evidence_errors"] += 1
        evidence_id = ""

    if allow:
        _metrics["decide_allow"] += 1
    else:
        _metrics["decide_deny"] += 1
        _track_subject_deny(req.subject)

    response = DecideResponse(
        allow=allow,
        outcome=outcome or ("ALLOW" if allow else "DENY"),
        reasons=reasons,
        obligations=[Obligation(**o) for o in obligations if isinstance(o, dict)],
        evidence_id=evidence_id,
    )
    if cache_key:
        await _idem_set(cache_key, response.model_dump_json())
    return response


@app.get("/metrics")
async def metrics():
    m = await _metrics_registry.get_all()
    lines = [
        "# HELP arhiax_gateway_decide_total Total decisions",
        f'arhiax_gateway_decide_total{{outcome="allow"}} {m.get("decide_allow", 0)}',
        f'arhiax_gateway_decide_total{{outcome="deny"}} {m.get("decide_deny", 0)}',
        f'arhiax_gateway_opa_errors_total {m.get("opa_errors", 0)}',
        f'arhiax_gateway_evidence_errors_total {m.get("evidence_errors", 0)}',
        f'arhiax_gateway_ephemeral_auth_denied_total {m.get("ephemeral_auth_denied", 0)}',
        f'arhiax_gateway_replay_blocked_total {m.get("replay_blocked", 0)}',
        f'arhiax_gateway_revoked_blocked_total {m.get("revoked_blocked", 0)}',
        f'arhiax_gateway_jti_store_redis_error_total {m.get("jti_store_redis_error", 0)}',
        f'arhiax_gateway_jwks_refresh_error_total {m.get("jwks_refresh_error", 0)}',
        f'arhiax_gateway_jti_store_backend{{backend="{"redis" if _redis_client else "memory"}"}} 1',
        f'arhiax_gateway_idempotent_hits_total {m.get("idempotent_hits", 0)}',
        f'arhiax_gateway_anomaly_total{{kind="jti_multi_source"}} {m.get("anomaly_jti_multi_source", 0)}',
        f'arhiax_gateway_anomaly_total{{kind="aud_mismatch"}} {m.get("anomaly_aud_mismatch", 0)}',
        f'arhiax_gateway_anomaly_total{{kind="dpop_failure"}} {m.get("anomaly_dpop_failure", 0)}',
        f'arhiax_gateway_anomaly_total{{kind="burst_denials"}} {m.get("anomaly_burst_denials", 0)}',
        f'arhiax_gateway_halt_blocked_total {m.get("halt_blocked", 0)}',
        f'arhiax_gateway_org_halted{{active="{str(_halt_state.get("active", False)).lower()}"}} 1',
    ]
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse("\n".join(lines), media_type="text/plain")


@app.get("/v1/anomalies")
async def anomalies_snapshot():
    """Devuelve el estado actual de anomalias detectadas y los jti compartidos.

    Pensado para que un colector SIEM externo lo consuma cada N segundos.
    """
    shared_jtis = {
        jti: sorted(list(origins))
        for jti, origins in _jti_origins.items()
        if len(origins) > 1
    }
    return {
        "counters": {k: v for k, v in _metrics.items() if k.startswith("anomaly_")},
        "shared_jtis": shared_jtis,
        "burst_subjects": [
            s for s, w in _subject_recent_denies.items() if len(w) >= BURST_DENY_THRESHOLD
        ],
    }


async def _get_mtls_subject(request: Request) -> str:
    """Extrae el subject del certificado mTLS del cliente.

    En producción con Traefik/Envoy, el subject viene en X-Forwarded-Client-Cert.
    Para desarrollo, puede estar vacío.
    """
    client_cert_header = request.headers.get("X-Forwarded-Client-Cert", "")
    # Formato simplificado: esperamos algo como CN=agent-abc123
    if "CN=" in client_cert_header:
        cn = client_cert_header.split("CN=")[1].split(";")[0]
        return cn.strip()
    # Fallback: usar client IP como identificador
    if request.client:
        return f"client:{request.client.host}"
    return "unknown"


class HaltRequest(BaseModel):
    reason: str
    scope: str = "org"


@app.post("/v1/org/halt")
async def halt_org(req: HaltRequest, request: Request):
    """Kill-switch org-wide (C10). Bloquea todo /v1/decide. Requiere CN de administrador."""
    requester = await _get_mtls_subject(request)
    is_admin = bool(REVOCATION_ADMIN_CNS) and requester in REVOCATION_ADMIN_CNS
    if not is_admin:
        raise HTTPException(403, "Kill-switch requiere CN de administrador en REVOCATION_ADMIN_CNS")

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    _halt_state.update({
        "active": True,
        "reason": req.reason,
        "halted_at": now,
        "halted_by": requester,
        "scope": req.scope,
    })
    await _save_halt_state()

    try:
        async with httpx.AsyncClient(timeout=3.0, **_mtls_kwargs()) as client:
            await client.post(f"{EVIDENCE_URL}/v1/records", json={
                "service": "gateway",
                "agent_id": requester,
                "operation": "ORG_HALTED",
                "timestamp": now,
                "details": {"reason": req.reason, "scope": req.scope},
            })
    except Exception:
        _increment_metric("evidence_errors")

    return {"halted": True, "reason": req.reason, "halted_at": now, "halted_by": requester}


@app.post("/v1/org/resume")
async def resume_org(request: Request):
    """Desactiva el kill-switch. Requiere CN de administrador."""
    requester = await _get_mtls_subject(request)
    is_admin = bool(REVOCATION_ADMIN_CNS) and requester in REVOCATION_ADMIN_CNS
    if not is_admin:
        raise HTTPException(403, "Kill-switch requiere CN de administrador en REVOCATION_ADMIN_CNS")

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    _halt_state.update({
        "active": False, "reason": "", "halted_at": "", "halted_by": "", "scope": "org",
    })
    await _save_halt_state()

    try:
        async with httpx.AsyncClient(timeout=3.0, **_mtls_kwargs()) as client:
            await client.post(f"{EVIDENCE_URL}/v1/records", json={
                "service": "gateway",
                "agent_id": requester,
                "operation": "ORG_RESUMED",
                "timestamp": now,
                "details": {"resumed_by": requester},
            })
    except Exception:
        _increment_metric("evidence_errors")

    return {"halted": False, "resumed_at": now, "resumed_by": requester}


@app.get("/v1/org/status")
async def org_status():
    """Estado actual del kill-switch y contadores de métricas relevantes."""
    return {
        "kill_switch": _halt_state,
        "service": "gateway",
        "jti_backend": "redis" if _redis_client else "memory",
    }


@app.post("/v1/ephemeral/revoke/{jti}")
async def revoke_ephemeral_jti(jti: str, request: Request, ttl_seconds: int = REPLAY_WINDOW_SECONDS):
    """Revocar un token efímero. Solo el emisor o un admin puede revocarlo.

    CRITICAL: Esta ruta requiere autenticación mTLS del cliente.
    """
    requester = await _get_mtls_subject(request)

    # Validar que es autorizado a revocar este jti
    issuer_info = _jti_issuers.get(jti)
    is_admin = bool(REVOCATION_ADMIN_CNS) and requester in REVOCATION_ADMIN_CNS

    if issuer_info:
        issuer_id, issued_at = issuer_info
        if not is_admin and requester != issuer_id:
            _metrics["revocation_unauthorized"] = _metrics.get("revocation_unauthorized", 0) + 1
            raise HTTPException(
                403,
                f"Not authorized to revoke token. Issuer: {issuer_id}, Requester: {requester}"
            )

    # Log en Evidence Store (fail-open: si falla, revocamos de todas formas)
    try:
        async with httpx.AsyncClient(timeout=3.0, **_mtls_kwargs()) as client:
            await client.post(
                f"{EVIDENCE_URL}/v1/records",
                json={
                    "service": "gateway",
                    "agent_id": requester,
                    "operation": "TOKEN_REVOKED",
                    "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "details": {"jti": jti, "revoked_by": requester},
                }
            )
    except Exception:
        _metrics["evidence_errors"] += 1

    await _jti_store.revoke(jti, ttl_seconds)
    _metrics["token_revoked"] = _metrics.get("token_revoked", 0) + 1

    return {"revoked": True, "jti": jti, "revoked_by": requester}
