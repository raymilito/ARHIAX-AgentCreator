"""Credential Broker ARHIAX.

Emite credenciales efimeras por accion para herramientas y servicios
sin exponer tokens amplios al agente o al modelo.

Firma con ES256 (clave EC P-256) y expone JWKS publica en
`/.well-known/jwks.json` para que el gateway verifique sin compartir
secretos simetricos.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

app = FastAPI(title="ARHIAX Credential Broker", version="1.1.0")

DEFAULT_TTL_SECONDS = int(os.getenv("BROKER_DEFAULT_TTL_SECONDS", "60"))
MAX_TTL_SECONDS = int(os.getenv("BROKER_MAX_TTL_SECONDS", "300"))
SIGNING_KEY_PATH = os.getenv("BROKER_SIGNING_KEY_PATH", "/data/broker_signing_key.pem")
KEY_PERSIST = os.getenv("BROKER_PERSIST_KEY", "true").lower() not in {"0", "false", "no"}
AIM_URL = os.getenv("AIM_URL", "http://aim-service:8200")
_CA_CERT = os.getenv("ARHIAX_CA_CERT") or False
_CLIENT_CERT = os.getenv("ARHIAX_TLS_CLIENT_CERT")
_CLIENT_KEY = os.getenv("ARHIAX_TLS_CLIENT_KEY")
REQUIRE_SIGNED_AGENT_PROOF = os.getenv(
    "BROKER_REQUIRE_SIGNED_AGENT_PROOF", "false"
).lower() in {"1", "true", "yes"}
AGENT_PROOF_MAX_SKEW_SECONDS = int(os.getenv("BROKER_AGENT_PROOF_MAX_SKEW_SECONDS", "60"))


def _mtls_kwargs() -> dict:
    kwargs = {"verify": _CA_CERT}
    if _CLIENT_CERT and _CLIENT_KEY:
        kwargs["cert"] = (_CLIENT_CERT, _CLIENT_KEY)
    return kwargs


# ─── Modelos ────────────────────────────────────────────────────────────────

class ToolTokenRequest(BaseModel):
    agent_id: str
    tool_name: str
    audience: str
    scope: str
    invocation_id: str
    context_binding: Dict[str, str] = Field(default_factory=dict)
    ttl_seconds: int = DEFAULT_TTL_SECONDS
    requested_autonomy_level: str = "A1"
    # JWK publica del cliente para proof-of-possession (DPoP, RFC 9449).
    # Si se provee el token incorpora cnf.jkt = thumbprint(jwk).
    dpop_jwk: Optional[Dict[str, str]] = None
    # Cadena de delegacion para inter-agent calls (RFC 8693 token exchange).
    # `act_chain[0]` es el delegador mas reciente; el claim `act` del JWT se
    # serializa anidado.
    act_chain: Optional[list[str]] = None
    # Prueba de posesion de la credencial AIM del agente. No se serializa al JWT.
    agent_credential_hmac: Optional[str] = None
    # Prueba firmada por request. Evita transportar el parent_chain_hmac crudo.
    # signature = HMAC-SHA256(parent_chain_hmac, canonical_request)
    agent_credential_proof: Optional[Dict[str, str]] = None


class ToolTokenResponse(BaseModel):
    token: str
    token_type: str = "DPoP"
    expires_at: str
    issued_at: str
    jti: str
    audience: str
    scope: str
    resource: str
    invocation_id: str
    context_binding: Dict[str, str]
    proof_key_id: str
    delegated_by: str
    kid: str


# ─── Clave de firma ES256 ────────────────────────────────────────────────────

def _load_or_create_signing_key() -> ec.EllipticCurvePrivateKey:
    """Carga la clave EC P-256 desde disco o genera una nueva si no existe.

    Para tests/dev sin volumen persistente, `BROKER_PERSIST_KEY=false` evita
    el intento de escritura y mantiene la clave solo en memoria.
    """
    path = Path(SIGNING_KEY_PATH)
    if KEY_PERSIST and path.exists():
        with open(path, "rb") as fh:
            return serialization.load_pem_private_key(fh.read(), password=None)

    key = ec.generate_private_key(ec.SECP256R1())
    if KEY_PERSIST:
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            pem = key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            with open(path, "wb") as fh:
                fh.write(pem)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except OSError:
            # Sin volumen escribible (dev/tests) mantenemos la clave en memoria
            pass
    return key


_PRIVATE_KEY = _load_or_create_signing_key()
_PUBLIC_KEY = _PRIVATE_KEY.public_key()


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _b64u_uint(n: int, byte_len: int = 32) -> str:
    return _b64u(n.to_bytes(byte_len, "big"))


def _compute_kid(pub: ec.EllipticCurvePublicKey) -> str:
    """kid = thumbprint RFC 7638 truncado a 16 hex chars."""
    nums = pub.public_numbers()
    jwk_min = {
        "crv": "P-256",
        "kty": "EC",
        "x": _b64u_uint(nums.x),
        "y": _b64u_uint(nums.y),
    }
    raw = json.dumps(jwk_min, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(raw).hexdigest()[:16]


def _validate_p256_coordinate(coord_b64u: str) -> bool:
    """Valida que una coordenada P-256 (x o y) este dentro del rango valido.

    P-256 field prime: p = 2^256 - 2^224 + 2^192 + 2^128 - 1
    Las coordenadas deben estar en el rango [0, p).
    """
    try:
        # Decodifica base64url; agrega padding si es necesario
        padding = 4 - (len(coord_b64u) % 4)
        padded = coord_b64u + ("=" * padding if padding < 4 else "")
        coord_bytes = base64.urlsafe_b64decode(padded)
        if len(coord_bytes) != 32:
            return False
        coord = int.from_bytes(coord_bytes, "big")
        # P-256 field prime
        p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
        return 0 <= coord < p
    except (ValueError, Exception):
        return False


def _jwk_thumbprint(jwk: Dict[str, str]) -> str:
    """SHA-256 thumbprint RFC 7638 b64url de la JWK publica del cliente."""
    required = sorted({"crv", "kty", "x", "y"}.intersection(jwk.keys()))
    if set(required) != {"crv", "kty", "x", "y"}:
        raise HTTPException(400, "JWK incompleta para thumbprint DPoP")
    if jwk.get("crv") != "P-256":
        raise HTTPException(400, "Solo P-256 soportado para DPoP")
    if not _validate_p256_coordinate(jwk["x"]):
        raise HTTPException(400, "Coordenada x de P-256 invalida")
    if not _validate_p256_coordinate(jwk["y"]):
        raise HTTPException(400, "Coordenada y de P-256 invalida")
    canonical = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
    raw = json.dumps(canonical, separators=(",", ":"), sort_keys=True).encode()
    return _b64u(hashlib.sha256(raw).digest())


_KID = _compute_kid(_PUBLIC_KEY)
_proof_nonces: Dict[str, int] = {}
MAX_NONCE_CACHE_SIZE = int(os.getenv("BROKER_MAX_NONCE_CACHE_SIZE", "10000"))
NONCE_TTL_SECONDS = int(os.getenv("BROKER_NONCE_TTL_SECONDS", "120"))


def _public_jwk() -> dict:
    nums = _PUBLIC_KEY.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64u_uint(nums.x),
        "y": _b64u_uint(nums.y),
        "alg": "ES256",
        "use": "sig",
        "kid": _KID,
    }


def _encode_segment(value: dict) -> str:
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return _b64u(raw)


def _sign_es256(unsigned: bytes) -> bytes:
    der = _PRIVATE_KEY.sign(unsigned, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def _canonical_agent_proof_message(req: ToolTokenRequest, nonce: str, issued_at: str) -> str:
    binding = json.dumps(req.context_binding, separators=(",", ":"), sort_keys=True)
    return "|".join([
        req.agent_id,
        req.tool_name,
        req.audience,
        req.scope,
        req.invocation_id,
        str(req.ttl_seconds),
        req.requested_autonomy_level,
        binding,
        nonce,
        issued_at,
    ])


def _cleanup_proof_nonces(now_ts: int) -> None:
    """Limpia nonces expirados y aplica LRU si se excede el tamano maximo."""
    expired = [nonce for nonce, exp in _proof_nonces.items() if exp <= now_ts]
    for nonce in expired:
        _proof_nonces.pop(nonce, None)
    if len(_proof_nonces) > MAX_NONCE_CACHE_SIZE:
        oldest = min(_proof_nonces.items(), key=lambda x: x[1])
        _proof_nonces.pop(oldest[0], None)


def _validate_signed_agent_proof(req: ToolTokenRequest, expected_hmac: str) -> bool:
    proof = req.agent_credential_proof or {}
    nonce = proof.get("nonce", "")
    issued_at_raw = proof.get("issued_at", "")
    signature = proof.get("signature", "")
    if not nonce or not issued_at_raw or not signature:
        return False

    try:
        issued_at = int(issued_at_raw)
    except ValueError:
        return False
    now_ts = int(_utc_now().timestamp())
    if abs(now_ts - issued_at) > AGENT_PROOF_MAX_SKEW_SECONDS:
        return False

    _cleanup_proof_nonces(now_ts)
    nonce_key = f"{req.agent_id}:{nonce}"
    if nonce_key in _proof_nonces:
        raise HTTPException(409, "Prueba de credencial AIM reutilizada")

    message = _canonical_agent_proof_message(req, nonce, issued_at_raw)
    expected_signature = hmac.new(
        expected_hmac.encode(), message.encode(), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        return False

    _proof_nonces[nonce_key] = now_ts + NONCE_TTL_SECONDS
    return True


# ─── Emision ────────────────────────────────────────────────────────────────

def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


async def _load_agent_credential(agent_id: str) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(timeout=3.0, **_mtls_kwargs()) as client:
            response = await client.get(f"{AIM_URL.rstrip('/')}/v1/credentials/{agent_id}")
        if response.status_code == 404:
            raise HTTPException(403, "Agente no registrado en AIM")
        response.raise_for_status()
        return response.json()
    except HTTPException:
        raise
    except httpx.HTTPStatusError as exc:
        raise HTTPException(502, f"AIM rechazo la consulta de credencial: HTTP {exc.response.status_code}")
    except httpx.HTTPError as exc:
        raise HTTPException(502, f"AIM no disponible para autorizar emision: {exc}")


def _expected_operation(req: ToolTokenRequest) -> str:
    return "interAgentCall" if req.scope.startswith("agent:invoke:") else "toolCall"


def _validate_scope_binding(req: ToolTokenRequest) -> None:
    if req.scope.startswith("tool:execute:"):
        expected = f"tool:execute:{req.tool_name}"
        if req.scope != expected or req.audience != req.tool_name:
            raise HTTPException(403, "Scope/audience no coincide con la herramienta solicitada")
        return

    if req.scope.startswith("agent:invoke:"):
        target_agent = req.scope.removeprefix("agent:invoke:")
        expected_audience = f"agent:{target_agent}"
        if req.tool_name != expected_audience or req.audience != expected_audience:
            raise HTTPException(403, "Scope/audience no coincide con el agente destino")
        return

    raise HTTPException(403, "Scope no permitido para emision efimera")


async def _authorize_tool_token(req: ToolTokenRequest) -> None:
    _validate_scope_binding(req)
    credential = await _load_agent_credential(req.agent_id)

    if credential.get("lifecycle_state") not in {"ACTIVE", "ROTATING"}:
        raise HTTPException(403, "Credencial AIM no esta activa")

    expected_hmac = credential.get("parent_chain_hmac") or ""
    if not expected_hmac:
        raise HTTPException(401, "Prueba de credencial AIM requerida")

    signed_ok = _validate_signed_agent_proof(req, expected_hmac)
    if not signed_ok:
        if REQUIRE_SIGNED_AGENT_PROOF:
            raise HTTPException(401, "Prueba firmada de credencial AIM requerida")
        if not req.agent_credential_hmac:
            raise HTTPException(401, "Prueba de credencial AIM requerida")
        if not hmac.compare_digest(req.agent_credential_hmac, expected_hmac):
            raise HTTPException(401, "Prueba de credencial AIM invalida")

    operation = _expected_operation(req)
    permitted_operations = credential.get("permitted_operations") or []
    if operation not in permitted_operations and "*" not in permitted_operations:
        raise HTTPException(403, f"Operacion no autorizada para el agente: {operation}")

    if operation == "toolCall":
        permitted_tools = credential.get("permitted_tools") or []
        if req.tool_name not in permitted_tools and "*" not in permitted_tools:
            raise HTTPException(403, f"Herramienta no autorizada para el agente: {req.tool_name}")


def _mint_ephemeral_token(req: ToolTokenRequest) -> ToolTokenResponse:
    ttl = max(1, min(req.ttl_seconds, MAX_TTL_SECONDS))
    issued_at = _utc_now()
    expires_at = issued_at + timedelta(seconds=ttl)
    jti = f"jti-{uuid.uuid4().hex}"
    proof_key_id = f"pop-{hashlib.sha256(f'{req.agent_id}:{req.tool_name}'.encode()).hexdigest()[:16]}"

    cnf: Dict[str, str] = {"kid": proof_key_id}
    if req.dpop_jwk:
        cnf["jkt"] = _jwk_thumbprint(req.dpop_jwk)

    # Construye `act` segun RFC 8693:
    #   - delegacion simple: act = agent_id (str)
    #   - cadena: act = {"sub": A, "act": {"sub": B, ...}}
    if req.act_chain:
        act_claim: Any = None
        for actor in reversed(req.act_chain):
            act_claim = {"sub": actor, "act": act_claim} if act_claim else {"sub": actor}
    else:
        act_claim = req.agent_id

    payload = {
        "iss": "arhiax-credential-broker",
        "sub": req.agent_id,
        "act": act_claim,
        "aud": req.audience,
        "scope": req.scope,
        "jti": jti,
        "iat": int(issued_at.timestamp()),
        "nbf": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "cnf": cnf,
        "tool_name": req.tool_name,
        "invocation_id": req.invocation_id,
        "context_binding": req.context_binding,
        "requested_autonomy_level": req.requested_autonomy_level,
    }
    header = {"alg": "ES256", "typ": "JWT", "kid": _KID}
    unsigned = f"{_encode_segment(header)}.{_encode_segment(payload)}"
    sig = _sign_es256(unsigned.encode())
    token = f"{unsigned}.{_b64u(sig)}"
    return ToolTokenResponse(
        token=token,
        expires_at=expires_at.isoformat().replace("+00:00", "Z"),
        issued_at=issued_at.isoformat().replace("+00:00", "Z"),
        jti=jti,
        audience=req.audience,
        scope=req.scope,
        resource=req.tool_name,
        invocation_id=req.invocation_id,
        context_binding=req.context_binding,
        proof_key_id=proof_key_id,
        delegated_by=req.agent_id,
        kid=_KID,
    )


# ─── Rutas ──────────────────────────────────────────────────────────────────

@app.get("/healthz")
async def healthz():
    return {"status": "ok", "service": "credential-broker", "version": "1.1.0"}


@app.get("/readyz")
async def readyz():
    return {"status": "ready", "kid": _KID}


@app.get("/.well-known/jwks.json")
async def jwks():
    return {"keys": [_public_jwk()]}


@app.post("/v1/tokens/tool", response_model=ToolTokenResponse)
async def issue_tool_token(req: ToolTokenRequest):
    if not req.agent_id or not req.tool_name or not req.audience:
        raise HTTPException(400, "agent_id, tool_name y audience son obligatorios")
    await _authorize_tool_token(req)
    return _mint_ephemeral_token(req)
