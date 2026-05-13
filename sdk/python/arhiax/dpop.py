"""Soporte DPoP (RFC 9449) para tokens efimeros ARHIAX.

Cada agente mantiene una clave EC P-256 propia con la cual:
  - publica un JWK al broker (que la liga al token via cnf.jkt = thumbprint)
  - firma un DPoP-proof por cada peticion al gateway, demostrando posesion

Ningun material privado sale del proceso del agente.
"""
from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Dict

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature


def _b64u(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _b64u_uint(n: int, length: int = 32) -> str:
    return _b64u(n.to_bytes(length, "big"))


class DPoPKey:
    """Clave DPoP del cliente. Genera nuevas por defecto, una por agente."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey | None = None) -> None:
        self._priv = private_key or ec.generate_private_key(ec.SECP256R1())
        nums = self._priv.public_key().public_numbers()
        self._jwk: Dict[str, str] = {
            "kty": "EC",
            "crv": "P-256",
            "x": _b64u_uint(nums.x),
            "y": _b64u_uint(nums.y),
        }
        canonical = json.dumps(self._jwk, separators=(",", ":"), sort_keys=True).encode()
        self._jkt = _b64u(hashlib.sha256(canonical).digest())

    @property
    def public_jwk(self) -> Dict[str, str]:
        return dict(self._jwk)

    @property
    def jkt(self) -> str:
        return self._jkt

    def make_proof(self, *, htm: str, htu: str) -> str:
        """Construye un DPoP-proof JWT firmado con esta clave."""
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self._jwk}
        payload = {
            "htm": htm.upper(),
            "htu": htu,
            "iat": int(time.time()),
            "jti": uuid.uuid4().hex,
        }
        h_b64 = _b64u(json.dumps(header, separators=(",", ":"), sort_keys=True).encode())
        p_b64 = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
        signed = f"{h_b64}.{p_b64}".encode()
        der = self._priv.sign(signed, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        raw_sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return f"{h_b64}.{p_b64}.{_b64u(raw_sig)}"
