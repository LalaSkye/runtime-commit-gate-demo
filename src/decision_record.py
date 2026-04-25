"""
Decision Record.

Signed, scoped, time-bound. Required for any state mutation.

V4: adds optional parameter binding.
- Mode A: `params_hash` field. Caller supplies params at call time; gate
  re-hashes and compares.
- Mode B: `params` field. Params embedded directly in the signed record;
  gate applies them without accepting caller-supplied params.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# HMAC secret. In production, stored in a vault.
DEFAULT_SECRET = b"commit-gate-demo-secret-v0"


class InvalidParamsType(Exception):
    """Raised when params contain unserialisable / unhashable types."""


def canonical_params(params: Optional[Dict[str, Any]]) -> str:
    """
    Deterministic JSON for params. Raises InvalidParamsType on
    unserialisable content. `None` serialises to the JSON literal `null`.
    """
    try:
        return json.dumps(
            params,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as e:
        raise InvalidParamsType(f"Params contain unserialisable content: {e}") from e


def hash_params(params: Optional[Dict[str, Any]]) -> str:
    """sha256 hex of canonical-JSON params. None hashes to hash of JSON null."""
    return hashlib.sha256(canonical_params(params).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class DecisionRecord:
    """Immutable. Fields fixed at construction.

    V4: `params_hash` (Mode A) and `params` (Mode B) are optional signed fields.
    Both default `None` for forward-compat with V1-V3 records.
    """

    decision_id: str
    actor_id: str
    action: str
    object_id: str
    environment: str
    verdict: str
    policy_version: str
    issued_at: str
    expires_at: str
    reason_codes: tuple
    nonce: str
    signature: str = ""
    # V4 additions
    params_hash: Optional[str] = None
    params: Optional[Dict[str, Any]] = None

    def canonical_payload(self) -> str:
        """Deterministic JSON of all fields except signature."""
        payload = {
            "decision_id": self.decision_id,
            "actor_id": self.actor_id,
            "action": self.action,
            "object_id": self.object_id,
            "environment": self.environment,
            "verdict": self.verdict,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "reason_codes": list(self.reason_codes),
            "nonce": self.nonce,
            # V4: always included. `None` serialises to `null`, keeping
            # V1-V3 signatures stable (they were signed without these keys
            # in the payload; see next note).
        }
        # Forward-compatibility: if BOTH new fields are None, we sign
        # using the legacy payload shape so V1-V3 records still verify.
        if self.params_hash is not None or self.params is not None:
            payload["params_hash"] = self.params_hash
            payload["params"] = self.params
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    def to_dict(self) -> dict:
        d = {
            "decision_id": self.decision_id,
            "actor_id": self.actor_id,
            "action": self.action,
            "object_id": self.object_id,
            "environment": self.environment,
            "verdict": self.verdict,
            "policy_version": self.policy_version,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "reason_codes": list(self.reason_codes),
            "nonce": self.nonce,
            "signature": self.signature,
            "params_hash": self.params_hash,
            "params": self.params,
        }
        return d


def sign_record(record: DecisionRecord, secret: bytes = DEFAULT_SECRET) -> DecisionRecord:
    """Return a new DecisionRecord with a valid HMAC-SHA256 signature."""
    sig = hmac.new(secret, record.canonical_payload().encode(), hashlib.sha256).hexdigest()
    return DecisionRecord(
        decision_id=record.decision_id,
        actor_id=record.actor_id,
        action=record.action,
        object_id=record.object_id,
        environment=record.environment,
        verdict=record.verdict,
        policy_version=record.policy_version,
        issued_at=record.issued_at,
        expires_at=record.expires_at,
        reason_codes=record.reason_codes,
        nonce=record.nonce,
        signature=sig,
        params_hash=record.params_hash,
        params=record.params,
    )


def verify_signature(record: DecisionRecord, secret: bytes = DEFAULT_SECRET) -> bool:
    """Check HMAC signature against canonical payload."""
    expected = hmac.new(secret, record.canonical_payload().encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(record.signature, expected)


def _default_expiry(now: datetime) -> str:
    # Robust expiry: add 5 minutes without overflowing minute/hour.
    return (now.replace(microsecond=0) + __import__("datetime").timedelta(minutes=5)).isoformat()


def make_record(
    actor_id: str,
    action: str,
    object_id: str,
    environment: str,
    verdict: str = "ALLOW",
    policy_version: str = "2026-03-28.1",
    issued_at: Optional[str] = None,
    expires_at: Optional[str] = None,
    reason_codes: Optional[List[str]] = None,
    nonce: Optional[str] = None,
    secret: bytes = DEFAULT_SECRET,
) -> DecisionRecord:
    """Build and sign a legacy (unbound) decision record. V1-V3 shape."""
    now = datetime.now(timezone.utc)
    rec = DecisionRecord(
        decision_id=f"dr_{uuid.uuid4().hex[:12]}",
        actor_id=actor_id,
        action=action,
        object_id=object_id,
        environment=environment,
        verdict=verdict,
        policy_version=policy_version,
        issued_at=issued_at or now.isoformat(),
        expires_at=expires_at
        or (now.replace(minute=now.minute + 5) if now.minute < 55
            else now.replace(hour=now.hour + 1, minute=0)).isoformat(),
        reason_codes=tuple(reason_codes or ["AUTH_VALID", "SCOPE_VALID"]),
        nonce=nonce or uuid.uuid4().hex,
        signature="",
        params_hash=None,
        params=None,
    )
    return sign_record(rec, secret)


def make_record_with_params_hash(
    actor_id: str,
    action: str,
    object_id: str,
    environment: str,
    params: Optional[Dict[str, Any]],
    verdict: str = "ALLOW",
    policy_version: str = "2026-03-28.1",
    issued_at: Optional[str] = None,
    expires_at: Optional[str] = None,
    reason_codes: Optional[List[str]] = None,
    nonce: Optional[str] = None,
    secret: bytes = DEFAULT_SECRET,
) -> DecisionRecord:
    """Build a Mode A record: signs over hash(params). Caller transports
    params out-of-band and supplies them at execute() time.
    """
    # This raises InvalidParamsType if params are unhashable — tested by H12.
    phash = hash_params(params)
    now = datetime.now(timezone.utc)
    rec = DecisionRecord(
        decision_id=f"dr_{uuid.uuid4().hex[:12]}",
        actor_id=actor_id,
        action=action,
        object_id=object_id,
        environment=environment,
        verdict=verdict,
        policy_version=policy_version,
        issued_at=issued_at or now.isoformat(),
        expires_at=expires_at
        or (now.replace(minute=now.minute + 5) if now.minute < 55
            else now.replace(hour=now.hour + 1, minute=0)).isoformat(),
        reason_codes=tuple(reason_codes or ["AUTH_VALID", "SCOPE_VALID"]),
        nonce=nonce or uuid.uuid4().hex,
        signature="",
        params_hash=phash,
        params=None,
    )
    return sign_record(rec, secret)


def make_record_with_params(
    actor_id: str,
    action: str,
    object_id: str,
    environment: str,
    params: Dict[str, Any],
    verdict: str = "ALLOW",
    policy_version: str = "2026-03-28.1",
    issued_at: Optional[str] = None,
    expires_at: Optional[str] = None,
    reason_codes: Optional[List[str]] = None,
    nonce: Optional[str] = None,
    secret: bytes = DEFAULT_SECRET,
) -> DecisionRecord:
    """Build a Mode B record: embeds params directly in the signed payload.
    `execute_bound()` applies exactly these params with no caller override.
    """
    # Validate serialisability now. H12.
    canonical_params(params)
    now = datetime.now(timezone.utc)
    rec = DecisionRecord(
        decision_id=f"dr_{uuid.uuid4().hex[:12]}",
        actor_id=actor_id,
        action=action,
        object_id=object_id,
        environment=environment,
        verdict=verdict,
        policy_version=policy_version,
        issued_at=issued_at or now.isoformat(),
        expires_at=expires_at
        or (now.replace(minute=now.minute + 5) if now.minute < 55
            else now.replace(hour=now.hour + 1, minute=0)).isoformat(),
        reason_codes=tuple(reason_codes or ["AUTH_VALID", "SCOPE_VALID"]),
        nonce=nonce or uuid.uuid4().hex,
        signature="",
        params_hash=None,
        params=params,
    )
    return sign_record(rec, secret)
