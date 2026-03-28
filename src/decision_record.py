"""
Decision Record — the licence that governs mutation.

A decision record is a signed, scoped, time-bound authorisation.
Without one, no state change occurs. Period.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional


# Shared secret for HMAC signing. In production this lives in a vault.
# For this demo it proves the mechanism, not the key management.
DEFAULT_SECRET = b"commit-gate-demo-secret-v0"


@dataclass(frozen=True)
class DecisionRecord:
    """Immutable licence for a single governed action."""

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
        }
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
    )


def verify_signature(record: DecisionRecord, secret: bytes = DEFAULT_SECRET) -> bool:
    """Check HMAC signature against canonical payload."""
    expected = hmac.new(secret, record.canonical_payload().encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(record.signature, expected)


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
    """Convenience: build and sign a decision record in one call."""
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
        expires_at=expires_at or (now.replace(minute=now.minute + 5) if now.minute < 55 else now.replace(hour=now.hour + 1, minute=0)).isoformat(),
        reason_codes=tuple(reason_codes or ["AUTH_VALID", "SCOPE_VALID"]),
        nonce=nonce or uuid.uuid4().hex,
        signature="",
    )
    return sign_record(rec, secret)
