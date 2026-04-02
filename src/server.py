"""
Server. Four endpoints, one gate, one entry guard.

POST /decide  - issue a signed decision record
POST /execute - attempt a governed action through entry guard then gate
GET  /state   - read current state
GET  /audit   - read append-only audit log

Pipeline: entry guard -> commit gate -> mutation -> state store
server.py never calls state_store.apply_mutation() directly.
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .audit import AuditLog
from .decision_record import DecisionRecord, make_record, sign_record
from .entry_guard import validate_entry, GuardResult
from .gate import CommitGate, GateResult
from .state_store import StateStore


# -- Initialise components --

store = StateStore()
audit = AuditLog()
gate = CommitGate(store, audit)
app = FastAPI(title="Runtime Commit Gate Demo", version="0.2.0")


# -- Request / Response models --

class DecideRequest(BaseModel):
    actor_id: str
    action: str
    object_id: str
    environment: str
    verdict: str = "ALLOW"
    expires_in_seconds: int = 300


class ExecuteRequest(BaseModel):
    action: str
    object_id: str
    environment: str
    actor_id: str
    decision: Optional[Dict[str, Any]] = None
    params: Optional[Dict[str, Any]] = None
    entry_condition: Optional[Dict[str, Any]] = None


class GateResponse(BaseModel):
    allowed: bool
    reason: str
    decision_id: Optional[str] = None
    action: Optional[str] = None
    object_id: Optional[str] = None


# -- Endpoints --

@app.post("/decide")
def decide(req: DecideRequest) -> dict:
    """Issue a signed decision record."""
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=req.expires_in_seconds)

    record = make_record(
        actor_id=req.actor_id,
        action=req.action,
        object_id=req.object_id,
        environment=req.environment,
        verdict=req.verdict,
        issued_at=now.isoformat(),
        expires_at=expires.isoformat(),
    )
    return record.to_dict()


@app.post("/execute", response_model=GateResponse)
def execute(req: ExecuteRequest) -> GateResponse:
    """
    Attempt a governed action.

    Pipeline:
    1. Entry guard (if entry_condition present) - validates condition structure
    2. Commit gate - validates decision record
    3. Mutation - applies state change

    Entry guard failure -> HOLD. Request never reaches the gate.
    """

    # -- LAYER 1: Entry guard --
    if req.entry_condition is not None:
        packet = {
            "action": req.action,
            **req.entry_condition,
        }
        guard_result = validate_entry(packet)
        if not guard_result.passed:
            return GateResponse(
                allowed=False,
                reason=f"ENTRY_GUARD_HOLD:{guard_result.failed_check}:{guard_result.reason}",
                action=req.action,
                object_id=req.object_id,
            )

    # -- LAYER 2: Commit gate --
    decision = None
    if req.decision is not None:
        try:
            decision = DecisionRecord(
                decision_id=req.decision.get("decision_id", ""),
                actor_id=req.decision.get("actor_id", ""),
                action=req.decision.get("action", ""),
                object_id=req.decision.get("object_id", ""),
                environment=req.decision.get("environment", ""),
                verdict=req.decision.get("verdict", ""),
                policy_version=req.decision.get("policy_version", ""),
                issued_at=req.decision.get("issued_at", ""),
                expires_at=req.decision.get("expires_at", ""),
                reason_codes=tuple(req.decision.get("reason_codes", [])),
                nonce=req.decision.get("nonce", ""),
                signature=req.decision.get("signature", ""),
            )
        except Exception as e:
            return GateResponse(
                allowed=False,
                reason=f"MALFORMED_DECISION:{str(e)}",
                action=req.action,
                object_id=req.object_id,
            )

    result = gate.execute(
        action=req.action,
        object_id=req.object_id,
        environment=req.environment,
        actor_id=req.actor_id,
        decision=decision,
        params=req.params,
    )

    return GateResponse(
        allowed=result.allowed,
        reason=result.reason,
        decision_id=result.decision_id,
        action=result.action,
        object_id=result.object_id,
    )


@app.get("/state")
def get_state() -> dict:
    """Read current state."""
    return store.read()


@app.get("/audit")
def get_audit() -> list:
    """Read audit log."""
    return audit.read_all()


@app.post("/reset")
def reset() -> dict:
    """Reset state, audit, nonces. Testing only."""
    store.reset()
    audit.clear()
    gate.reset_nonces()
    return {"status": "reset"}
