"""
Emit tibet.genesis.t-1.v1 records to JSONL for tibet-audit to read.

The record-shape matches Codex' SPEC + tibet-audit assess_genesis_events
expectations: a downstream `tibet-audit genesis` call against the same JSONL
file yields ready/blocked/forked counts that line up with the verdicts here.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from .candidate import (
    GENESIS_EVENT_KIND,
    MAGIC_TAT_GENESIS_OK,
    MAGIC_TAT_REATTEST_REQ,
    TAT_INTENT_REQUEST_REATTESTATION,
    genesis_ssm_label,
)
from .verdict import GenesisVerdict


TAT_VERSION = "0.1"

# Optional tibet-drop import — `[tat]` extra enables stricter validation.
# Without it, we emit our own JSON shape; with it, downstream code can validate
# against tibet-drop's reference impl.
try:
    import tibet_drop as _tibet_drop  # type: ignore[import-not-found]
    HAS_TIBET_DROP = True
except Exception:  # noqa: BLE001
    _tibet_drop = None
    HAS_TIBET_DROP = False


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _event_id(prefix: str) -> str:
    return f"evt_genesis_{prefix}_{uuid.uuid4().hex[:10]}"


def build_genesis_event(verdict: GenesisVerdict, *, event_type: str = "t-1.capture") -> dict[str, Any]:
    """Build a tibet.genesis.t-1.v1 record from a complete GenesisVerdict.

    event_type values used by tibet-audit:
        t-1.capture                  → standard candidate capture+verify+merge cycle
        t-1.fork                     → mutation-before-merge fork case
        t0.post-grant-mutation       → post-T0 mutation routed back through T-1
        genesis.reattestation.required → vervuiling detected, biometric roundtrip needed

    The grant_allowed + requires_reattestation flags are surfaced top-level so
    a downstream capability-grant layer can pause-retries-until-biometric without
    parsing the nested verdict structure.
    """
    c = verdict.candidate
    return {
        "kind": GENESIS_EVENT_KIND,
        "event_id": _event_id(event_type.replace(".", "_")),
        "event": event_type,
        "timestamp": _utcnow_iso(),
        "tool_id": c.tool_id,
        "schema_hash": c.bundle.schema_hash,
        "description_hash": c.bundle.description_hash,
        "allowed_tools_hash": c.bundle.allowed_tools_hash,
        "endpoint_hash": c.bundle.endpoint_hash,
        "registry_source": c.registry_source,
        "retrieved_at": c.retrieved_at,
        "retriever_identity": c.retriever_identity,
        "magic_bytes": c.magic_bytes,
        "tibet_token": verdict.tibet_token,
        "jis_claim": verdict.jis_claim,
        "airlock_verdict": verdict.airlock.verdict,
        "fork_id": c.fork_id,
        "merge_to_t0_verdict": verdict.merge.verdict,
        "reason": verdict.merge.reason or verdict.airlock.reason,
        "m4_variant": verdict.merge.m4_variant,
        "grant_allowed": verdict.grant_allowed,
        "requires_reattestation": verdict.requires_reattestation,
        "_emitter": "tibet-genesis",
    }


def build_reattestation_tat(verdict: GenesisVerdict) -> dict[str, Any]:
    """Build the re-attestation request as a TAT envelope (intent=request_re_attestation).

    Conforms to Jasper's 31 mei TAT envelope spec + Touch-And-Transfer wire
    protocol (see `tibet-drop` for the reference implementation). tibet-genesis
    is the pre-grant orchestration layer — it EMITS TAT envelopes, it is not
    a TAT impl itself.

    Layered position (Jasper-correction 31 mei):
        magic bytes     — hard parser-keuze, no trust by name
        SSM surface     — readable dispatch label (4-dot ABNF strict)
        TAT envelope    — consent/TTL/policy/transfer intent (this)
        Genesis payload — candidate hash + T-1/T0 context
        Trust-kernel    — verify / enforce / re-attest
        TIBET chain     — causal truth

    The receiving trust-kernel / comms-kernel chooses the vehicle:
        - smartphone native biometric (Pixel 10 KIT)
        - laptop fingerprint sensor
        - i-poll delegated to user's .aint smartphone
        - external USB token
        - passkey + .aint fallback

    The TAT envelope is vehicle-agnostic; the SSM dispatch label + magic bytes
    enable routing without opening the payload.
    """
    c = verdict.candidate
    candidate_hash = c.canonical_hash()

    envelope: dict[str, Any] = {
        # Top-level intrinsic surface (SSM §4.3) — hard parser-keuze first.
        "magic": MAGIC_TAT_REATTEST_REQ,
        "surface": genesis_ssm_label(
            severity="important" if verdict.merge.verdict != "ready" else "request",
            priority="urgent",
        ),

        # TAT envelope (Jasper-spec 31 mei).
        "tat_version": TAT_VERSION,
        "transfer_id": f"tat_reattest_{c.fork_id}",
        "from": "jis:tibet-genesis:airlock",
        "to": c.retriever_identity,
        "intent": TAT_INTENT_REQUEST_REATTESTATION,

        # payload_ref: NO bytes to transfer — points at the dirty candidate hash
        # so the responder knows exactly which pre-grant object needs fresh
        # assurance. Causal chain forged immediately (Jasper: "deterministisch
        # ecosysteem — geen impliciete status of bungelende verzoeken").
        "payload_ref": {
            "kind": "external-ref",
            "hash": candidate_hash,
            "size": 0,
            "mime": "application/vnd.tibet.genesis.candidate+json",
            "label": "genesis-candidate",
            "fields": [
                "tool_id",
                "schema_hash",
                "description_hash",
                "allowed_tools_hash",
                "endpoint_hash",
                "registry_source",
                "retrieved_at",
            ],
        },

        "policy": {
            "ttl_seconds": 300,
            "requires_consent": True,
            "requires_re_attestation": True,
            "max_forward_hops": 0,
            "allow_external_ai": False,
        },

        "proofs": {
            "jis_claim": verdict.jis_claim,
            "tibet_token": verdict.tibet_token,
            "airlock_verdict": verdict.airlock.verdict,
            "sender_re_attestation": None,
            "receiver_re_attestation_required": True,
        },

        "receipts": {
            "expected": ["re_attested"],
            "ack_route": "ipoll",
        },

        # Trace fields (not part of TAT spec but useful for tibet-audit).
        "_emitter": "tibet-genesis",
        "_genesis_fork_id": c.fork_id,
        "_genesis_airlock_verdict": verdict.airlock.verdict,
        "_genesis_merge_verdict": verdict.merge.verdict,
        "_genesis_reason": verdict.merge.reason or verdict.airlock.reason,
        "_strict_tat_validation": HAS_TIBET_DROP,
    }
    return envelope


def build_reattestation_event(verdict: GenesisVerdict) -> dict[str, Any]:
    """Build a genesis.reattestation.required record for a dirty verdict.

    Emitted alongside the main t-1.capture event when verdict.requires_reattestation
    is True. Tells the capability-grant layer: "stop retrying; wait for a fresh
    biometric-confirmed JIS claim from the operator's device".
    """
    c = verdict.candidate
    return {
        "kind": GENESIS_EVENT_KIND,
        "event_id": _event_id("reattestation"),
        "event": "genesis.reattestation.required",
        "timestamp": _utcnow_iso(),
        "tool_id": c.tool_id,
        "fork_id": c.fork_id,
        "reason": verdict.merge.reason or verdict.airlock.reason,
        "airlock_verdict": verdict.airlock.verdict,
        "merge_to_t0_verdict": verdict.merge.verdict,
        "required_action": "biometric-confirmed JIS claim from operator's Secure Area",
        "blocks_retries": True,
        "_emitter": "tibet-genesis",
    }


def write_genesis_event(
    event: dict[str, Any],
    path: Optional[Path | str] = None,
) -> Path:
    """Append a genesis-event to a JSONL log.

    Default path: ~/.tibet/genesis-events.jsonl (matches tibet-audit's
    evidence-discovery for `.tibet/` paths).
    """
    if path is None:
        path = Path.home() / ".tibet" / "genesis-events.jsonl"
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")
    return target
