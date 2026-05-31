"""
T-1 Genesis candidate — capture phase.

Step 1-4 of Codex' 10-step flow:
  1. Registry/schema/tool object ophalen in untrusted/pre-grant state.
  2. In airlock importeren, nog geen capability grant.
  3. Canonical hashes vastleggen (tool_id, schema_hash, description_hash,
     allowed_tools_hash, endpoint_hash, registry_source, retrieved_at,
     retriever_identity).
  4. Magic bytes / clean-slate marker maken.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


GENESIS_EVENT_KIND = "tibet.genesis.t-1.v1"
MAGIC_BYTES_CLEAN_SLATE = "T1_CLEAN_SLATE"

# Magic bytes for hard parser-keuze on genesis-emitted records (SSM §4 — magic
# bytes are intrinsic surface, no trust by name alone but enable dispatch
# without decrypting the sealed payload).
MAGIC_TAT_REATTEST_REQ = "T1_REATTEST_REQ"
MAGIC_TAT_GENESIS_OK = "T1_GENESIS_OK"

# TAT envelope intent for tibet-genesis dirty verdicts. Jasper 31 mei: separate
# from send_attestation. send_attestation = ik stuur een bewijsobject;
# request_re_attestation = ik vraag fresh assurance vóór ik iets vertrouw.
TAT_INTENT_REQUEST_REATTESTATION = "request_re_attestation"


def _ssm_safe(s: str) -> str:
    """Lower + dot-stripped + dash-stripped slug for SSM dispatch labels.

    SSM ABNF (draft-vandemeent-tibet-semantic-surface-manifest-00 §9):
    surface-name = time-fragment "." context "." profile "." priority
    Each segment must be flat, low-leakage, no embedded dots.
    """
    safe = "".join(c if c.isalnum() or c == "-" else "_" for c in s.lower())
    return safe.strip("_-") or "anon"


def genesis_ssm_label(
    severity: str = "request",
    *,
    priority: str = "urgent",
    time_fragment: str = "now",
) -> str:
    """Build a 4-dot canonical SSM dispatch label for a genesis envelope.

    Follows SSM ABNF strictly (draft-vandemeent-tibet-semantic-surface-manifest-00 §9):
        surface-name = time-fragment "." context "." profile "." priority

    Default: `now.request.genesis-reattest.urgent`

    Conventions:
        now.request.genesis-reattest.urgent     — operator must rescan (airlock dirty)
        now.important.genesis-reattest.urgent   — merge-time rejection, escalated
        now.confirm.genesis-ready.normal        — clean verdict, grant ok

    Tool_id is NOT included in the surface — SSM spec mandates low-leakage
    labels (tool_id may contain paths / sensitive strings). The tool_id
    travels in `payload_ref.label` inside the TAT envelope.

    SSM one-line: makes sealed containers routable without making them
    trustable by name alone. Trust comes from deep verify (trust-kernel +
    biometric roundtrip), not from the dispatch label.
    """
    if severity not in {"request", "important", "confirm", "urgent"}:
        severity = "request"
    profile = "genesis-ready" if severity == "confirm" else "genesis-reattest"
    return f"{time_fragment}.{severity}.{profile}.{priority}"


def canonical_hash(value: Any) -> str:
    """sha256:<hex> over canonical JSON encoding of value. Stable across runs."""
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return f"sha256:{hashlib.sha256(canonical.encode('utf-8')).hexdigest()}"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


@dataclass(frozen=True)
class HashBundle:
    """The canonical content-hashes captured during T-1 import."""
    schema_hash: str
    description_hash: str
    allowed_tools_hash: str
    endpoint_hash: str

    def as_dict(self) -> dict[str, str]:
        return {
            "schema_hash": self.schema_hash,
            "description_hash": self.description_hash,
            "allowed_tools_hash": self.allowed_tools_hash,
            "endpoint_hash": self.endpoint_hash,
        }


@dataclass(frozen=True)
class GenesisCandidate:
    """A T-1 candidate — untrusted tool/registry object captured in airlock.

    Until a clean merge_to_t0_verdict=ready is reached, this object is NOT
    a tool. It is a pre-grant candidate awaiting bilateral self-consent.
    """
    tool_id: str
    bundle: HashBundle
    registry_source: str
    retrieved_at: str
    retriever_identity: str
    magic_bytes: str
    fork_id: str
    raw: dict[str, Any] = field(default_factory=dict)

    def to_canonical_dict(self) -> dict[str, Any]:
        """The dict shape that gets hashed/signed and shows up in events."""
        return {
            "tool_id": self.tool_id,
            **self.bundle.as_dict(),
            "registry_source": self.registry_source,
            "retrieved_at": self.retrieved_at,
            "retriever_identity": self.retriever_identity,
            "magic_bytes": self.magic_bytes,
            "fork_id": self.fork_id,
        }

    def canonical_hash(self) -> str:
        """Single hash over the candidate's canonical fields (NOT including raw)."""
        return canonical_hash(self.to_canonical_dict())


def capture_candidate(
    *,
    tool_id: str,
    schema: Any,
    description: str,
    allowed_tools: list[str],
    endpoint: str,
    registry_source: str,
    retriever_identity: str = "jis:humotica:t-1-airlock",
    magic_bytes: str = MAGIC_BYTES_CLEAN_SLATE,
    fork_id: Optional[str] = None,
    raw: Optional[dict[str, Any]] = None,
) -> GenesisCandidate:
    """Step 1-4: capture an untrusted tool/registry object as a T-1 candidate.

    The caller passes the as-observed values; this function computes the
    canonical hashes and returns an immutable GenesisCandidate. No verify
    or merge happens here — that is step 5+.
    """
    bundle = HashBundle(
        schema_hash=canonical_hash(schema),
        description_hash=canonical_hash(description),
        allowed_tools_hash=canonical_hash(sorted(list(allowed_tools))),
        endpoint_hash=canonical_hash(endpoint),
    )
    return GenesisCandidate(
        tool_id=tool_id,
        bundle=bundle,
        registry_source=registry_source,
        retrieved_at=_utcnow_iso(),
        retriever_identity=retriever_identity,
        magic_bytes=magic_bytes,
        fork_id=fork_id or f"fork_{uuid.uuid4().hex[:12]}",
        raw=dict(raw or {}),
    )
