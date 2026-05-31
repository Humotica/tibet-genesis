"""
T-1 Genesis verdict — verify, diff, merge phases.

Step 5-9 of Codex' 10-step flow:
  5. Dual verify: JIS claim + TIBET token/provenance.
  6. T-1 fork candidate maken (done in capture).
  7. Diff T-1 candidate tegen T0 ready state.
  8. Alleen clean diff + clean airlock verdict mag merge_to_t0_verdict=ready geven.
  9. Dirty registry, substitution before merge, endpoint redirect, allowed-tools
     escalation, schema mutation => blocked/forked/no-grant.

The JIS/TIBET verify functions are pluggable: in production they wire to
jis-core + tibet-core (already required deps); in tests/skeleton mode the
defaults give deterministic clean/dirty verdicts so the audit contract is
end-to-end testable.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .candidate import GenesisCandidate, canonical_hash


# Verdict strings — match tibet-audit assess_genesis_events vocabulary.
AIRLOCK_CLEAN = "clean"
AIRLOCK_POISONED = "poisoned"
AIRLOCK_FORK = "fork"
AIRLOCK_BLOCKED = "blocked"

MERGE_READY = "ready"
MERGE_NO_GRANT = "no-grant"
MERGE_FORK = "fork"


@dataclass(frozen=True)
class AirlockVerdict:
    """Result of step 5+8 — airlock verify + clean-slate check."""
    verdict: str       # AIRLOCK_CLEAN | AIRLOCK_POISONED | AIRLOCK_FORK | AIRLOCK_BLOCKED
    reason: str
    jis_ok: bool
    tibet_ok: bool


@dataclass(frozen=True)
class MergeVerdict:
    """Result of step 7+8 — diff against T0 ready state + merge decision."""
    verdict: str          # MERGE_READY | MERGE_NO_GRANT | MERGE_FORK
    reason: str
    diff_clean: bool
    m4_variant: Optional[str] = None  # e.g. "dirty-registry-before-T-1"


@dataclass(frozen=True)
class GenesisVerdict:
    """Composed verdict: airlock + merge for the same candidate."""
    candidate: GenesisCandidate
    airlock: AirlockVerdict
    merge: MergeVerdict
    tibet_token: str
    jis_claim: str

    @property
    def grant_allowed(self) -> bool:
        """True iff capability-bearing tool may be allowed (step 10)."""
        return (
            self.airlock.verdict == AIRLOCK_CLEAN
            and self.merge.verdict == MERGE_READY
        )

    @property
    def requires_reattestation(self) -> bool:
        """True iff a dirty/forked/blocked outcome was reached.

        Jasper 2026-05-31: "Als je vervuiling ziet die niet opnieuw je ID inleest
        dmv vingerafdruk, kan je toch geen schoon lanceerpad creeeren." A blocked
        verdict is a dead-end — to start fresh, the operator MUST run a new
        biometric-confirmed claim through their device's Secure Area (Android
        Keystore / iOS Secure Enclave). Until that re-attestation roundtrip
        completes, no new T-1 capture for this tool is valid.

        Downstream (capability-grant pad) should treat this flag as: "pause all
        re-tries until a fresh biometric-confirmed JIS claim arrives".
        """
        return not self.grant_allowed


# ─── Default pluggable verifiers ──────────────────────────────────────


def _default_jis_verify(candidate: GenesisCandidate) -> tuple[bool, str]:
    """Default JIS verify — treats `jis:humotica:*` retrievers as accepted.

    Production override: real Ed25519 signature verification via jis-core.
    """
    if candidate.retriever_identity.startswith("jis:"):
        return True, f"jis-claim-{candidate.fork_id}"
    return False, ""


def _default_tibet_token(candidate: GenesisCandidate) -> str:
    """Default TIBET token — content-hash of canonical candidate fields.

    Production override: real TIBET token mint via tibet-core Provider.
    """
    return f"tok_genesis_{candidate.canonical_hash()[7:23]}"


def verify_candidate(
    candidate: GenesisCandidate,
    *,
    jis_verify: Optional[Callable[[GenesisCandidate], tuple[bool, str]]] = None,
    tibet_token_mint: Optional[Callable[[GenesisCandidate], str]] = None,
) -> tuple[AirlockVerdict, str, str]:
    """Step 5 + part of step 8: dual JIS+TIBET verify, return airlock verdict.

    Returns:
        (airlock_verdict, tibet_token, jis_claim)

    The airlock verdict is `clean` only when both JIS and TIBET checks pass
    AND the magic_bytes match the expected clean-slate marker.
    """
    jis_fn = jis_verify or _default_jis_verify
    tibet_fn = tibet_token_mint or _default_tibet_token

    jis_ok, jis_claim = jis_fn(candidate)
    tibet_token = tibet_fn(candidate)
    tibet_ok = bool(tibet_token)

    from .candidate import MAGIC_BYTES_CLEAN_SLATE
    magic_ok = candidate.magic_bytes == MAGIC_BYTES_CLEAN_SLATE

    if jis_ok and tibet_ok and magic_ok:
        return (
            AirlockVerdict(verdict=AIRLOCK_CLEAN, reason="dual-verify ok", jis_ok=True, tibet_ok=True),
            tibet_token, jis_claim,
        )
    reason = []
    if not jis_ok: reason.append("jis-claim rejected")
    if not tibet_ok: reason.append("tibet-token mint failed")
    if not magic_ok: reason.append(f"magic_bytes mismatch ({candidate.magic_bytes!r})")
    return (
        AirlockVerdict(verdict=AIRLOCK_POISONED, reason="; ".join(reason),
                       jis_ok=jis_ok, tibet_ok=tibet_ok),
        tibet_token, jis_claim,
    )


# ─── Diff + merge ────────────────────────────────────────────────────


def diff_against_t0(
    candidate: GenesisCandidate,
    *,
    t0_expected_hash: Optional[str] = None,
    m4_simulate: Optional[str] = None,
) -> MergeVerdict:
    """Step 7-8: diff the T-1 candidate against the claimed T0 ready state.

    - If t0_expected_hash matches candidate.canonical_hash() → ready.
    - If they differ → blocked (registry served different state than what
      we captured = registry-phase substitution = Mahipal M4).
    - m4_simulate is for tests: forces a specific failure mode for fixture
      generation. Production sets t0_expected_hash from the registry claim.
    """
    if m4_simulate:
        if m4_simulate == "dirty-registry-before-T-1":
            return MergeVerdict(MERGE_NO_GRANT, "dirty registry before T-1 capture",
                                diff_clean=False, m4_variant=m4_simulate)
        if m4_simulate == "mutation-before-merge":
            return MergeVerdict(MERGE_FORK, "schema/endpoint mutation between capture and merge",
                                diff_clean=False, m4_variant=m4_simulate)
        if m4_simulate == "post-t0-mutation":
            return MergeVerdict(MERGE_NO_GRANT, "post-T0 mutation routed back through T-1",
                                diff_clean=False, m4_variant=m4_simulate)
        if m4_simulate == "endpoint-redirect":
            return MergeVerdict(MERGE_NO_GRANT, "endpoint hash drifted between capture and merge",
                                diff_clean=False, m4_variant=m4_simulate)

    candidate_hash = candidate.canonical_hash()
    if t0_expected_hash is None:
        # First-truth case: no prior T0 state to diff against → clean by definition.
        # (Honest first-grant. The audit chain has to start somewhere.)
        return MergeVerdict(MERGE_READY, "first-truth: no prior T0 state",
                            diff_clean=True, m4_variant=None)
    if t0_expected_hash == candidate_hash:
        return MergeVerdict(MERGE_READY, "T-1 candidate matches claimed T0",
                            diff_clean=True, m4_variant=None)
    return MergeVerdict(
        MERGE_NO_GRANT,
        f"T-1/T0 hash mismatch (candidate={candidate_hash[:16]}, claimed={t0_expected_hash[:16]})",
        diff_clean=False, m4_variant="hash-mismatch",
    )


def merge_or_block(
    candidate: GenesisCandidate,
    *,
    airlock: AirlockVerdict,
    merge: MergeVerdict,
    tibet_token: str,
    jis_claim: str,
) -> GenesisVerdict:
    """Step 8-10: compose verdicts. grant_allowed=True only if both clean+ready."""
    return GenesisVerdict(
        candidate=candidate,
        airlock=airlock,
        merge=merge,
        tibet_token=tibet_token,
        jis_claim=jis_claim,
    )
