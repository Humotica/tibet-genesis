"""
tibet-genesis — T-1 Genesis pass for pre-grant trust formation.

Codex' SPEC (2026-05-31): `tibet.genesis.t-1.v1`.
Jasper's framing: "alsof je FIR/A met jezelf uitvoert" — the system does
bilateral consent between its own pre-grant-self (T-1 candidate captured in
airlock) and its own post-grant-self (T0 ready state). Mutation between
capture and merge → mismatch → no grant.

Closes Mahipal's M4 ("registry-phase substitution before t0") by ensuring
that T0 only exists after a clean diff-merge of a fresh, isolated,
dual-verified T-1 candidate.

This package is an **enforcement skeleton** — the 10-step flow is real, but
the airlock and JIS verify functions are pluggable. Wire them to
`tibet-airlock-kernel` (Rust) and `jis-core` for production; the included
implementations are sufficient for testing the audit contract end-to-end.

Public API:
    from tibet_genesis import (
        GenesisCandidate, GenesisVerdict,
        capture_candidate, verify_candidate, diff_against_t0,
        merge_or_block, build_genesis_event, write_genesis_event,
    )
"""

__version__ = "0.1.1"

from .candidate import (
    GENESIS_EVENT_KIND,
    GenesisCandidate,
    HashBundle,
    capture_candidate,
    canonical_hash,
)
from .verdict import (
    AirlockVerdict,
    GenesisVerdict,
    MergeVerdict,
    diff_against_t0,
    merge_or_block,
    verify_candidate,
)
from .events import (
    build_genesis_event,
    build_reattestation_event,
    write_genesis_event,
)

__all__ = [
    "__version__",
    "GENESIS_EVENT_KIND",
    "GenesisCandidate",
    "HashBundle",
    "AirlockVerdict",
    "GenesisVerdict",
    "MergeVerdict",
    "capture_candidate",
    "canonical_hash",
    "verify_candidate",
    "diff_against_t0",
    "merge_or_block",
    "build_genesis_event",
    "build_reattestation_event",
    "write_genesis_event",
]
