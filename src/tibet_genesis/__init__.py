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

__version__ = "0.1.3"

from .candidate import (
    GENESIS_EVENT_KIND,
    MAGIC_BYTES_CLEAN_SLATE,
    MAGIC_TAT_GENESIS_OK,
    MAGIC_TAT_REATTEST_REQ,
    TAT_INTENT_REQUEST_REATTESTATION,
    GenesisCandidate,
    HashBundle,
    capture_candidate,
    canonical_hash,
    genesis_ssm_label,
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
    TAT_VERSION,
    HAS_TIBET_DROP,
    build_genesis_event,
    build_reattestation_event,
    build_reattestation_tat,
    write_genesis_event,
)

__all__ = [
    "__version__",
    "GENESIS_EVENT_KIND",
    "MAGIC_BYTES_CLEAN_SLATE",
    "MAGIC_TAT_GENESIS_OK",
    "MAGIC_TAT_REATTEST_REQ",
    "TAT_INTENT_REQUEST_REATTESTATION",
    "TAT_VERSION",
    "HAS_TIBET_DROP",
    "GenesisCandidate",
    "HashBundle",
    "AirlockVerdict",
    "GenesisVerdict",
    "MergeVerdict",
    "capture_candidate",
    "canonical_hash",
    "genesis_ssm_label",
    "verify_candidate",
    "diff_against_t0",
    "merge_or_block",
    "build_genesis_event",
    "build_reattestation_event",
    "build_reattestation_tat",
    "write_genesis_event",
]
