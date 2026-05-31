"""End-to-end tests for tibet-genesis: capture → verify → diff → merge → event."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tibet_genesis import (
    GENESIS_EVENT_KIND,
    build_genesis_event,
    capture_candidate,
    diff_against_t0,
    merge_or_block,
    verify_candidate,
    write_genesis_event,
)
from tibet_genesis.candidate import canonical_hash, MAGIC_BYTES_CLEAN_SLATE
from tibet_genesis.verdict import (
    AIRLOCK_CLEAN, AIRLOCK_POISONED,
    MERGE_READY, MERGE_NO_GRANT, MERGE_FORK,
)


# ─── canonical_hash ─────────────────────────────────────


def test_canonical_hash_stable():
    h1 = canonical_hash({"b": 2, "a": 1})
    h2 = canonical_hash({"a": 1, "b": 2})
    assert h1 == h2  # key order does not matter
    assert h1.startswith("sha256:")


def test_canonical_hash_diff_for_diff_content():
    assert canonical_hash({"a": 1}) != canonical_hash({"a": 2})


# ─── capture ────────────────────────────────────────────


def test_capture_candidate_fills_required_fields():
    c = capture_candidate(
        tool_id="mcp:filesystem",
        schema={"type": "function"},
        description="read/write files",
        allowed_tools=["read", "write"],
        endpoint="https://api.example/fs",
        registry_source="https://registry.example/tools",
    )
    assert c.tool_id == "mcp:filesystem"
    assert c.bundle.schema_hash.startswith("sha256:")
    assert c.bundle.description_hash.startswith("sha256:")
    assert c.bundle.allowed_tools_hash.startswith("sha256:")
    assert c.bundle.endpoint_hash.startswith("sha256:")
    assert c.magic_bytes == MAGIC_BYTES_CLEAN_SLATE
    assert c.fork_id.startswith("fork_")
    assert c.retrieved_at  # ISO timestamp


def test_capture_canonical_hash_stable_for_same_inputs():
    """Same input → same canonical_hash (modulo fork_id + retrieved_at)."""
    c1 = capture_candidate(
        tool_id="t1", schema={"x": 1}, description="d", allowed_tools=["r"],
        endpoint="e", registry_source="r", fork_id="fixed",
    )
    c2 = capture_candidate(
        tool_id="t1", schema={"x": 1}, description="d", allowed_tools=["r"],
        endpoint="e", registry_source="r", fork_id="fixed",
    )
    # retrieved_at may differ within the same second, so only check field hashes
    assert c1.bundle == c2.bundle


# ─── verify ────────────────────────────────────────────


def test_verify_clean_candidate_returns_clean_airlock():
    c = capture_candidate(
        tool_id="t", schema={}, description="", allowed_tools=[],
        endpoint="", registry_source="reg",
    )
    airlock, token, claim = verify_candidate(c)
    assert airlock.verdict == AIRLOCK_CLEAN
    assert airlock.jis_ok is True
    assert airlock.tibet_ok is True
    assert token.startswith("tok_genesis_")
    assert claim.startswith("jis-claim-")


def test_verify_bad_magic_bytes_poisons():
    c = capture_candidate(
        tool_id="t", schema={}, description="", allowed_tools=[],
        endpoint="", registry_source="reg",
        magic_bytes="NOT_CLEAN_SLATE",
    )
    airlock, _, _ = verify_candidate(c)
    assert airlock.verdict == AIRLOCK_POISONED
    assert "magic_bytes mismatch" in airlock.reason


def test_verify_non_jis_retriever_rejected():
    c = capture_candidate(
        tool_id="t", schema={}, description="", allowed_tools=[],
        endpoint="", registry_source="reg",
        retriever_identity="not-a-jis-identity",
    )
    airlock, _, _ = verify_candidate(c)
    assert airlock.verdict == AIRLOCK_POISONED
    assert airlock.jis_ok is False


# ─── diff + merge ──────────────────────────────────────


def test_diff_first_truth_is_ready():
    c = capture_candidate(
        tool_id="t", schema={}, description="", allowed_tools=[],
        endpoint="", registry_source="reg",
    )
    m = diff_against_t0(c, t0_expected_hash=None)
    assert m.verdict == MERGE_READY
    assert m.diff_clean is True


def test_diff_matching_hash_is_ready():
    c = capture_candidate(
        tool_id="t", schema={"x": 1}, description="", allowed_tools=[],
        endpoint="", registry_source="reg",
    )
    m = diff_against_t0(c, t0_expected_hash=c.canonical_hash())
    assert m.verdict == MERGE_READY


def test_diff_hash_mismatch_blocked():
    c = capture_candidate(
        tool_id="t", schema={"x": 1}, description="", allowed_tools=[],
        endpoint="", registry_source="reg",
    )
    m = diff_against_t0(c, t0_expected_hash="sha256:0000000000")
    assert m.verdict == MERGE_NO_GRANT
    assert m.m4_variant == "hash-mismatch"


@pytest.mark.parametrize("variant,expected_verdict", [
    ("dirty-registry-before-T-1", MERGE_NO_GRANT),
    ("mutation-before-merge", MERGE_FORK),
    ("post-t0-mutation", MERGE_NO_GRANT),
    ("endpoint-redirect", MERGE_NO_GRANT),
])
def test_diff_simulated_attacks(variant, expected_verdict):
    c = capture_candidate(
        tool_id="t", schema={}, description="", allowed_tools=[],
        endpoint="", registry_source="reg",
    )
    m = diff_against_t0(c, m4_simulate=variant)
    assert m.verdict == expected_verdict
    assert m.m4_variant == variant


# ─── compose + event emit ──────────────────────────────


def test_clean_path_grant_allowed():
    c = capture_candidate(
        tool_id="t", schema={}, description="", allowed_tools=[],
        endpoint="", registry_source="reg",
    )
    airlock, token, claim = verify_candidate(c)
    merge = diff_against_t0(c)
    verdict = merge_or_block(c, airlock=airlock, merge=merge,
                             tibet_token=token, jis_claim=claim)
    assert verdict.grant_allowed is True


def test_dirty_registry_grant_denied():
    c = capture_candidate(
        tool_id="t", schema={}, description="", allowed_tools=[],
        endpoint="", registry_source="reg",
    )
    airlock, token, claim = verify_candidate(c)
    merge = diff_against_t0(c, m4_simulate="dirty-registry-before-T-1")
    verdict = merge_or_block(c, airlock=airlock, merge=merge,
                             tibet_token=token, jis_claim=claim)
    assert verdict.grant_allowed is False


def test_build_event_matches_audit_contract():
    """build_genesis_event() must emit fields tibet-audit's assess_genesis_events expects."""
    c = capture_candidate(
        tool_id="mcp:demo", schema={"k": "v"}, description="d", allowed_tools=["a"],
        endpoint="https://e", registry_source="https://r",
    )
    airlock, token, claim = verify_candidate(c)
    merge = diff_against_t0(c)
    verdict = merge_or_block(c, airlock=airlock, merge=merge,
                             tibet_token=token, jis_claim=claim)
    event = build_genesis_event(verdict)

    # Contract fields required by tibet-audit
    required = [
        "kind", "tool_id", "schema_hash", "description_hash",
        "allowed_tools_hash", "endpoint_hash", "registry_source",
        "retrieved_at", "retriever_identity", "magic_bytes",
        "tibet_token", "jis_claim", "airlock_verdict",
        "fork_id", "merge_to_t0_verdict",
    ]
    for field in required:
        assert field in event, f"missing required field {field!r}"
    assert event["kind"] == GENESIS_EVENT_KIND


def test_write_event_appends_jsonl(tmp_path):
    out = tmp_path / "genesis.jsonl"
    c = capture_candidate(
        tool_id="t", schema={}, description="", allowed_tools=[],
        endpoint="", registry_source="r",
    )
    airlock, token, claim = verify_candidate(c)
    merge = diff_against_t0(c)
    verdict = merge_or_block(c, airlock=airlock, merge=merge,
                             tibet_token=token, jis_claim=claim)
    event = build_genesis_event(verdict)

    path = write_genesis_event(event, out)
    assert path == out
    line = out.read_text(encoding="utf-8").strip()
    rec = json.loads(line)
    assert rec["kind"] == GENESIS_EVENT_KIND


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
