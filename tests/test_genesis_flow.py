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


# --- 0.1.2: TAT envelope shape + SSM dispatch label + canonical hash --------


def test_genesis_ssm_label_4dot_canonical():
    from tibet_genesis import genesis_ssm_label
    label = genesis_ssm_label("request")
    assert label.count(".") == 3, "SSM ABNF strict: 4 segments separated by 3 dots"
    parts = label.split(".")
    assert parts == ["now", "request", "genesis-reattest", "urgent"]


def test_genesis_ssm_label_severity_changes_profile_for_confirm():
    from tibet_genesis import genesis_ssm_label
    confirm = genesis_ssm_label("confirm", priority="normal")
    assert confirm == "now.confirm.genesis-ready.normal"


def test_genesis_ssm_label_unknown_severity_falls_back():
    from tibet_genesis import genesis_ssm_label
    label = genesis_ssm_label("nonsense")
    assert label.startswith("now.request.")  # falls back to request


def test_genesis_ssm_label_low_leakage_no_tool_id():
    """SSM spec mandates low-leakage labels — tool_id must NOT appear in surface."""
    from tibet_genesis import genesis_ssm_label
    label = genesis_ssm_label("important")
    assert "mcp:" not in label
    assert "/" not in label
    assert "secret" not in label


def test_build_reattestation_tat_envelope_shape():
    from tibet_genesis import (
        TAT_VERSION,
        TAT_INTENT_REQUEST_REATTESTATION,
        MAGIC_TAT_REATTEST_REQ,
        capture_candidate,
        verify_candidate,
        diff_against_t0,
        merge_or_block,
        build_reattestation_tat,
    )
    candidate = capture_candidate(
        tool_id="mcp:test",
        schema={"x": 1},
        description="dirty",
        allowed_tools=["a"],
        endpoint="https://example",
        registry_source="https://registry.example",
        magic_bytes="WRONG_MAGIC",  # forces airlock=poisoned
    )
    airlock, tibet_token, jis_claim = verify_candidate(candidate)
    merge = diff_against_t0(candidate)
    verdict = merge_or_block(candidate, airlock=airlock, merge=merge,
                             tibet_token=tibet_token, jis_claim=jis_claim)

    env = build_reattestation_tat(verdict)
    # TAT envelope structural shape
    assert env["tat_version"] == TAT_VERSION
    assert env["intent"] == TAT_INTENT_REQUEST_REATTESTATION
    assert env["magic"] == MAGIC_TAT_REATTEST_REQ
    assert env["surface"].count(".") == 3
    assert env["from"] == "jis:tibet-genesis:airlock"
    # payload_ref points at canonical candidate_hash, not just schema_hash
    assert env["payload_ref"]["kind"] == "external-ref"
    assert env["payload_ref"]["hash"] == candidate.canonical_hash()
    assert env["payload_ref"]["hash"] != candidate.bundle.schema_hash
    assert env["payload_ref"]["mime"] == "application/vnd.tibet.genesis.candidate+json"
    assert env["payload_ref"]["label"] == "genesis-candidate"
    assert "tool_id" in env["payload_ref"]["fields"]
    assert "schema_hash" in env["payload_ref"]["fields"]
    assert "retrieved_at" in env["payload_ref"]["fields"]
    # policy: no-fail-open + no external AI + zero hops
    assert env["policy"]["requires_consent"] is True
    assert env["policy"]["requires_re_attestation"] is True
    assert env["policy"]["max_forward_hops"] == 0
    assert env["policy"]["allow_external_ai"] is False
    # receipts: i-poll default + only re_attested expected
    assert env["receipts"]["ack_route"] == "ipoll"
    assert env["receipts"]["expected"] == ["re_attested"]


def test_canonical_candidate_hash_covers_all_jasper_spec_fields():
    """Jasper spec 31 mei: candidate_hash = H(tool_id, schema_hash, description_hash,
    allowed_tools_hash, endpoint_hash, registry_source, retrieved_at).
    Verify changing any of those fields changes the hash.
    """
    from tibet_genesis import capture_candidate
    base = capture_candidate(
        tool_id="mcp:base", schema={"x": 1}, description="d",
        allowed_tools=["a"], endpoint="https://e", registry_source="https://r",
    )
    h0 = base.canonical_hash()
    # changing tool_id changes hash
    alt = capture_candidate(
        tool_id="mcp:OTHER", schema={"x": 1}, description="d",
        allowed_tools=["a"], endpoint="https://e", registry_source="https://r",
        fork_id=base.fork_id,  # same fork
    )
    assert alt.canonical_hash() != h0
    # changing endpoint changes hash
    alt2 = capture_candidate(
        tool_id="mcp:base", schema={"x": 1}, description="d",
        allowed_tools=["a"], endpoint="https://DIFFERENT", registry_source="https://r",
        fork_id=base.fork_id,
    )
    assert alt2.canonical_hash() != h0
    # changing description changes hash
    alt3 = capture_candidate(
        tool_id="mcp:base", schema={"x": 1}, description="DIFFERENT",
        allowed_tools=["a"], endpoint="https://e", registry_source="https://r",
        fork_id=base.fork_id,
    )
    assert alt3.canonical_hash() != h0
