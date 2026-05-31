"""
tibet-genesis — CLI for the T-1 Genesis pass.

Commands:
    tibet-genesis fork    — capture a T-1 candidate, dual-verify, diff vs T0, decide
    tibet-genesis demo    — run all 4 M4 fixture variants end-to-end
    tibet-genesis version — print version

Closes Mahipal's M4 ("registry-phase substitution before t0") by running the
self-FIR/A flow Jasper described: T0 only exists after a clean diff-merge of
a T-1 candidate captured in airlock + dual JIS+TIBET-verified.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .candidate import capture_candidate
from .events import (
    HAS_TIBET_DROP,
    build_genesis_event,
    build_reattestation_event,
    build_reattestation_tat,
    write_genesis_event,
)
from .verdict import diff_against_t0, merge_or_block, verify_candidate


def cmd_version(args) -> int:
    print(f"tibet-genesis {__version__}")
    return 0


def cmd_fork(args) -> int:
    """Capture + verify + diff + decide for one tool. Writes one JSONL event."""
    schema_obj: object
    try:
        schema_obj = json.loads(args.schema) if args.schema else {}
    except json.JSONDecodeError:
        schema_obj = {"raw": args.schema}

    allowed = (args.allowed_tools or "").split(",") if args.allowed_tools else []

    candidate = capture_candidate(
        tool_id=args.tool,
        schema=schema_obj,
        description=args.description or "",
        allowed_tools=[a for a in allowed if a],
        endpoint=args.endpoint or "",
        registry_source=args.registry,
        retriever_identity=args.retriever,
        magic_bytes=args.magic_bytes,
    )

    airlock, tibet_token, jis_claim = verify_candidate(candidate)
    merge = diff_against_t0(
        candidate,
        t0_expected_hash=args.expect_hash,
    )
    verdict = merge_or_block(
        candidate,
        airlock=airlock,
        merge=merge,
        tibet_token=tibet_token,
        jis_claim=jis_claim,
    )

    event_type = "t-1.capture"
    event = build_genesis_event(verdict, event_type=event_type)
    tat_envelope = None
    paths = []
    if not args.no_log:
        paths.append(write_genesis_event(event, args.output))
        if verdict.requires_reattestation:
            # 1) JSONL audit-event for tibet-audit.
            reattest_event = build_reattestation_event(verdict)
            paths.append(write_genesis_event(reattest_event, args.output))
            # 2) TAT envelope (Jasper 31 mei): intent=request_re_attestation
            #    routable via SSM dispatch surface, consumable by trust-kernel
            #    which chooses the biometric vehicle (smartphone/laptop/passkey).
            tat_envelope = build_reattestation_tat(verdict)
            paths.append(write_genesis_event(tat_envelope, args.output))

    if args.json:
        out = {"genesis": event}
        if verdict.requires_reattestation:
            out["reattestation_required"] = build_reattestation_event(verdict)
            out["reattestation_tat"] = tat_envelope or build_reattestation_tat(verdict)
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0 if verdict.grant_allowed else 1

    print(f"T-1 Genesis pass: {args.tool}")
    print(f"  retriever:        {args.retriever}")
    print(f"  airlock verdict:  {airlock.verdict}  ({airlock.reason})")
    print(f"  merge verdict:    {merge.verdict}  ({merge.reason})")
    print(f"  grant_allowed:    {verdict.grant_allowed}")
    print(f"  fork_id:          {candidate.fork_id}")
    print(f"  tibet_token:      {tibet_token}")
    if verdict.requires_reattestation:
        print(f"  ↳ REATTESTATION REQUIRED: operator must scan fingerprint")
        print(f"    (capability-grant layer should pause all retries until then)")
        if tat_envelope is not None:
            print(f"  ↳ TAT envelope emitted:")
            print(f"      magic:      {tat_envelope['magic']}")
            print(f"      surface:    {tat_envelope['surface']}  (SSM 4-dot)")
            print(f"      intent:     {tat_envelope['intent']}")
            print(f"      candidate:  {tat_envelope['payload_ref']['hash']}")
            print(f"      ttl:        {tat_envelope['policy']['ttl_seconds']}s")
            strict = "strict TAT (tibet-drop)" if HAS_TIBET_DROP else "self-validating shape (no tibet-drop installed)"
            print(f"      validation: {strict}")
    if paths:
        print(f"  audit-log:        {paths[0]}")
        if len(paths) > 1:
            print(f"  reattest events:  appended ({len(paths)} entries total)")
        print(f"  read with:        tibet-audit genesis {paths[0]}")
    return 0 if verdict.grant_allowed else 1


def cmd_demo(args) -> int:
    """Run all 4 M4 variants end-to-end and write 4 JSONL events for audit."""
    out = Path(args.output) if args.output else Path.home() / ".tibet" / "genesis-demo.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()

    scenarios = [
        # (tool_id, simulate_attack, magic_bytes_override)
        ("tool.clean.local", None, None),
        ("tool.poisoned.registry", "dirty-registry-before-T-1", None),
        ("tool.mutated.before.merge", "mutation-before-merge", None),
        ("tool.post.t0", "post-t0-mutation", None),
    ]
    for tool_id, attack, magic_override in scenarios:
        candidate = capture_candidate(
            tool_id=tool_id,
            schema={"type": "demo", "tool": tool_id},
            description=f"Demo candidate for {tool_id}",
            allowed_tools=["read", "list"],
            endpoint="https://example.local/api",
            registry_source="https://registry.example.local/tools",
            magic_bytes=magic_override or "T1_CLEAN_SLATE",
        )
        airlock, tibet_token, jis_claim = verify_candidate(candidate)
        merge = diff_against_t0(candidate, m4_simulate=attack)
        verdict = merge_or_block(candidate, airlock=airlock, merge=merge,
                                 tibet_token=tibet_token, jis_claim=jis_claim)
        event_type = "t-1.capture"
        if merge.m4_variant == "mutation-before-merge":
            event_type = "t-1.fork"
        elif merge.m4_variant == "post-t0-mutation":
            event_type = "t0.post-grant-mutation"
        event = build_genesis_event(verdict, event_type=event_type)
        write_genesis_event(event, out)
        status = "✓ ready" if verdict.grant_allowed else f"✗ {merge.verdict}"
        if not args.json:
            print(f"  {tool_id:<35}  airlock={airlock.verdict:<10} merge={merge.verdict:<10} → {status}")

    if args.json:
        print(json.dumps({"written_to": str(out), "scenarios": len(scenarios)}, indent=2))
    else:
        print()
        print(f"4 genesis-events written to: {out}")
        print(f"Read with: tibet-audit genesis {out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="tibet-genesis",
        description="T-1 Genesis pass — pre-grant airlock for tool/agent capability grants.",
    )
    p.add_argument("--json", action="store_true", help="emit raw JSON instead of human output")
    p.add_argument("--version", action="version", version=f"tibet-genesis {__version__}")

    sub = p.add_subparsers(dest="cmd", required=True)

    p_fork = sub.add_parser("fork", help="capture + verify + diff + decide for one tool")
    p_fork.add_argument("--tool", required=True, help="tool_id of the candidate (e.g. mcp:filesystem)")
    p_fork.add_argument("--registry", required=True, help="registry source URL")
    p_fork.add_argument("--schema", default="", help="JSON schema string (or raw text)")
    p_fork.add_argument("--description", default="", help="human description of the tool")
    p_fork.add_argument("--allowed-tools", default="", help="comma-separated allowed tools")
    p_fork.add_argument("--endpoint", default="", help="tool endpoint URL")
    p_fork.add_argument("--retriever", default="jis:humotica:t-1-airlock",
                        help="jis: identity of the retriever (default airlock)")
    p_fork.add_argument("--magic-bytes", default="T1_CLEAN_SLATE", help="clean-slate marker")
    p_fork.add_argument("--expect-hash", default=None,
                        help="claimed T0 canonical hash; diff against captured (skip = first-truth)")
    # Test/dev-only attack simulation lives in the demo command + tests/, not here.
    # Real production detection comes from comparing the actual airlock-captured
    # hashes against what the registry claims at merge time (--expect-hash).
    p_fork.add_argument("--output", default=None,
                        help="JSONL audit-log path (default: ~/.tibet/genesis-events.jsonl)")
    p_fork.add_argument("--no-log", action="store_true", help="skip JSONL append")
    p_fork.set_defaults(func=cmd_fork)

    p_demo = sub.add_parser("demo", help="run all 4 M4 variants and write JSONL for tibet-audit")
    p_demo.add_argument("--output", default=None, help="JSONL output path")
    p_demo.set_defaults(func=cmd_demo)

    p_ver = sub.add_parser("version", help="print version")
    p_ver.set_defaults(func=cmd_version)

    return p


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
