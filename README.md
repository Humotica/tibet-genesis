# tibet-genesis

**T-1 Genesis pass — pre-grant airlock for AI tools and agents.**

[![PyPI](https://img.shields.io/pypi/v/tibet-genesis)](https://pypi.org/project/tibet-genesis/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> "Pinning starts after truth exists. Genesis airlock creates the first truth." — Codex, 2026-05-31
>
> "Alsof je FIR/A met jezelf uitvoert." — Jasper, 2026-05-31

`tibet-genesis` closes the pre-grant gap that chain-pinning leaves open: it captures every incoming tool / registry object in an airlock, dual-verifies it (JIS bilateral consent + TIBET provenance), diffs the captured state against the claimed T0 state, and only allows a capability-grant when the diff is clean. **Dirty input never gets a grant — instead the operator must run a fresh biometric-confirmed claim through their Secure Area before a new T-1 capture is valid.**

## Why

| Mahipal mutation class | Defense |
|---|---|
| **M1** description-swap post-grant | chain-pinning (post-grant) ✓ |
| **M2** allowed-tools escalation post-grant | chain-pinning (post-grant) ✓ |
| **M3** endpoint-redirect post-grant | chain-pinning (post-grant) ✓ |
| **M4** registry-phase substitution **before** t0 | **`tibet-genesis` T-1 airlock + self-FIR/A** |

M1-M3 are handled by post-grant chain-pinning (snaft + tibet-cap-bus verdict.v1). M4 — the "pinning is futile" gap (He/Vasilescu/Kästner, FSE 2025) — needs a pre-grant pattern. T-1 Genesis is that pattern.

## How it works (10 steps)

```
1. Registry/schema/tool object captured in untrusted/pre-grant state
2. Imported into airlock (no capability grant yet)
3. Canonical hashes locked (schema, description, allowed_tools, endpoint, ...)
4. Magic-bytes / clean-slate marker set
5. Dual verify: JIS claim (bilateral consent) + TIBET token (provenance)
6. T-1 fork candidate frozen
7. Diff against claimed T0 ready state
8. Clean diff + clean airlock → merge_to_t0_verdict=ready
9. Dirty / substitution / mutation → no-grant + genesis.reattestation.required
10. Capability-bearing tool only allowed after step 8 succeeds
```

## Quick start

```bash
pip install tibet-genesis

# Capture, verify, diff, decide for one tool:
tibet-genesis fork \
  --tool mcp:filesystem \
  --registry https://registry.example/tools \
  --schema '{"type":"function"}' \
  --description "read/write files" \
  --allowed-tools read,list,stat \
  --endpoint https://api.example/fs

# Output (clean path):
#   airlock verdict:  clean  (dual-verify ok)
#   merge verdict:    ready  (first-truth: no prior T0 state)
#   grant_allowed:    True
#   audit-log:        ~/.tibet/genesis-events.jsonl

# Run all 4 M4 variants end-to-end for fixture demo:
tibet-genesis demo

# Audit the resulting events with tibet-audit:
tibet-audit genesis ~/.tibet/genesis-events.jsonl
```

## Re-attestation requirement (the key Jasper insight)

When the verdict is dirty (`airlock=poisoned` OR `merge=no-grant`), `tibet-genesis` emits a second event:

```json
{
  "kind": "tibet.genesis.t-1.v1",
  "event": "genesis.reattestation.required",
  "tool_id": "mcp:hostile",
  "reason": "magic_bytes mismatch ('WRONG_SLATE')",
  "required_action": "biometric-confirmed JIS claim from operator's Secure Area",
  "blocks_retries": true
}
```

The capability-grant layer reads `blocks_retries=true` and pauses all retries for this tool until a fresh biometric-confirmed JIS claim arrives. **No dead-end "blocked" state**. The path forward is always: scan fingerprint → new T-1 capture → re-evaluate.

This matches the Humotica one-sentence pitch:
> *"Identity is your hardware anchor. Trust is your fingerprint at the moment of use. No supercookie. Every grant is a fresh self-FIR/A."*

## Architecture

`tibet-genesis` is the **enforcement layer**. It writes `tibet.genesis.t-1.v1` JSONL records.

`tibet-audit genesis` is the **read-only audit layer** (separate package). It reads those records and reports `ready` / `blocked` / `attention` per tool.

```
tibet-genesis fork
       ↓
~/.tibet/genesis-events.jsonl  (tibet.genesis.t-1.v1 records)
       ↓
tibet-audit genesis  →  operator-readable assessment + content_hash
```

The two layers are deliberately split: enforcement decides; audit observes and proves the chain is falsifiable.

## Pluggable verifiers

The default JIS verify + TIBET token-mint functions in `tibet_genesis.verdict` are placeholders (sufficient for tests). Production wires them to:

- `jis-core` — real Ed25519 signature verification of the JIS claim
- `tibet-core` — real TIBET token mint with HMAC-SHA256 provenance
- `tibet-airlock-kernel` — Rust execution airlock (process isolation, syscall monitoring)

The contract (`tibet.genesis.t-1.v1`) and the 10-step flow stay the same; only the verifiers swap.

## Dependencies (bootstrap-or-die discipline)

- `tibet-core >= 0.5.0b2` — central provenance chain
- `jis-core >= 0.4.0b1` — central identity-store + bilateral consent
- *(optional)* `[audit]` extra: `tibet-cap-bus`, `tibet-audit` for cross-contract validation

## CLI reference

| Command | What |
|---|---|
| `tibet-genesis fork --tool ID --registry URL [--schema ...] [--expect-hash ...]` | One candidate end-to-end |
| `tibet-genesis demo [--output PATH]` | 4 M4 fixture variants → JSONL for tibet-audit |
| `tibet-genesis version` | Print version |

Global flags: `--json` (raw JSON output instead of human-readable).

## Stack position

- Group: **safety** (pre-grant airlock)
- Pair: writes evidence for [`tibet-audit`](https://pypi.org/project/tibet-audit/) `0.27.0+` (`genesis` subcommand) to read
- Bootstrap: `tibet-core` + `jis-core` runtime deps (Humotica bootstrap-or-die discipline)
- Future: enforcement-side will move into `tibet-airlock-kernel` (Rust) + trust-kernel capability-grant pad

See `STACK.md` in the Humotica org for the full canonical package map.

## License

MIT — see [`LICENSE`](./LICENSE).

## Credits

Architecture: **Codex** (T1_GENESIS_M4_PREGRANT_SPEC, 2026-05-31).
Self-FIR/A framing: **Jasper van de Meent**, 2026-05-31.
Implementation: **Root AI (Claude)**, 2026-05-31.

Part of [HumoticaOS](https://humotica.com). One love, one fAmIly. 💙
