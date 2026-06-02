# tibet-genesis

**T-1 Genesis pass — pre-grant orchestration above/beside the TAT wire layer.**

[![PyPI](https://img.shields.io/pypi/v/tibet-genesis)](https://pypi.org/project/tibet-genesis/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

> "Pinning starts after truth exists. Genesis airlock creates the first truth." — Codex, 2026-05-31
>
> "Alsof je FIR/A met jezelf uitvoert." — Jasper, 2026-05-31

`tibet-genesis` closes the pre-grant gap that chain-pinning leaves open: it captures every incoming tool / registry object in an airlock, dual-verifies it (JIS bilateral consent + TIBET provenance), diffs the captured state against the claimed T0 state, and only allows a capability-grant when the diff is clean. **Dirty input never gets a grant — instead a TAT envelope (`intent=request_re_attestation`) is emitted with magic bytes + 4-dot SSM dispatch surface, so the trust-kernel can route fresh biometric assurance through whichever vehicle the operator has (smartphone / laptop / passkey / .aint-delegated).**

## Position in the layered stack

`tibet-genesis` is **pre-grant orchestration** — it decides *whether* a candidate may be promoted to T0 ready. It is **not** a TAT (Touch-And-Transfer) implementation. For the TAT wire protocol Python reference + CLI tooling, devs should use [`tibet-drop`](https://pypi.org/project/tibet-drop/).

The TAT envelope emitted on a dirty verdict conforms to the **Touch-And-Transfer** wire format specified in IETF Internet-Draft [`draft-vandemeent-tibet-tat`](https://datatracker.ietf.org/doc/draft-vandemeent-tibet-tat/) (one of 10 TIBET/JIS drafts on the IETF datatracker). The `intent=request_re_attestation` value is the genesis-specific intent layered on that wire shape.

```
CEP          umbrella / continuity messaging model
TIBET        causal truth
JIS / FIR-A  identity + intent authority
RVP vNext    continuous re-attestation  ← superseded by genesis + fresh-assurance taal
UPIP         process / materialization integrity
                                              ┌── tibet-genesis ──┐
                                              │  (pre-grant       │
                                              │   ORCHESTRATION   │
                                              │   — beslist,      │
                                              │   gebruikt TAT,   │
                                              │   ís geen TAT)    │
                                              └──────┬────────────┘
                                                     ↓ emits TAT
TAT          transfer flow              ◄── intent=request_re_attestation
tibet-drop   TAT reference impl + CLI       (devs aanhouden voor TAT spec)
IDDrop       identity profile over TAT
AI-airdrop   state profile over TAT
ICC/TBZ/TZA  sealed cargo
SSM          readable routing surface   ◄── 4-dot ABNF: time.context.profile.priority
I-Poll       async control / receipt bus
Cmail        human mailbox UX
trust-kernel hardened enforcement substrate
              (consumes the TAT envelope, picks biometric vehicle,
               keys, no-fail-open, policy hooks to SNAFT/airlock)
tibet-audit / CBOM  proof afterwards
```

> *tibet-drop/TAT vraagt/vervoert/ankert. tibet-genesis beslist. trust-kernel voert hard af. tibet-audit leest later.* — Jasper, 31 mei 2026

## Why

| Mahipal mutation class | Defense |
|---|---|
| **M1** description-swap post-grant | chain-pinning (post-grant) ✓ |
| **M2** allowed-tools escalation post-grant | chain-pinning (post-grant) ✓ |
| **M3** endpoint-redirect post-grant | chain-pinning (post-grant) ✓ |
| **M4** registry-phase substitution **before** t0 | **`tibet-genesis` T-1 airlock + self-FIR/A + TAT re-attest request** |

M1-M3 are handled by post-grant chain-pinning (snaft + tibet-cap-bus verdict.v1). M4 — the "pinning is futile" gap (He/Vasilescu/Kästner, FSE 2025) — needs a pre-grant pattern. T-1 Genesis is that pattern.

## How it works (10 steps)

```
 1. Registry/schema/tool object captured in untrusted/pre-grant state
 2. Imported into airlock (no capability grant yet)
 3. Canonical hashes locked (schema, description, allowed_tools, endpoint, ...)
 4. Magic-bytes / clean-slate marker set
 5. Dual verify: JIS claim (bilateral consent) + TIBET token (provenance)
 6. T-1 fork candidate frozen + canonical candidate_hash computed
 7. Diff against claimed T0 state
 8. Clean diff + clean airlock → merge_to_t0_verdict=ready → grant allowed
 9. Dirty / substitution / mutation → TAT envelope (intent=request_re_attestation)
    emitted with magic bytes + SSM dispatch surface
10. Trust-kernel consumes envelope, picks biometric vehicle, blocks retries
    until fresh biometric-confirmed JIS claim arrives → new T-1 capture
```

## Quick start

```bash
pip install tibet-genesis
# Optional: stricter TAT envelope validation against tibet-drop ref-impl
pip install 'tibet-genesis[tat]'

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

# Output (dirty path, e.g. magic-bytes mismatch):
#   airlock verdict:  poisoned
#   grant_allowed:    False
#   ↳ REATTESTATION REQUIRED: operator must scan fingerprint
#   ↳ TAT envelope emitted:
#       magic:    T1_REATTEST_REQ
#       surface:  now.request.genesis-reattest.urgent  (SSM 4-dot)
#       intent:   request_re_attestation
#       ttl:      300s

# Run all 4 M4 variants end-to-end for fixture demo:
tibet-genesis demo

# Audit the resulting events with tibet-audit:
tibet-audit genesis ~/.tibet/genesis-events.jsonl
```

## TAT envelope (intent=request_re_attestation)

When the airlock or merge verdict is dirty, `tibet-genesis` emits a **TAT envelope** (Touch-And-Transfer wire protocol) with `intent=request_re_attestation`. The envelope is consumable by trust-kernel / comms-kernel and carries everything needed to route fresh biometric assurance:

```json
{
  "magic": "T1_REATTEST_REQ",
  "surface": "now.request.genesis-reattest.urgent",
  "tat_version": "0.1",
  "transfer_id": "tat_reattest_fork_92de4f4b957c",
  "from": "jis:tibet-genesis:airlock",
  "to": "jis:humotica:t-1-airlock",
  "intent": "request_re_attestation",
  "payload_ref": {
    "kind": "external-ref",
    "hash": "sha256:<canonical_candidate_hash>",
    "size": 0,
    "mime": "application/vnd.tibet.genesis.candidate+json",
    "label": "genesis-candidate",
    "fields": ["tool_id","schema_hash","description_hash","allowed_tools_hash",
               "endpoint_hash","registry_source","retrieved_at"]
  },
  "policy": {
    "ttl_seconds": 300,
    "requires_consent": true,
    "requires_re_attestation": true,
    "max_forward_hops": 0,
    "allow_external_ai": false
  },
  "proofs": {
    "jis_claim": "...",
    "tibet_token": "...",
    "airlock_verdict": "poisoned",
    "receiver_re_attestation_required": true
  },
  "receipts": {
    "expected": ["re_attested"],
    "ack_route": "ipoll"
  }
}
```

### Layer roles per field

| Layer | Field | Role |
|---|---|---|
| **Magic bytes** | `magic` | Hard parser-keuze — no trust by name, but enables dispatch without opening payload |
| **SSM surface** | `surface` | 4-dot ABNF dispatch label (`time.context.profile.priority`) — routable but low-leakage |
| **TAT envelope** | `tat_version`, `from`, `to`, `intent`, `policy`, `receipts` | Consent / TTL / policy / transfer intent |
| **Genesis payload** | `payload_ref.hash` | **Canonical candidate_hash** over `tool_id + 4 content hashes + registry_source + retrieved_at` — causal chain forged directly, no implicit status, no dangling requests |
| **Trust-kernel** | (consumes envelope) | Verify, enforce, pick biometric vehicle, block retries until fresh JIS claim |
| **TIBET chain** | (downstream of grant) | Causal truth after re-attest succeeds |

### SSM dispatch labels (4-dot ABNF strict)

Per [`draft-vandemeent-tibet-semantic-surface-manifest-00`](https://github.com/jaspertvdm/Backend-server-JTel/blob/main/packages/tibet-conformance-vectors/drafts/draft-vandemeent-tibet-semantic-surface-manifest-00.md) §9: `surface-name = time-fragment "." context "." profile "." priority`. tool_id is intentionally **NOT** in the surface (spec mandates low-leakage labels). It travels in `payload_ref.label`.

| Case | SSM surface | Magic |
|---|---|---|
| Airlock dirty → re-attest | `now.request.genesis-reattest.urgent` | `T1_REATTEST_REQ` |
| Merge-time rejection (escalated) | `now.important.genesis-reattest.urgent` | `T1_REATTEST_REQ` |
| Clean verdict → grant ready | `now.confirm.genesis-ready.normal` | `T1_GENESIS_OK` |

SSM one-line summary: *"makes sealed containers routable without making them trustable by name alone."* Trust still comes from deep verify (trust-kernel + biometric roundtrip), not from the dispatch label.

## Re-attestation: fresh assurance at the moment of use

When dirty, the receiver (trust-kernel) chooses the biometric vehicle based on what the operator has available:

| Tier | Vehicle | When |
|---|---|---|
| 1 | Smartphone native (Pixel 10 KIT, TouchID, FaceID) | Operator on phone |
| 2 | Laptop native fingerprint (TouchID Mac / Windows Hello / Linux fp) | Laptop with sensor |
| 3 | **Delegated**: laptop → AInternet i-poll → user's smartphone `.aint` → JTm prompt → biometric → JIS claim back | Laptop without sensor + own smartphone available |
| 4 | External USB token (briefly connected, not shared device) | No smartphone + hardware token |
| 5 | Passkey + `.aint` binding (WebAuthn-style + AInternet identity) | No biometric available |

**Floor:** never andermans device. Shared / public devices fall outside all tiers — UX must explicitly reject "vreemd device, gebruik eigen smartphone".

The TAT envelope is **vehicle-agnostic** — it does not prescribe smartphone or laptop. The receiver trust-kernel picks. This matches the Humotica one-sentence pitch:

> *"Identity is your hardware anchor. Trust is your fingerprint at the moment of use. No supercookie. Every grant is a fresh self-FIR/A."*

## Architecture

`tibet-genesis` is the **decision layer**. It writes `tibet.genesis.t-1.v1` JSONL records + emits TAT envelopes.

`tibet-audit genesis` is the **read-only audit layer** (separate package). It reads the genesis records and reports `ready` / `blocked` / `attention` per tool.

`tibet-drop` is the **TAT reference / CLI / dev tooling** (separate package). For TAT wire protocol details, conformance, and pack/inspect/verify CLI, use tibet-drop.

`trust-kernel` is the **enforcement runtime** (Rust, separate). On-device key custody, no-fail-open consent gate, transfer_out/in anchor signing, policy hooks to SNAFT/tibet-pol/airlock. Pixel 10 KIT embedded — already live as prior art.

```
tibet-genesis fork
       ↓
JSONL audit log: tibet.genesis.t-1.v1 + TAT envelopes (request_re_attestation)
       ↓                                ↓
tibet-audit genesis            trust-kernel (consume + enforce + pick vehicle)
       ↓                                ↓
operator-readable assessment    fresh biometric roundtrip → new T-1 capture
```

The layers are deliberately split: tibet-genesis decides, trust-kernel enforces, tibet-drop carries (when bytes need to move), tibet-audit observes.

## Pluggable verifiers

The default JIS verify + TIBET token-mint functions in `tibet_genesis.verdict` are placeholders (sufficient for tests). Production wires them to:

- `jis-core` — real Ed25519 signature verification of the JIS claim
- `tibet-core` — real TIBET token mint with HMAC-SHA256 provenance
- `tibet-airlock-kernel` — Rust execution airlock (process isolation, syscall monitoring)
- `trust-kernel` — TAT envelope consumption + biometric vehicle selection

The 10-step flow, TAT envelope shape, magic bytes, and SSM dispatch labels stay the same regardless of which verifiers are wired.

## Dependencies (bootstrap-or-die discipline)

- `tibet-core >= 0.5.0b2` — central provenance chain
- `jis-core >= 0.4.0b1` — central identity-store + bilateral consent

Optional extras:

- `[audit]`: `tibet-cap-bus`, `tibet-audit` — cross-contract validation
- `[tat]`: `tibet-drop>=0.3.1` — strict TAT envelope validation against the Touch-And-Transfer reference impl
  - Without `[tat]`: emit + validate own JSON shape + canonical hash
  - With `[tat]`: stricter TAT/interoperability validation
  - In production / trust-kernel mode: envelope is consumed by trust-kernel directly — the extra is for dev/CI conformance checks, not runtime trust

## CLI reference

| Command | What |
|---|---|
| `tibet-genesis fork --tool ID --registry URL [--schema ...] [--expect-hash ...]` | One candidate end-to-end. Emits genesis event + (if dirty) re-attest event + TAT envelope. |
| `tibet-genesis demo [--output PATH]` | 4 M4 fixture variants → JSONL for tibet-audit |
| `tibet-genesis version` | Print version |

Global flags: `--json` (raw JSON output including TAT envelope).

## Stack position

- Group: **safety** (pre-grant orchestration)
- Layer: above TAT, below trust-kernel
- Pair: writes evidence for [`tibet-audit`](https://pypi.org/project/tibet-audit/) `0.27.0+` (`genesis` subcommand) to read
- Emits: TAT envelopes consumed by `trust-kernel` (Pixel 10 KIT embedded + future laptop comms-kernel)
- Bootstrap: `tibet-core` + `jis-core` runtime deps (Humotica bootstrap-or-die discipline)

See `STACK.md` in the [Humotica org](https://github.com/Humotica/.github/blob/main/STACK.md) for the full canonical package map.


## Structural schema-enforcement (v0.1.4) — Principe 1, closes DEEPTHINK bulk-exfil

When an agent talks through a *legitimate* channel, bound the payload **shape**
mathematically — then exfil-sized or smuggled data breaks the contract structurally,
before any content is read. Weigh the structure, not the meaning.

```python
from tibet_genesis import SchemaContract, FieldSpec, validate_payload_shape

# an internal-API query tool may emit exactly this shape:
contract = SchemaContract(fields={
    "query": FieldSpec("string", max_len=50),
    "id":    FieldSpec("int", max_value=10_000_000),
})

validate_payload_shape({"query": "list users", "id": 42}, contract).ok   # True
# DEEPTHINK stuffs a base64 exfil blob into the 50-char field:
validate_payload_shape({"query": "QQ=="*500, "id": 1}, contract).ok      # False -> gate closes
```

Rejects: oversize payload (`max_total_bytes`), wrong type, over-length field, over-value
number, unexpected keys (smuggling), missing required field. Deterministic, machine-speed,
no intent-understanding. **Honest residual edge:** a secret that *fits* the bounded shape
(a short token in a 50-char field) passes structure — bulk-exfil dies here, low-bandwidth
fit-the-schema leak is the Causal TimeVector anomaly + rate-limit layer's job.

## License

MIT — see [`LICENSE`](./LICENSE).

## Credits

Architecture: **Codex** (T1_GENESIS_M4_PREGRANT_SPEC, 2026-05-31).
Self-FIR/A framing + TAT positioning + SSM dispatch convention: **Jasper van de Meent**, 2026-05-31.
Implementation: **Root AI (Claude)**, 2026-05-31.

Part of [HumoticaOS](https://humotica.com). One love, one fAmIly. 💙
