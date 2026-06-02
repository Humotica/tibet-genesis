"""Structural schema-enforcement for the T-1 genesis sluice (Principe 1, Jasper 1 juni).

Closes the DEEPTHINK bulk-exfil gap: when an agent talks through a *legitimate* channel,
bound the payload SHAPE mathematically. If the allowed output of a tool is exactly
{"query": string(max 50), "id": int}, then the moment a payload tries to stuff a base64
blob or a giant text block into it, structural validation collapses and SNAFT closes the
gate — at bare-metal level, deterministic, machine-speed.

**Weigh the structure, not the meaning.** No intent-understanding, no content-scanning;
just: does the payload's shape fit the mathematically-bounded contract? This is what makes
it cheap and un-foolable — a 50-char field cannot carry a 5KB exfil regardless of *what*
the 50 chars say.

Residual edge (honest, see SPECTER SLEEPER mapping): a secret that *fits* the bounded shape
(a 50-char field that IS a short token) passes structure. Bulk-exfil dies here; low-bandwidth
fit-the-schema leak is the TimeVector causal-anomaly + rate-limit layer's job, not this one.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class FieldSpec:
    """Bounded type-contract for one payload field."""
    type: str                       # "string" | "int" | "float" | "bool" | "list" | "object"
    max_len: Optional[int] = None   # strings (chars) / lists (items)
    max_value: Optional[int] = None # ints/floats (absolute)
    required: bool = True


@dataclass
class SchemaContract:
    """The mathematically-bounded shape a tool's payload may take.

    Example — an internal-API query tool:
        SchemaContract(fields={
            "query": FieldSpec("string", max_len=50),
            "id":    FieldSpec("int", max_value=10_000_000),
        })
    """
    fields: dict[str, FieldSpec] = field(default_factory=dict)
    allow_extra_keys: bool = False
    max_total_bytes: int = 4096      # hard ceiling on the serialized payload

    _PYTYPES = {
        "string": str, "int": int, "float": (int, float),
        "bool": bool, "list": list, "object": dict,
    }

    def _check_field(self, name: str, spec: FieldSpec, value: Any) -> list[str]:
        v: list[str] = []
        py = self._PYTYPES.get(spec.type)
        # bool is a subclass of int in Python — guard so an int field rejects True/False
        if spec.type == "int" and isinstance(value, bool):
            return [f"{name}: expected int, got bool"]
        if py is not None and not isinstance(value, py):
            return [f"{name}: expected {spec.type}, got {type(value).__name__}"]
        if spec.type in ("string", "list") and spec.max_len is not None:
            if len(value) > spec.max_len:
                v.append(f"{name}: {spec.type} length {len(value)} exceeds max_len {spec.max_len}")
        if spec.type in ("int", "float") and spec.max_value is not None:
            if abs(value) > spec.max_value:
                v.append(f"{name}: value {value} exceeds max_value {spec.max_value}")
        return v


@dataclass
class ShapeVerdict:
    ok: bool
    violations: list[str] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.ok


def validate_payload_shape(payload: Any, contract: SchemaContract) -> ShapeVerdict:
    """Structural-only validation of a payload against a bounded contract.

    Returns ok=False with reasons on ANY of: oversized payload, wrong type, over-length
    field, over-value number, unexpected key, missing required field. Deterministic; never
    inspects semantic content.
    """
    violations: list[str] = []

    # 1. Hard total-size ceiling (kills bulk-exfil regardless of structure).
    try:
        size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError):
        return ShapeVerdict(False, ["payload is not JSON-serializable"])
    if size > contract.max_total_bytes:
        violations.append(f"payload {size} bytes exceeds max_total_bytes {contract.max_total_bytes}")

    if not isinstance(payload, dict):
        violations.append(f"payload must be an object, got {type(payload).__name__}")
        return ShapeVerdict(False, violations)

    # 2. Unexpected keys (smuggling channel).
    if not contract.allow_extra_keys:
        extra = set(payload) - set(contract.fields)
        if extra:
            violations.append(f"unexpected keys (not in contract): {sorted(extra)}")

    # 3. Per-field type + bounds.
    for name, spec in contract.fields.items():
        if name not in payload:
            if spec.required:
                violations.append(f"{name}: required field missing")
            continue
        violations.extend(contract._check_field(name, spec, payload[name]))

    return ShapeVerdict(len(violations) == 0, violations)
