#!/usr/bin/env python3
"""ATT&CK technique-id lifecycle helpers shared by the builders and the validator.

One place that answers "is this technique id current, and if not, what replaced it?"
for every ATT&CK domain the library ships, so the edge builders (control rollup, CAPEC
backfill, CTID/vendor edges, the /mitre page loaders) and scripts/validate_jsonl.py all
apply the SAME supersession rule:

  * live        - a row in the domain's technique_profiles.jsonl that is not flagged
                  revoked/deprecated.
  * revoked     - an old_id in data/attack/superseded_by.jsonl whose new_id chain ends at
                  a live id of the same domain (followed transitively).
  * deprecated  - an old_id with reason "deprecated" and no successor.
  * dangling    - a revoked old_id whose chain ends at a non-live id (a data defect).
  * unknown     - in neither file (a data defect, e.g. a Mobile id in an Enterprise table).

Carry-forward: a mapping published against a revoked id (e.g. the CTID NIST 800-53
mapping, keyed on ATT&CK v16.1's T1562.001) still describes the same behaviour after
ATT&CK revoked it in favour of a successor (data/attack/superseded_by.jsonl), so builders re-key it to the live successor (T1685) and record the
predecessor id as provenance ("via_revoked"). The source rows themselves are kept.
"""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# paths relative to the repo root
DOMAIN_PROFILES = {
    "enterprise": "data/attack/technique_profiles.jsonl",
    "ics": "data/attack/ics/technique_profiles.jsonl",
    "mobile": "data/attack/mobile/technique_profiles.jsonl",
}
SUPERSEDED = "data/attack/superseded_by.jsonl"


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class AttackIds:
    """Technique-id status and successor resolution, per ATT&CK domain."""

    def __init__(self, root: Path = ROOT):
        self.profiles: dict[str, dict[str, dict]] = {}
        self.live: dict[str, set[str]] = {}
        for dom, rel in DOMAIN_PROFILES.items():
            rows = {r["technique_id"]: r for r in read_jsonl(root / rel)}
            self.profiles[dom] = rows
            self.live[dom] = {t for t, r in rows.items()
                              if not r.get("revoked") and not r.get("deprecated")}
        self.sup: dict[str, dict[str, dict]] = {d: {} for d in DOMAIN_PROFILES}
        for r in read_jsonl(root / SUPERSEDED):
            self.sup.setdefault(r.get("domain") or "enterprise", {})[r["old_id"]] = r

    # ------------------------------------------------------------------ resolution
    def terminal(self, tid: str, domain: str = "enterprise") -> str | None:
        """Follow superseded_by from tid to the end of its chain (None if the chain
        ends in a deprecation). Returns tid itself if it is not superseded."""
        sup = self.sup.get(domain, {})
        seen = set()
        cur = tid
        while cur in sup and cur not in seen:
            seen.add(cur)
            nxt = sup[cur].get("new_id")
            if not nxt:
                return None
            cur = nxt
        return cur

    def status(self, tid: str, domain: str = "enterprise") -> tuple[str, str | None]:
        """(state, successor) where state is live|revoked|deprecated|dangling|unknown and
        successor is the live id a revoked id resolves to (else None)."""
        if tid in self.live.get(domain, ()):
            return "live", None
        rec = self.sup.get(domain, {}).get(tid)
        if rec is None:
            return "unknown", None
        end = self.terminal(tid, domain)
        if end is None:
            return "deprecated", None
        if end in self.live.get(domain, ()):
            return "revoked", end
        return "dangling", None

    def resolve(self, tid: str, domain: str = "enterprise") -> str | None:
        """The live id tid stands for today (tid itself if live), else None."""
        state, succ = self.status(tid, domain)
        if state == "live":
            return tid
        return succ if state == "revoked" else None

    def predecessors(self, domain: str = "enterprise") -> dict[str, list[str]]:
        """live successor id -> sorted revoked ids whose chain resolves to it."""
        out: dict[str, set] = {}
        for old in self.sup.get(domain, {}):
            state, succ = self.status(old, domain)
            if state == "revoked":
                out.setdefault(succ, set()).add(old)
        return {k: sorted(v) for k, v in out.items()}

    def carry_forward(self, edges: dict[str, set], domain: str = "enterprise"):
        """Given technique_id -> set(targets), return (merged, provenance):
        merged[t]     = edges[t] | every revoked predecessor's edges (t live)
        provenance[t] = {predecessor_id: sorted(targets)} for predecessors that carried
                        at least one target. Revoked ids keep their own edges."""
        merged = {t: set(v) for t, v in edges.items()}
        provenance: dict[str, dict[str, list]] = {}
        for succ, olds in self.predecessors(domain).items():
            for old in olds:
                carried = edges.get(old)
                if not carried:
                    continue
                merged.setdefault(succ, set()).update(carried)
                provenance.setdefault(succ, {})[old] = sorted(carried)
        return merged, provenance
