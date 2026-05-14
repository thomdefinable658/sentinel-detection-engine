#!/usr/bin/env python3
"""
CI validation for sentinel-detection-engine rules.

Checks every YAML under Detections/ and Hunting Queries/:
  1. Required fields are present (id, name, description, query, tactics, relevantTechniques).
  2. id is a valid UUID.
  3. severity (detections only) is one of Informational/Low/Medium/High.
  4. tactics values are valid ATT&CK tactic names.
  5. relevantTechniques values match the ATT&CK technique-ID regex (TNNNN or TNNNN.NNN).
  6. KQL block parses well enough — balanced parens/brackets, no obvious truncation.

Stdlib only.
"""
from __future__ import annotations

import re
import sys
import uuid
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parent.parent
RULE_DIRS = [
    (REPO / "Detections", True),         # (path, is_detection)
    (REPO / "Hunting Queries", False),
]

VALID_TACTICS = {
    "Reconnaissance", "ResourceDevelopment", "InitialAccess", "Execution",
    "Persistence", "PrivilegeEscalation", "DefenseEvasion", "CredentialAccess",
    "Discovery", "LateralMovement", "Collection", "CommandAndControl",
    "Exfiltration", "Impact",
}
VALID_SEVERITY = {"Informational", "Low", "Medium", "High"}
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
REQUIRED_COMMON = {"id", "name", "description", "query", "tactics", "relevantTechniques"}


def check_kql_balance(query: str, errs: list[str]) -> None:
    pairs = {"(": ")", "[": "]", "{": "}"}
    stack: list[str] = []
    for ch in query:
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in pairs.values():
            if not stack or stack[-1] != ch:
                errs.append(f"unbalanced bracket near '{ch}'")
                return
            stack.pop()
    if stack:
        errs.append(f"unclosed brackets, expected: {''.join(reversed(stack))}")


def validate_file(path: Path, is_detection: bool) -> list[str]:
    errs: list[str] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [f"YAML parse error: {exc}"]
    if not isinstance(data, dict):
        return ["top-level YAML is not a mapping"]

    missing = REQUIRED_COMMON - data.keys()
    if missing:
        errs.append(f"missing required fields: {sorted(missing)}")

    rid = data.get("id", "")
    try:
        uuid.UUID(str(rid))
    except ValueError:
        errs.append(f"id is not a valid UUID: {rid!r}")

    if is_detection:
        sev = data.get("severity")
        if sev not in VALID_SEVERITY:
            errs.append(f"severity {sev!r} not in {sorted(VALID_SEVERITY)}")

    for tac in data.get("tactics") or []:
        if tac not in VALID_TACTICS:
            errs.append(f"unknown tactic: {tac!r}")

    techs = data.get("relevantTechniques") or []
    if not techs:
        errs.append("relevantTechniques is empty")
    for t in techs:
        if not TECH_RE.match(str(t)):
            errs.append(f"bad ATT&CK technique id: {t!r}")

    query = data.get("query") or ""
    if not query.strip():
        errs.append("query is empty")
    else:
        check_kql_balance(query, errs)
        if len(query.strip().splitlines()) < 2:
            errs.append("query is suspiciously short (< 2 lines)")

    return errs


def main() -> int:
    failed = 0
    total = 0
    for d, is_det in RULE_DIRS:
        if not d.is_dir():
            continue
        for path in sorted(d.glob("*.yaml")):
            total += 1
            errs = validate_file(path, is_det)
            rel = path.relative_to(REPO).as_posix()
            if errs:
                failed += 1
                for e in errs:
                    print(f"::error file={rel}::{e}")
            else:
                print(f"ok  {rel}")
    print(f"\n{total - failed}/{total} files passed validation.")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
