#!/usr/bin/env python3
"""
Minimal Sigma → KQL converter, targeted at Microsoft Defender XDR / Sentinel tables.

Scope: handles the subset of Sigma we actually want from public repos —
process_creation, network_connection, image_load, registry_event for Windows.
Stdlib only (pyyaml optional, falls back to error if missing).

Usage:
    python scripts/sigma_to_kql.py <sigma-file.yml>
    python scripts/sigma_to_kql.py --batch sigma/process_creation/*.yml > converted.kql

Not a full pySigma replacement. It's a pragmatic bridge so you can ingest a
public Sigma rule, get 80% of the way to a Sentinel rule, then hand-tune.
"""
from __future__ import annotations

import argparse
import glob
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("pyyaml is required: pip install pyyaml", file=sys.stderr)
    sys.exit(2)

# Sigma logsource.category → MDE/Sentinel table + field map
TABLE_MAP = {
    "process_creation": {
        "table": "DeviceProcessEvents",
        "fields": {
            "Image": "FolderPath",
            "OriginalFileName": "FileName",
            "CommandLine": "ProcessCommandLine",
            "ParentImage": "InitiatingProcessFolderPath",
            "ParentCommandLine": "InitiatingProcessCommandLine",
            "User": "AccountName",
            "IntegrityLevel": "ProcessIntegrityLevel",
            "Hashes": "SHA256",
        },
    },
    "network_connection": {
        "table": "DeviceNetworkEvents",
        "fields": {
            "Image": "InitiatingProcessFolderPath",
            "DestinationIp": "RemoteIP",
            "DestinationPort": "RemotePort",
            "DestinationHostname": "RemoteUrl",
            "SourcePort": "LocalPort",
        },
    },
    "image_load": {
        "table": "DeviceImageLoadEvents",
        "fields": {
            "Image": "InitiatingProcessFolderPath",
            "ImageLoaded": "FolderPath",
            "OriginalFileName": "FileName",
        },
    },
    "registry_event": {
        "table": "DeviceRegistryEvents",
        "fields": {
            "TargetObject": "RegistryKey",
            "Details": "RegistryValueData",
            "EventType": "ActionType",
            "Image": "InitiatingProcessFolderPath",
        },
    },
}


def _render_value(field: str, value, table_fields: dict[str, str]) -> str:
    kql_field = table_fields.get(field, field)
    op_endswith = field.endswith("|endswith")
    op_startswith = field.endswith("|startswith")
    op_contains = field.endswith("|contains")
    op_re = field.endswith("|re")
    base_field = field.split("|", 1)[0]
    kql_field = table_fields.get(base_field, base_field)
    values = value if isinstance(value, list) else [value]
    quoted = [f'"{str(v)}"' for v in values]
    if op_re:
        return f"{kql_field} matches regex {quoted[0]}"
    if op_endswith:
        return f"{kql_field} endswith_cs any ({', '.join(quoted)})" if len(quoted) > 1 else f"{kql_field} endswith {quoted[0]}"
    if op_startswith:
        return f"{kql_field} startswith {quoted[0]}" if len(quoted) == 1 else f"{kql_field} has_any ({', '.join(quoted)})"
    if op_contains:
        return f"{kql_field} has_any ({', '.join(quoted)})"
    if len(quoted) > 1:
        return f"{kql_field} in~ ({', '.join(quoted)})"
    return f"{kql_field} =~ {quoted[0]}"


def _render_block(block: dict, table_fields: dict[str, str]) -> str:
    parts = [_render_value(k, v, table_fields) for k, v in block.items()]
    return " and ".join(parts)


def convert(sigma: dict) -> str:
    category = (sigma.get("logsource") or {}).get("category", "")
    if category not in TABLE_MAP:
        raise ValueError(f"Unsupported logsource.category: {category!r}")
    table = TABLE_MAP[category]["table"]
    fields = TABLE_MAP[category]["fields"]

    det = sigma.get("detection") or {}
    condition = det.get("condition", "selection")
    blocks = {k: v for k, v in det.items() if k != "condition" and k != "timeframe"}

    rendered = {}
    for name, block in blocks.items():
        if isinstance(block, list):
            sub = [_render_block(b, fields) if isinstance(b, dict) else "" for b in block]
            sub = [s for s in sub if s]
            rendered[name] = "(" + " or ".join(f"({s})" for s in sub) + ")"
        elif isinstance(block, dict):
            rendered[name] = "(" + _render_block(block, fields) + ")"

    expr = condition
    for name, val in rendered.items():
        expr = expr.replace(name, val)
    expr = expr.replace(" and ", " and ").replace(" or ", " or ").replace(" not ", " not ")

    title = sigma.get("title", "Converted Sigma rule")
    desc = sigma.get("description", "")
    sigma_id = sigma.get("id", "")
    techniques = []
    for tag in sigma.get("tags", []) or []:
        if tag.startswith("attack.t"):
            techniques.append(tag.split(".", 1)[1].upper())

    out = []
    out.append(f"// {title}")
    if sigma_id:
        out.append(f"// Sigma ID: {sigma_id}")
    if desc:
        for line in desc.splitlines():
            out.append(f"// {line.strip()}")
    if techniques:
        out.append(f"// ATT&CK: {', '.join(techniques)}")
    out.append(f"{table}")
    out.append(f"| where {expr}")
    out.append("")
    return "\n".join(out)


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("path", nargs="+", help="Sigma YAML file(s) or globs")
    p.add_argument("--batch", action="store_true", help="treat paths as globs")
    args = p.parse_args()

    files: list[Path] = []
    if args.batch:
        for pat in args.path:
            for f in glob.glob(pat):
                files.append(Path(f))
    else:
        files = [Path(p) for p in args.path]

    failures = 0
    for f in files:
        try:
            sigma = yaml.safe_load(f.read_text(encoding="utf-8"))
            print(convert(sigma))
        except Exception as exc:
            print(f"// FAILED: {f}: {exc}", file=sys.stderr)
            failures += 1
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
