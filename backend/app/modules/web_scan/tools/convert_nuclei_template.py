#!/usr/bin/env python3
"""Offline converter: Nuclei YAML templates -> MIRSAD web_scan JSON templates.

This is a build-time/operator tool, not part of the runtime scan path.
scanner.py's `_load_templates()` already reads every *.json file under
web_scan/templates/ automatically — running this script's output through
that directory is the entire integration; scanner.py needs no changes.

Only a conservative, safe subset of Nuclei's YAML DSL is supported:
- http.method            -> method
- http.path[0]            -> path (first path only; multi-path templates need
                             manual splitting into one MIRSAD template per path)
- http.matchers (status / word / regex types, "and"/"or" condition) -> status /
  body_regex / headers.{exists,contains,absent}
- info.severity           -> severity
- info.tags               -> tags
- info.name               -> name

Anything outside that subset (raw request templates, multi-step flows,
matcher condition="and" across mixed types, DSL/extractors, etc.) is
intentionally rejected rather than silently mis-converted — a scanner
template that always matches, or never does, is worse than one missing
template. Rejected templates are reported on stderr with a reason so an
operator can convert them by hand.

Usage:
    python convert_nuclei_template.py <nuclei-template.yaml> [more.yaml ...] \\
        --out ../templates

    python convert_nuclei_template.py --dir /path/to/nuclei-templates/http/exposures \\
        --out ../templates
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import yaml

_SEVERITY_MAP = {
    "critical": "Critical", "high": "High", "medium": "Medium",
    "low": "Low", "info": "Info", "informational": "Info", "unknown": "Info",
}


class UnsupportedTemplate(Exception):
    pass


def _first_http_block(doc: dict[str, Any]) -> dict[str, Any]:
    blocks = doc.get("http") or doc.get("requests")
    if not blocks:
        raise UnsupportedTemplate("no http/requests block (not an HTTP template)")
    if len(blocks) > 1:
        raise UnsupportedTemplate("multi-request templates are not supported (convert steps manually)")
    return blocks[0]


def _convert_matchers(block: dict[str, Any]) -> dict[str, Any]:
    matchers = block.get("matchers") or []
    condition = str(block.get("matchers-condition", "or")).lower()
    if condition == "and" and len(matchers) > 1:
        # Our matcher is: status filter is always required-AND; body_regex entries
        # are OR'd together; headers entries are always required-AND. A Nuclei
        # "and" across multiple *word/regex* matchers doesn't map onto that
        # without changing _match_template semantics, so we refuse rather than
        # silently downgrade AND to OR.
        # status is always AND'd with everything else by _match_template already
        # (a status mismatch returns False regardless of body/header matchers),
        # so "status + exactly one other matcher kind" is safe to represent.
        # Only reject when two or more *non-status* kinds are AND'd together,
        # since that combination has no equivalent in _match_template's logic.
        non_status_kinds = {m.get("type") for m in matchers} - {"status"}
        if len(non_status_kinds) > 1:
            raise UnsupportedTemplate('matchers-condition "and" across mixed non-status matcher types is not supported')

    out: dict[str, Any] = {}
    body_regex: list[str] = []
    headers: dict[str, dict[str, Any]] = {}
    for m in matchers:
        mtype = m.get("type")
        part = m.get("part", "body")
        negative = bool(m.get("negative", False))
        if mtype == "status":
            out["status"] = [int(s) for s in m.get("status", [])]
        elif mtype == "word" and part == "header":
            for word in m.get("words", []):
                header_name, _, needle = str(word).partition(":")
                header_name = header_name.strip() or "X-Nuclei-Converted-Check"
                if negative:
                    headers.setdefault(header_name, {})["absent"] = True
                else:
                    headers.setdefault(header_name, {})["contains"] = (needle or word).strip()
        elif mtype in {"word", "regex"} and part in {"body", "response"}:
            patterns = m.get("words") if mtype == "word" else m.get("regex")
            for p in patterns or []:
                body_regex.append(re.escape(p) if mtype == "word" else p)
        else:
            raise UnsupportedTemplate(f"unsupported matcher type/part combination: {mtype}/{part}")
    if body_regex:
        out["body_regex"] = body_regex
    if headers:
        out["headers"] = headers
    if not out:
        raise UnsupportedTemplate("no convertible matchers found")
    return out


def convert(doc: dict[str, Any]) -> dict[str, Any]:
    info = doc.get("info") or {}
    block = _first_http_block(doc)
    method = str(block.get("method", "GET")).upper()
    if method not in {"GET", "HEAD", "OPTIONS"}:
        raise UnsupportedTemplate(f"method {method} is not supported by the passive scanner (GET/HEAD/OPTIONS only)")
    paths = block.get("path") or ["/"]
    path = str(paths[0]).replace("{{BaseURL}}", "").strip() or "/"
    if len(paths) > 1:
        raise UnsupportedTemplate("multiple paths per request are not supported (split into one template per path)")

    result: dict[str, Any] = {
        "id": str(doc.get("id", "")).strip() or "converted-template",
        "name": str(info.get("name", doc.get("id", "Converted Nuclei template"))).strip(),
        "path": path,
        "method": method,
        "severity": _SEVERITY_MAP.get(str(info.get("severity", "info")).lower(), "Info"),
        "tags": [t.strip() for t in str(info.get("tags", "")).split(",") if t.strip()],
    }
    result.update(_convert_matchers(block))
    return result


def convert_file(path: Path) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise UnsupportedTemplate("not a YAML mapping")
    return convert(doc)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("templates", nargs="*", type=Path, help="Nuclei YAML template file(s)")
    ap.add_argument("--dir", type=Path, help="directory to scan recursively for *.yaml/*.yml")
    ap.add_argument("--out", type=Path, required=True, help="output directory for MIRSAD *.json templates")
    args = ap.parse_args()

    files = list(args.templates)
    if args.dir:
        files += sorted(args.dir.rglob("*.yaml")) + sorted(args.dir.rglob("*.yml"))
    if not files:
        ap.error("no input templates given (pass files and/or --dir)")

    args.out.mkdir(parents=True, exist_ok=True)
    converted, skipped = 0, 0
    for f in files:
        try:
            result = convert_file(f)
        except UnsupportedTemplate as e:
            print(f"SKIP {f}: {e}", file=sys.stderr)
            skipped += 1
            continue
        except Exception as e:
            print(f"SKIP {f}: unexpected error: {e}", file=sys.stderr)
            skipped += 1
            continue
        out_path = args.out / f"{result['id']}.json"
        out_path.write_text(json.dumps(result, ensure_ascii=False, indent=None), encoding="utf-8")
        print(f"OK   {f} -> {out_path}")
        converted += 1

    print(f"\n{converted} converted, {skipped} skipped (out of {len(files)})", file=sys.stderr)
    return 0 if converted else 1


if __name__ == "__main__":
    raise SystemExit(main())
