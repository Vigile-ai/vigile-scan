#!/usr/bin/env python3
"""Cross-repo parity gate for CRITICAL/HIGH detection patterns.

This checker compares API vs CLI pattern IDs/severities for:
- MCP patterns (TP/EX/PM/OB)
- Skill patterns (SK)
- Sentinel patterns (SN)

The check fails when parity drifts for CRITICAL/HIGH classes in either direction.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

STRICT_DEFAULT = {"critical", "high"}
GROUPS = ("mcp", "skill", "sentinel")
GROUP_PREFIXES = {
    "mcp": {"TP", "EX", "PM", "OB"},
    "skill": {"SK"},
    "sentinel": {"SN"},
}

REPO_FILES = {
    "api": {
        "mcp": "app/scan/scanner.py",
        "skill": "app/scan/skill_scanner.py",
        "sentinel": "app/sentinel/analyzer.py",
    },
    "cli": {
        "mcp": "src/scanner/patterns.ts",
        "skill": "src/scanner/skill-patterns.ts",
        "sentinel": "src/sentinel/sentinel-patterns.ts",
    },
}

TS_ID_SEV_RE = re.compile(
    r"\bid\s*:\s*['\"](?P<id>[A-Z]{2}-\d{3})['\"]\s*,"
    r"(?:(?!\bid\s*:)[\s\S]){0,260}?"
    r"\bseverity\s*:\s*['\"](?P<severity>[a-z]+)['\"]",
    re.MULTILINE,
)

PY_DICT_ID_SEV_RE = re.compile(
    r"['\"]id['\"]\s*:\s*['\"](?P<id>[A-Z]{2}-\d{3})['\"]\s*,"
    r"(?:(?!['\"]id['\"]\s*:)[\s\S]){0,260}?"
    r"['\"]severity['\"]\s*:\s*['\"](?P<severity>[a-z]+)['\"]",
    re.MULTILINE,
)

PY_TUPLE_ID_SEV_RE = re.compile(
    r"\(\s*['\"](?P<id>[A-Z]{2}-\d{3})['\"]\s*,\s*"
    r"['\"](?P<severity>[a-z]+)['\"]\s*,",
    re.MULTILINE,
)


@dataclass(frozen=True)
class Drift:
    group: str
    pattern_id: str
    severity: str
    source: str


@dataclass(frozen=True)
class SeverityMismatch:
    group: str
    pattern_id: str
    self_severity: str
    counterpart_severity: str


def _prefix(pattern_id: str) -> str:
    return pattern_id.split("-", 1)[0]


def _add_pair(target: Dict[str, str], pattern_id: str, severity: str, file_path: Path) -> None:
    normalized = severity.lower().strip()
    if pattern_id in target and target[pattern_id] != normalized:
        raise ValueError(
            f"Pattern {pattern_id} has conflicting severities in {file_path}: "
            f"{target[pattern_id]} vs {normalized}"
        )
    target[pattern_id] = normalized


def _extract_pairs(file_path: Path, repo_kind: str) -> Dict[str, str]:
    text = file_path.read_text(encoding="utf-8")
    pairs: Dict[str, str] = {}

    if repo_kind == "cli":
        for match in TS_ID_SEV_RE.finditer(text):
            _add_pair(pairs, match.group("id"), match.group("severity"), file_path)
        return pairs

    for match in PY_DICT_ID_SEV_RE.finditer(text):
        _add_pair(pairs, match.group("id"), match.group("severity"), file_path)
    for match in PY_TUPLE_ID_SEV_RE.finditer(text):
        _add_pair(pairs, match.group("id"), match.group("severity"), file_path)

    return pairs


def parse_repo(repo_root: Path, repo_kind: str) -> Dict[str, Dict[str, str]]:
    parsed: Dict[str, Dict[str, str]] = {group: {} for group in GROUPS}
    file_map = REPO_FILES[repo_kind]

    for group, rel_path in file_map.items():
        path = repo_root / rel_path
        if not path.exists():
            raise FileNotFoundError(f"Missing required file: {path}")

        all_pairs = _extract_pairs(path, repo_kind)
        prefixes = GROUP_PREFIXES[group]
        filtered = {
            pattern_id: severity
            for pattern_id, severity in all_pairs.items()
            if _prefix(pattern_id) in prefixes
        }
        parsed[group] = filtered

    return parsed


def run_parity_check(
    self_repo_root: Path,
    counterpart_root: Path,
    self_repo_kind: str,
    strict_severities: set[str],
) -> dict:
    counterpart_kind = "cli" if self_repo_kind == "api" else "api"

    self_patterns = parse_repo(self_repo_root, self_repo_kind)
    counterpart_patterns = parse_repo(counterpart_root, counterpart_kind)

    missing_in_counterpart: list[Drift] = []
    missing_in_self: list[Drift] = []
    severity_mismatches: list[SeverityMismatch] = []

    for group in GROUPS:
        mine = self_patterns[group]
        other = counterpart_patterns[group]

        for pattern_id, severity in sorted(mine.items()):
            if pattern_id not in other and severity in strict_severities:
                missing_in_counterpart.append(
                    Drift(group=group, pattern_id=pattern_id, severity=severity, source=self_repo_kind)
                )

        for pattern_id, severity in sorted(other.items()):
            if pattern_id not in mine and severity in strict_severities:
                missing_in_self.append(
                    Drift(group=group, pattern_id=pattern_id, severity=severity, source=counterpart_kind)
                )

        for pattern_id in sorted(set(mine.keys()) & set(other.keys())):
            mine_sev = mine[pattern_id]
            other_sev = other[pattern_id]
            if mine_sev != other_sev and (mine_sev in strict_severities or other_sev in strict_severities):
                severity_mismatches.append(
                    SeverityMismatch(
                        group=group,
                        pattern_id=pattern_id,
                        self_severity=mine_sev,
                        counterpart_severity=other_sev,
                    )
                )

    ok = not missing_in_counterpart and not missing_in_self and not severity_mismatches

    return {
        "ok": ok,
        "self_repo_kind": self_repo_kind,
        "counterpart_repo_kind": counterpart_kind,
        "strict_severities": sorted(strict_severities),
        "counts": {
            "self": {group: len(self_patterns[group]) for group in GROUPS},
            "counterpart": {group: len(counterpart_patterns[group]) for group in GROUPS},
        },
        "missing_in_counterpart": [d.__dict__ for d in missing_in_counterpart],
        "missing_in_self": [d.__dict__ for d in missing_in_self],
        "severity_mismatches": [m.__dict__ for m in severity_mismatches],
    }


def _print_report(report: dict) -> None:
    print("=== Pattern Parity Gate (CRITICAL/HIGH) ===")
    print(
        f"self={report['self_repo_kind']} counterpart={report['counterpart_repo_kind']} "
        f"strict={','.join(report['strict_severities'])}"
    )
    print(
        "counts self="
        f"{report['counts']['self']['mcp']} MCP, "
        f"{report['counts']['self']['skill']} SK, "
        f"{report['counts']['self']['sentinel']} SN"
    )
    print(
        "counts counterpart="
        f"{report['counts']['counterpart']['mcp']} MCP, "
        f"{report['counts']['counterpart']['skill']} SK, "
        f"{report['counts']['counterpart']['sentinel']} SN"
    )

    if report["ok"]:
        print("PASS: no CRITICAL/HIGH parity drift")
        return

    if report["missing_in_counterpart"]:
        print("FAIL: strict patterns missing in counterpart")
        for item in report["missing_in_counterpart"]:
            print(f"  - {item['pattern_id']} ({item['severity']}) [{item['group']}]")

    if report["missing_in_self"]:
        print("FAIL: strict patterns missing in self")
        for item in report["missing_in_self"]:
            print(f"  - {item['pattern_id']} ({item['severity']}) [{item['group']}]")

    if report["severity_mismatches"]:
        print("FAIL: strict severity mismatches")
        for item in report["severity_mismatches"]:
            print(
                f"  - {item['pattern_id']} [{item['group']}] "
                f"self={item['self_severity']} counterpart={item['counterpart_severity']}"
            )


def _default_counterpart(self_root: Path, self_repo_kind: str) -> Path:
    sibling = "vigile-cli" if self_repo_kind == "api" else "vigile-api"
    return self_root.parent / sibling


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-repo", choices=("api", "cli"), required=True)
    parser.add_argument("--self-root", default=".", help="Root path of current repo")
    parser.add_argument(
        "--counterpart-root",
        default=None,
        help="Root path of counterpart repo (defaults to sibling checkout)",
    )
    parser.add_argument(
        "--strict-severities",
        default="critical,high",
        help="Comma-separated severities treated as hard-fail (default: critical,high)",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON report")
    args = parser.parse_args()

    self_root = Path(args.self_root).resolve()
    counterpart_root = (
        Path(args.counterpart_root).resolve()
        if args.counterpart_root
        else _default_counterpart(self_root, args.self_repo)
    )

    strict = {s.strip().lower() for s in args.strict_severities.split(",") if s.strip()}
    if not strict:
        print("ERROR: strict severity set is empty", file=sys.stderr)
        return 2

    try:
        report = run_parity_check(
            self_repo_root=self_root,
            counterpart_root=counterpart_root,
            self_repo_kind=args.self_repo,
            strict_severities=strict,
        )
    except Exception as exc:
        print(f"ERROR: parity check failed to execute: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        _print_report(report)

    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
