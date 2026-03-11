#!/usr/bin/env python3
"""Regression tests for the CRITICAL/HIGH parity gate."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "check_pattern_parity.py"
SPEC = importlib.util.spec_from_file_location("check_pattern_parity", SCRIPT_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Unable to load check_pattern_parity.py")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


def _ts_objects(entries: list[tuple[str, str]], include_removed_comment: bool = False) -> str:
    lines = ["export const PATTERNS = ["]
    if include_removed_comment:
        lines.extend(
            [
                "  // TP-003 removed: old broad pattern",
                "  // this comment intentionally includes a pattern id",
            ]
        )
    for pattern_id, severity in entries:
        lines.append(f"  {{ id: '{pattern_id}', severity: '{severity}', title: 'x' }},")
    lines.append("];\n")
    return "\n".join(lines)


def _py_dicts(entries: list[tuple[str, str]]) -> str:
    body = ",\n".join([f'    {{"id": "{pid}", "severity": "{sev}"}}' for pid, sev in entries])
    return f"PATTERNS = [\n{body}\n]\n"


def _py_tuples(entries: list[tuple[str, str]]) -> str:
    body = ",\n".join([f'    ("{pid}", "{sev}", "title")' for pid, sev in entries])
    return f"ALL_SKILL_PATTERNS = [\n{body}\n]\n"


def _write_cli_repo(root: Path, mcp: list[tuple[str, str]], skill: list[tuple[str, str]], sentinel: list[tuple[str, str]], include_removed_comment: bool = False) -> None:
    (root / "src/scanner").mkdir(parents=True, exist_ok=True)
    (root / "src/sentinel").mkdir(parents=True, exist_ok=True)

    (root / "src/scanner/patterns.ts").write_text(_ts_objects(mcp, include_removed_comment), encoding="utf-8")
    (root / "src/scanner/skill-patterns.ts").write_text(_ts_objects(skill), encoding="utf-8")
    (root / "src/sentinel/sentinel-patterns.ts").write_text(_ts_objects(sentinel), encoding="utf-8")


def _write_api_repo(root: Path, mcp: list[tuple[str, str]], skill: list[tuple[str, str]], sentinel: list[tuple[str, str]]) -> None:
    (root / "app/scan").mkdir(parents=True, exist_ok=True)
    (root / "app/sentinel").mkdir(parents=True, exist_ok=True)

    (root / "app/scan/scanner.py").write_text(_py_dicts(mcp), encoding="utf-8")
    (root / "app/scan/skill_scanner.py").write_text(_py_tuples(skill), encoding="utf-8")
    (root / "app/sentinel/analyzer.py").write_text(_py_dicts(sentinel), encoding="utf-8")


class PatternParityCheckerTests(unittest.TestCase):
    def test_ignores_removed_comment_and_passes_when_strict_patterns_match(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cli = root / "cli"
            api = root / "api"

            _write_cli_repo(
                cli,
                mcp=[("TP-001", "critical")],
                skill=[("SK-001", "critical")],
                sentinel=[("SN-001", "high")],
                include_removed_comment=True,
            )
            _write_api_repo(
                api,
                mcp=[("TP-001", "critical")],
                skill=[("SK-001", "critical")],
                sentinel=[("SN-001", "high")],
            )

            report = CHECKER.run_parity_check(cli, api, "cli", {"critical", "high"})
            self.assertTrue(report["ok"])

    def test_fails_when_cli_has_high_pattern_missing_in_api(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cli = root / "cli"
            api = root / "api"

            _write_cli_repo(
                cli,
                mcp=[("TP-001", "critical"), ("EX-004", "high")],
                skill=[("SK-001", "critical")],
                sentinel=[("SN-001", "high")],
            )
            _write_api_repo(
                api,
                mcp=[("TP-001", "critical")],
                skill=[("SK-001", "critical")],
                sentinel=[("SN-001", "high")],
            )

            report = CHECKER.run_parity_check(cli, api, "cli", {"critical", "high"})
            self.assertFalse(report["ok"])
            missing = {item["pattern_id"] for item in report["missing_in_counterpart"]}
            self.assertIn("EX-004", missing)

    def test_fails_when_api_has_critical_pattern_missing_in_cli(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cli = root / "cli"
            api = root / "api"

            _write_cli_repo(
                cli,
                mcp=[("TP-001", "critical")],
                skill=[("SK-001", "critical")],
                sentinel=[("SN-001", "high")],
            )
            _write_api_repo(
                api,
                mcp=[("TP-001", "critical")],
                skill=[("SK-001", "critical"), ("SK-062", "critical")],
                sentinel=[("SN-001", "high")],
            )

            report = CHECKER.run_parity_check(cli, api, "cli", {"critical", "high"})
            self.assertFalse(report["ok"])
            missing = {item["pattern_id"] for item in report["missing_in_self"]}
            self.assertIn("SK-062", missing)

    def test_medium_gap_does_not_fail_strict_gate(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cli = root / "cli"
            api = root / "api"

            _write_cli_repo(
                cli,
                mcp=[("TP-001", "critical"), ("TP-007", "medium")],
                skill=[("SK-001", "critical")],
                sentinel=[("SN-001", "high")],
            )
            _write_api_repo(
                api,
                mcp=[("TP-001", "critical")],
                skill=[("SK-001", "critical")],
                sentinel=[("SN-001", "high")],
            )

            report = CHECKER.run_parity_check(cli, api, "cli", {"critical", "high"})
            self.assertTrue(report["ok"])

    def test_fails_on_strict_severity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cli = root / "cli"
            api = root / "api"

            _write_cli_repo(
                cli,
                mcp=[("TP-001", "critical")],
                skill=[("SK-001", "critical")],
                sentinel=[("SN-001", "high")],
            )
            _write_api_repo(
                api,
                mcp=[("TP-001", "high")],
                skill=[("SK-001", "critical")],
                sentinel=[("SN-001", "high")],
            )

            report = CHECKER.run_parity_check(cli, api, "cli", {"critical", "high"})
            self.assertFalse(report["ok"])
            mismatch_ids = {item["pattern_id"] for item in report["severity_mismatches"]}
            self.assertIn("TP-001", mismatch_ids)


if __name__ == "__main__":
    unittest.main(verbosity=2)
