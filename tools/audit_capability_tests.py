#!/usr/bin/env python3
"""Audit that every capability's claimed verification actually runs.

A capability row in `CapabilityRegistry.kt` names the test that proves it. That claim is only
true if a `@Test`-annotated method with that name exists in the JVM sources — a method that
loses its `@Test` annotation keeps compiling, never runs, and silently leaves the capability
unverified (exactly the bug this script was written to catch).

Usage: python3 tools/audit_capability_tests.py [--strict]
  --strict  exit non-zero when a claimed test is missing or declared without @Test
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "app/src/main/java/com/adshield/pro/engine/platform/CapabilityRegistry.kt"
TESTS = ROOT / "app/src/test/java/com/adshield/pro"

MANUAL_PREFIX = ("Manual", "manual", "n/a", "Deployment")
FILE_EXTENSIONS = {"py", "kt", "md", "yml", "yaml", "json", "js", "mjs", "sh", "toml", "html", "css"}
METHOD_RE = re.compile(r"([A-Za-z0-9_]+)\.([A-Za-z0-9_]+)")
BARE_TEST_RE = re.compile(r"\b(test[A-Z][A-Za-z0-9_]+)\b")
SUITE_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*(?:Test|TestSuite|Suite))\b")
CAP_RE = re.compile(r'cap\(\s*"([^"]+)",(.*?)\n\s*\)', re.DOTALL)
STRING_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
FUN_RE = re.compile(r"\s*fun ([A-Za-z0-9_]+)\(")
CLASS_RE = re.compile(r"^\s*class ([A-Za-z0-9_]+)")


def parse_registry() -> list[tuple[str, str]]:
    source = REGISTRY.read_text()
    rows: list[tuple[str, str]] = []
    for match in CAP_RE.finditer(source):
        strings = STRING_RE.findall(match.group(2))
        rows.append((match.group(1), strings[-1] if strings else ""))
    return rows


def parse_tests() -> tuple[set[str], set[str], dict[str, int]]:
    annotated: set[str] = set()
    unannotated: set[str] = set()
    per_class: dict[str, int] = {}
    for path in sorted(TESTS.glob("*.kt")):
        lines = path.read_text().splitlines()
        current_class = path.stem
        count = 0
        for index, line in enumerate(lines):
            class_match = CLASS_RE.match(line)
            if class_match:
                if count:
                    per_class[current_class] = per_class.get(current_class, 0) + count
                current_class = class_match.group(1)
                count = 0
            fun_match = FUN_RE.match(line)
            if not fun_match or "suspend" in line:
                continue
            lookback = "\n".join(lines[max(0, index - 5):index])
            if "@Test" in lookback:
                annotated.add(fun_match.group(1))
                count += 1
            else:
                unannotated.add(fun_match.group(1))
        if count:
            per_class[current_class] = per_class.get(current_class, 0) + count
    return annotated, unannotated, per_class


def claimed_methods(verification: str) -> list[str]:
    """Only `Suite.method` references and `testXxx` names are real, checkable claims."""
    if verification.startswith(MANUAL_PREFIX):
        return []
    methods = [
        match.group(2)
        for match in METHOD_RE.finditer(verification)
        if match.group(2) not in FILE_EXTENSIONS
        and "/" not in match.group(1)
        and "." not in match.group(1)
    ]
    methods += BARE_TEST_RE.findall(verification)
    return methods


def main(argv: list[str]) -> int:
    strict = "--strict" in argv
    annotated, unannotated, per_class = parse_tests()
    rows = parse_registry()

    not_running: list[tuple[str, str]] = []
    missing: list[tuple[str, str]] = []
    empty_suites: list[tuple[str, str]] = []
    manual = 0
    checked = 0

    for capability_id, verification in rows:
        methods = claimed_methods(verification)
        suites = [name for name in SUITE_RE.findall(verification) if name in per_class]
        for suite in suites:
            if per_class.get(suite, 0) == 0:
                empty_suites.append((capability_id, suite))
        if not methods and not suites:
            manual += 1
            continue
        for method in methods:
            checked += 1
            if method in annotated:
                continue
            if method in unannotated:
                not_running.append((capability_id, method))
            else:
                missing.append((capability_id, method))

    print(f"capability rows:          {len(rows)}")
    print(f"rows with a named test:   {len(rows) - manual} ({manual} manual/architecture-only)")
    print(f"test claims checked:      {checked}")
    print(f"@Test methods found:      {len(annotated)} across {len(per_class)} classes")

    if not_running:
        print("\nDECLARED BUT NOT RUNNING (missing @Test):")
        for capability_id, method in sorted(set(not_running)):
            print(f"  - {capability_id}: {method}")
    if missing:
        print("\nCLAIMED TEST DOES NOT EXIST:")
        for capability_id, method in sorted(set(missing)):
            print(f"  - {capability_id}: {method}")
    if empty_suites:
        print("\nSUITE REFERENCED BUT HAS NO @Test METHODS:")
        for capability_id, suite in sorted(set(empty_suites)):
            print(f"  - {capability_id}: {suite}")
    if not not_running and not missing and not empty_suites:
        print("\nOK: every named capability test exists, is annotated with @Test, and runs.")

    if strict and (missing or not_running or empty_suites):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
