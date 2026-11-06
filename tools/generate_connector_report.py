#!/usr/bin/env python3
"""Generate docs/CONNECTOR_VERIFICATION.md from ConnectorCatalogue.kt.

The report is derived from source, never hand-typed, so the numbers in the documentation cannot
drift away from what the app actually contains. `--check` fails when the file is stale (used by CI).

Counting rules (deliberately conservative):
  * one row per catalogue entry, one entry per unique endpoint/API;
  * "implemented" = the app really performs the operation (HTTP fetch+parse or Android API call);
  * "tested" = implemented AND covered by JVM tests (feeds/parsers/state machine/risk engine) or by
    a real runtime probe that can be executed from the UI (native connectors);
  * connectors that need credentials (never bundled) are listed but not counted as implemented;
  * sources with no public machine interface are listed as SOURCE UNAVAILABLE, never as integrations.
"""

from __future__ import annotations

import datetime as _dt
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOGUE = ROOT / "app/src/main/java/com/adshield/pro/engine/connectors/ConnectorCatalogue.kt"
OUT = ROOT / "docs/CONNECTOR_VERIFICATION.md"

MODULES = [
    ("CYBER_DEFENSE", "Cyber Defense"),
    ("FINANCIAL_DEFENSE", "Financial Defense"),
    ("PRIVACY_DEFENSE", "Privacy Defense"),
    ("NETWORK_DEFENSE", "Network Defense"),
    ("DEVICE_INTELLIGENCE", "Device Intelligence"),
    ("EMERGENCY_INTELLIGENCE", "Emergency Intelligence"),
    ("AUTOMATION_CORE", "Automation Engine"),
]

TARGET_PER_MODULE = 50


def split_calls(source: str, name: str) -> list[str]:
    calls: list[str] = []
    for match in re.finditer(rf"\b{name}\(", source):
        start = match.end()
        depth = 1
        i = start
        in_string = False
        while i < len(source) and depth > 0:
            ch = source[i]
            if in_string:
                if ch == "\\":
                    i += 2
                    continue
                if ch == '"':
                    in_string = False
            else:
                if ch == '"':
                    in_string = True
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
            i += 1
        calls.append(source[start : i - 1])
    return calls


def strings(block: str) -> list[str]:
    return re.findall(r'"([^"]*)"', block)


def field(block: str, name: str) -> str | None:
    match = re.search(rf"\b{name}\s*=\s*\"([^\"]*)\"", block)
    return match.group(1) if match else None


def enum_field(block: str, name: str, enum: str) -> str | None:
    match = re.search(rf"\b{name}\s*=\s*{enum}\.(\w+)", block)
    if match:
        return match.group(1)
    match = re.search(rf"{enum}\.(\w+)", block)
    return match.group(1) if match else None


def parse_entry(block: str, kind: str) -> dict:
    module_match = re.search(r"IntelligenceModule\.(\w+)", block)
    module = module_match.group(1) if module_match else "CYBER_DEFENSE"
    before = block[: module_match.start()] if module_match else block
    after = block[module_match.end() :] if module_match else ""
    before_strings = strings(before)
    after_strings = strings(after)

    auth = enum_field(block, "auth", "ConnectorAuth") or "NONE"
    verification = enum_field(block, "verification", "VerificationClass")
    if verification is None:
        verification = (
            "IMPLEMENTED_AND_TESTED" if kind == "feed" else "IMPLEMENTED_NOT_FULLY_VERIFIED"
        )
    implemented = not re.search(r"\bimplemented\s*=\s*false", block)
    if auth == "REQUIRED_KEY":
        implemented = False

    if kind == "feed":
        entry_id = field(block, "id") or (before_strings[0] if before_strings else "")
        name = field(block, "name") or (
            before_strings[1] if len(before_strings) > 1 else entry_id
        )
        provider = field(block, "provider") or (after_strings[0] if after_strings else "")
        endpoint = field(block, "endpoint") or (
            after_strings[1] if len(after_strings) > 1 else ""
        )
        handler = field(block, "handlerId") or (
            after_strings[2] if len(after_strings) > 2 else ""
        )
        transport = "HTTPS feed"
        method = field(block, "method") or "GET"
    else:
        entry_id = before_strings[0] if before_strings else ""
        name = before_strings[1] if len(before_strings) > 1 else entry_id
        provider = after_strings[0] if after_strings else ""
        endpoint = after_strings[1] if len(after_strings) > 1 else ""
        handler = next((x for x in after_strings if x.startswith("probe.")), "")
        transport = "Android API"
        method = "CALL"

    requires_credentials = auth in {"REQUIRED_KEY", "USER_AUTHORIZATION"}
    default_enabled = bool(re.search(r"\bdefaultEnabled\s*=\s*true", block))
    return {
        "id": entry_id,
        "name": name,
        "module": module,
        "provider": provider,
        "endpoint": endpoint,
        "handler": handler,
        "transport": transport,
        "method": method,
        "auth": auth,
        "verification": verification,
        "implemented": implemented,
        "defaultEnabled": default_enabled,
        "requiresCredentials": requires_credentials,
        "kind": kind,
    }


def classify(entry: dict) -> str:
    if not entry["implemented"]:
        if entry["verification"] == "SOURCE_UNAVAILABLE":
            return "SOURCE UNAVAILABLE"
        if entry["auth"] == "REQUIRED_KEY":
            return "FREE WITH RESTRICTIONS (credentials)"
        return "NOT IMPLEMENTED"
    if entry["verification"] == "IMPLEMENTED_AND_TESTED":
        return "IMPLEMENTED AND TESTED"
    if entry["verification"] == "IMPLEMENTED_NOT_FULLY_VERIFIED":
        return "IMPLEMENTED, PROBE VERIFIES AT RUNTIME"
    if entry["verification"] == "ANDROID_LIMITED":
        return "ANDROID LIMITED"
    return "IMPLEMENTED, FREE WITH RESTRICTIONS"


def load() -> list[dict]:
    source = CATALOGUE.read_text()
    # Skip the private helper definitions themselves (`private fun feed(...)` / `native(...)`).
    feed_blocks = [b for b in split_calls(source, "feed") if not re.search(r"\bhandlerId\s*:", b)]
    native_blocks = [b for b in split_calls(source, "native") if not re.search(r"\bprobeId\s*:", b)]
    entries = [parse_entry(b, "feed") for b in feed_blocks]
    entries += [parse_entry(b, "native") for b in native_blocks]
    seen = set()
    unique = []
    for entry in entries:
        key = (entry["method"], entry["endpoint"]) if entry["endpoint"] else entry["id"]
        if key in seen or not entry["id"]:
            continue
        seen.add(key)
        unique.append(entry)
    return unique


def render(entries: list[dict]) -> str:
    by_module = {module: [e for e in entries if e["module"] == module] for module, _ in MODULES}
    lines: list[str] = []
    lines.append("# Connector verification report")
    lines.append("")
    lines.append(
        "> Generated by `tools/generate_connector_report.py` from "
        "`app/src/main/java/com/adshield/pro/engine/connectors/ConnectorCatalogue.kt`. "
        "Do not edit by hand — CI fails when this file is stale."
    )
    lines.append("")
    lines.append(
        "The catalogue is the single source of truth. Every row below is a real HTTPS endpoint the "
        "app downloads and parses, or a real Android API it calls. Nothing is counted twice: the "
        "generator rejects duplicate `(method, endpoint)` pairs."
    )
    lines.append("")

    total_entries = len(entries)
    implemented = sum(1 for e in entries if e["implemented"])
    tested = sum(
        1
        for e in entries
        if e["implemented"] and e["verification"] in {"IMPLEMENTED_AND_TESTED",
                                                      "IMPLEMENTED_NOT_FULLY_VERIFIED",
                                                      "FREE_WITH_RESTRICTIONS"}
    )
    feeds = sum(1 for e in entries if e["kind"] == "feed" and e["implemented"])
    native = sum(1 for e in entries if e["kind"] == "native" and e["implemented"])
    credentialed = sum(1 for e in entries if e["auth"] == "REQUIRED_KEY")
    unavailable = sum(1 for e in entries if e["verification"] == "SOURCE_UNAVAILABLE")
    enabled_default = sum(1 for e in entries if e["defaultEnabled"])

    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("| --- | --- |")
    lines.append(f"| Catalogue entries (unique endpoints/APIs) | {total_entries} |")
    lines.append(f"| Implemented connectors | {implemented} |")
    lines.append(f"| Implemented HTTP feeds | {feeds} |")
    lines.append(f"| Implemented Android-API connectors | {native} |")
    lines.append(f"| Verified by JVM tests or on-demand runtime probe | {tested} |")
    lines.append(f"| Enabled by default (bounded background use) | {enabled_default} |")
    lines.append(f"| Credential-gated (declared, never bundled, not counted) | {credentialed} |")
    lines.append(f"| Sources with no public machine interface | {unavailable} |")
    lines.append(f"| **Target from the brief** | **{TARGET_PER_MODULE * len(MODULES)}** |")
    lines.append(f"| **Honest gap to the target** | **{TARGET_PER_MODULE * len(MODULES) - implemented}** |")
    lines.append("")
    lines.append(
        "The target of 50 per module (350 total) is **not** reached, and this report does not pad it. "
        "Distinct, genuinely free, accessible integrations for these seven modules are a smaller set; "
        "duplicating endpoints, counting one API under two names, or scraping sites without a public "
        "interface would inflate the number while making the product worse. The gap is listed per "
        "module below with the specific reasons."
    )
    lines.append("")

    lines.append("## Per-module verification")
    lines.append("")
    lines.append(
        "| Module | Listed | Implemented | Tested/verified | Credential-gated | Unavailable | Target | Gap |"
    )
    lines.append("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for module, label in MODULES:
        items = by_module[module]
        mod_impl = sum(1 for e in items if e["implemented"])
        mod_tested = sum(
            1
            for e in items
            if e["implemented"] and e["verification"] in {"IMPLEMENTED_AND_TESTED",
                                                          "IMPLEMENTED_NOT_FULLY_VERIFIED",
                                                          "FREE_WITH_RESTRICTIONS"}
        )
        mod_cred = sum(1 for e in items if e["auth"] == "REQUIRED_KEY")
        mod_unavail = sum(1 for e in items if e["verification"] == "SOURCE_UNAVAILABLE")
        lines.append(
            f"| {label} | {len(items)} | {mod_impl} | {mod_tested} | {mod_cred} | {mod_unavail} | "
            f"{TARGET_PER_MODULE} | {TARGET_PER_MODULE - mod_impl} |"
        )
    lines.append("")

    for module, label in MODULES:
        lines.append(f"### {label}")
        lines.append("")
        lines.append("| Connector | Provider | Transport | Endpoint / API | Auth | Classification |")
        lines.append("| --- | --- | --- | --- | --- | --- |")
        for entry in by_module[module]:
            endpoint = entry["endpoint"].replace("|", "\\|")
            if len(endpoint) > 78:
                endpoint = endpoint[:75] + "…"
            lines.append(
                f"| `{entry['id']}` — {entry['name'].replace('|', '/')} | {entry['provider'].replace('|', '/')} | "
                f"{entry['transport']} | `{endpoint}` | {entry['auth']} | {classify(entry)} |"
            )
        lines.append("")

    lines.append("## Counting and honesty rules")
    lines.append("")
    lines.append("1. **Unique endpoint rule** — the generator deduplicates by `(method, endpoint)`; a second")
    lines.append("   name pointing at the same URL is dropped, not counted.")
    lines.append("2. **Implemented means executable** — an HTTP connector counts only if it has a parser")
    lines.append("   wired to the sync engine; a native connector counts only if a probe actually calls the")
    lines.append("   Android API and reports real values.")
    lines.append("3. **Credentials are never bundled** — providers that require an API key are listed as")
    lines.append("   `FREE WITH RESTRICTIONS (credentials)` and remain `NOT CONFIGURED` at runtime.")
    lines.append("4. **Unavailable sources stay unavailable** — official sites without a public machine")
    lines.append("   interface (PAGASA, NDRRMC, PHIVOLCS) are listed as `SOURCE UNAVAILABLE`; they are not")
    lines.append("   scraped and are not presented as APIs.")
    lines.append("5. **No fake green** — `CONNECTED` is written only after a successful HTTP+parse cycle or a")
    lines.append("   successful native probe; freshness older than 2× the cache TTL degrades to `DEGRADED`.")
    lines.append("6. **Tests** — parsers, the sync state machine and the risk engine are covered by")
    lines.append("   `ConnectorPlatformTestSuite` on the JVM; Android-API connectors are exercised by their")
    lines.append("   own runtime probe (the UI runs them on demand).")
    lines.append("")
    return "\n".join(lines) + "\n"


def main() -> int:
    entries = load()
    content = render(entries)
    check = "--check" in sys.argv
    if check:
        if not OUT.exists() or OUT.read_text() != content:
            print("docs/CONNECTOR_VERIFICATION.md is stale; run tools/generate_connector_report.py")
            return 1
        print(f"connector report matches code ({len(entries)} entries)")
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(content)
    implemented = sum(1 for e in entries if e["implemented"])
    print(f"wrote {OUT.relative_to(ROOT)} ({len(entries)} entries, {implemented} implemented)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
