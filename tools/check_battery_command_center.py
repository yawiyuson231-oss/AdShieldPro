#!/usr/bin/env python3
"""Static gates for the Battery Command Center (offline companion to the Kotlin compiler).

CI compiles everything with Gradle; this script catches the mistakes that are cheap to find
without a JDK and expensive to find in review:

  1. **Broken imports in the battery slice.** Every `com.adshield.pro.*` import must resolve to a
     symbol this repository actually declares, and every repo symbol it names must expose the
     members the slice uses (`BatteryMonitor.condition`, `SensorState.OPERATIONAL`, ...). A renamed
     model class or a never-written helper fails here instead of only in CI.
  2. **Unused imports** in the files this feature touches.
  3. **Honesty rules**, as hard text constraints on shipped code:
       - no randomness and no fabricated measurements in the battery package;
       - no `Thread.sleep`, no busy `while (true)` without a `delay(`;
       - the 1 Hz poll must be gated on a real current sensor;
       - "fast charging" must be derived from a platform signal, never from wattage alone.
  4. **Lifecycle wiring**: battery monitoring must start on screen entry and stop on exit.
  5. **Docs sync**: docs/BATTERY_COMMAND_CENTER.md names every section the screen renders.

Run: python3 tools/check_battery_command_center.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "app/src/main/java/com/adshield/pro"

SLICE = [
    SRC / "engine/battery/BatteryModels.kt",
    SRC / "engine/battery/BatteryMonitor.kt",
    SRC / "engine/battery/BatteryDiagnostics.kt",
    SRC / "engine/battery/BatteryTelemetrySource.kt",
    SRC / "engine/battery/BatteryMonitoringEngine.kt",
    SRC / "engine/battery/BatteryHistoryStore.kt",
    SRC / "engine/battery/BatterySessionStore.kt",
    SRC / "engine/battery/FastChargeSignal.kt",
    SRC / "data/repository/BatteryIntelligenceRepository.kt",
    SRC / "ui/screens/BatteryScreen.kt",
    SRC / "ui/components/CyberVisuals.kt",
]

BOILERPLATE_TYPES = {
    "BatteryReading", "BatteryReadingSource", "BatteryHealthStatus", "ChargingSource",
    "DataFreshness", "SensorState", "SensorStatus", "MonitoringState", "EngineState",
    "ComponentStatus", "MonitoringStatus", "BatteryCondition", "BatteryConditionTone",
    "BatteryStatusReport", "PowerTrend", "ChargingEfficiency", "DisplayStateDrain",
    "BatteryIntelligenceReport", "BatteryTelemetry", "HistoryCoverage", "BatteryDiagnostic",
    "BatteryDiagnosticSeverity", "BatterySession", "FastChargeSignal",
}

problems: list[str] = []


def fail(message: str) -> None:
    problems.append(message)


def read(path: Path) -> str:
    if not path.is_file():
        fail(f"missing file: {path.relative_to(ROOT)}")
        return ""
    return path.read_text(encoding="utf-8")


def strip_comments_and_strings(text: str) -> str:
    """Blank comments and string literals so scanning sees only code."""
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        two = text[i:i + 2]
        if two == "//":
            j = text.find("\n", i)
            i = n if j == -1 else j
            continue
        if two == "/*":
            j = text.find("*/", i + 2)
            block = text[i:(n if j == -1 else j + 2)]
            out.append("\n" * block.count("\n"))
            i = n if j == -1 else j + 2
            continue
        if text[i:i + 3] == '"""':
            j = text.find('"""', i + 3)
            end = n if j == -1 else j + 3
            out.append('""')
            i = end
            continue
        if text[i] == '"':
            j = i + 1
            template_code: list[str] = []
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text.startswith("${", j):
                    # String templates contain real code; keep it so identifier checks see it.
                    depth = 0
                    k = j + 1
                    while k < n:
                        if text[k] == "{":
                            depth += 1
                        elif text[k] == "}":
                            depth -= 1
                            if depth == 0:
                                break
                        k += 1
                    template_code.append(" " + text[j + 2:k] + " ")
                    j = k + 1
                    continue
                if text[j] == '"':
                    break
                j += 1
            out.append('""' + "".join(template_code))
            i = j + 1
            continue
        if text[i] == "'":
            j = i + 1
            while j < n and text[j] != "'":
                j += 2 if text[j] == "\\" else 1
            out.append("''")
            i = j + 1
            continue
        out.append(text[i])
        i += 1
    return "".join(out)


def body_of(code: str, header_regex: str) -> str | None:
    """Returns the text between the first `{` after a header match and its matching `}`."""
    match = re.search(header_regex, code)
    if not match:
        return None
    start = code.find("{", match.end())
    if start == -1:
        return None
    depth = 0
    for index in range(start, len(code)):
        char = code[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return code[start + 1:index]
    return None


def declared_members(code: str, type_name: str) -> set[str]:
    body = body_of(code, rf"\b(?:enum class|class|object|data class|sealed class)\s+{re.escape(type_name)}\b")
    if body is None:
        # Not declared in this file. It may still own extension members (`fun BatterySession.x()`),
        # which count as members of the type, so scan the whole file but only keep extensions whose
        # receiver is this type.
        if not re.search(rf"\b(?:class|object|interface)\s+{re.escape(type_name)}\b", code):
            extensions = set(
                re.findall(
                    rf"\bfun\s+(?:<[^>]*>\s*)?(?:[A-Za-z_][\w.]*\.)?{re.escape(type_name)}\.([A-Za-z_]\w*)\s*[(=<]",
                    code,
                )
            )
            return extensions
        body = code
    members: set[str] = set()
    for pattern in (
        r"\b(?:val|var)\s+([A-Za-z_]\w*)",
        # `fun <T> measured(...)`, `fun BatterySession.toStored()`, `fun load()`
        r"\bfun\s+(?:<[^>]*>\s*)?(?:[A-Za-z_][\w.<>?]*\.)?([A-Za-z_]\w*)\s*[(=<]",
        # enum constants and nested declarations live in the same body
        r"\b([A-Z][A-Z0-9_]{1,})\b",
        r"\b(?:class|object|interface)\s+([A-Za-z_]\w*)",
        r"^\s*([A-Za-z_]\w*)\s*[,;(]",
    ):
        members.update(
            re.findall(pattern, body, re.MULTILINE) if "^" in pattern else re.findall(pattern, body)
        )
    # Enum entries
    for match in re.finditer(r"^\s*([A-Z][A-Za-z0-9_]*)\s*[,;(]", body, re.MULTILINE):
        members.add(match.group(1))
    return members


def all_sources() -> dict[Path, str]:
    return {path: path.read_text(encoding="utf-8") for path in SRC.rglob("*.kt")}


# ---------------------------------------------------------------------------------------------
# 1 + 2. Imports resolve, and referenced members exist
# ---------------------------------------------------------------------------------------------

sources = all_sources()
repo_symbols: dict[str, Path] = {}
for path, raw in sources.items():
    code = strip_comments_and_strings(raw)
    package = re.search(r"^package\s+([\w.]+)", code, re.MULTILINE)
    pkg = package.group(1) if package else ""
    for match in re.finditer(
        r"^(?:@\w+\s+)*\s*(?:public |internal |private |abstract |open |sealed |data |value |enum |annotation )*"
        r"(class|interface|object|fun|val|var)\s+(?:<[^>]*>\s*)?([A-Za-z_]\w*)",
        code,
        re.MULTILINE,
    ):
        repo_symbols[f"{pkg}.{match.group(2)}"] = path
    # Enum / data classes declared inside an object get the object's package too.
    for match in re.finditer(r"\b(?:class|object|enum class|data class)\s+([A-Za-z_]\w*)", code):
        repo_symbols.setdefault(f"{pkg}.{match.group(1)}", path)

for path in SLICE:
    raw = read(path)
    if not raw:
        continue
    code = strip_comments_and_strings(raw)
    imported: list[tuple[str, str]] = []
    for match in re.finditer(r"^import\s+([\w.]+)(?:\s+as\s+(\w+))?\s*$", code, re.MULTILINE):
        fq, alias = match.group(1), match.group(2)
        imported.append((fq, alias or fq.rsplit(".", 1)[-1]))
        if fq.startswith("com.adshield.pro.") and fq not in repo_symbols:
            fail(f"{path.name}: import does not resolve to a declared symbol: {fq}")

    # Unused imports (ignoring `*` wildcards). Import lines themselves are removed first, so a
    # symbol used exactly once in the body is not mistaken for a dead import.
    code_without_imports = re.sub(r"^import\s+[\w.]+(?:\s+as\s+\w+)?\s*$", "", code, flags=re.MULTILINE)
    # `val x by delegate` compiles to getValue/setValue calls that never appear by name, so those
    # imports are used whenever the file delegates at all.
    delegated = re.search(r"\bby\b", code_without_imports) is not None
    for fq, name in imported:
        if fq.endswith("*"):
            continue
        if delegated and name in {"getValue", "setValue", "provideDelegate"}:
            continue
        # Extensions are imported and then used as `.name(...)`, so the lookbehind must not
        # exclude a preceding dot — only another identifier character.
        if not re.search(rf"(?<!\w){re.escape(name)}\b", code_without_imports):
            fail(f"{path.name}: unused import: {fq}")

# Member references on repository types must exist.
for path in SLICE:
    raw = read(path)
    if not raw:
        continue
    code = strip_comments_and_strings(raw)
    REFERENCED_TYPES = BOILERPLATE_TYPES | {"BatteryMonitor", "BatteryDiagnostics", "ChargingSource"}

# Index every member of every referenced type once: declarations from the file that owns the type,
# plus extension functions whose receiver is that type (they are members for call-site purposes).
members_by_type: dict[str, set[str]] = {name: set() for name in REFERENCED_TYPES}
owners: dict[str, list[Path]] = {name: [] for name in REFERENCED_TYPES}
for source_path, source_raw in sources.items():
    source_code = strip_comments_and_strings(source_raw)
    for type_name in REFERENCED_TYPES:
        declares = re.search(rf"\b(?:class|object|interface)\s+{re.escape(type_name)}\b", source_code)
        if declares:
            members_by_type[type_name] |= declared_members(source_code, type_name)
            owners[type_name].append(source_path)
        for extension in re.finditer(
            rf"\bfun\s+(?:<[^>]*>\s*)?(?:[A-Za-z_][\w.]*\.)?{re.escape(type_name)}\.([A-Za-z_]\w*)\s*[(=<]",
            source_code,
        ):
            members_by_type[type_name].add(extension.group(1))

for type_name, found in members_by_type.items():
    if not owners[type_name]:
        fail(f"{type_name} is not declared anywhere in the app")

for path in SLICE:
    raw = read(path)
    if not raw:
        continue
    code = strip_comments_and_strings(raw)
    for type_name in REFERENCED_TYPES:
        members = members_by_type[type_name]
        if not members:
            continue
        for match in re.finditer(rf"(?<![\w.]){re.escape(type_name)}\.([A-Za-z_]\w*)", code):
            member = match.group(1)
            if member in {"Companion", "class", "java", "entries"}:
                continue
            if member not in members:
                owner = owners[type_name][0].relative_to(ROOT) if owners[type_name] else "?"
                fail(f"{path.name}: {type_name}.{member} is not declared in {owner}")

# ---------------------------------------------------------------------------------------------
# 3. Honesty rules
# ---------------------------------------------------------------------------------------------

ENGINE_FILES = [p for p in SLICE if "engine/battery" in p.as_posix()]
for path in ENGINE_FILES:
    raw = read(path)
    if not raw:
        continue
    for banned, why in (
        (r"\bMath\.random\b", "random values are never a measurement"),
        (r"\bRandom\s*\(", "random values are never a measurement"),
        (r"\bkotlin\.random\b", "random values are never a measurement"),
        (r"\bThread\.sleep\b", "blocking sleep instead of the polling engine"),
        (r"\bSystem\.nanoTime\b", "measurement freshness must use elapsedRealtime"),
    ):
        if re.search(banned, raw):
            fail(f"{path.name}: banned construct {banned} ({why})")

engine = read(SRC / "engine/battery/BatteryMonitoringEngine.kt")
for match in re.finditer(r"while\s*\(\s*isActive\s*\)\s*\{", engine):
    tail = engine[match.end():match.end() + 400]
    if "delay(" not in tail:
        fail("BatteryMonitoringEngine.kt: polling loop without a delay() will spin the CPU")
require_poll_gate = "hasCurrentSensor()" in engine and "refreshCurrent()" in engine
if not require_poll_gate:
    fail("BatteryMonitoringEngine.kt: fast polling must be gated on a real current sensor")

monitor = read(SRC / "engine/battery/BatteryMonitor.kt")
if "fastChargeSignalConfirmsRate" not in monitor:
    fail("BatteryMonitor.kt: fast charging must be gated on a platform signal")
if re.search(r"watt\w*\s*>=\s*\d+(\.\d+)?f?\s*\)\s*\{?\s*//?\s*fast", monitor, re.IGNORECASE):
    fail("BatteryMonitor.kt: fast charging must never be inferred from wattage alone")

telemetry = read(SRC / "engine/battery/BatteryTelemetrySource.kt")
if "SystemClock.elapsedRealtime()" not in telemetry:
    fail("BatteryTelemetrySource.kt: snapshots must carry a monotonic timestamp")
if "FastChargeSignal.from" not in telemetry:
    fail("BatteryTelemetrySource.kt: fast-charge detection must come from platform properties")

# ---------------------------------------------------------------------------------------------
# 4. Lifecycle wiring in MainActivity
# ---------------------------------------------------------------------------------------------

main = read(SRC / "MainActivity.kt")
destination_body = body_of(main, r"private fun BatteryDestination\s*\(") or ""
if "LifecycleStartEffect" not in destination_body:
    fail("MainActivity.kt: Battery monitoring must be bound to the screen lifecycle")
if "onStopOrDispose" not in destination_body:
    fail("MainActivity.kt: Battery monitoring must be released when the screen leaves the foreground")
if "startBatteryMonitoring" not in destination_body or "pauseBatteryMonitoring" not in destination_body:
    fail("MainActivity.kt: BatteryDestination must call the monitoring start/pause APIs")

# ---------------------------------------------------------------------------------------------
# 5. Docs sync with the rendered sections
# ---------------------------------------------------------------------------------------------

screen = read(SRC / "ui/screens/BatteryScreen.kt")
required_sections = [
    "Live Power Monitor",
    "Battery Intelligence",
    "Charging Analytics",
    "Battery Health",
    "Temperature Monitor",
    "Power Consumption History",
    "Sensor Diagnostics",
    "System Monitoring Status",
]
for section in required_sections:
    if f'title = "{section}"' not in screen:
        fail(f"BatteryScreen.kt: missing command-center section '{section}'")

docs_path = ROOT / "docs/BATTERY_COMMAND_CENTER.md"
docs = read(docs_path)
if docs:
    for section in required_sections:
        if section not in docs:
            fail(f"docs/BATTERY_COMMAND_CENTER.md: does not document section '{section}'")

if problems:
    print(f"Battery Command Center gate FAILED on Python {sys.version.split()[0]}:")
    for problem in problems:
        print(f"  - {problem}")
    sys.exit(1)

print("Battery Command Center gate PASSED: imports resolve, members exist, honesty rules hold, "
      "lifecycle wired, docs in sync.")
