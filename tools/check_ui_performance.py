#!/usr/bin/env python3
"""Static UI performance gates for the Android app.

These are cheap guardrails, not a frame profiler: they keep the long screens lazy, keep repeated
rows keyed, keep the shell from collecting every tab's live state, and keep idle animation off.
On-device frame timing still belongs in the manual smoke checklist.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
UI = ROOT / "app/src/main/java/com/adshield/pro"

problems: list[str] = []


def read(rel: str) -> str:
    return (UI / rel).read_text(encoding="utf-8")


def require(condition: bool, message: str) -> None:
    if not condition:
        problems.append(message)


home = read("ui/screens/HomeScreen.kt")
require("LazyColumn(" in home, "HomeScreen must render its long layout with LazyColumn")
require(".verticalScroll(" not in home, "HomeScreen must not eagerly compose a verticalScroll column")
require("ScrollToTopButton(" in home, "HomeScreen should expose a scroll-to-top affordance")

live = read("ui/screens/LiveNetworkScreen.kt")
require("items(snapshot.recentEvents, key = { it.id }" in live, "Live event feed must be lazy and keyed by log id")
require("rememberInfiniteTransition" not in live, "Live screen must not own a per-frame infinite transition")
require(".verticalScroll(" not in live, "Live screen must not nest vertical scrolling")

shield = read("ui/components/ProtectionShield.kt")
require("rememberAnimationsEnabled()" in shield, "Shield animation must respect system animation settings")
require("Canvas(" in shield, "Shield animation should be draw-state, not recomposition")
require("Animatable(" not in shield, "Shield must not drive composition with Animatable.value reads")

main = read("MainActivity.kt")
for destination in ("HomeDestination", "AdBlockerDestination", "LiveDestination", "SecurityDestination",
                    "OptimizerDestination", "BatteryDestination", "StatisticsDestination",
                    "SettingsDestination", "StatusDestination"):
    require(f"private fun {destination}" in main, f"Missing isolated state destination: {destination}")
require("CyberBottomNav" in main, "Bottom navigation should use the lazy cyber nav")
shell = main.split("fun AdShieldMainApp", 1)[1].split("Scaffold(", 1)[0]
for flow in ("recentLogs", "batteryTelemetry", "ramSnapshot", "installedApps", "filterSources", "liveNetwork"):
    require(f"viewModel.{flow}.collect" not in shell, f"Shell must not collect per-tab flow: {flow}")

settings = read("ui/screens/SettingsScreen.kt")
require("LazyColumn(modifier = Modifier.weight(1f)" in settings, "App-exclusion dialog list must be bounded and lazy")
security = read("ui/screens/SecurityScreen.kt")
require("LazyColumn(\n            modifier = Modifier.weight(1f)" in security, "App audit list must take bounded remaining height")

# Repeated rows must have stable keys and content types so scrolling recycles correctly.
for path in sorted((UI / "ui/screens").glob("*.kt")):
    text = path.read_text(encoding="utf-8")
    for match in re.finditer(r"\bitems(?:Indexed)?\(([^\n]*)", text):
        line = match.group(0)
        if "key =" not in line:
            problems.append(f"{path.name}: lazy items call without a stable key: {line.strip()}")
for name in ("ActivityScreen.kt", "RulesScreen.kt", "FiltersScreen.kt", "CapabilitiesScreen.kt",
             "BatteryScreen.kt", "SecurityScreen.kt", "LiveNetworkScreen.kt"):
    require("contentType =" in read(f"ui/screens/{name}"), f"{name}: repeated rows should declare contentType")

if problems:
    print("UI performance gate FAILED:")
    for problem in problems:
        print(f"  - {problem}")
    sys.exit(1)

print("UI performance gate PASSED: lazy Home/Live feeds, keyed rows, isolated tab state, idle-safe animation.")
