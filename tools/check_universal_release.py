#!/usr/bin/env python3
"""Universal-build gate — runs before any release is published.

A release may only be published if the APK is packaged for every supported device:
one ABI-independent package, correct minSdk/targetSdk, no per-device splits, and the
offline rule sets present. This script fails the release job otherwise, so "universal"
packaging is verified rather than promised. It does not prove runtime behavior on every
physical device.

Checks
  1. build config: minSdk == 29, targetSdk >= 29, no abiFilters / splits / native build.
  2. source manifest: no required hardware/library features or screen-size exclusions;
     optional hardware declarations are allowed. This protects phones, tablets and
     foldables instead of checking CPU architectures alone.
  3. merged APK manifest: aapt confirms the packaged version/SDK values and rejects
          required or implied hardware/library filters introduced by manifest merging.
  4. APK: every native library ships for ALL supported ABIs (arm64-v8a, armeabi-v7a,
          x86, x86_64) — a pure-JVM APK passes trivially; AndroidX libraries such as
          libandroidx.graphics.path.so are fine as long as no ABI is left behind.
          Contains classes*.dex, resources.arsc, AndroidManifest.xml.
  5. APK: bundled offline rule sets are present and non-trivial.

Requires Android build-tools (`aapt`) on PATH or under ANDROID_HOME/ANDROID_SDK_ROOT.
Usage: python3 tools/check_universal_release.py app/build/outputs/apk/release/app-release.apk
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD_FILE = ROOT / "app/build.gradle.kts"
MANIFEST_FILE = ROOT / "app/src/main/AndroidManifest.xml"
ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

MIN_SDK_REQUIRED = 29
SUPPORTED_ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}


def read_int(pattern: str, text: str, label: str) -> int:
    match = re.search(pattern, text)
    if not match:
        raise SystemExit(f"could not read {label} from app/build.gradle.kts")
    return int(match.group(1))


def read_string(pattern: str, text: str, label: str) -> str:
    match = re.search(pattern, text)
    if not match:
        raise SystemExit(f"could not read {label} from app/build.gradle.kts")
    return match.group(1)


def check_build_config(problems: list[str]) -> dict:
    text = BUILD_FILE.read_text(encoding="utf-8")
    debug_suffix = re.search(r'versionNameSuffix\s*=\s*"([^"]*)"', text)
    info = {
        "minSdk": read_int(r"minSdk\s*=\s*(\d+)", text, "minSdk"),
        "targetSdk": read_int(r"targetSdk\s*=\s*(\d+)", text, "targetSdk"),
        "compileSdk": read_int(r"compileSdk\s*=\s*(\d+)", text, "compileSdk"),
        "versionCode": read_int(r"versionCode\s*=\s*(\d+)", text, "versionCode"),
        "versionName": read_string(r'versionName\s*=\s*"([^"]+)"', text, "versionName"),
        "debugVersionNameSuffix": debug_suffix.group(1) if debug_suffix else "",
    }
    if info["minSdk"] != MIN_SDK_REQUIRED:
        problems.append(f"minSdk is {info['minSdk']}, expected {MIN_SDK_REQUIRED} (universal baseline)")
    if info["targetSdk"] < MIN_SDK_REQUIRED:
        problems.append(f"targetSdk {info['targetSdk']} is below minSdk")
    for forbidden, why in (
        ("abiFilters", "per-ABI filtering makes the APK non-universal"),
        ("splits {", "APK splits produce per-device packages"),
        ("externalNativeBuild", "native code would need per-ABI artifacts"),
        ("ndk {", "NDK configuration makes the build ABI-specific"),
    ):
        if forbidden in text:
            problems.append(f"build.gradle.kts contains '{forbidden}' — {why}")
    return info


def check_source_manifest(problems: list[str]) -> dict:
    """Reject install-time device filters in the app's source manifest.

    A complete set of native libraries does not make an APK universal if the merged
    application also demands a camera, telephony, or one particular screen size. The
    source manifest is checked here; the packaged manifest is still asserted to exist
    by ``check_apk``. Optional features (``android:required="false"``) do not restrict
    installation and are therefore allowed.
    """
    if not MANIFEST_FILE.is_file():
        problems.append(f"source manifest not found: {MANIFEST_FILE}")
        return {}
    try:
        root = ET.parse(MANIFEST_FILE).getroot()
    except (ET.ParseError, OSError) as exc:
        problems.append(f"could not parse source manifest: {exc}")
        return {}

    optional_features: list[str] = []
    for feature in root.findall("uses-feature"):
        name = feature.get(f"{ANDROID_NS}name")
        label = name or f"OpenGL ES {feature.get(f'{ANDROID_NS}glEsVersion', 'version unspecified')}"
        if feature.get(f"{ANDROID_NS}required", "true").lower() != "false":
            problems.append(f"manifest requires hardware/feature '{label}', excluding devices without it")
        else:
            optional_features.append(label)

    for library in root.iter("uses-library"):
        name = library.get(f"{ANDROID_NS}name", "unnamed library")
        if library.get(f"{ANDROID_NS}required", "true").lower() != "false":
            problems.append(f"manifest requires shared library '{name}', excluding devices without it")

    if root.find("compatible-screens") is not None:
        problems.append("manifest contains <compatible-screens>, which limits installation to listed screens")

    supports = root.find("supports-screens")
    if supports is not None:
        for attribute, value in supports.attrib.items():
            local_name = attribute.removeprefix(ANDROID_NS)
            normalized = value.lower()
            if local_name in {"requiresSmallestWidthDp", "compatibleWidthLimitDp", "largestWidthLimitDp"}:
                problems.append(f"manifest screen restriction android:{local_name}={value!r} is not universal")
            elif normalized == "false" and (
                local_name.endswith("Screens") or local_name in {"resizeable", "anyDensity"}
            ):
                problems.append(f"manifest disables screen support with android:{local_name}=\"false\"")

    return {"optional_features": optional_features}


def find_aapt() -> Path | None:
    """Locate Android build-tools' aapt, preferring the newest installed version."""
    on_path = shutil.which("aapt")
    if on_path:
        return Path(on_path)
    candidates: list[Path] = []
    for variable in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        root = os.environ.get(variable)
        if not root:
            continue
        build_tools = Path(root) / "build-tools"
        candidates.extend(build_tools.glob("*/aapt"))
        candidates.extend(build_tools.glob("*/aapt.exe"))
    if not candidates:
        return None

    def version_key(path: Path) -> tuple[int, ...]:
        return tuple(int(part) if part.isdigit() else 0 for part in path.parent.name.split("."))

    return sorted(candidates, key=version_key)[-1]


def check_badging(output: str, expected: dict, problems: list[str]) -> dict:
    """Validate aapt's description of the final, merged APK manifest."""
    package = re.search(r"^package: .*versionCode='(\d+)' versionName='([^']*)'", output, re.MULTILINE)
    if not package:
        problems.append("aapt badging did not report the packaged versionCode/versionName")
    else:
        version_code = int(package.group(1))
        version_name = package.group(2)
        if version_code != expected["versionCode"] or version_name != expected["versionName"]:
            problems.append(
                "packaged version does not match build config: "
                f"APK={version_name} ({version_code}), config={expected['versionName']} ({expected['versionCode']})"
            )

    for label, key in (("sdkVersion", "minSdk"), ("targetSdkVersion", "targetSdk")):
        match = re.search(rf"^{label}:'(\d+)'", output, re.MULTILINE)
        if not match:
            problems.append(f"aapt badging did not report {label}")
        elif int(match.group(1)) != expected[key]:
            problems.append(f"packaged {label}={match.group(1)}, expected {expected[key]}")

    required_features = re.findall(r"^uses-feature: name='([^']+)'", output, re.MULTILINE)
    for feature in required_features:
        problems.append(f"merged APK requires hardware/feature '{feature}', excluding devices without it")
    implied_features = re.findall(r"^uses-implied-feature: name='([^']+)'", output, re.MULTILINE)
    for feature in implied_features:
        problems.append(
            f"merged APK implies required hardware/feature '{feature}'; "
            "declare it explicitly with android:required=\"false\" if it is optional"
        )
    required_libraries = re.findall(r"^uses-library: name='([^']+)'", output, re.MULTILINE)
    for library in required_libraries:
        problems.append(f"merged APK requires shared library '{library}', excluding devices without it")
    if re.search(r"^compatible-screens:", output, re.MULTILINE):
        problems.append("merged APK contains a compatible-screens installation restriction")

    return {
        "versionCode": int(package.group(1)) if package else None,
        "versionName": package.group(2) if package else None,
        "optional_features": re.findall(r"^uses-feature-not-required: name='([^']+)'", output, re.MULTILINE),
    }


def check_packaged_manifest(apk: Path, expected: dict, problems: list[str]) -> dict:
    if not apk.is_file():
        return {}
    aapt = find_aapt()
    if aapt is None:
        problems.append(
            "Android build-tools 'aapt' was not found; refusing to certify universality "
            "without inspecting the merged APK manifest (set ANDROID_HOME)"
        )
        return {}
    try:
        result = subprocess.run(
            [str(aapt), "dump", "badging", str(apk)],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        problems.append(f"could not inspect merged APK manifest with aapt: {exc}")
        return {}
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        problems.append(f"aapt dump badging failed: {detail[-1] if detail else 'unknown error'}")
        return {}
    info = check_badging(result.stdout, expected, problems)
    info["aapt"] = str(aapt)
    return info


def check_apk(apk: Path, problems: list[str]) -> dict:
    if not apk.is_file():
        problems.append(f"APK not found: {apk}")
        return {}
    with zipfile.ZipFile(apk) as archive:
        names = archive.namelist()
        # Universality means "runs on every supported ABI", not "contains zero native code".
        # AndroidX (Compose graphics-path, DataStore shared counter) ships small .so helpers
        # for ALL ABIs inside one APK — that is still universal. What breaks devices is a
        # library that exists for some ABIs but not others, or an unexpected ABI subset.
        abi_libs: dict[str, set[str]] = {}
        for name in names:
            if name.startswith("lib/") and name.count("/") >= 2 and name.endswith(".so"):
                parts = name.split("/")
                abi_libs.setdefault(parts[1], set()).add("/".join(parts[2:]))
        native = sorted(abi_libs)
        if abi_libs:
            unknown = set(abi_libs) - SUPPORTED_ABIS
            if unknown:
                problems.append(f"APK bundles native libraries for unexpected ABIs {sorted(unknown)}")
            missing = SUPPORTED_ABIS - set(abi_libs)
            if missing:
                problems.append(
                    f"native libraries are missing for {sorted(missing)} — the APK would fail on those devices"
                )
            all_libs = set().union(*abi_libs.values())
            for abi in sorted(set(abi_libs) & SUPPORTED_ABIS):
                gap = all_libs - abi_libs[abi]
                if gap:
                    problems.append(f"{abi} is missing {sorted(gap)} that other ABIs bundle")
        if not any(re.fullmatch(r"classes\d*\.dex", name) for name in names):
            problems.append("APK has no classes*.dex")
        if "resources.arsc" not in names:
            problems.append("APK has no resources.arsc")
        if "AndroidManifest.xml" not in names:
            problems.append("APK has no AndroidManifest.xml")

        assets = {
            "core_max_ads.txt": 100_000,
            "core_max_threats.txt": 100_000,
            "core_lite_ads.txt": 40_000,
        }
        for asset, minimum_lines in assets.items():
            entry = f"assets/{asset}"
            if entry not in names:
                problems.append(f"offline rule set missing from APK: {asset}")
                continue
            if archive.getinfo(entry).file_size < minimum_lines * 8:
                problems.append(f"{asset} looks truncated in the APK")

        lib_names = sorted(set().union(*abi_libs.values())) if abi_libs else []
        return {
            "size_mb": round(apk.stat().st_size / (1024 * 1024), 2),
            "native_abis": [f"{', '.join(native)} (all ABIs: {', '.join(lib_names)})"] if native
            else ["none (pure JVM — runs on every ABI)"],
            "dex": sum(1 for name in names if re.fullmatch(r"classes\d*\.dex", name)),
        }


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__)
    apk = Path(sys.argv[1])
    problems: list[str] = []
    config = check_build_config(problems)
    source_problem_count = len(problems)
    manifest_info = check_source_manifest(problems)
    source_manifest_ok = len(problems) == source_problem_count
    apk_info = check_apk(apk, problems)
    packaged_expected = dict(config)
    if apk.parent.name == "debug":
        # app/build.gradle.kts declares versionNameSuffix = "-debug" only for this variant.
        packaged_expected["versionName"] = f"{config['versionName']}{config['debugVersionNameSuffix']}"
    packaged_info = check_packaged_manifest(apk, packaged_expected, problems)

    print("Universal build gate")
    print(f"  version        : {config.get('versionName')} (versionCode {config.get('versionCode')})")
    print(f"  sdk            : min {config.get('minSdk')} / target {config.get('targetSdk')} / compile {config.get('compileSdk')}")
    if manifest_info and source_manifest_ok:
        optional = manifest_info["optional_features"]
        print(f"  source devices : no required hardware or screen-size exclusions; {len(optional)} optional feature(s)")
    if packaged_info:
        optional = packaged_info["optional_features"]
        print(f"  merged manifest: version/SDK/device filters inspected with aapt; {len(optional)} optional feature(s)")
    if apk_info:
        print(f"  apk            : {apk.name}, {apk_info['size_mb']} MB, {apk_info['dex']} dex file(s)")
        print(f"  native libs    : {', '.join(apk_info['native_abis'])}")

    if problems:
        print("\nFAILED — this build is not universal:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("\nPASSED — one APK for Android 10+ (API 29+), all four supported CPU ABIs, and phone/tablet/foldable screen types.")
    print("Scope: package compatibility only; installation and runtime behavior still require real-device testing.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
