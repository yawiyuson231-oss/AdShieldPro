#!/usr/bin/env python3
"""Universal-build gate — runs before any release is published.

A release may only be published if the APK actually works on every supported device:
one ABI-independent package, correct minSdk/targetSdk, no per-device splits, and the
offline rule sets present. This script fails the release job otherwise, so "universal"
is a verified property of each build rather than a promise.

Checks
  1. build config: minSdk == 29, targetSdk >= 29, no abiFilters / splits / native build.
  2. APK: every native library ships for ALL supported ABIs (arm64-v8a, armeabi-v7a,
          x86, x86_64) — a pure-JVM APK passes trivially; AndroidX libraries such as
          libandroidx.graphics.path.so are fine as long as no ABI is left behind.
          Contains classes*.dex, resources.arsc, AndroidManifest.xml.
  3. APK: bundled offline rule sets are present and non-trivial; the AETHER model matches source.
  4. APK manifest (read with Android SDK aapt2): application ID, versionCode/versionName,
     minSdk and targetSdk match the intended debug or release variant. Reject split APKs.

Usage: python3 tools/check_universal_release.py app/build/outputs/apk/release/app-release.apk
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BUILD_FILE = ROOT / "app/build.gradle.kts"

MIN_SDK_REQUIRED = 29
SUPPORTED_ABIS = {"arm64-v8a", "armeabi-v7a", "x86", "x86_64"}


def read_int(pattern: str, text: str, label: str) -> int:
    match = re.search(pattern, text)
    if not match:
        raise SystemExit(f"could not read {label} from app/build.gradle.kts")
    return int(match.group(1))


def read_string(field: str, text: str) -> str:
    match = re.search(rf'\b{field}\s*=\s*"([^"]+)"', text)
    if not match:
        raise SystemExit(f"could not read {field} from app/build.gradle.kts")
    return match.group(1)


def check_build_config(problems: list[str], variant: str = "release") -> dict:
    text = BUILD_FILE.read_text(encoding="utf-8")
    info = {
        "applicationId": read_string("applicationId", text),
        "minSdk": read_int(r"minSdk\s*=\s*(\d+)", text, "minSdk"),
        "targetSdk": read_int(r"targetSdk\s*=\s*(\d+)", text, "targetSdk"),
        "compileSdk": read_int(r"compileSdk\s*=\s*(\d+)", text, "compileSdk"),
        "versionCode": read_int(r"versionCode\s*=\s*(\d+)", text, "versionCode"),
        "versionName": read_string("versionName", text),
    }
    if variant == "debug":
        info["applicationId"] += read_string("applicationIdSuffix", text)
        info["versionName"] += read_string("versionNameSuffix", text)
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

        model_path = "assets/aether/task_model.tsv"
        weights = (ROOT / "app/src/main" / model_path).read_bytes()
        if (model_path not in names or archive.getinfo(model_path).file_size != len(weights)
                or archive.read(model_path) != weights):
            problems.append("APK is missing the checked-in AETHER task model weights")

        lib_names = sorted(set().union(*abi_libs.values())) if abi_libs else []
        return {
            "size_mb": round(apk.stat().st_size / (1024 * 1024), 2),
            "native_abis": [f"{', '.join(native)} (all ABIs: {', '.join(lib_names)})"] if native
            else ["none (pure JVM — runs on every ABI)"],
            "dex": sum(1 for name in names if re.fullmatch(r"classes\d*\.dex", name)),
        }


def find_aapt2() -> str | None:
    # CI installs this version. Local users can also supply --aapt2 or put it on PATH.
    sdk = os.getenv("ANDROID_HOME") or os.getenv("ANDROID_SDK_ROOT")
    if sdk:
        binary = "aapt2.exe" if os.name == "nt" else "aapt2"
        path = Path(sdk) / "build-tools" / "36.0.0" / binary
        if path.is_file():
            return str(path)
    return shutil.which("aapt2")


def check_packaged_metadata(apk: Path, config: dict, aapt2: str | None, problems: list[str]) -> None:
    if not aapt2:
        problems.append("aapt2 not found; install Android build-tools 36.0.0 or pass --aapt2")
        return
    try:
        result = subprocess.run(
            [aapt2, "dump", "badging", str(apk.resolve())],
            check=True, capture_output=True, encoding="utf-8", timeout=30,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        problems.append("aapt2 could not read the packaged Android manifest")
        return

    badging = result.stdout
    package_line = re.search(r"^package: (.*)$", badging, re.MULTILINE)
    package = dict(re.findall(r"(\w+)='([^']*)'", package_line.group(1))) if package_line else {}
    if package.get("split"):
        problems.append("APK is a split package, not an installable standalone package")
    for field, value in (("applicationId", package.get("name")),
                         ("versionCode", package.get("versionCode")),
                         ("versionName", package.get("versionName")),
                         ("minSdk", re.search(r"^sdkVersion:'(\d+)'$", badging, re.MULTILINE)),
                         ("targetSdk", re.search(r"^targetSdkVersion:'(\d+)'$", badging, re.MULTILINE))):
        actual = value.group(1) if isinstance(value, re.Match) else value
        if actual != str(config[field]):
            problems.append(f"APK manifest {field}: expected {config[field]}, got {actual or 'missing'}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate the packaged standalone AdShield APK.")
    parser.add_argument("apk", type=Path)
    parser.add_argument("--variant", choices=("debug", "release"), default="release")
    parser.add_argument("--aapt2", help="Path to the Android SDK aapt2 executable")
    args = parser.parse_args()
    apk = args.apk
    problems: list[str] = []
    config = check_build_config(problems, args.variant)
    try:
        apk_info = check_apk(apk, problems)
    except (OSError, zipfile.BadZipFile) as error:
        problems.append(f"cannot read APK ZIP: {error}")
        apk_info = {}
    if apk_info:
        check_packaged_metadata(apk, config, args.aapt2 or find_aapt2(), problems)

    print("Universal build gate")
    print(f"  variant        : {args.variant}, {config['applicationId']}")
    print(f"  version        : {config['versionName']} (versionCode {config['versionCode']})")
    print(f"  sdk            : min {config['minSdk']} / target {config['targetSdk']} / compile {config['compileSdk']}")
    if apk_info:
        print(f"  apk            : {apk.name}, {apk_info['size_mb']} MB, {apk_info['dex']} dex file(s)")
        print(f"  native libs    : {', '.join(apk_info['native_abis'])}")

    if problems:
        print("\nFAILED — this build is not universal:")
        for problem in problems:
            print(f"  - {problem}")
        return 1

    print("\nPASSED — single ABI-independent APK for Android 10+ (API 29-37) on any CPU architecture.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
