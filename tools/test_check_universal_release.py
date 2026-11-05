#!/usr/bin/env python3
"""Regression tests for the universal APK release gate."""
from __future__ import annotations

import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import check_universal_release as gate


class UniversalBuildConfigGateTest(unittest.TestCase):
    def test_repository_config_is_universal_and_declares_debug_suffix(self) -> None:
        problems: list[str] = []
        info = gate.check_build_config(problems)
        self.assertEqual([], problems)
        self.assertEqual(29, info["minSdk"])
        self.assertEqual("-debug", info["debugVersionNameSuffix"])

    def test_abi_splits_are_rejected(self) -> None:
        build_file = """
            android {
                compileSdk = 37
                defaultConfig {
                    minSdk = 29
                    targetSdk = 36
                    versionCode = 1
                    versionName = "1.0.0"
                }
                splits { abi { enable = true } }
            }
        """
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "build.gradle.kts"
            path.write_text(build_file, encoding="utf-8")
            problems: list[str] = []
            with patch.object(gate, "BUILD_FILE", path):
                gate.check_build_config(problems)
        self.assertTrue(any("splits" in problem for problem in problems))


class UniversalManifestGateTest(unittest.TestCase):
    def test_repository_manifest_has_no_device_type_exclusions(self) -> None:
        problems: list[str] = []
        info = gate.check_source_manifest(problems)
        self.assertEqual([], problems)
        self.assertIn("android.hardware.touchscreen", info["optional_features"])

    def test_optional_hardware_does_not_restrict_installation(self) -> None:
        problems = self._check_manifest(
            '<uses-feature android:name="android.hardware.camera" android:required="false" />'
        )
        self.assertEqual([], problems)

    def test_required_hardware_is_rejected(self) -> None:
        problems = self._check_manifest(
            '<uses-feature android:name="android.hardware.telephony" />'
        )
        self.assertTrue(any("requires hardware/feature" in problem for problem in problems))

    def test_required_shared_library_is_rejected(self) -> None:
        problems = self._check_manifest(
            '<application><uses-library android:name="com.example.device.only" /></application>'
        )
        self.assertTrue(any("requires shared library" in problem for problem in problems))

    def test_screen_size_exclusions_are_rejected(self) -> None:
        problems = self._check_manifest(
            '<supports-screens android:smallScreens="false" android:requiresSmallestWidthDp="600" />'
        )
        self.assertTrue(any("disables screen support" in problem for problem in problems))
        self.assertTrue(any("requiresSmallestWidthDp" in problem for problem in problems))

    def test_compatible_screens_allowlist_is_rejected(self) -> None:
        problems = self._check_manifest(
            '<compatible-screens><screen android:screenSize="normal" android:screenDensity="hdpi" /></compatible-screens>'
        )
        self.assertTrue(any("compatible-screens" in problem for problem in problems))

    @staticmethod
    def _check_manifest(body: str) -> list[str]:
        manifest = (
            '<manifest xmlns:android="http://schemas.android.com/apk/res/android">'
            f"{body}</manifest>"
        )
        problems: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "AndroidManifest.xml"
            path.write_text(manifest, encoding="utf-8")
            with patch.object(gate, "MANIFEST_FILE", path):
                gate.check_source_manifest(problems)
        return problems


class UniversalMergedManifestGateTest(unittest.TestCase):
    EXPECTED = {
        "versionCode": 20700,
        "versionName": "2.7.0",
        "minSdk": 29,
        "targetSdk": 36,
    }

    def test_valid_merged_manifest_badging_passes(self) -> None:
        problems: list[str] = []
        info = gate.check_badging(
            "package: name='com.adshield.pro' versionCode='20700' versionName='2.7.0'\n"
            "sdkVersion:'29'\n"
            "targetSdkVersion:'36'\n"
            "uses-feature-not-required: name='android.hardware.touchscreen'\n",
            self.EXPECTED,
            problems,
        )
        self.assertEqual([], problems)
        self.assertEqual(["android.hardware.touchscreen"], info["optional_features"])

    def test_merged_manifest_version_and_sdk_must_match_config(self) -> None:
        problems: list[str] = []
        gate.check_badging(
            "package: name='com.adshield.pro' versionCode='1' versionName='0.0.1'\n"
            "sdkVersion:'21'\n"
            "targetSdkVersion:'35'\n",
            self.EXPECTED,
            problems,
        )
        self.assertEqual(3, len(problems))
        self.assertTrue(any("packaged version" in problem for problem in problems))
        self.assertTrue(any("sdkVersion=21" in problem for problem in problems))
        self.assertTrue(any("targetSdkVersion=35" in problem for problem in problems))

    def test_merged_required_and_implied_features_are_rejected(self) -> None:
        problems: list[str] = []
        gate.check_badging(
            "package: name='com.adshield.pro' versionCode='20700' versionName='2.7.0'\n"
            "sdkVersion:'29'\n"
            "targetSdkVersion:'36'\n"
            "uses-feature: name='android.hardware.telephony'\n"
            "uses-implied-feature: name='android.hardware.camera' reason='permission'\n"
            "uses-library: name='com.example.device.only'\n"
            "compatible-screens: 'normal'\n",
            self.EXPECTED,
            problems,
        )
        self.assertTrue(any("requires hardware/feature" in problem for problem in problems))
        self.assertTrue(any("implies required hardware/feature" in problem for problem in problems))
        self.assertTrue(any("requires shared library" in problem for problem in problems))
        self.assertTrue(any("compatible-screens" in problem for problem in problems))


class UniversalApkGateTest(unittest.TestCase):
    def test_pure_jvm_apk_is_cpu_independent(self) -> None:
        problems, info = self._check_apk(native_abis=set())
        self.assertEqual([], problems)
        self.assertEqual(["none (pure JVM — runs on every ABI)"], info["native_abis"])

    def test_identical_native_libraries_for_all_abis_pass(self) -> None:
        problems, info = self._check_apk(native_abis=set(gate.SUPPORTED_ABIS))
        self.assertEqual([], problems)
        for abi in gate.SUPPORTED_ABIS:
            self.assertIn(abi, info["native_abis"][0])

    def test_missing_cpu_architecture_is_rejected(self) -> None:
        problems, _ = self._check_apk(native_abis={"arm64-v8a", "x86_64"})
        self.assertTrue(any("native libraries are missing" in problem for problem in problems))
        self.assertTrue(any("armeabi-v7a" in problem for problem in problems))
        self.assertTrue(any("x86" in problem for problem in problems))

    def test_mismatched_library_set_is_rejected(self) -> None:
        problems, _ = self._check_apk(
            native_abis=set(gate.SUPPORTED_ABIS), extra_x86_library=True
        )
        self.assertTrue(any("is missing ['libextra.so']" in problem for problem in problems))

    def _check_apk(
        self, native_abis: set[str], extra_x86_library: bool = False
    ) -> tuple[list[str], dict]:
        problems: list[str] = []
        with tempfile.TemporaryDirectory() as directory:
            apk = Path(directory) / "test.apk"
            with zipfile.ZipFile(apk, "w") as archive:
                archive.writestr("AndroidManifest.xml", b"manifest")
                archive.writestr("resources.arsc", b"resources")
                archive.writestr("classes.dex", b"dex")
                for asset, minimum_lines in (
                    ("core_max_ads.txt", 100_000),
                    ("core_max_threats.txt", 100_000),
                    ("core_lite_ads.txt", 40_000),
                ):
                    archive.writestr(f"assets/{asset}", b"x" * (minimum_lines * 8))
                for abi in native_abis:
                    archive.writestr(f"lib/{abi}/libhelper.so", b"native")
                if extra_x86_library:
                    archive.writestr("lib/x86/libextra.so", b"native")
            info = gate.check_apk(apk, problems)
        return problems, info


if __name__ == "__main__":
    unittest.main()
