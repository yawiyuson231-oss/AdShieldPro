import subprocess
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.check_universal_release import check_build_config, check_packaged_metadata


class PackagedApkMetadataTest(unittest.TestCase):
    def config(self, variant):
        problems = []
        config = check_build_config(problems, variant)
        self.assertEqual(problems, [])
        return config

    def check(self, variant, replacements=None, omit_package=False, min_sdk_label="minSdkVersion"):
        config = self.config(variant)
        values = {**config, **(replacements or {})}
        package = (f"package: name='{values['applicationId']}' versionCode='{values['versionCode']}' "
                   f"versionName='{values['versionName']}' {values.get('extraPackageFields', '')}\n")
        output = ("" if omit_package else package) + (
            f"{min_sdk_label}:'{values['minSdk']}'\ntargetSdkVersion:'{values['targetSdk']}'\n"
        )
        problems = []
        with patch("tools.check_universal_release.subprocess.run", return_value=mock_aapt(output)) as run:
            apk = Path("fixture.apk")
            check_packaged_metadata(apk, config, "aapt2", problems)
            self.assertEqual(run.call_args.args[0], ["aapt2", "dump", "badging", str(apk.resolve())])
        return problems

    def test_accepts_metadata_for_both_variants_including_debug_suffixes(self):
        self.assertNotEqual(self.config("debug")["applicationId"], self.config("release")["applicationId"])
        self.assertEqual(self.check("debug"), [])
        self.assertEqual(self.check("release"), [])

    def test_accepts_older_aapt2_sdk_version_spelling(self):
        self.assertEqual(self.check("release", min_sdk_label="sdkVersion"), [])

    def test_rejects_wrong_variant_stale_version_and_sdk_mismatch(self):
        release = self.config("release")
        problems = self.check("debug", {
            "applicationId": release["applicationId"], "versionName": release["versionName"],
            "versionCode": release["versionCode"] - 1, "minSdk": 35, "targetSdk": 35,
        })
        for field in ("applicationId", "versionCode", "versionName", "minSdk", "targetSdk"):
            self.assertTrue(any(f"manifest {field}:" in line for line in problems), problems)

    def test_rejects_split_package_or_missing_package_line(self):
        self.assertIn("split package", self.check("release", {"extraPackageFields": "split='config.arm64_v8a'"})[0])
        self.assertTrue(any("applicationId" in problem for problem in self.check("release", omit_package=True)))

    def test_missing_tool_or_invalid_manifest_cannot_pass(self):
        config = self.config("release")
        problems = []
        check_packaged_metadata(Path("fixture.apk"), config, None, problems)
        self.assertIn("aapt2 not found", problems[0])
        problems.clear()
        with patch("tools.check_universal_release.subprocess.run", side_effect=subprocess.CalledProcessError(1, ["aapt2"])):
            check_packaged_metadata(Path("fixture.apk"), config, "aapt2", problems)
        self.assertEqual(problems, ["aapt2 could not read the packaged Android manifest"])


def mock_aapt(output):
    return subprocess.CompletedProcess(["aapt2"], 0, stdout=output, stderr="")
