"""
Universal Security Super App tests — verifies 50 modules, platform support,
master control, diagnostics, and no iOS.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from core.universal import MODULES_50, PLATFORM_SUPPORT, PLATFORM_CAPABILITIES

def test_50_modules():
    assert len(MODULES_50) == 50, f"Expected 50 modules, got {len(MODULES_50)}"
    ids = [m["id"] for m in MODULES_50]
    assert ids == list(range(1, 51)), f"Module IDs must be 1-50, got {ids[:5]}...{ids[-5:]}"
    # Check categories
    cats = {}
    for m in MODULES_50:
        cats[m["category"]] = cats.get(m["category"], 0) + 1
    assert cats["AI Protection"] == 10
    assert cats["Device Protection"] == 10
    assert cats["Privacy Protection"] == 10
    assert cats["Advanced Cyber Defense"] == 10
    assert cats["Security Intelligence"] == 10
    print("✓ 50 modules correct")

def test_no_ios():
    # iOS permanently excluded
    for plat in PLATFORM_CAPABILITIES:
        assert "iOS" not in plat and "iPhone" not in plat, f"iOS found in {plat}"
    assert "iOS" not in PLATFORM_CAPABILITIES
    assert "iPhone" not in PLATFORM_CAPABILITIES
    # Check excluded platforms not in support matrix
    for plat_key in PLATFORM_SUPPORT:
        assert plat_key != "iOS" and plat_key != "iPhone"
    print("✓ No iOS/iPhone — permanently excluded")

def test_platforms():
    assert set(PLATFORM_CAPABILITIES.keys()) == {"Android", "Windows", "macOS"}
    print("✓ Platforms: Android, Windows, macOS only")

def test_apk_only_on_android():
    # Module 14 APK scanning only on Android
    assert 14 in MODULES_50[13].values() or MODULES_50[13]["id"] == 14
    # Windows should NOT support APK
    assert PLATFORM_SUPPORT.get("Windows", {}).get(14) is False
    assert PLATFORM_SUPPORT.get("macOS", {}).get(14) is False
    print("✓ APK scanning (M14) Android-only")

def test_process_isolation_limits():
    # M40 not supported on Android, limited on macOS
    assert PLATFORM_SUPPORT["Android"][40] is False
    assert PLATFORM_SUPPORT["macOS"][40] == "limited"
    print("✓ Process isolation correctly marked as limited/unsupported")

def test_universal_manager():
    from core.universal import UniversalManager
    from unittest.mock import MagicMock
    mock_store = MagicMock()
    mock_store.add_audit = MagicMock()
    mock_intel = MagicMock()
    mock_feed = MagicMock()
    mock_feed.status = "verified"
    mock_feed.indicator_count = 14419
    mock_intel.current.return_value = mock_feed
    mock_detection = MagicMock()
    mgr = UniversalManager(Path("/tmp"), mock_store, mock_intel, mock_detection)
    assert len(mgr.get_modules()) == 50
    # Ingest diagnostics
    fake_report = {"results": [{"module_id": 1, "status": "WORKING"}], "working": 1}
    res = mgr.ingest_diagnostics("Android", fake_report)
    assert res["ok"] and res["platform"] == "Android"
    agg = mgr.get_aggregated_status()
    assert agg["total"] == 50
    assert "Android" in agg["platforms"]
    print("✓ UniversalManager ingest + aggregation")

def test_desktop_agent_common():
    sys.path.insert(0, str(Path(__file__).parent.parent.parent / "desktop" / "common"))
    from universal_agent import MODULE_DEFINITIONS, derive_status
    assert len(MODULE_DEFINITIONS) == 50
    assert derive_status(True, True, True, True) == "WORKING"
    assert derive_status(True, True, True, False) == "PARTIALLY_WORKING"
    assert derive_status(False, True, True, True) == "NOT_WORKING"
    print("✓ Desktop common agent logic")

def test_module_names():
    expected = {
        1: "AI Real-time Threat Detection",
        11: "Real-time Malware Scanning",
        21: "Camera Access Monitoring",
        31: "Anti-Ransomware Protection",
        41: "Global Threat Intelligence",
        50: "One-tap Security Activation",
    }
    mod_map = {m["id"]: m["name"] for m in MODULES_50}
    for k, v in expected.items():
        assert mod_map[k] == v, f"M{k} name mismatch: {mod_map[k]} vs {v}"
    print("✓ Module names correct")

if __name__ == "__main__":
    test_50_modules()
    test_no_ios()
    test_platforms()
    test_apk_only_on_android()
    test_process_isolation_limits()
    test_universal_manager()
    test_desktop_agent_common()
    test_module_names()
    print("\nAll universal tests passed (8 checks)")
