#!/usr/bin/env python3
"""
AdShield Pro — macOS Security Agent
Integrates: Gatekeeper, XProtect, System Extensions (where entitled), Network Extension
Uses only supported Apple frameworks: spctl, system_profiler, Endpoint Security where entitled.

Usage:
  python agent.py --status
  python agent.py --diagnose
  python agent.py --report
"""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "common"))
from universal_agent import run_all_diagnostics, generate_report, get_system_info, check_gatekeeper_macos, check_xprotect_macos

def macos_security_status() -> dict:
    gatekeeper = check_gatekeeper_macos()
    xprotect = check_xprotect_macos()
    sys_info = get_system_info()
    # Check macOS version
    import platform as plat
    mac_ver = plat.mac_ver()[0] if plat.mac_ver()[0] else "unknown"
    return {
        "platform": "macOS",
        "system_info": sys_info,
        "macos_version": mac_ver,
        "gatekeeper": gatekeeper,
        "xprotect": xprotect,
        "status": "active" if gatekeeper.get("available") or xprotect.get("available") else "unknown",
        "detail": f"macOS {mac_ver} — Gatekeeper={gatekeeper.get('detail')} XProtect={xprotect.get('detail')}",
        "limitations": [
            "Requires macOS 13+ (Ventura) or later",
            "Endpoint Security requires entitlement + MDM approval",
            "Network Extension requires system approval",
            "Gatekeeper status via spctl",
            "No universal app-level blocking without extension",
        ],
        "timestamp": int(time.time()*1000),
    }

def main():
    parser = argparse.ArgumentParser(description="AdShield Pro macOS Agent")
    parser.add_argument("--status", action="store_true", help="Show platform security status")
    parser.add_argument("--diagnose", action="store_true", help="Run 50-module diagnostics")
    parser.add_argument("--report", action="store_true", help="Generate JSON report")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--aether-url", default="http://127.0.0.1:8000", help="AETHER backend URL")
    parser.add_argument("--token", default=None, help="AETHER API token")
    parser.add_argument("--forward", action="store_true", help="Forward results to AETHER backend")
    parser.add_argument("--output", default=None, help="Output file path")
    args = parser.parse_args()

    if args.status:
        status = macos_security_status()
        if args.json or args.report:
            print(json.dumps(status, indent=2))
        else:
            print("AdShield Pro — macOS Security Agent")
            print(f"Platform: macOS {status['macos_version']}")
            print(f"Gatekeeper: {status['gatekeeper']}")
            print(f"XProtect: {status['xprotect']}")
            print(f"Detail: {status['detail']}")
            print("Limitations:")
            for lim in status["limitations"]:
                print(f"  • {lim}")
        if args.output:
            Path(args.output).write_text(json.dumps(status, indent=2))
    elif args.diagnose or args.report:
        results = run_all_diagnostics("Darwin")
        report = generate_report(results, "Darwin")
        report["macos_specific"] = macos_security_status()
        output = json.dumps(report, indent=2)
        print(output)
        if args.output:
            Path(args.output).write_text(output)
        if args.forward and args.token:
            try:
                import urllib.request
                url = args.aether_url.rstrip("/") + "/api/v1/universal/diagnostics"
                data = json.dumps({"platform": "macOS", "report": report}).encode()
                req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "Authorization": f"Bearer {args.token}"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    print(f"Forwarded to AETHER: {resp.status} {resp.read().decode()[:200]}")
            except Exception as e:
                print(f"Forward failed: {e}", file=sys.stderr)
    else:
        parser.print_help()
        print("\n--- Default: macOS Status ---")
        print(json.dumps(macos_security_status(), indent=2))

if __name__ == "__main__":
    main()
