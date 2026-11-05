#!/usr/bin/env python3
"""
AdShield Pro — Windows 10/11 Security Agent
Integrates: Windows Defender, Windows Firewall, Windows Security Center
Uses only supported APIs: PowerShell WMI, netsh, Defender cmdlets where available.

Usage:
  python agent.py --status          # Platform status
  python agent.py --diagnose        # Full 50-module diagnostics
  python agent.py --report          # JSON report
  python agent.py --aether-url http://127.0.0.1:8000 --token TOKEN --forward
"""
import argparse
import json
import sys
import time
from pathlib import Path

# Add common to path
sys.path.insert(0, str(Path(__file__).parent.parent / "common"))
from universal_agent import run_all_diagnostics, generate_report, get_system_info, check_defender_windows, check_firewall_windows

def windows_security_status() -> dict:
    defender = check_defender_windows()
    firewall = check_firewall_windows()
    sys_info = get_system_info()
    return {
        "platform": "Windows",
        "system_info": sys_info,
        "defender": defender,
        "firewall": firewall,
        "windows_version": sys_info.get("platform_version", "unknown"),
        "status": "active" if defender.get("available") else "unknown",
        "detail": f"Windows {sys_info.get('platform_version')} — Defender available={defender.get('available')} Firewall available={firewall.get('available')}",
        "limitations": [
            "Requires Windows 10/11 with PowerShell",
            "Defender WMI requires admin for full status",
            "Firewall rules via netsh require elevation",
            "No kernel driver installed — uses existing OS protections",
            "Process isolation via Win32 where permitted",
        ],
        "timestamp": int(time.time()*1000),
    }

def main():
    parser = argparse.ArgumentParser(description="AdShield Pro Windows Agent")
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
        status = windows_security_status()
        if args.json or args.report:
            print(json.dumps(status, indent=2))
        else:
            print("AdShield Pro — Windows Security Agent")
            print(f"Platform: {status['system_info']['platform']} {status['system_info']['platform_version']}")
            print(f"Defender: {status['defender']}")
            print(f"Firewall: {status['firewall']}")
            print(f"Detail: {status['detail']}")
            print("Limitations:")
            for lim in status["limitations"]:
                print(f"  • {lim}")
        if args.output:
            Path(args.output).write_text(json.dumps(status, indent=2))

    elif args.diagnose or args.report:
        results = run_all_diagnostics("Windows")
        report = generate_report(results, "Windows")
        # Add Windows-specific info
        report["windows_specific"] = windows_security_status()
        output = json.dumps(report, indent=2)
        print(output)
        if args.output:
            Path(args.output).write_text(output)
        if args.forward and args.token:
            try:
                import urllib.request
                url = args.aether_url.rstrip("/") + "/api/v1/universal/diagnostics"
                data = json.dumps({"platform": "Windows", "report": report}).encode()
                req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json", "Authorization": f"Bearer {args.token}"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    print(f"Forwarded to AETHER: {resp.status} {resp.read().decode()[:200]}")
            except Exception as e:
                print(f"Forward failed: {e}", file=sys.stderr)
    else:
        parser.print_help()
        # Default: show status
        print("\n--- Default: Windows Status ---")
        print(json.dumps(windows_security_status(), indent=2))

if __name__ == "__main__":
    main()
