#!/usr/bin/env python3
"""
Arabic Phishing Detector — CLI
Usage: python cli.py <url> [--json]
"""

import argparse
import json
import logging
import logging.handlers
import sys
from pathlib import Path
from colorama import Fore, Style, init as colorama_init

from detector.analyzer import analyze

# Configure logging for CLI use (mirrors the Django logging config)
_LOG_FILE = Path(__file__).parent / "logs" / "app.log"
_LOG_FILE.parent.mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.handlers.TimedRotatingFileHandler(
            _LOG_FILE, when="midnight", backupCount=30, encoding="utf-8"
        ),
    ],
)
# Silence noisy third-party libraries
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("charset_normalizer").setLevel(logging.WARNING)

colorama_init(autoreset=True)

STATUS_COLORS = {
    "HIGH RISK":  Fore.RED,
    "SUSPICIOUS": Fore.YELLOW,
    "CAUTION":    Fore.YELLOW,
    "UNKNOWN":    Fore.CYAN,
    "PASS":       Fore.GREEN,
}

RISK_COLORS = {
    "High":    Fore.RED,
    "Medium":  Fore.YELLOW,
    "Low":     Fore.GREEN,
    "Unknown": Fore.CYAN,
}


def print_report(report: dict) -> None:
    print()
    print(f"{Style.BRIGHT}[*] Analyzing: {report['url']}{Style.RESET_ALL}")
    print()

    if report["error"]:
        print(f"{Fore.RED}[!] Error: {report['error']}")
        return

    for check in report["checks"]:
        color = STATUS_COLORS.get(check["status"], Fore.WHITE)
        label = f"[{check['name']}]"
        status = check["status"]
        detail = check["detail"]
        print(f"  {Style.BRIGHT}{label:<25}{Style.RESET_ALL} {color}{status:<12}{Style.RESET_ALL} {detail}")

    print()
    risk_color = RISK_COLORS.get(report["risk_level"], Fore.WHITE)
    score_bar = "#" * (report["score"] // 5) + "-" * ((100 - report["score"]) // 5)
    print(f"{Style.BRIGHT}  Risk Score : {risk_color}{report['score']}/100  [{score_bar}]{Style.RESET_ALL}")
    print(f"{Style.BRIGHT}  Risk Level : {risk_color}{report['risk_level'].upper()}{Style.RESET_ALL}")
    print()
    print(f"  Verdict: {risk_color}{report['verdict']}{Style.RESET_ALL}")
    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Detect phishing URLs targeting Arabic/Saudi brand sites.",
        epilog="Example: python cli.py https://stc.com.sa",
    )
    parser.add_argument("url", help="The URL to analyze (must start with http:// or https://)")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON instead of formatted text",
    )
    args = parser.parse_args()

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        print(f"{Fore.RED}[!] Error: URL must start with http:// or https://")
        sys.exit(1)

    report = analyze(url)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_report(report)

    # Exit code: 1 if high risk, 0 otherwise (useful for scripting)
    if report["risk_level"] == "High":
        sys.exit(1)


if __name__ == "__main__":
    main()
