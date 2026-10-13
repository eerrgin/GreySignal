#!/usr/bin/env python3
"""GreySignal: a one-request, passive HTTP security-header auditor."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

CHECKS = {
    "Strict-Transport-Security": (
        "Recommended for HTTPS sites. Helps browsers keep using HTTPS.",
        "review",
    ),
    "Content-Security-Policy": (
        "Restricts permitted content sources; policy should fit the application.",
        "review",
    ),
    "X-Content-Type-Options": (
        "Usually set to 'nosniff' to reduce MIME-sniffing risks.",
        "review",
    ),
    "X-Frame-Options": (
        "Helps control framing; CSP frame-ancestors is the modern companion.",
        "review",
    ),
    "Referrer-Policy": (
        "Controls how much referrer information browsers send.",
        "review",
    ),
    "Permissions-Policy": (
        "Can limit browser features such as camera, microphone, and geolocation.",
        "review",
    ),
}


def validate_url(value: str) -> str:
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Provide a complete http:// or https:// URL.")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are not accepted.")
    return value


def audit(url: str) -> dict:
    validate_url(url)
    # Deliberately one request only, with redirects disabled and a short timeout.
    response = requests.get(
        url,
        timeout=(3.05, 7),
        allow_redirects=False,
        headers={"User-Agent": "GreySignal/1.0 (passive security-header audit)"},
    )
    headers = {key.lower(): value for key, value in response.headers.items()}
    results = []

    for name, (purpose, _) in CHECKS.items():
        value = headers.get(name.lower())
        results.append({
            "header": name,
            "status": "present" if value else "missing",
            "value": value,
            "purpose": purpose,
        })

    return {
        "tool": "GreySignal",
        "version": "1.0.0",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "requested_url": url,
        "http_status": response.status_code,
        "redirect_followed": False,
        "checks": results,
        "notice": (
            "A missing header is not by itself proof of a vulnerability. "
            "Assess only systems you own or are authorized to test."
        ),
    }


def print_report(report: dict) -> None:
    print(f"\nGreySignal | Passive Header Audit")
    print("=" * 38)
    print(f"URL:    {report['requested_url']}")
    print(f"HTTP:   {report['http_status']}")
    print("-" * 38)
    for item in report["checks"]:
        mark = "OK" if item["status"] == "present" else "CHECK"
        print(f"[{mark:5}] {item['header']}")
        if item["value"]:
            print(f"        Value: {item['value']}")
        print(f"        {item['purpose']}")
    print("\nNote:", report["notice"])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="One-request passive HTTP security-header auditor."
    )
    parser.add_argument("url", help="HTTP(S) URL you own or are authorized to assess")
    parser.add_argument("--json", metavar="FILE", help="write the report as JSON")
    args = parser.parse_args()

    try:
        report = audit(args.url)
    except (ValueError, requests.RequestException) as exc:
        print(f"GreySignal error: {exc}", file=sys.stderr)
        return 2

    print_report(report)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)
        print(f"\nJSON report written to {args.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
