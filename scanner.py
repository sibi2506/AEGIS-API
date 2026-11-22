import json
from datetime import datetime, timezone

import requests

TARGET_URL = "http://127.0.0.1:5000"

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Helps control which resources a browser can load.",
        "severity": "LOW",
    },
    "X-Content-Type-Options": {
        "description": "Helps prevent MIME-type sniffing.",
        "severity": "LOW",
    },
    "X-Frame-Options": {
        "description": "Helps control whether a page can be embedded in frames.",
        "severity": "LOW",
    },
    "Strict-Transport-Security": {
        "description": "Helps browsers use HTTPS for future connections.",
        "severity": "INFO",
    },
    "Referrer-Policy": {
        "description": "Controls how much referrer information browsers send.",
        "severity": "LOW",
    },
}


def scan_security_headers(url):
    print("\n=== AegisAPI Security Header Scanner ===")
    print(f"Target: {url}")
    print("-" * 50)

    findings = []

    try:
        response = requests.get(url, timeout=5)

        print(f"HTTP Status Code: {response.status_code}")
        print("\nChecking security headers:\n")

        for header, details in SECURITY_HEADERS.items():
            if header in response.headers:
                print(f"[PASS] {header}")
            else:
                finding = {
                    "header": header,
                    "severity": details["severity"],
                    "description": details["description"],
                }

                findings.append(finding)

                print(
                    f"[{finding['severity']}] "
                    f"Missing: {header}"
                )
                print(f"       Purpose: {details['description']}")

        report = {
            "tool": "AegisAPI",
            "scan_time_utc": datetime.now(timezone.utc).isoformat(),
            "target": url,
            "http_status": response.status_code,
            "headers_checked": len(SECURITY_HEADERS),
            "findings_count": len(findings),
            "findings": findings,
        }

        with open("report.json", "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("\n" + "=" * 50)
        print(f"Headers checked: {len(SECURITY_HEADERS)}")
        print(f"Findings recorded: {len(findings)}")
        print("Report saved to report.json")
        print("=" * 50)

        return findings

    except requests.exceptions.RequestException as error:
        print(f"[ERROR] Could not connect to the API: {error}")
        return []


if __name__ == "__main__":
    scan_security_headers(TARGET_URL)