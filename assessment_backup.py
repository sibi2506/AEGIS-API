import requests

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "description": "Controls which resources a browser can load.",
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

COMMON_ENDPOINTS = [
    "/",
    "/api",
    "/api/health",
    "/api/users",
    "/api/products",
    "/api/login",
    "/api/register",
    "/api/docs",
    "/openapi.json",
    "/swagger.json",
]


def run_assessment(target_url):
    target_url = target_url.strip().rstrip("/")

    if not target_url.startswith(("http://", "https://")):
        raise ValueError("Enter a valid URL beginning with http:// or https://")

    results = {
        "target": target_url,
        "endpoints": [],
        "findings": [],
        "errors": [],
    }

    session = requests.Session()

    # 1. Check the target and inspect its security headers.
    try:
        response = session.get(target_url, timeout=5)

        results["target_status"] = response.status_code

        for header, details in SECURITY_HEADERS.items():
            if header not in response.headers:
                results["findings"].append({
                    "category": "Security Headers",
                    "endpoint": "/",
                    "method": "GET",
                    "issue": f"Missing {header}",
                    "severity": details["severity"],
                    "evidence": details["description"],
                })

    except requests.RequestException as error:
        raise ConnectionError(
            f"Could not connect to the target: {error}"
        ) from error

    # 2. Check common endpoint paths.
    for path in COMMON_ENDPOINTS:
        url = target_url + path

        try:
            response = session.get(url, timeout=5)

            if response.status_code != 404:
                results["endpoints"].append({
                    "path": path,
                    "method": "GET",
                    "status_code": response.status_code,
                    "content_type": response.headers.get(
                        "Content-Type", "Unknown"
                    ),
                })

        except requests.RequestException as error:
            results["errors"].append({
                "endpoint": path,
                "message": str(error),
            })

    results["summary"] = {
        "endpoints_found": len(results["endpoints"]),
        "findings_count": len(results["findings"]),
        "high": sum(
            item["severity"] == "HIGH"
            for item in results["findings"]
        ),
        "medium": sum(
            item["severity"] == "MEDIUM"
            for item in results["findings"]
        ),
        "low": sum(
            item["severity"] == "LOW"
            for item in results["findings"]
        ),
        "info": sum(
            item["severity"] == "INFO"
            for item in results["findings"]
        ),
    }

    return results


if __name__ == "__main__":
    target = input("Enter your test API URL: ").strip()

    try:
        assessment = run_assessment(target)

        print("\n=== AegisAPI Assessment Results ===")
        print(f"Target: {assessment['target']}")
        print(f"Endpoints found: {assessment['summary']['endpoints_found']}")
        print(f"Findings: {assessment['summary']['findings_count']}")

        for finding in assessment["findings"]:
            print(
                f"[{finding['severity']}] "
                f"{finding['issue']} at {finding['endpoint']}"
            )

    except (ValueError, ConnectionError) as error:
        print(f"\n[ERROR] {error}")