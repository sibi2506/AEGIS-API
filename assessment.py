import requests
from urllib.parse import urlparse
import ipaddress
import socket

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
    "/api/profile",
    "/api/search",
]


def add_finding(results, category, endpoint, method, issue, severity, evidence):
    results["findings"].append({
        "category": category,
        "endpoint": endpoint,
        "method": method,
        "issue": issue,
        "severity": severity,
        "evidence": evidence,
    })


def run_assessment(target_url):

    results = {
        "target": target_url,
        "endpoints": [],
        "findings": [],
        "errors": [],
        "checks": [],
    }

    target_url = target_url.strip().rstrip("/")

    parsed_url = urlparse(target_url)

    if (
        parsed_url.scheme not in ("http", "https")
        or not parsed_url.hostname
        or parsed_url.username
        or parsed_url.password
    ):
        raise ValueError(
            "Enter a valid HTTP or HTTPS URL without embedded credentials."
        )

    try:
        parsed_url.port
    except ValueError:
        raise ValueError("The URL contains an invalid port number.")

    hostname = parsed_url.hostname

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        try:
            socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            raise ValueError("The target hostname could not be resolved.")

    session = requests.Session()

    # 1. Check the target and inspect security headers.
    try:
        response = session.get(target_url, timeout=5)
        results["target_status"] = response.status_code

        for header, details in SECURITY_HEADERS.items():
            if header not in response.headers:
                add_finding(
                    results,
                    "Security Headers",
                    "/",
                    "GET",
                    f"Missing {header}",
                    details["severity"],
                    details["description"],
                )

    except requests.RequestException as error:
        raise ConnectionError(
            f"Could not connect to the target: {error}"
        ) from error

        # 2. Discover common endpoints and inspect supported methods.
    for path in COMMON_ENDPOINTS:
        try:
            response = session.get(
                target_url + path,
                timeout=5,
                allow_redirects=False,
            )

            if response.status_code == 404:
                continue

            allowed_methods = []

            # Check supported methods if GET is not allowed.
            if response.status_code == 405:
                options_response = session.options(
                    target_url + path,
                    timeout=5,
                    allow_redirects=False,
                )

                allow_header = options_response.headers.get("Allow", "")
                allowed_methods = [
                    method.strip()
                    for method in allow_header.split(",")
                    if method.strip()
                ]

            results["endpoints"].append({
                "path": path,
                "method": "GET",
                "status_code": response.status_code,
                "allowed_methods": allowed_methods,
                "content_type": response.headers.get(
                    "Content-Type", "Unknown"
                ),
            })

        except requests.RequestException as error:
            results["errors"].append({
                "endpoint": path,
                "message": str(error),
            })

    # 3. Test login behavior on the controlled local test API.
    login_path = "/api/login"

    try:
        invalid_login = session.post(
            target_url + login_path,
            json={
                "username": "invalid-user",
                "password": "invalid-password",
            },
            timeout=5,
        )

        if invalid_login.status_code == 401:
            results["checks"] = results.get("checks", [])
            results["checks"].append({
                "name": "Invalid login rejection",
                "status": "PASS",
                "details": "Invalid credentials were rejected with HTTP 401.",
            })
        elif invalid_login.status_code == 200:
            add_finding(
                results,
                "Authentication",
                login_path,
                "POST",
                "Invalid credentials accepted",
                "HIGH",
                "The test login request used invalid credentials but returned HTTP 200. "
                "Review the response and authentication logic to confirm whether login succeeded.",
            )
        else:
            results["checks"] = results.get("checks", [])
            results["checks"].append({
                "name": "Invalid login rejection",
                "status": "REVIEW",
                "details": (
                    f"Invalid login returned HTTP {invalid_login.status_code}; "
                    "manual review is needed."
                ),
            })

    except requests.RequestException as error:
        results["errors"].append({
            "endpoint": login_path,
            "message": str(error),
        })

    # 4. Check that the profile endpoint rejects requests without a token.
        # 4. Check protected profile authentication.
    profile_path = "/api/profile"

    try:
        profile_response = session.get(
            target_url + profile_path,
            headers={"Authorization": ""},
            timeout=5,
        )

        if profile_response.status_code == 401:
            results["checks"].append({
                "name": "Protected profile authentication",
                "status": "PASS",
                "details": (
                    "The profile endpoint rejected an unauthenticated request "
                    "with HTTP 401."
                ),
            })

        elif profile_response.status_code == 403:
            results["checks"].append({
                "name": "Protected profile authentication",
                "status": "PASS",
                "details": (
                    "The profile endpoint denied unauthenticated access "
                    "with HTTP 403."
                ),
            })

        elif profile_response.status_code == 200:
            add_finding(
                results,
                "Authentication",
                profile_path,
                "GET",
                "Protected endpoint returned success without authentication",
                "HIGH",
                "The profile endpoint returned HTTP 200 without an "
                "Authorization token. Review whether protected data was disclosed.",
            )

        else:
            results["checks"].append({
                "name": "Protected profile authentication",
                "status": "REVIEW",
                "details": (
                    f"The endpoint returned HTTP {profile_response.status_code}; "
                    "manual review is needed."
                ),
            })

    except requests.RequestException as error:
        results["errors"].append({
            "endpoint": profile_path,
            "message": str(error),
        })

    # 5. Check input-length validation.
    search_path = "/api/search"

    try:
        long_query = "A" * 101

        search_response = session.get(
            target_url + search_path,
            params={"q": long_query},
            timeout=5,
        )

        if search_response.status_code == 400:
            results["checks"] = results.get("checks", [])
            results["checks"].append({
                "name": "Search input-length validation",
                "status": "PASS",
                "details": "The endpoint rejected a query longer than 100 characters.",
            })
        elif search_response.status_code == 200:
            add_finding(
                results,
                "Input Validation",
                search_path,
                "GET",
                "Search endpoint accepted input exceeding its documented limit",
                "LOW",
                "A 101-character query returned HTTP 200 although the test API is "
                "configured to reject queries longer than 100 characters. "
                "Confirm the response behavior before treating this as a vulnerability.",
            )
        else:
            results["checks"] = results.get("checks", [])
            results["checks"].append({
                "name": "Search input-length validation",
                "status": "REVIEW",
                "details": (
                    f"The endpoint returned HTTP {search_response.status_code}; "
                    "manual review is needed."
                ),
            })

    except requests.RequestException as error:
        results["errors"].append({
            "endpoint": search_path,
            "message": str(error),
        })

    # 6. Calculate severity totals.
    findings = results["findings"]

    results["summary"] = {
        "endpoints_found": len(results["endpoints"]),
        "findings_count": len(findings),
        "high": sum(item["severity"] == "HIGH" for item in findings),
        "medium": sum(item["severity"] == "MEDIUM" for item in findings),
        "low": sum(item["severity"] == "LOW" for item in findings),
        "info": sum(item["severity"] == "INFO" for item in findings),
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

        print("\n--- Severity Summary ---")
        for severity in ("high", "medium", "low", "info"):
            print(
                f"{severity.upper()}: "
                f"{assessment['summary'][severity]}"
            )

        print("\n--- Findings ---")
        for finding in assessment["findings"]:
            print(
                f"[{finding['severity']}] "
                f"{finding['issue']} at {finding['endpoint']}"
            )

        print("\n--- Additional Checks ---")
        for check in assessment.get("checks", []):
            print(
                f"[{check['status']}] {check['name']}: "
                f"{check['details']}"
            )

        if assessment["errors"]:
            print("\n--- Errors ---")
            for error in assessment["errors"]:
                print(f"{error['endpoint']}: {error['message']}")

    except (ValueError, ConnectionError) as error:
        print(f"\n[ERROR] {error}")

