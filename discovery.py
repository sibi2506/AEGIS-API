import requests

BASE_URL = "http://127.0.0.1:5000"

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


def discover_endpoints(base_url):
    print("\n=== AegisAPI Endpoint Discovery ===")
    print(f"Target: {base_url}")
    print("-" * 50)

    discovered = []

    for path in COMMON_ENDPOINTS:
        url = base_url.rstrip("/") + path

        try:
            response = requests.get(url, timeout=5)

            if response.status_code != 404:
                result = {
                    "path": path,
                    "status_code": response.status_code,
                    "content_type": response.headers.get(
                        "Content-Type", "Unknown"
                    ),
                }

                discovered.append(result)

                print(
                    f"[FOUND] {path} "
                    f"| HTTP {response.status_code}"
                )
            else:
                print(f"[NOT FOUND] {path}")

        except requests.exceptions.RequestException as error:
            print(f"[ERROR] {path}: {error}")

    print("\n" + "=" * 50)
    print(f"Paths checked: {len(COMMON_ENDPOINTS)}")
    print(f"Potential endpoints found: {len(discovered)}")
    print("=" * 50)

    return discovered


if __name__ == "__main__":
    discover_endpoints(BASE_URL)