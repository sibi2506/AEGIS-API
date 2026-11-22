from urllib.parse import urlparse

print("========================================")
print("AegisAPI Security Assessment")
print("========================================")

target = input("Enter your authorized API URL: ")
parsed = urlparse(target)

valid_scheme = parsed.scheme in ("http", "https")
valid_host = bool(parsed.hostname)

print("Target:", target)
print("Valid HTTP/HTTPS scheme:", valid_scheme)
print("Hostname provided:", valid_host)
print("URL validation check completed.")