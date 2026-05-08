import socket
import ssl
import requests
from urllib.parse import urlparse
from datetime import datetime

BRAND_KEYWORDS = [
    "facebook", "google", "paypal",
    "apple", "microsoft", "amazon",
    "instagram", "netflix", "bank", "login", "secure"
]

LEGIT_DOMAINS = [
    "facebook.com", "google.com", "paypal.com",
    "apple.com", "microsoft.com", "amazon.com",
    "instagram.com", "netflix.com"
]


def analyze_url(url: str):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    result = {
        "url": url,
        "domain": domain,
        "ip": None,
        "ssl_expiry": None,
        "issues": []
    }

    # ---------------- DNS CHECK ----------------
    try:
        result["ip"] = socket.gethostbyname(domain)
    except:
        result["issues"].append("DNS lookup failed (domain may not exist)")

    # ---------------- IP BASED URL ----------------
    try:
        socket.inet_aton(domain.split(":")[0])
        result["issues"].append("Uses raw IP address instead of domain name")
    except:
        pass

    # ---------------- BRAND SPOOF CHECK ----------------
    for word in BRAND_KEYWORDS:
        if word in domain.lower():
            if not any(domain.endswith(ld) for ld in LEGIT_DOMAINS):
                result["issues"].append(
                    f"Suspicious brand keyword used: '{word}'"
                )

    # ---------------- DOMAIN PATTERN CHECK ----------------
    if domain.count("-") > 2:
        result["issues"].append("Too many hyphens (common in phishing URLs)")

    if len(domain) > 40:
        result["issues"].append("Unusually long domain name")

    # ---------------- HTTP CHECK ----------------
    try:
        res = requests.get(url, timeout=5)
        if res.status_code >= 400:
            result["issues"].append(f"HTTP error: {res.status_code}")
    except requests.exceptions.SSLError:
        result["issues"].append("SSL certificate problem")
    except requests.exceptions.ConnectionError:
        result["issues"].append("Website is not reachable")
    except:
        result["issues"].append("Unknown connection error")

    # ---------------- SSL CHECK ----------------
    if parsed.scheme == "https":
        try:
            hostname = domain.split(":")[0]
            ctx = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    expiry = datetime.strptime(
                        cert["notAfter"],
                        "%b %d %H:%M:%S %Y %Z"
                    )
                    result["ssl_expiry"] = expiry.strftime("%Y-%m-%d")

        except:
            result["issues"].append("Could not read SSL certificate")
    else:
        result["issues"].append("Website does not use HTTPS")

    return result
