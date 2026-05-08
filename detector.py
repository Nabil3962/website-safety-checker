import socket
import ssl
import requests
from urllib.parse import urlparse
from datetime import datetime

BRANDS = [
    "facebook", "google", "paypal",
    "apple", "microsoft", "amazon",
    "instagram", "netflix"
]


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


def analyze_url(url):
    url = normalize_url(url)
    parsed = urlparse(url)

    domain = parsed.netloc

    result = {
        "url": url,
        "domain": domain,
        "ip": None,
        "final_url": None,
        "ssl_expiry": None,
        "issues": []
    }

    # ---------------- DNS CHECK ----------------
    try:
        result["ip"] = socket.gethostbyname(domain)
    except:
        result["issues"].append("DNS lookup failed (domain may not exist)")

    # ---------------- IP DETECTION ----------------
    try:
        socket.inet_aton(domain.split(":")[0])
        result["issues"].append("Raw IP address used instead of domain")
    except:
        pass

    # ---------------- BRAND SPOOFING ----------------
    for b in BRANDS:
        if b in domain.lower() and not domain.endswith(b + ".com"):
            result["issues"].append(f"Possible brand impersonation: {b}")

    # ---------------- DOMAIN PATTERN ----------------
    if domain.count("-") > 2:
        result["issues"].append("Excessive hyphens detected")

    if len(domain) > 40:
        result["issues"].append("Unusually long domain name")

    # ---------------- REQUEST (REDIRECT SAFE) ----------------
    try:
        res = requests.get(url, timeout=6, allow_redirects=True)
        result["final_url"] = res.url

        if res.status_code >= 400:
            result["issues"].append(f"HTTP error: {res.status_code}")

    except requests.exceptions.SSLError:
        result["issues"].append("SSL certificate error")

    except requests.exceptions.ConnectionError:
        result["issues"].append("Website not reachable")

    except:
        result["issues"].append("Unknown connection issue")

    # ---------------- SSL CHECK ----------------
    try:
        host = urlparse(result["final_url"]).netloc if result["final_url"] else domain

        ctx = ssl.create_default_context()

        with socket.create_connection((host, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

                expiry = datetime.strptime(
                    cert["notAfter"],
                    "%b %d %H:%M:%S %Y %Z"
                )

                result["ssl_expiry"] = expiry.strftime("%Y-%m-%d")

    except:
        result["issues"].append("SSL info not available or invalid HTTPS")

    return result
