from flask import Flask, render_template, request
from urllib.parse import urlparse
import socket
import ssl
import requests
from datetime import datetime

app = Flask(__name__)

KNOWN_BRANDS = [
    "facebook", "google", "paypal",
    "microsoft", "apple", "amazon",
    "instagram", "netflix", "bank",
    "login", "secure"
]


def analyze_website(url):
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    domain = parsed.netloc

    issues = []
    resolved_ip = None
    ssl_expiry = None

    # IP Address Detection
    try:
        socket.inet_aton(domain.split(":")[0])
        issues.append("Uses raw IP address instead of domain.")
    except:
        pass

    # Suspicious Brand Usage
    for brand in KNOWN_BRANDS:
        if brand in domain.lower():

            legit_domains = [
                "facebook.com",
                "google.com",
                "paypal.com",
                "microsoft.com",
                "apple.com",
                "amazon.com",
                "instagram.com",
                "netflix.com"
            ]

            if not any(domain.endswith(ld) for ld in legit_domains):
                issues.append(
                    f"Contains suspicious brand-related word: {brand}"
                )

    # Hyphen Check
    if domain.count("-") >= 2:
        issues.append("Too many hyphens in domain.")

    # Long Domain Check
    if len(domain) > 35:
        issues.append("Unusually long domain name.")

    # DNS Lookup
    try:
        resolved_ip = socket.gethostbyname(domain)
    except:
        issues.append("DNS lookup failed.")

    # Connection Test
    try:
        response = requests.get(url, timeout=5)

        if response.status_code >= 400:
            issues.append(f"Website returned HTTP {response.status_code}")

    except requests.exceptions.SSLError:
        issues.append("Invalid SSL certificate.")

    except requests.exceptions.ConnectionError:
        issues.append("Could not connect to website.")

    except:
        issues.append("Unknown connection error.")

    # SSL Expiry
    if parsed.scheme == "https":
        try:
            hostname = domain.split(":")[0]

            context = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:

                    cert = ssock.getpeercert()

                    expiry_str = cert['notAfter']

                    expiry_date = datetime.strptime(
                        expiry_str,
                        "%b %d %H:%M:%S %Y %Z"
                    )

                    ssl_expiry = expiry_date.strftime("%Y-%m-%d")

        except:
            issues.append("Could not retrieve SSL certificate.")

    else:
        issues.append("Website is not using HTTPS.")

    return {
        "url": url,
        "domain": domain,
        "resolved_ip": resolved_ip,
        "ssl_expiry": ssl_expiry,
        "issues": issues
    }


@app.route("/", methods=["GET", "POST"])
def home():

    result = None

    if request.method == "POST":
        url = request.form.get("url")
        result = analyze_website(url)

    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
