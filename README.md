# 🔍 Website Safety Checker

A simple cybersecurity-focused web application built with Flask that analyzes website URLs and checks whether they look safe or suspicious.

This tool performs basic phishing-style detection checks such as suspicious domains, fake login patterns, broken SSL certificates, DNS failures, raw IP links, and unreachable websites.

---

# 🚀 Features

- Analyze website URLs
- Detect suspicious phishing-style domains
- Detect raw IP address links
- DNS lookup verification
- SSL certificate validation
- SSL expiry date check
- Website connection testing
- Detect suspicious brand usage
- Human-readable security report
- Simple dark-themed interface

---

# 🛠 Technologies Used

- Python 3
- Flask
- Requests
- Socket
- SSL
- HTML
- CSS
- JavaScript

---

# 📂 Project Structure

```text
website-safety-checker/
│
├── app.py
├── requirements.txt
├── README.md
│
├── templates/
│   └── index.html
│
├── static/
│   ├── style.css
│   └── script.js
```

---

# ⚙ Installation

Clone the repository:

```bash
git clone https://github.com/yourusername/website-safety-checker.git
cd website-safety-checker
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python app.py
```

Open in browser:

```text
http://127.0.0.1:5000
```

---

# 🧪 Example Test URLs

## Safe Examples

```text
facebook.com
google.com
openai.com
github.com
```

## Suspicious Examples

```text
facebook-security-login.com
paypal-account-verify-secure.com
http://192.168.1.1/login
```

---

# 📸 Example Checks

The tool may detect:

- Suspicious domain names
- Fake login-style URLs
- Missing HTTPS
- Invalid SSL certificates
- Dead websites
- DNS lookup failures
- Raw IP address links
- Excessive hyphens in domains

---

# ⚠ Disclaimer

This project is for educational purposes only.

It is NOT a real antivirus, penetration testing framework, or guaranteed phishing detector.

The scanner only performs basic analysis and may produce false positives or miss advanced threats.

Always use professional security tools and browser protection for real-world security.

---

# 👨‍💻 Author

Developed as a beginner cybersecurity and web security learning project.
