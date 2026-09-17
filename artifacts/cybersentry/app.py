"""CyberSentry: an educational, local-only URL investigation dashboard."""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import urlsplit

from flask import Flask, jsonify, render_template, request

app = Flask(__name__)

SUSPICIOUS_KEYWORDS = {
    "account": "Account-related language can be used to pressure someone into signing in.",
    "bank": "Banking language can be used to imitate a financial institution.",
    "bonus": "Bonus or reward language can create urgency and encourage impulsive clicks.",
    "confirm": "Confirmation language can make a link feel like an urgent task.",
    "crypto": "Cryptocurrency language is commonly used in high-pressure scam campaigns.",
    "free": "Free offers are sometimes used as bait on deceptive landing pages.",
    "invoice": "Invoice language can imitate a payment request or business notification.",
    "login": "Login language may be trying to collect credentials.",
    "payment": "Payment language can be used to imitate a checkout or billing notice.",
    "password": "Password language may be trying to collect or reset credentials.",
    "secure": "Security language can be used to make a suspicious link appear trustworthy.",
    "urgent": "Urgent language is a common social-engineering tactic.",
    "update": "Update language can be used to pressure someone into visiting quickly.",
    "verify": "Verification language may be trying to collect credentials or personal data.",
    "wallet": "Wallet language can be used to target cryptocurrency accounts.",
}


def _indicator(
    indicator_id: str,
    title: str,
    explanation: str,
    evidence: str,
    severity: str = "medium",
) -> dict[str, str]:
    return {
        "id": indicator_id,
        "title": title,
        "explanation": explanation,
        "evidence": evidence,
        "severity": severity,
    }


def analyze_url(raw_url: str) -> dict:
    """Inspect URL text only. This function never makes a network request."""
    value = raw_url.strip()
    indicators: list[dict[str, str]] = []

    candidate = value if re.match(r"^[a-z][a-z0-9+.-]*://", value, re.I) else f"https://{value}"
    parsed = urlsplit(candidate)
    hostname = parsed.hostname or ""
    lowered = value.lower()

    if len(value) > 120:
        indicators.append(
            _indicator(
                "long-url",
                "Unusually long URL",
                "Long URLs can hide the important part of a link among many parameters or encoded characters.",
                f"{len(value)} characters detected",
            )
        )

    if "@" in value:
        indicators.append(
            _indicator(
                "at-symbol",
                "At symbol in URL",
                "An @ symbol can make text before it look like the destination while the browser uses the hostname after it.",
                "@ symbol present",
                "high",
            )
        )

    try:
        ipaddress.ip_address(hostname)
        indicators.append(
            _indicator(
                "ip-hostname",
                "IP-address hostname",
                "Direct IP addresses are less common for public websites and can make ownership harder to verify.",
                hostname,
                "high",
            )
        )
    except ValueError:
        pass

    if hostname.startswith("xn--") or ".xn--" in hostname:
        indicators.append(
            _indicator(
                "punycode",
                "Punycode hostname",
                "Punycode can represent lookalike internationalized characters that are difficult to distinguish at a glance.",
                hostname,
                "high",
            )
        )

    if hostname.count(".") >= 4:
        indicators.append(
            _indicator(
                "nested-subdomains",
                "Many nested subdomains",
                "Several subdomain levels can obscure the registered domain you need to verify.",
                f"{hostname.count('.') + 1} hostname segments",
            )
        )

    try:
        port = parsed.port
    except ValueError:
        port = None
        indicators.append(
            _indicator(
                "invalid-port",
                "Invalid port format",
                "The hostname includes a port value that is not a valid number, so the URL should be treated carefully.",
                "Port could not be parsed",
                "high",
            )
        )

    if port is not None and port not in (80, 443):
        indicators.append(
            _indicator(
                "nonstandard-port",
                "Non-standard port",
                "A port outside the usual web ports is worth checking because it is uncommon for ordinary public links.",
                f"Port {port}",
            )
        )

    matched_keywords = [
        keyword for keyword in SUSPICIOUS_KEYWORDS if re.search(rf"(?<![a-z]){re.escape(keyword)}(?![a-z])", lowered)
    ]
    if matched_keywords:
        keyword_list = ", ".join(matched_keywords[:4])
        if len(matched_keywords) > 4:
            keyword_list += f" +{len(matched_keywords) - 4} more"
        explanation = " ".join(SUSPICIOUS_KEYWORDS[keyword] for keyword in matched_keywords[:2])
        indicators.append(
            _indicator(
                "suspicious-keywords",
                "Suspicious keywords",
                explanation,
                keyword_list,
                "medium",
            )
        )

    if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
        indicators.append(
            _indicator(
                "unusual-scheme",
                "Unusual URL scheme",
                "This is not a standard HTTP or HTTPS web link, so confirm you intended to inspect this format.",
                parsed.scheme,
                "high",
            )
        )

    return {
        "url": value,
        "hostname": hostname or "Unable to identify hostname",
        "category": "Needs Review" if indicators else "No Obvious Indicators",
        "indicator_count": len(indicators),
        "indicators": indicators,
        "note": "This result is based on URL text patterns only. It does not visit, open, or resolve the URL.",
    }


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/analyze")
def analyze():
    payload = request.get_json(silent=True) or {}
    raw_url = payload.get("url", "")
    if not isinstance(raw_url, str) or not raw_url.strip():
        return jsonify({"error": "Enter a URL to analyze."}), 400
    if len(raw_url.strip()) > 4096:
        return jsonify({"error": "Please enter a URL shorter than 4,096 characters."}), 400
    return jsonify(analyze_url(raw_url))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")