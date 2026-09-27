"""CyberSentry: an educational, local-only URL investigation dashboard."""

from __future__ import annotations

import ipaddress
import os
import re
from urllib.parse import parse_qsl, urlsplit

from flask import Flask, jsonify, render_template, request
from ml.ml_predict import predict

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

URL_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*://", re.IGNORECASE)
ENCODED_COMPONENT_RE = re.compile(r"%[0-9a-f]{2}", re.IGNORECASE)


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


def normalize_url(raw_url: str) -> tuple[str, object]:
    """Normalize and validate URL text without resolving or fetching it."""
    if not isinstance(raw_url, str):
        raise ValueError("Enter a URL to analyze.")

    value = raw_url.strip()
    if not value:
        raise ValueError("Enter a URL to analyze.")
    if len(value) > 4096:
        raise ValueError("Please enter a URL shorter than 4,096 characters.")
    if any(character.isspace() for character in value):
        raise ValueError("URLs cannot contain spaces. Remove spaces and try again.")

    if value.startswith("//"):
        normalized = f"https:{value}"
    elif URL_SCHEME_RE.match(value):
        normalized = value
    else:
        normalized = f"https://{value}"

    try:
        parsed = urlsplit(normalized)
    except ValueError as error:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from error

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs can be analyzed.")
    if not parsed.netloc or not parsed.hostname:
        raise ValueError("Enter a URL with a hostname, such as example.com.")

    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("The URL contains an invalid port number.") from error
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("The URL port must be between 1 and 65,535.")

    return normalized, parsed


def analyze_url(raw_url: str) -> dict:
    """Inspect URL text only. This function never makes a network request."""
    normalized, parsed = normalize_url(raw_url)
    indicators: list[dict[str, str]] = []
    hostname = parsed.hostname or ""
    lowered = normalized.lower()
    encoded_component_count = len(ENCODED_COMPONENT_RE.findall(normalized))
    query_parameter_count = len(parse_qsl(parsed.query, keep_blank_values=True)) if parsed.query else 0
    try:
        ipaddress.ip_address(hostname)
        hostname_is_ip = True
    except ValueError:
        hostname_is_ip = False

    if len(normalized) > 120:
        indicators.append(
            _indicator(
                "long-url",
                "Unusually long URL",
                "Long URLs can hide the important part of a link among many parameters or encoded characters.",
                f"{len(normalized)} characters detected",
            )
        )

    if "@" in normalized:
        indicators.append(
            _indicator(
                "at-symbol",
                "At symbol in URL",
                "An @ symbol can make text before it look like the destination while the browser uses the hostname after it.",
                "@ symbol present",
                "high",
            )
        )

    if hostname_is_ip:
        indicators.append(
            _indicator(
                "ip-hostname",
                "IP-address hostname",
                "Direct IP addresses are less common for public websites and can make ownership harder to verify.",
                hostname,
                "high",
            )
        )

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

    port = parsed.port
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

    if encoded_component_count >= 3:
        indicators.append(
            _indicator(
                "encoded-components",
                "Multiple encoded components",
                "Several percent-encoded values can make the visible URL harder to read and the destination harder to inspect at a glance.",
                f"{encoded_component_count} percent-encoded values",
                "medium",
            )
        )

    if query_parameter_count >= 6:
        indicators.append(
            _indicator(
                "many-query-parameters",
                "Many query parameters",
                "A large parameter string can obscure tracking, redirect, or data-collection behavior in the visible link.",
                f"{query_parameter_count} query parameters",
                "medium",
            )
        )

    return {
        "url": normalized,
        "features": {
            "length": len(normalized),
            "scheme": parsed.scheme.lower(),
            "hostname": hostname,
            "hostname_is_ip": hostname_is_ip,
            "port": port,
            "path": parsed.path or "/",
            "query_parameter_count": query_parameter_count,
            "encoded_component_count": encoded_component_count,
            "has_fragment": bool(parsed.fragment),
            "has_credentials": parsed.username is not None or parsed.password is not None,
        },
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
    try:
        return jsonify(analyze_url(raw_url))
    except ValueError as error:
        return jsonify({"error": str(error)}), 400


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=os.environ.get("FLASK_DEBUG") == "1")