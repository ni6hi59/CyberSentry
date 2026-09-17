# CyberSentry

CyberSentry is an educational cybersecurity URL investigation dashboard. It checks the text of a URL for a small set of common warning signs without visiting, resolving, or opening the destination.

## Included checks

- Unusually long URLs
- `@` symbols in the URL
- IP-address hostnames
- Punycode hostnames
- Many nested subdomains
- Non-standard ports
- Suspicious words such as `login`, `verify`, `password`, `payment`, and `urgent`

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000` in a browser. The app also respects the `PORT` environment variable:

```bash
PORT=5000 python app.py
```

Scan history is kept in the browser's local storage. The Flask server does not store URLs, and the analyzer never makes a request to a submitted URL.

## Important note

This is an educational prototype, not a reliable real-world phishing detector. A clean result does not mean a URL is safe.