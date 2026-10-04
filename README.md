# WebGuard: Automated Web Application Security Assessment and Vulnerability Reporting System

Educational, **passive and non-destructive** web security assessment tool (Flask + SQLite + Bootstrap 5).
**Use only against websites you own or are explicitly authorized to test.**

## Features
- URL validation, reachability, status code, redirects tracking and chains, response time
- Security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- Cookie analysis (Secure, HttpOnly, SameSite, domain/path specific), HTTPS/TLS checks (protocol, certificate validity, issuer, subject)
- HTML Analysis (insecure forms, mixed content, iframes, meta generators, debug indicators)
- Explainable score (100 minus Critical 25 / High 15 / Medium 8 / Low 3), configuration ratings, OWASP educational mapping
- Dashboard, scan history (SQLite), safe scan deletion
- Real PDF generation for offline reports

## Architecture
`app.py` routes -> `scanner/` (url_validator, header/cookie/exposure/tls/html analyzers, score_engine, pdf_generator) -> `models/database.py` (SQLite) -> Jinja templates in `templates/`.

## Installation (macOS)
```
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

## Safety design
Only the submitted URL is requested (response body downloaded up to 2MB); 10s timeout; max 5 redirects, each re-validated;
no JavaScript execution, form submission, authentication or crawling; private/loopback targets blocked (set `WEBGUARD_ALLOW_PRIVATE=1` only to test against your own local lab server); no stack traces shown to users.

## Tests
Run tests using:
```
python3 -m pytest tests/
```

## Notes
Bootstrap is loaded from a CDN, so an internet connection is needed for styling. Results are indicators, not proof of exploitability; manual verification may be required.
