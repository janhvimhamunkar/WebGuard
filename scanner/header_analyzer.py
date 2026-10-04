from .findings import make, PASS_SEV

HEADERS = [
 ("Content-Security-Policy", "Medium", "CSP restricts which sources of scripts and content a browser may load.",
  "Helps limit the impact of content-injection issues such as XSS.",
  "Define a Content-Security-Policy suited to the application; test in report-only mode first."),
 ("Strict-Transport-Security", "Medium", "HSTS tells browsers to use HTTPS only for this site.",
  "Reduces exposure to protocol downgrade and some man-in-the-middle scenarios.",
  "Send Strict-Transport-Security (e.g. max-age=31536000; includeSubDomains) over HTTPS."),
 ("X-Content-Type-Options", "Low", "Prevents browsers from MIME-sniffing responses.",
  "MIME sniffing can cause content to be interpreted as an unexpected type.", "Set X-Content-Type-Options: nosniff."),
 ("X-Frame-Options", "Low", "Controls whether the page may be embedded in frames.",
  "Missing framing controls may allow clickjacking-style attacks.",
  "Set X-Frame-Options: DENY/SAMEORIGIN or use CSP frame-ancestors."),
 ("Referrer-Policy", "Low", "Controls how much referrer information is sent to other sites.",
  "URLs may leak to third parties through the Referer header.",
  "Set Referrer-Policy: strict-origin-when-cross-origin (or stricter)."),
 ("Permissions-Policy", "Low", "Restricts access to browser features (camera, geolocation, ...).",
  "Unrestricted feature access increases exposure if embedded content misbehaves.",
  "Define a Permissions-Policy that disables unused browser features."),
]

def analyze_headers(headers, is_https):
    h = {k.lower(): v for k, v in headers.items()}
    csp = h.get("content-security-policy", "")
    out = []
    for name, sev, desc, why, rec in HEADERS:
        if name == "Strict-Transport-Security" and not is_https:
            continue  # only meaningful over HTTPS; the HTTPS finding covers plain HTTP
        value = h.get(name.lower())
        if name == "X-Frame-Options" and value is None and "frame-ancestors" in csp.lower():
            value = "(covered by CSP frame-ancestors)"
        present = value is not None
        out.append(make(id=f"hdr-{name.lower()}", name=name, category="headers",
            severity=PASS_SEV if present else sev, present=present, value=value,
            description=f"{name} is present. {desc}" if present else f"Detected configuration issue: {name} is missing. {desc}",
            why=why, recommendation="No action required." if present else rec + " Manual verification may be required.",
            evidence=f"{name}: {value}" if present else f"{name} not observed in the response.",
            owasp="A05:2021 Security Misconfiguration"))
    return out
