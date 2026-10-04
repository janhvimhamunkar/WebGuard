import re
from .findings import make, PASS_SEV

def _parse(raw):
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0]
    attrs = {}
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            attrs[k.lower()] = v
        else:
            attrs[p.lower()] = True
    return name, attrs

def analyze_cookies(set_cookie_headers, is_https):
    out, seen = [], set()
    for raw in set_cookie_headers:
        name, attrs = _parse(raw)
        
        path = attrs.get("path", "/")
        domain = attrs.get("domain", "")
        # Use a combination of name, domain, path to uniquely identify a cookie
        cookie_id = f"{name}:{domain}:{path}"
        if cookie_id in seen:
            continue
        seen.add(cookie_id)
        
        sess = bool(re.search(r"sess|auth|token|sid|login", name, re.I))
        
        # Build display attributes
        samesite_val = attrs.get("samesite", "Not Set") if attrs.get("samesite") is not True else "Set (No Value)"
        expires_val = attrs.get("expires", attrs.get("max-age", "Session"))
        
        attr_display = f"Path={path}; Domain={domain or '(current)'}; SameSite={samesite_val}; Expires/Max-Age={expires_val}"
        
        checks = [
          ("Secure", "secure" in attrs, "Medium" if sess else "Low", is_https,
           "Cookie may be sent over unencrypted HTTP.", "Cookie contents could be observed on insecure networks.",
           "Add the Secure attribute.", "A02:2021 Cryptographic Failures"),
          ("HttpOnly", "httponly" in attrs, "Medium" if sess else "Low", True,
           "Cookie is readable by client-side scripts.", "If script injection exists elsewhere, the cookie could be read.",
           "Add HttpOnly unless scripts genuinely need the cookie.", "A07:2021 Identification and Authentication Failures"),
          ("SameSite", "samesite" in attrs, "Low", True,
           "No SameSite attribute set.", "Cookie may be sent on cross-site requests, relevant to CSRF defenses.",
           "Set SameSite=Lax or Strict.", "A05:2021 Security Misconfiguration"),
        ]
        
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '', name)
        
        for attr, ok, sev, applicable, desc, why, rec, owasp in checks:
            if not applicable:
                continue
            out.append(make(id=f"cookie-{safe_name}-{attr}-{len(seen)}", name=f"Cookie '{name}': {attr}", category="cookies",
                severity=PASS_SEV if ok else sev, present=ok,
                description=f"{attr} attribute is set." if ok else "Potential security concern: " + desc, why=why,
                recommendation="No action required." if ok else rec + " Manual verification may be required.",
                evidence=f"Set-Cookie: {name}=<redacted>; {attr_display}", owasp=owasp))
    return out
