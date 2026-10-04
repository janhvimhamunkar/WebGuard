import re
from .findings import make, PASS_SEV

def analyze_exposure(headers):
    h = {k.lower(): v for k, v in headers.items()}
    out = []
    for name in ("Server", "X-Powered-By", "X-AspNet-Version"):
        v = h.get(name.lower())
        sev = PASS_SEV if v is None else ("Low" if re.search(r"\d+\.\d+", v) else "Informational")
        out.append(make(id=f"exp-{name.lower()}", name=f"{name} header", category="exposure", severity=sev,
            present=v is not None, value=v,
            description=f"{name} discloses '{v}'." if v else f"{name} is not exposed.",
            why="Technology details can help profiling. This is not proof the application is exploitable.",
            recommendation="No action required." if v is None else "Consider removing or minimizing version details.",
            evidence=f"{name}: {v}" if v else "", owasp="A05:2021 Security Misconfiguration"))
    return out
