PASS_SEV = "Pass"
STATUS = {"Pass": "PASS", "Informational": "INFO", "Low": "WARNING", "Medium": "WARNING",
          "High": "HIGH", "Critical": "CRITICAL"}

def make(id, name, category, severity, description, why, recommendation,
         evidence="", owasp="", present=None, value=None):
    return {"id": id, "name": name, "category": category, "severity": severity,
            "status": STATUS[severity], "description": description, "why": why,
            "recommendation": recommendation, "evidence": evidence, "owasp": owasp,
            "present": present, "value": value}
