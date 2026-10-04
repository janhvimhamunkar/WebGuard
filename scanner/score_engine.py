DEDUCT = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Informational": 0}

def calculate(findings):
    uniq = list({f["id"]: f for f in findings}.values())   # never count the same finding twice
    issues = [f for f in uniq if f["severity"] != "Pass"]
    n = lambda s: sum(1 for f in issues if f["severity"] == s)
    score = max(0, min(100, 100 - sum(DEDUCT[f["severity"]] for f in issues)))
    
    if score >= 90: rating = "Strong Configuration"
    elif score >= 75: rating = "Generally Well Configured"
    elif score >= 50: rating = "Needs Improvement"
    elif score >= 25: rating = "Weak Configuration"
    else: rating = "Significant Configuration Issues"
    
    risk_score = 100 - score
    if risk_score <= 10: risk_level = "LOW RISK"
    elif risk_score <= 25: risk_level = "MODERATE RISK"
    elif risk_score <= 50: risk_level = "ELEVATED RISK"
    elif risk_score <= 75: risk_level = "HIGH RISK"
    else: risk_level = "CRITICAL RISK"
    
    return {"score": score, "rating": rating, "risk_score": risk_score, "risk_level": risk_level, "total_findings": len(issues), "critical": n("Critical"), "high": n("High"),
            "medium": n("Medium"), "low": n("Low"), "info": n("Informational"),
            "passed": sum(1 for f in uniq if f["severity"] == "Pass")}
