from scanner.score_engine import calculate

def test_score_calculation():
    findings = [
        {"id": "1", "severity": "Critical"},
        {"id": "2", "severity": "High"},
        {"id": "3", "severity": "Medium"}
    ]
    res = calculate(findings)
    assert res["score"] == 52
    assert res["rating"] == "Needs Improvement"

def test_duplicate_handling():
    findings = [
        {"id": "1", "severity": "Critical"},
        {"id": "1", "severity": "Critical"}
    ]
    res = calculate(findings)
    assert res["score"] == 75

def test_score_boundaries():
    findings = [{"id": str(i), "severity": "Critical"} for i in range(10)]
    res = calculate(findings)
    assert res["score"] == 0
