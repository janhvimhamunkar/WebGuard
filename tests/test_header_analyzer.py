from scanner.header_analyzer import analyze_headers

def test_missing_headers():
    findings = analyze_headers({}, is_https=True)
    assert len(findings) > 0
    csp = next(f for f in findings if f["name"] == "Content-Security-Policy")
    assert csp["severity"] == "Medium"
    assert csp["present"] is False

def test_present_headers():
    findings = analyze_headers({"Content-Security-Policy": "default-src 'self'"}, is_https=True)
    csp = next(f for f in findings if f["name"] == "Content-Security-Policy")
    assert csp["severity"] == "Pass"
    assert csp["present"] is True
