from scanner.cookie_analyzer import analyze_cookies

def test_cookie_parsing():
    headers = ["session_id=123; Secure; HttpOnly; SameSite=Strict; Path=/"]
    findings = analyze_cookies(headers, is_https=True)
    assert len(findings) > 0
    secure_finding = next(f for f in findings if f["name"].endswith(": Secure"))
    assert secure_finding["severity"] == "Pass"
