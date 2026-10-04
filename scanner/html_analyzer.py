from bs4 import BeautifulSoup
from urllib.parse import urlparse
from .findings import make, PASS_SEV
import re

def analyze_html(html_content, final_url):
    out = []
    if not html_content:
        return out
        
    soup = BeautifulSoup(html_content, 'html.parser')
    is_https = urlparse(final_url).scheme == "https"
    
    # 1. Check forms
    forms = soup.find_all('form')
    if forms:
        out.append(make("html-forms", "HTML Forms Detected", "html", "Informational",
            f"Found {len(forms)} form(s) on the page.", "Forms are typical entry points for injection and should be reviewed.",
            "Ensure input validation and CSRF protection are in place.", "", ""))
            
        for i, form in enumerate(forms):
            action = form.get('action', '')
            action_url = urlparse(action)
            # Forms submitting over HTTP
            if action_url.scheme == 'http' and is_https:
                out.append(make(f"html-form-http-{i}", "Form Submits over HTTP", "html", "High",
                    "A form on an HTTPS page submits data to a plain HTTP URL.", "Data sent over HTTP is unencrypted.",
                    "Change the form action to use HTTPS.", f"Form action: {action}", "A02:2021 Cryptographic Failures"))
                    
            # Check for password fields
            passwords = form.find_all('input', type=re.compile('password', re.I))
            if passwords and action_url.scheme != 'https' and not (not action_url.scheme and is_https):
                # If action is relative and page is https, it's https.
                # If action is explicit http, or page is http
                out.append(make(f"html-form-pwd-{i}", "Password Form Insecure Submission", "html", "High",
                    "A form with a password field may submit over an insecure connection.", "Credentials will be exposed.",
                    "Ensure the page and form action are HTTPS.", f"Form action: {action}", "A07:2021 Identification and Authentication Failures"))
                    
    # 2. Mixed Content
    if is_https:
        mixed_scripts = [s.get('src') for s in soup.find_all('script', src=True) if urlparse(s.get('src')).scheme == 'http']
        if mixed_scripts:
            out.append(make("html-mixed-scripts", "Mixed Content: Scripts", "html", "High",
                f"Found {len(mixed_scripts)} script(s) loaded over HTTP on an HTTPS page.", "Active mixed content can compromise the entire page.",
                "Load all scripts over HTTPS.", f"Example: {mixed_scripts[0]}", "A05:2021 Security Misconfiguration"))
                
        mixed_img = [i.get('src') for i in soup.find_all('img', src=True) if urlparse(i.get('src')).scheme == 'http']
        if mixed_img:
            out.append(make("html-mixed-img", "Mixed Content: Images", "html", "Low",
                f"Found {len(mixed_img)} image(s) loaded over HTTP.", "Passive mixed content allows network observers to see/modify the images.",
                "Load all images over HTTPS.", f"Example: {mixed_img[0]}", "A05:2021 Security Misconfiguration"))
                
    # 3. IFrames
    iframes = soup.find_all('iframe')
    if iframes:
        out.append(make("html-iframes", "IFrames Detected", "html", "Low",
            f"Found {len(iframes)} iframe(s).", "IFrames can be used for clickjacking or loading untrusted content.",
            "Ensure framed content is trusted and consider CSP frame-ancestors.", "", "A05:2021 Security Misconfiguration"))
            
    # 4. Meta Generator
    generator = soup.find('meta', attrs={'name': lambda x: x and x.lower() == 'generator'})
    if generator:
        val = generator.get('content', '')
        out.append(make("html-meta-gen", "Meta Generator Tag", "html", "Low",
            "A meta generator tag discloses the technology stack.", "Information exposure aids in reconnaissance.",
            "Remove the meta generator tag if possible.", f"Content: {val}", "A05:2021 Security Misconfiguration"))
            
    # 5. Debug indicators
    html_text = soup.get_text().lower()
    if "stack trace" in html_text or "var_dump(" in html_text or "exception:" in html_text:
         out.append(make("html-debug", "Possible Debug Information", "html", "Medium",
            "Found text patterns often associated with debug output or stack traces.", "Detailed errors can expose application logic or data.",
            "Ensure debug mode is disabled in production.", "Requires manual review.", "A05:2021 Security Misconfiguration"))

    return out
