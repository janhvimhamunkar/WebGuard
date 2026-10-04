"""Passive scan orchestrator: one URL, headers only, no body download, no JS, no forms, no auth."""
import time, requests
from urllib.parse import urljoin, urlparse
import config
from .url_validator import validate_url, InvalidTarget
from .header_analyzer import analyze_headers
from .cookie_analyzer import analyze_cookies
from .exposure_analyzer import analyze_exposure
from .tls_analyzer import analyze_tls
from .html_analyzer import analyze_html
from . import score_engine

class ScanError(Exception):
    pass

def _fetch(url):
    """GET with manual redirects so every hop is re-validated."""
    cookies, start = [], time.time()
    original_url = url
    redirect_chain = [url]
    with requests.Session() as s:
        for _ in range(config.MAX_REDIRECTS + 1):
            r = s.get(url, allow_redirects=False, stream=True, timeout=config.REQUEST_TIMEOUT,
                      headers={"User-Agent": config.USER_AGENT})
            cookies += r.raw.headers.getlist("Set-Cookie")
            if r.is_redirect and r.headers.get("Location"):
                nxt = validate_url(urljoin(url, r.headers["Location"]))
                r.close()
                url = nxt
                redirect_chain.append(url)
                continue
            
            headers, code = dict(r.headers), r.status_code
            html_content = ""
            if "text/html" in headers.get("Content-Type", "").lower():
                html_content = r.raw.read(2 * 1024 * 1024).decode('utf-8', errors='ignore')
                
            ms = round((time.time() - start) * 1000)
            r.close()
            return original_url, url, redirect_chain, code, headers, cookies, ms, html_content
    raise ScanError("Redirect problem: too many redirects (limit %d)." % config.MAX_REDIRECTS)

def run_scan(url):
    try:
        url = validate_url(url)
        original_url, final_url, redirect_chain, code, headers, cookies, ms, html_content = _fetch(url)
    except InvalidTarget as e:
        raise ScanError(str(e))
    except ScanError:
        raise
    except requests.exceptions.SSLError:
        raise ScanError("SSL certificate error: the certificate could not be verified.")
    except requests.exceptions.ConnectTimeout:
        raise ScanError("Connection timed out while contacting the target.")
    except requests.exceptions.ReadTimeout:
        raise ScanError("The target took too long to respond (timeout).")
    except requests.exceptions.TooManyRedirects:
        raise ScanError("Redirect problem: too many redirects.")
    except requests.exceptions.ConnectionError:
        raise ScanError("Connection failed: refused, reset, or host unreachable.")
    except Exception:
        raise ScanError("Unexpected error while scanning this target.")
    
    is_https = urlparse(final_url).scheme == "https"
    original_protocol = urlparse(original_url).scheme
    final_protocol = "https" if is_https else "http"
    
    findings = []
    
    if original_protocol == "http" and final_protocol == "https":
        from .findings import make, PASS_SEV
        findings.append(make("tls-redirect", "HTTP to HTTPS Redirect", "tls", PASS_SEV,
                             "The target successfully redirected from HTTP to HTTPS.",
                             "Ensures users are securely upgraded to an encrypted connection.",
                             "No action required.", "Redirect chain: " + " -> ".join(redirect_chain),
                             "A02:2021 Cryptographic Failures"))

    findings += analyze_tls(final_url) + analyze_headers(headers, is_https) \
        + analyze_cookies(cookies, is_https) + analyze_exposure(headers) + analyze_html(html_content, final_url)
        
    note = {403: "HTTP 403: access forbidden. The server may block automated requests; results may be partial.",
            404: "HTTP 404: page not found. Headers of the error response were analyzed.",
            500: "HTTP 500: the target returned a server error; results may be partial."}.get(code) \
        or (f"HTTP {code} returned; results may be partial." if code >= 400 else None)
        
    redirect_information = {
        "original_url": original_url,
        "final_url": final_url,
        "redirect_count": len(redirect_chain) - 1,
        "redirect_chain": redirect_chain,
        "original_protocol": original_protocol,
        "final_protocol": final_protocol
    }
        
    return {"target_url": url, "final_url": final_url, "status_code": code, "https": is_https,
            "response_time_ms": ms, "redirect_information": redirect_information, "note": note, 
            "findings": findings, "summary": score_engine.calculate(findings)}
