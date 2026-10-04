import socket, ssl, datetime
from urllib.parse import urlparse
import config
from .findings import make, PASS_SEV

OW = "A02:2021 Cryptographic Failures"

def format_name(name):
    try:
        return ", ".join(f"{k}={v}" for part in name for k, v in part)
    except Exception:
        return str(name)

def analyze_tls(final_url):
    p = urlparse(final_url)
    if p.scheme != "https":
        return [make("tls-https", "HTTPS not used", "tls", "High", "The final URL is served over plain HTTP.",
            "Traffic can potentially be read or modified on the network path.",
            "Serve the site over HTTPS and redirect HTTP to HTTPS.", f"Final URL: {final_url}", OW)]
    
    out = [make("tls-https", "HTTPS in use", "tls", PASS_SEV, "The final URL uses HTTPS.",
                "Encrypts traffic in transit.", "No action required.", f"Final URL: {final_url}", OW)]
    
    try:
        with socket.create_connection((p.hostname, p.port or 443), timeout=config.REQUEST_TIMEOUT) as s:
            with ssl.create_default_context().wrap_socket(s, server_hostname=p.hostname) as t:
                ver, cert = t.version(), t.getpeercert()
        exp = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), datetime.timezone.utc)
        val_from = datetime.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), datetime.timezone.utc)
        
        out.append(make("tls-verify", "Certificate verification successful", "tls", PASS_SEV,
            "The certificate is signed by a trusted authority.", "Ensures the identity of the server.", "No action required.", "", OW))
            
    except ssl.SSLCertVerificationError as e:
        out.append(make("tls-verify", "Certificate verification failed", "tls", "High",
            "The certificate could not be verified.", "This may indicate an invalid, self-signed, or improperly configured certificate chain.",
            "Ensure the certificate is issued by a trusted CA and the full chain is provided.", str(e), OW))
        return out
    except Exception as e:
        out.append(make("tls-info", "TLS details unavailable", "tls", "Informational",
            "Could not read certificate details.", "Manual verification may be required.",
            "Check the certificate with a dedicated TLS tool.", str(e)[:200]))
        return out

    weak = ver in ("TLSv1", "TLSv1.1", "SSLv3")
    out.append(make("tls-version", f"Negotiated protocol: {ver}", "tls", "Medium" if weak else PASS_SEV,
        "Deprecated protocol negotiated." if weak else "Modern TLS protocol negotiated.",
        "Older protocol versions have known weaknesses.",
        "Disable TLS 1.0/1.1; support TLS 1.2+." if weak else "No action required.", f"Protocol: {ver}", OW))
        
    days = (exp - datetime.datetime.now(datetime.timezone.utc)).days
    
    if days < 0:
        out.append(make("tls-expiry", "Certificate is expired", "tls", "Critical",
            "The certificate has expired.", "Browsers will block access to the site.",
            "Renew the certificate immediately.", f"notAfter: {cert['notAfter']} ({days} days ago)", OW))
    elif days < 30:
        out.append(make("tls-expiry", f"Certificate expires in {days} days", "tls", "Medium",
            "Certificate expires soon.", "Expired certificates cause browser warnings and outages.",
            "Renew the certificate / enable automatic renewal.", f"notAfter: {cert['notAfter']}", OW))
    else:
        out.append(make("tls-expiry", f"Certificate is valid for {days} days", "tls", PASS_SEV,
            "Certificate validity period is healthy.", "No action required.", "", f"notAfter: {cert['notAfter']}", OW))
            
    # Add subject and issuer findings (informational)
    subject = format_name(cert.get("subject", ()))
    issuer = format_name(cert.get("issuer", ()))
    
    out.append(make("tls-subject", "Certificate Subject", "tls", "Informational",
        "The subject of the certificate.", "Identity information.", "No action required.", subject, OW))
    out.append(make("tls-issuer", "Certificate Issuer", "tls", "Informational",
        "The issuer of the certificate.", "Authority information.", "No action required.", issuer, OW))

    return out
