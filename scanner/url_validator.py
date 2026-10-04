import ipaddress, socket
from urllib.parse import urlparse
import config

class InvalidTarget(Exception):
    pass

def validate_url(url):
    """Return a normalized URL or raise InvalidTarget."""
    url = (url or "").strip()
    if not url or len(url) > config.MAX_URL_LENGTH:
        raise InvalidTarget("Please enter a valid URL (max 2048 characters).")
    try:
        p = urlparse(url)
        host, port = p.hostname, p.port
    except ValueError:
        raise InvalidTarget("The URL is malformed.")
    if p.scheme not in ("http", "https") or not host:
        raise InvalidTarget("URL must start with http:// or https:// and include a hostname.")
    if p.username or p.password:
        raise InvalidTarget("URLs containing credentials are not allowed.")
    try:
        infos = socket.getaddrinfo(host, port or (443 if p.scheme == "https" else 80))
    except socket.gaierror:
        raise InvalidTarget("DNS lookup failed: the hostname could not be resolved.")
    if not config.ALLOW_PRIVATE_TARGETS:
        for info in infos:
            if not ipaddress.ip_address(info[4][0]).is_global:
                raise InvalidTarget("Private, loopback and reserved addresses cannot be scanned.")
    return p.geturl()
