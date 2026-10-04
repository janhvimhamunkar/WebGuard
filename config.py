import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SECRET_KEY = os.environ.get("WEBGUARD_SECRET", "dev-only-change-me")
DATABASE = os.path.join(BASE_DIR, "database", "webguard.db")
REQUEST_TIMEOUT = 10          # seconds
MAX_REDIRECTS = 5
MAX_URL_LENGTH = 2048
USER_AGENT = "WebGuard-Educational-Scanner/1.0 (passive; authorized use only)"
# Blocks localhost/private IPs (SSRF protection). Set WEBGUARD_ALLOW_PRIVATE=1 only for local lab testing.
ALLOW_PRIVATE_TARGETS = os.environ.get("WEBGUARD_ALLOW_PRIVATE") == "1"
