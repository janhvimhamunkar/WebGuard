import pytest
from scanner.url_validator import validate_url, InvalidTarget
import config

def test_valid_urls():
    assert validate_url("http://example.com") == "http://example.com"
    assert validate_url("https://example.com/") == "https://example.com/"

def test_invalid_urls():
    with pytest.raises(InvalidTarget):
        validate_url("not a url")
    with pytest.raises(InvalidTarget):
        validate_url("ftp://example.com")

def test_private_targets():
    config.ALLOW_PRIVATE_TARGETS = False
    with pytest.raises(InvalidTarget):
        validate_url("http://127.0.0.1")
    config.ALLOW_PRIVATE_TARGETS = True
    assert validate_url("http://127.0.0.1") == "http://127.0.0.1"
