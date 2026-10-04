import os
import pytest
import config
from models import database as db

@pytest.fixture(autouse=True)
def setup_db(tmp_path):
    config.DATABASE = str(tmp_path / "test.db")
    db.init_db()

def test_save_and_read():
    result = {
        "target_url": "http://example.com",
        "summary": {"score": 80, "rating": "Good", "total_findings": 2, "critical": 0, "high": 0, "medium": 1, "low": 1, "passed": 5}
    }
    scan_id = db.save_scan(result)
    assert scan_id > 0
    
    scan = db.get_scan(scan_id)
    assert scan["target_url"] == "http://example.com"
    assert scan["summary"]["score"] == 80
