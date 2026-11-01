import importlib
import sys
from pathlib import Path

import pytest


BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


@pytest.fixture()
def app_modules(tmp_path, monkeypatch):
    db_path = tmp_path / "test-bank.db"
    monkeypatch.setenv("DB_PATH", str(db_path))
    monkeypatch.setenv("DEMO_MODE", "true")
    monkeypatch.setenv("DAILY_YELLOW_LIMIT", "1000")
    monkeypatch.setenv("DAILY_TRANSFER_LIMIT", "50000")

    from app import config

    importlib.reload(config)

    from app import db, security, seed

    importlib.reload(db)
    importlib.reload(seed)
    importlib.reload(security)
    seed.seed()

    yield {"db": db, "security": security, "db_path": db_path}
