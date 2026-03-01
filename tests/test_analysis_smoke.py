import pytest
from sqlalchemy.exc import OperationalError

from app.analysis import analyze_url
from app.db.database import SessionLocal


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com",
        "http://bit.ly",
    ],
)
def test_analyze_smoke(url):
    db = SessionLocal()
    try:
        res = analyze_url(url, db)
    except OperationalError:
        pytest.skip("DB not ready")
    finally:
        db.close()
    assert res.normalized_url
    assert res.signals.get("redirect_chain") is not None
    assert res.breakdown is not None
