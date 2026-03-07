from __future__ import annotations

from sqlalchemy.orm import Session

from app.detection.engine import run_detection
from app.detection.models import DetectionResult


def analyze_url(raw_url: str, db: Session, resolver=None) -> DetectionResult:
    """
    High-level entrypoint used by the API and tests.
    Delegates to the modular detection engine.
    """
    return run_detection(raw_url, db, resolver=resolver)


def analyze_text_or_url(text: str, db: Session, resolver=None) -> DetectionResult:
    """For now, treat input as URL; future SMS/text parsing can be added."""
    return analyze_url(text, db, resolver=resolver)
