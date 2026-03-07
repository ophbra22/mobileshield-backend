"""Modular phishing detection engine components."""

from app.detection.engine import run_detection
from app.detection.config import DEFAULT_CONFIG
from app.detection.models import DetectionResult

__all__ = ['run_detection', 'DEFAULT_CONFIG', 'DetectionResult']
