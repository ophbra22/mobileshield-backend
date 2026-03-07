from __future__ import annotations

from app.detection.config import DEFAULT_CONFIG, DetectionConfig
from app.detection.models import ClassificationStatus, Confidence
from app.detection.risk_scorer import ScoreResult


def classify(score: ScoreResult, config: DetectionConfig = DEFAULT_CONFIG) -> tuple[ClassificationStatus, Confidence]:
    thresholds = config.thresholds
    strong = len(set(score.strong))
    medium = len(set(score.medium))

    status: ClassificationStatus = 'legitimate'

    # Multi-signal gating to prevent single weak triggers
    if score.total >= thresholds.suspicious_max + 1:
        if strong >= 2 or (strong >= 1 and medium >= 1) or score.total >= 80:
            status = 'phishing'
        elif medium >= 3:
            status = 'phishing'
        else:
            status = 'suspicious'
    elif score.total > thresholds.legitimate_max or strong >= 1 or medium >= 2:
        status = 'suspicious'

    confidence: Confidence
    if status == 'phishing' and (strong >= 2 or score.total >= 80):
        confidence = 'high'
    elif status == 'suspicious' and (strong >= 1 or medium >= 2):
        confidence = 'medium'
    else:
        confidence = 'low'

    return status, confidence
